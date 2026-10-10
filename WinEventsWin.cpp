// Windows Event Log subscriptions (wevtapi, part of Windows since Vista).
#include "edgevitals/WinEventWatcher.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winevt.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace ev {
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);  // flawfinder: ignore -- length in characters from the sizing call; buffer allocated to that size
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);  // flawfinder: ignore -- length in characters from the sizing call; buffer allocated to that size
    return w;
}

std::string narrow(const wchar_t* w, size_t len) {
    if (!w || !len) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len), &s[0], n, nullptr, nullptr);
    return s;
}

// Renders an event or bookmark handle to UTF-8 XML.
bool renderXml(EVT_HANDLE h, DWORD flags, std::string& out) {
    DWORD used = 0, props = 0;
    if (!EvtRender(nullptr, h, flags, 0, nullptr, &used, &props) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return false;
    if (used == 0 || used > 4u * 1024u * 1024u) return false;   // a 4 MB event is not an event
    std::vector<wchar_t> buf(used / sizeof(wchar_t) + 1);
    if (!EvtRender(nullptr, h, flags, used, buf.data(), &used, &props)) return false;
    size_t len = used / sizeof(wchar_t);
    while (len && buf[len - 1] == L'\0') --len;
    out = narrow(buf.data(), len);
    return true;
}

std::string safeName(const std::string& channel) {
    std::string s;
    for (char c : channel) s.push_back(std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
    return s;
}

}  // namespace

struct WinEventWatcher::Sub {
    std::string channel;
    std::string bookmarkPath;
    EVT_HANDLE sub = nullptr;
    EVT_HANDLE bookmark = nullptr;
    HANDLE signal = nullptr;
};

WinEventWatcher::WinEventWatcher(const WinEventsConfig& cfg, std::string stateDir)
    : cfg_(cfg), dir_(std::move(stateDir)) {}

WinEventWatcher::~WinEventWatcher() {
    for (Sub* s : subs_) {
        if (s->sub) EvtClose(s->sub);
        if (s->bookmark) EvtClose(s->bookmark);
        if (s->signal) CloseHandle(s->signal);
        delete s;
    }
}

std::vector<void*> WinEventWatcher::signals() const {
    std::vector<void*> v;
    for (const Sub* s : subs_)
        if (s->sub && s->signal) v.push_back(s->signal);
    return v;
}

int WinEventWatcher::activeChannels() const {
    int n = 0;
    for (const Sub* s : subs_) n += s->sub ? 1 : 0;
    return n;
}

std::vector<std::string> WinEventWatcher::start() {
    std::vector<std::string> status;
    std::error_code ec;
    fs::create_directories(dir_, ec);
    for (const auto& ch : cfg_.channels) {
        if (!ch.enabled) continue;
        const std::string xpath = buildChannelXPath(cfg_, ch);
        if (xpath.empty()) {
            status.push_back(ch.name + ": nothing configured to collect");
            continue;
        }
        Sub* s = new Sub();
        s->channel = ch.name;
        s->bookmarkPath = (fs::path(dir_) / ("winevents-bookmark-" + safeName(ch.name) + ".xml")).string();
        s->signal = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        // Resume after the saved bookmark when there is one.
        std::string saved;
        {
            std::ifstream in(s->bookmarkPath, std::ios::binary);
            if (in) {
                std::stringstream ss;
                ss << in.rdbuf();
                saved = ss.str();
            }
        }
        DWORD flags = EvtSubscribeStartAtOldestRecord;   // bounded by the XPath time window
        if (!saved.empty()) {
            s->bookmark = EvtCreateBookmark(widen(saved).c_str());
            if (s->bookmark) flags = EvtSubscribeStartAfterBookmark;
        }
        if (!s->bookmark) s->bookmark = EvtCreateBookmark(nullptr);

        s->sub = EvtSubscribe(nullptr, s->signal, widen(ch.name).c_str(), widen(xpath).c_str(),
                              flags == EvtSubscribeStartAfterBookmark ? s->bookmark : nullptr,
                              nullptr, nullptr, flags);
        if (!s->sub) {
            const DWORD e = GetLastError();
            std::string why = "error " + std::to_string(e);
            if (e == ERROR_ACCESS_DENIED) why = "access denied";
            else if (e == 15007) why = "channel not present on this machine";   // ERROR_EVT_CHANNEL_NOT_FOUND
            else if (e == 15001) why = "filter rejected";                       // ERROR_EVT_INVALID_QUERY
            status.push_back(ch.name + ": NOT subscribed (" + why + ") -- not recorded; agent continues");
        } else {
            status.push_back(ch.name + ": subscribed" +
                             (flags == EvtSubscribeStartAfterBookmark ? " (resuming after bookmark)"
                                                                      : " (first start: last " +
                                                                            std::to_string(cfg_.backfillHours) + " h)"));
        }
        subs_.push_back(s);
    }
    return status;
}

void WinEventWatcher::poll(int max, std::vector<WinEvent>& out) {
    out.clear();
    for (Sub* s : subs_) {
        if (!s->sub) continue;
        // Reset BEFORE draining: an event arriving during the drain then
        // re-signals. Resetting after (3.3) could swallow that signal, and the
        // event waited for the next tick.
        ResetEvent(s->signal);
        bool advanced = false;
        while (static_cast<int>(out.size()) < max) {
            EVT_HANDLE batch[32];
            DWORD got = 0;
            const DWORD want = static_cast<DWORD>(std::min<int>(32, max - static_cast<int>(out.size())));
            if (!EvtNext(s->sub, want, batch, 0, 0, &got)) break;   // ERROR_NO_MORE_ITEMS: drained
            for (DWORD i = 0; i < got; ++i) {
                std::string xml;
                WinEvent e;
                if (renderXml(batch[i], EvtRenderEventXml, xml) && parseEventXml(xml, e)) {
                    if (e.channel.empty()) e.channel = s->channel;
                    out.push_back(std::move(e));
                }
                EvtUpdateBookmark(s->bookmark, batch[i]);
                advanced = true;
                EvtClose(batch[i]);
            }
            if (got < want) break;
        }
        // Budget reached with events possibly left: signal again so the next
        // wait wakes for them instead of sleeping on a backlog.
        if (static_cast<int>(out.size()) >= max) SetEvent(s->signal);
        if (advanced) {
            // Saved after every batch, written to a temp file and renamed so
            // a power cut leaves the old bookmark or the new, never half.
            std::string xml;
            if (renderXml(s->bookmark, EvtRenderBookmark, xml)) {
                const std::string tmp = s->bookmarkPath + ".tmp";
                {
                    std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
                    o << xml;
                }
                std::error_code ec;
                fs::rename(tmp, s->bookmarkPath, ec);
                if (ec) {
                    fs::remove(s->bookmarkPath, ec);
                    fs::rename(tmp, s->bookmarkPath, ec);
                }
            }
        }
    }
}

}  // namespace ev
