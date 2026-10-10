#include "edgevitals/WinEvents.h"

#include "edgevitals/Json.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>

namespace ev {
namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool ieq(const std::string& a, const std::string& b) { return lower(a) == lower(b); }

std::string esc(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            default:
                if (c < 0x20) {
                    char b[8];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), "\\u%04x", ...)
                    (void)std::snprintf(b, sizeof(b), "\\u%04x", c);
                    o += b;
                } else {
                    o.push_back(static_cast<char>(c));
                }
        }
    }
    return o;
}
std::string q(const std::string& s) { return "\"" + esc(s) + "\""; }

// ── XML helpers: bounded scanning, no allocation beyond the output ─────────

std::string decodeEntities(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '&') { o.push_back(s[i]); continue; }
        const size_t semi = s.find(';', i);
        if (semi == std::string::npos || semi - i > 10) { o.push_back('&'); continue; }
        const std::string ent = s.substr(i + 1, semi - i - 1);
        if (ent == "amp") o.push_back('&');
        else if (ent == "lt") o.push_back('<');
        else if (ent == "gt") o.push_back('>');
        else if (ent == "quot") o.push_back('"');
        else if (ent == "apos") o.push_back('\'');
        else if (!ent.empty() && ent[0] == '#') {
            const long v = ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X')
                               ? std::strtol(ent.c_str() + 2, nullptr, 16)
                               : std::strtol(ent.c_str() + 1, nullptr, 10);
            // ASCII only; anything else becomes '?' (values are identifiers,
            // codes and names, not prose).
            o.push_back(v > 0 && v < 128 ? static_cast<char>(v) : '?');
        } else {
            o.push_back('?');
        }
        i = semi;
    }
    return o;
}

// Value of attribute `name` inside the tag text [tagStart, tagEnd).
std::string attr(const std::string& x, size_t tagStart, size_t tagEnd, const std::string& name) {
    size_t p = tagStart;
    while (p < tagEnd) {
        const size_t a = x.find(name, p);
        if (a == std::string::npos || a >= tagEnd) return std::string();
        const bool boundary = a > 0 && std::isspace(static_cast<unsigned char>(x[a - 1]));
        size_t e = a + name.size();
        while (e < tagEnd && std::isspace(static_cast<unsigned char>(x[e]))) ++e;
        if (boundary && e < tagEnd && x[e] == '=') {
            ++e;
            while (e < tagEnd && std::isspace(static_cast<unsigned char>(x[e]))) ++e;
            if (e < tagEnd && (x[e] == '"' || x[e] == '\'')) {
                const char qc = x[e];
                const size_t end = x.find(qc, e + 1);
                if (end == std::string::npos || end > tagEnd) return std::string();
                return decodeEntities(x.substr(e + 1, end - e - 1));
            }
        }
        p = a + name.size();
    }
    return std::string();
}

// Finds <tag ...> (not </tag>) from pos; returns start and end ('>' index).
bool findTag(const std::string& x, const std::string& tag, size_t from, size_t limit, size_t& s, size_t& e) {
    size_t p = from;
    const std::string openTag = "<" + tag;
    while (true) {
        p = x.find(openTag, p);
        if (p == std::string::npos || p >= limit) return false;
        const size_t after = p + openTag.size();
        if (after < x.size() && (x[after] == '>' || x[after] == '/' || std::isspace(static_cast<unsigned char>(x[after])))) {
            const size_t gt = x.find('>', after);
            if (gt == std::string::npos || gt >= limit) return false;
            s = p;
            e = gt;
            return true;
        }
        p = after;
    }
}

// Text between <tag ...> and </tag>; empty if self-closing or missing.
std::string elementText(const std::string& x, const std::string& tag, size_t from, size_t limit) {
    size_t s, e;
    if (!findTag(x, tag, from, limit, s, e)) return std::string();
    if (x[e - 1] == '/') return std::string();
    const size_t close = x.find("</" + tag, e);
    if (close == std::string::npos || close > limit) return std::string();
    return decodeEntities(x.substr(e + 1, close - e - 1));
}

// Digits only, at most maxDigits, value <= maxValue; otherwise -1. Replaces
// atoi, which has undefined behaviour on overflow -- and any program can
// write an event with whatever text it likes.
int boundedUInt(std::string s, size_t maxDigits, int maxValue) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    s = s.substr(b);
    if (s.empty() || s.size() > maxDigits) return -1;
    int v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (c - '0');
    }
    return v <= maxValue ? v : -1;
}

const char* levelName(int level) {
    switch (level) {
        case 1: return "critical";
        case 2: return "error";
        case 3: return "warning";
        default: return "info";
    }
}

std::string isoNowFromRecord(const std::string& t) { return t; }

}  // namespace

// ── config ──────────────────────────────────────────────────────────────────

WinEventsConfig defaultWinEventsConfig() {
    WinEventsConfig c;
    c.channels = {
        {"System", true, 2},
        {"Application", true, 2},
        {"Security", false, 0},   // only with the bank's approval
        {"Microsoft-Windows-Windows Defender/Operational", false, 0},
        {"Microsoft-Windows-CodeIntegrity/Operational", false, 0},
    };
    c.rules = {
        {"unexpected_restart", "System", "Microsoft-Windows-Kernel-Power", {41}, "critical"},
        {"bugcheck", "System", "BugCheck", {1001}, "critical"},
        {"unexpected_shutdown", "System", "EventLog", {6008}, "critical"},
        {"os_start_stop", "System", "Microsoft-Windows-Kernel-General", {12, 13}, "info"},
        {"clock_changed", "System", "Microsoft-Windows-Kernel-General", {1}, "warning"},
        {"log_cleared", "System", "Microsoft-Windows-Eventlog", {104}, "critical"},
        {"service_crashed", "System", "Service Control Manager", {7031, 7034}, "error"},
        {"service_failed_start", "System", "Service Control Manager", {7000, 7009, 7023}, "error"},
        {"service_installed", "System", "Service Control Manager", {7045}, "warning"},
        {"disk_error", "System", "disk", {7, 11, 51, 153}, "error"},
        {"filesystem_corrupt", "System", "Ntfs", {55}, "critical"},
        {"hardware_error", "System", "Microsoft-Windows-WHEA-Logger", {17, 18, 19, 47}, "critical"},
        {"low_memory", "System", "Microsoft-Windows-Resource-Exhaustion-Detector", {2004}, "critical"},
        {"shadow_copies_removed", "System", "volsnap", {25, 36}, "warning"},
        {"driver_load_failed", "System", "Microsoft-Windows-Kernel-PnP", {219}, "warning"},
        {"removable_media", "System", "Microsoft-Windows-Kernel-PnP", {400, 410}, "warning"},
        {"usb_device", "System", "Microsoft-Windows-DriverFrameworks-UserMode", {2003, 2100, 2102}, "warning"},
        {"app_crash", "Application", "Application Error", {1000}, "error"},
        {"app_hang", "Application", "Application Hang", {1002}, "error"},
        {"security_log_cleared", "Security", "Microsoft-Windows-Eventlog", {1102}, "critical"},
        {"logon_failed", "Security", "Microsoft-Windows-Security-Auditing", {4625}, "warning"},
        {"account_changed", "Security", "Microsoft-Windows-Security-Auditing", {4720, 4722, 4724, 4732, 4740}, "warning"},
        {"service_installed_audit", "Security", "Microsoft-Windows-Security-Auditing", {4697}, "warning"},
        {"time_changed_audit", "Security", "Microsoft-Windows-Security-Auditing", {4616}, "warning"},
        {"malware_detected", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", {1116, 1117}, "critical"},
        {"realtime_protection_off", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", {5001}, "critical"},
        {"code_integrity_block", "Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity", {3033, 3077}, "warning"},
    };
    c.deniedFieldWords = {"user", "account", "path", "file", "image", "domain", "sid",
                          "workstation", "ip", "address", "computer", "machine", "command", "subject",
                          "target", "member", "client", "host", "url", "query", "principal", "email"};
    return c;
}

bool parseWinEventsConfig(const Json& h, WinEventsConfig& out, std::string& err) {
    WinEventsConfig c = defaultWinEventsConfig();
    if (h.isObject()) {
        c.enabled = h["enabled"].asBool(c.enabled);
        if (h.has("channels")) {
            c.channels.clear();
            const Json& a = h["channels"];
            for (size_t i = 0; i < a.size(); ++i) {
                WinEventChannel ch;
                ch.name = a[i]["name"].asString();
                ch.enabled = a[i]["enabled"].asBool(false);
                ch.forwardUnlistedMaxLevel = static_cast<int>(a[i]["forward_unlisted_max_level"].asInt(0));
                if (ch.name.empty()) { err = "winevents.channels[" + std::to_string(i) + "] has no name"; return false; }
                if (ch.forwardUnlistedMaxLevel < 0) ch.forwardUnlistedMaxLevel = 0;
                if (ch.forwardUnlistedMaxLevel > 3) ch.forwardUnlistedMaxLevel = 3;   // never informational
                c.channels.push_back(ch);
            }
        }
        if (h.has("rules")) {
            c.rules.clear();
            const Json& a = h["rules"];
            for (size_t i = 0; i < a.size(); ++i) {
                WinEventRule r;
                r.name = a[i]["name"].asString();
                r.channel = a[i]["channel"].asString();
                r.provider = a[i]["provider"].asString();
                r.severity = a[i]["severity"].asString("warning");
                const Json& fl = a[i]["fields"];
                for (size_t k = 0; k < fl.size(); ++k)
                    if (!fl[k].asString().empty()) r.fields.push_back(fl[k].asString());
                const Json& ids = a[i]["ids"];
                for (size_t k = 0; k < ids.size(); ++k) {
                    const long long v = ids[k].asInt(-1);
                    if (v >= 0 && v <= 65535) r.ids.push_back(static_cast<int>(v));
                }
                if (r.name.empty() || r.provider.empty() || r.ids.empty()) {
                    err = "winevents.rules[" + std::to_string(i) + "] needs name, provider and ids";
                    return false;
                }
                if (r.severity != "critical" && r.severity != "error" && r.severity != "warning" && r.severity != "info")
                    r.severity = "warning";
                c.rules.push_back(r);
            }
        }
        c.backfillHours = static_cast<int>(h["backfill_hours"].asInt(c.backfillHours));
        c.maxPerTick = static_cast<int>(h["max_per_tick"].asInt(c.maxPerTick));
        const Json& rl = h["rate_limits"];
        if (rl.isObject()) {
            c.perKeyPerHour = static_cast<int>(rl["per_key_per_hour"].asInt(c.perKeyPerHour));
            c.perMinute = static_cast<int>(rl["per_minute"].asInt(c.perMinute));
            c.perDay = static_cast<int>(rl["per_day"].asInt(c.perDay));
            c.summaryEverySec = rl["summary_every_s"].asNumber(c.summaryEverySec);
        }
        const Json& pv = h["privacy"];
        if (pv.isObject()) {
            c.maxFields = static_cast<int>(pv["max_fields"].asInt(c.maxFields));
            c.maxValueLen = static_cast<int>(pv["max_value_len"].asInt(c.maxValueLen));
            if (pv.has("denied_field_words")) {
                // Additive: configuration can deny more, never fewer.
                const Json& w = pv["denied_field_words"];
                for (size_t i = 0; i < w.size(); ++i)
                    if (!w[i].asString().empty()) c.deniedFieldWords.push_back(lower(w[i].asString()));
            }
        }
    }
    // Clamps: a typo must not turn the limits off or open the floodgates.
    c.backfillHours = std::max(0, std::min(c.backfillHours, 24 * 30));
    c.maxPerTick = std::max(1, std::min(c.maxPerTick, 2000));
    c.perKeyPerHour = std::max(1, std::min(c.perKeyPerHour, 3600));
    c.perMinute = std::max(1, std::min(c.perMinute, 600));
    c.perDay = std::max(1, std::min(c.perDay, 200000));
    if (c.summaryEverySec < 30) c.summaryEverySec = 30;
    c.maxFields = std::max(0, std::min(c.maxFields, 32));
    c.maxValueLen = std::max(8, std::min(c.maxValueLen, 512));
    out = std::move(c);
    return true;
}

// ── XML ─────────────────────────────────────────────────────────────────────

bool parseEventXml(const std::string& x, WinEvent& out) {
    out = WinEvent();
    size_t sysS, sysE;
    if (!findTag(x, "System", 0, x.size(), sysS, sysE)) return false;
    const size_t sysClose = x.find("</System>", sysE);
    const size_t lim = sysClose == std::string::npos ? x.size() : sysClose;

    size_t s, e;
    if (findTag(x, "Provider", sysE, lim, s, e)) {
        out.provider = attr(x, s, e, "Name");
        out.sourceName = attr(x, s, e, "EventSourceName");
    }
    const std::string id = elementText(x, "EventID", sysE, lim);
    out.id = boundedUInt(id, 5, 65535);
    const std::string lv = elementText(x, "Level", sysE, lim);
    out.level = boundedUInt(lv, 3, 255);
    if (findTag(x, "TimeCreated", sysE, lim, s, e)) out.timeUtc = attr(x, s, e, "SystemTime");
    const std::string rid = elementText(x, "EventRecordID", sysE, lim);
    if (!rid.empty()) out.recordId = std::strtoull(rid.c_str(), nullptr, 10);
    out.channel = elementText(x, "Channel", sysE, lim);
    if ((out.provider.empty() && out.sourceName.empty()) || out.id < 0) return false;

    // EventData: <Data Name='x'>v</Data> or unnamed <Data>v</Data>.
    size_t edS, edE;
    if (findTag(x, "EventData", lim, x.size(), edS, edE) && x[edE - 1] != '/') {
        const size_t edClose = x.find("</EventData>", edE);
        const size_t edLim = edClose == std::string::npos ? x.size() : edClose;
        size_t p = edE;
        int unnamed = 0;
        while (out.data.size() < 64 && findTag(x, "Data", p, edLim, s, e)) {
            std::string name = attr(x, s, e, "Name");
            if (name.empty()) name = "data" + std::to_string(++unnamed);
            std::string val;
            if (x[e - 1] != '/') {
                const size_t close = x.find("</Data>", e);
                if (close == std::string::npos || close > edLim) break;
                val = decodeEntities(x.substr(e + 1, close - e - 1));
                p = close + 7;
            } else {
                p = e + 1;
            }
            out.data.emplace_back(name, val);
        }
        // <Binary>hex</Binary>, bounded. Hex digits only; anything else is dropped.
        size_t bS, bE;
        if (findTag(x, "Binary", edE, edLim, bS, bE) && x[bE - 1] != '/') {
            const size_t close = x.find("</Binary>", bE);
            if (close != std::string::npos && close <= edLim) {
                for (size_t i = bE + 1; i < close && out.binary.size() < 512; ++i)
                    if (std::isxdigit(static_cast<unsigned char>(x[i]))) out.binary.push_back(x[i]);
                    else { out.binary.clear(); break; }
            }
        }
    } else if (findTag(x, "UserData", lim, x.size(), edS, edE) && x[edE - 1] != '/') {
        // UserData: take leaf elements <Name>value</Name> (one wrapper deep).
        const size_t udClose = x.find("</UserData>", edE);
        const size_t udLim = udClose == std::string::npos ? x.size() : udClose;
        size_t p = edE + 1;
        while (out.data.size() < 64 && p < udLim) {
            const size_t lt = x.find('<', p);
            if (lt == std::string::npos || lt >= udLim) break;
            const size_t gt = x.find('>', lt);
            if (gt == std::string::npos || gt >= udLim) break;
            if (x[lt + 1] == '/' || x[gt - 1] == '/') { p = gt + 1; continue; }
            size_t nameEnd = lt + 1;
            while (nameEnd < gt && !std::isspace(static_cast<unsigned char>(x[nameEnd]))) ++nameEnd;
            const std::string tag = x.substr(lt + 1, nameEnd - lt - 1);
            const size_t nextLt = x.find('<', gt + 1);
            if (nextLt != std::string::npos && nextLt < udLim && x.compare(nextLt, tag.size() + 2, "</" + tag) == 0) {
                out.data.emplace_back(tag, decodeEntities(x.substr(gt + 1, nextLt - gt - 1)));
                p = nextLt + tag.size() + 3;
            } else {
                p = gt + 1;   // a wrapper element; descend
            }
        }
    }
    return true;
}

std::string buildChannelXPath(const WinEventsConfig& c, const WinEventChannel& ch) {
    std::vector<int> ids;
    for (const auto* list : {&c.rules, &c.routes})
        for (const auto& r : *list)
            if (r.channel.empty() || ieq(r.channel, ch.name))
                for (int id : r.ids)
                    if (std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
    std::string cond;
    if (ch.forwardUnlistedMaxLevel > 0)
        cond = "(Level>=1 and Level<=" + std::to_string(ch.forwardUnlistedMaxLevel) + ")";
    if (!ids.empty()) {
        std::string idc;
        for (int id : ids) idc += (idc.empty() ? "" : " or ") + std::string("EventID=") + std::to_string(id);
        cond += (cond.empty() ? "" : " or ") + std::string("(") + idc + ")";
    }
    if (cond.empty()) return std::string();
    // Bounds the first read after install (or a stale bookmark); live events
    // are always inside the window, so it costs nothing afterwards.
    const long long ms = static_cast<long long>(c.backfillHours) * 3600LL * 1000LL;
    return "*[System[(" + cond + ") and TimeCreated[timediff(@SystemTime) <= " + std::to_string(ms) + "]]]";
}

// ── privacy ─────────────────────────────────────────────────────────────────

bool fieldAllowed(const std::string& name, const std::string& value,
                  const std::vector<std::string>& deniedWords) {
    const std::string n = lower(name);
    for (const auto& w : deniedWords)
        if (!w.empty() && n.find(w) != std::string::npos) return false;
    if (value.empty()) return false;
    // Shape checks, whatever the field is called.
    if (value.find('\\') != std::string::npos || value.find('/') != std::string::npos) return false;  // paths, URLs, DOMAIN\user
    if (value.size() >= 2 && std::isalpha(static_cast<unsigned char>(value[0])) && value[1] == ':') return false;  // C:...
    if (value.find('@') != std::string::npos) return false;                                          // e-mail, UPN
    const std::string lv = lower(value);
    if (lv.rfind("s-1-", 0) == 0) return false;                                                     // SIDs
    // Dotted quads and IPv6-looking values.
    int dots = 0, digits = 0, colons = 0;
    for (char ch : value) {
        if (ch == '.') ++dots;
        else if (ch == ':') ++colons;
        else if (std::isdigit(static_cast<unsigned char>(ch))) ++digits;
    }
    if (dots == 3 && digits >= 4 && digits + dots == static_cast<int>(value.size())) return false;
    if (colons >= 2 && value.find(' ') == std::string::npos) return false;
    return true;
}

// ── filter ──────────────────────────────────────────────────────────────────

WinEventFilter::WinEventFilter(WinEventsConfig cfg, std::map<std::string, std::string> exeToRole)
    : cfg_(std::move(cfg)), exeToRole_(std::move(exeToRole)) {
    for (auto& w : cfg_.deniedFieldWords) w = lower(w);
}

const WinEventRule* WinEventFilter::match(const WinEvent& e) const {
    for (const auto& r : cfg_.rules) {
        if (!r.channel.empty() && !ieq(r.channel, e.channel)) continue;
        if (!ieq(r.provider, e.provider) && !ieq(r.provider, e.sourceName)) continue;
        if (std::find(r.ids.begin(), r.ids.end(), e.id) != r.ids.end()) return &r;
    }
    return nullptr;
}

bool WinEventFilter::admit(const WinEvent& e, double now, std::string& record) {
    record.clear();
    const WinEventChannel* ch = nullptr;
    for (const auto& c : cfg_.channels)
        if (c.enabled && ieq(c.name, e.channel)) ch = &c;
    if (!ch) return false;

    const WinEventRule* r = match(e);
    if (!r && !(e.level >= 1 && e.level <= ch->forwardUnlistedMaxLevel)) return false;   // not collected
    const std::string severity = r ? r->severity : levelName(e.level);
    const std::string key = e.channel + "/" + (e.sourceName.empty() ? e.provider : e.sourceName) + "/" + std::to_string(e.id);

    // Limits. Criticals skip the global per-minute and per-day caps (they are
    // rare and are exactly what must get through) but not the per-key cap,
    // so even a critical event that repeats cannot flood.
    auto suppress = [&]() {
        ++suppressed_[key];
        ++tickSuppressed_;
        return false;
    };
    auto& pk = perKey_[key];
    if (pk.second == 0 || now - pk.first >= 3600) pk = std::make_pair(now, 0);
    if (pk.second >= cfg_.perKeyPerHour) return suppress();
    const bool critical = severity == "critical";
    while (!lastMinute_.empty() && now - lastMinute_.front() >= 60) lastMinute_.pop_front();
    if (dayStart_ < 0 || now - dayStart_ >= 86400) { dayStart_ = now; dayCount_ = 0; }
    if (!critical) {
        if (static_cast<int>(lastMinute_.size()) >= cfg_.perMinute) return suppress();
        if (dayCount_ >= cfg_.perDay) return suppress();
    }
    ++pk.second;
    lastMinute_.push_back(now);
    ++dayCount_;

    std::string fields, role;
    int nf = 0;
    for (const auto& kv : e.data) {
        if (nf >= cfg_.maxFields) break;
        if (r && !r->fields.empty()) {
            bool listed = false;
            for (const auto& name : r->fields) listed = listed || ieq(name, kv.first);
            if (!listed) continue;
        }
        if (!fieldAllowed(kv.first, kv.second, cfg_.deniedFieldWords)) continue;
        std::string v = kv.second;
        if (static_cast<int>(v.size()) > cfg_.maxValueLen) v.resize(static_cast<size_t>(cfg_.maxValueLen));
        if (role.empty()) {
            auto it = exeToRole_.find(lower(v));
            if (it != exeToRole_.end()) role = it->second;
        }
        fields += (fields.empty() ? "" : ",") + q(kv.first) + ":" + q(v);
        ++nf;
    }
    record = "{\"type\":\"winevent\",\"ts_utc\":" + q(isoNowFromRecord(e.timeUtc)) + ",\"channel\":" + q(e.channel) +
             ",\"provider\":" + q(e.provider);
    if (!e.sourceName.empty() && e.sourceName != e.provider) record += ",\"source\":" + q(e.sourceName);
    record += ",\"event_id\":" + std::to_string(e.id) + ",\"level\":" + std::to_string(e.level) +
              ",\"severity\":" + q(severity) + ",\"record_id\":" + std::to_string(e.recordId) +
              ",\"rule\":" + q(r ? r->name : "unlisted");
    if (!role.empty()) record += ",\"role\":" + q(role);
    record += ",\"fields\":{" + fields + "}}";
    ++tickRecorded_;
    lastSeverity_ = severity;
    return true;
}

bool WinEventFilter::summaryDue(double now, const std::string& tsUtc, std::string& record) {
    if (suppressed_.empty() || now - lastSummary_ < cfg_.summaryEverySec) return false;
    long long total = 0;
    std::string counts;
    for (const auto& kv : suppressed_) {
        counts += (counts.empty() ? "" : ",") + q(kv.first) + ":" + std::to_string(kv.second);
        total += kv.second;
    }
    record = "{\"type\":\"winevent_suppressed\",\"ts_utc\":" + q(tsUtc) + ",\"window_s\":" +
             std::to_string(static_cast<long long>(now - lastSummary_)) + ",\"total\":" + std::to_string(total) +
             ",\"counts\":{" + counts + "}}";
    suppressed_.clear();
    lastSummary_ = now;
    return true;
}

void WinEventFilter::takeCounts(int& recorded, int& suppressed) {
    recorded = tickRecorded_;
    suppressed = tickSuppressed_;
    tickRecorded_ = tickSuppressed_ = 0;
}

// ── daily writer ────────────────────────────────────────────────────────────

bool WinEventLog::write(const std::string& line, const Date& today) {
    if (!haveDay_ || day_ != today || !file_.isOpen()) {  // flawfinder: ignore -- ChainedFile::isOpen, not POSIX open()
        file_.close();   // seals the outgoing day
        day_ = today;
        haveDay_ = true;
        std::string err;
        const std::string p = (std::filesystem::path(dir_) / (prefix_ + today.iso() + ".jsonl")).string();
        if (!file_.open(p, err)) return false;  // flawfinder: ignore -- ChainedFile::open, which uses openLogFile
    }
    return file_.append(line + "\n");
}

}  // namespace ev
