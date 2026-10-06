// Health link transport (Windows).
//
// Pipe: message mode, newline-delimited JSON, overlapped I/O. Overlapped
// because advisories are pushed UNSOLICITED while a read is outstanding: with
// synchronous I/O a write on a handle waits for the pending read to finish,
// so a push would stall until EdgeBastion happened to send something.
//
// Access: SYSTEM plus the configured accounts (default NT SERVICE\EdgeBastion),
// network logons denied first, remote clients rejected, protected DACL so
// nothing is inherited. The DACL actually applied is logged at start.
#include "edgevitals/HealthServer.h"

#include "edgevitals/Agent.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <sddl.h>

#include <chrono>
#include <set>

namespace ev {
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

std::string narrow(const wchar_t* w) {
    if (!w) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

// Account name -> SID string. A raw SID ("S-1-...") passes through.
std::string sidFor(const std::string& account, std::string& why) {
    if (account.rfind("S-1-", 0) == 0) return account;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sid);
    wchar_t domain[256];
    DWORD domSize = 256;
    SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, widen(account).c_str(), sid, &sidSize, domain, &domSize, &use)) {
        why = "LookupAccountName error " + std::to_string(GetLastError());
        return std::string();
    }
    LPWSTR str = nullptr;
    if (!ConvertSidToStringSidW(sid, &str)) {
        why = "ConvertSidToStringSid error " + std::to_string(GetLastError());
        return std::string();
    }
    std::string out = narrow(str);
    LocalFree(str);
    return out;
}

}  // namespace

struct HealthServer::Client {
    HANDLE pipe = nullptr;
    HANDLE pushEv = nullptr;
    std::mutex mu;
    std::deque<std::string> queue;
    bool done = false;
};

HealthServer::HealthServer(HealthModel& model, ILogger& log, std::function<double()> clock)
    : model_(model), log_(log), clock_(std::move(clock)) {}

HealthServer::~HealthServer() { stop(); }

bool HealthServer::start(std::string& err) {
    std::string dacl = "D:P(D;;GA;;;NU)(A;;GRGW;;;SY)";
    std::set<std::string> seen{"S-1-5-18"};
    for (const auto& a : model_.config().allowedAccounts) {
        std::string why;
        const std::string sid = sidFor(a, why);
        if (sid.empty()) {
            // Usually: EdgeBastion not installed yet. Fail closed -- only
            // SYSTEM can connect -- and say so once.
            log_.warn("health: allowed account '" + a + "' not resolvable (" + why +
                      ") -- excluded; only SYSTEM and resolvable accounts may connect");
            continue;
        }
        if (!seen.insert(sid).second) continue;
        dacl += "(A;;GRGW;;;" + sid + ")";
    }
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(dacl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        err = "health: SDDL rejected (" + dacl + ")";
        return false;
    }
    sd_ = sd;
    sddl_ = dacl;
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) {
        err = "health: CreateEvent failed";
        return false;
    }
    running_ = true;
    listener_ = std::thread([this] { listenLoop(); });
    return true;
}

void HealthServer::stop() {
    if (!running_.exchange(false)) return;
    SetEvent(static_cast<HANDLE>(stopEvent_));
    if (listener_.joinable()) listener_.join();
    // Client threads are detached; wait for them to leave before the objects
    // they use go away. They watch stopEvent_, so this is quick.
    for (int i = 0; i < 300 && clients_.load() > 0; ++i) Sleep(10);
    if (clients_.load() == 0) {
        CloseHandle(static_cast<HANDLE>(stopEvent_));
        stopEvent_ = nullptr;
    }
    if (sd_) {
        LocalFree(sd_);
        sd_ = nullptr;
    }
    listening_ = false;
}

void HealthServer::push(const std::string& line) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = live_.begin(); it != live_.end();) {
        std::lock_guard<std::mutex> ck((*it)->mu);
        if ((*it)->done) {
            it = live_.erase(it);
            continue;
        }
        // Bounded: a client that stops reading cannot grow our memory.
        if ((*it)->queue.size() >= 256) (*it)->queue.pop_front();
        (*it)->queue.push_back(line);
        SetEvent((*it)->pushEv);
        ++it;
    }
}

void HealthServer::listenLoop() {
    const std::string& name = model_.config().pipe;
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd_, FALSE};
    HANDLE connEv = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE stopEv = static_cast<HANDLE>(stopEvent_);
    bool first = true, warned = false;

    while (running_.load()) {
        DWORD mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if (first) mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;   // refuse a squatted name
        HANDLE p = CreateNamedPipeA(name.c_str(), mode,
                                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
                                        PIPE_REJECT_REMOTE_CLIENTS,
                                    PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &sa);
        if (p == INVALID_HANDLE_VALUE) {
            // Health availability is part of terminal health (EdgeBastion
            // fails its gate when we are unreachable), so keep retrying.
            if (!warned) {
                log_.error("health: pipe " + name + " could not be created (error " +
                           std::to_string(GetLastError()) + ") -- retrying every 5 s");
                warned = true;
            }
            if (WaitForSingleObject(stopEv, 5000) == WAIT_OBJECT_0) break;
            continue;
        }
        if (first) {
            first = false;
            listening_ = true;
            if (warned) log_.info("health: pipe " + name + " created after retry");
        }

        OVERLAPPED ov{};
        ov.hEvent = connEv;
        ResetEvent(connEv);
        BOOL ok = ConnectNamedPipe(p, &ov);
        DWORD e = ok ? 0 : GetLastError();
        if (!ok && e == ERROR_IO_PENDING) {
            HANDLE w[2] = {connEv, stopEv};
            if (WaitForMultipleObjects(2, w, FALSE, INFINITE) != WAIT_OBJECT_0) {
                CancelIoEx(p, &ov);
                DWORD n = 0;
                GetOverlappedResult(p, &ov, &n, TRUE);
                CloseHandle(p);
                break;
            }
            DWORD n = 0;
            if (!GetOverlappedResult(p, &ov, &n, FALSE)) {
                CloseHandle(p);
                continue;
            }
        } else if (!ok && e != ERROR_PIPE_CONNECTED) {
            CloseHandle(p);
            continue;
        }

        if (clients_.load() >= model_.config().maxClients) {
            DisconnectNamedPipe(p);
            CloseHandle(p);
            continue;
        }
        auto c = std::make_shared<Client>();
        c->pipe = p;
        c->pushEv = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        {
            std::lock_guard<std::mutex> lk(mu_);
            live_.push_back(c);
        }
        clients_.fetch_add(1);
        std::thread([this, c] { serve(c); }).detach();
    }
    CloseHandle(connEv);
}

void HealthServer::serve(std::shared_ptr<Client> c) {
    HANDLE p = c->pipe;
    HANDLE stopEv = static_cast<HANDLE>(stopEvent_);
    HANDLE rEv = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE wEv = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<char> buf(64 * 1024);
    std::string msg;
    OVERLAPPED ro{};
    bool reading = false;

    auto writeAll = [&](const std::string& s) -> bool {
        OVERLAPPED wo{};
        wo.hEvent = wEv;
        ResetEvent(wEv);
        DWORD n = 0;
        if (!WriteFile(p, s.data(), static_cast<DWORD>(s.size()), nullptr, &wo)) {
            if (GetLastError() != ERROR_IO_PENDING) return false;
            // A client that stops reading must not stall the agent.
            if (WaitForSingleObject(wEv, 2000) != WAIT_OBJECT_0) {
                CancelIoEx(p, &wo);
                GetOverlappedResult(p, &wo, &n, TRUE);
                return false;
            }
        }
        return GetOverlappedResult(p, &wo, &n, FALSE) && n == s.size();
    };

    bool alive = true;
    while (alive && running_.load()) {
        if (!reading) {
            ro = OVERLAPPED{};
            ro.hEvent = rEv;
            ResetEvent(rEv);
            if (!ReadFile(p, buf.data(), static_cast<DWORD>(buf.size()), nullptr, &ro)) {
                const DWORD e = GetLastError();
                if (e != ERROR_IO_PENDING && e != ERROR_MORE_DATA) break;
            }
            reading = true;
        }
        HANDLE w[3] = {rEv, c->pushEv, stopEv};
        const DWORD r = WaitForMultipleObjects(3, w, FALSE, INFINITE);
        if (r == WAIT_OBJECT_0 + 2) break;
        if (r == WAIT_OBJECT_0 + 1) {
            std::deque<std::string> out;
            {
                std::lock_guard<std::mutex> lk(c->mu);
                out.swap(c->queue);
            }
            for (const auto& s : out)
                if (!writeAll(s + "\n")) { alive = false; break; }
            continue;
        }
        DWORD n = 0;
        const BOOL ok = GetOverlappedResult(p, &ro, &n, FALSE);
        const DWORD e = ok ? 0 : GetLastError();
        reading = false;
        if (!ok && e != ERROR_MORE_DATA) break;   // client went away
        msg.append(buf.data(), n);
        if (msg.size() > 256 * 1024) break;       // hostile or broken client
        if (!ok) continue;                        // rest of a long message follows

        size_t start = 0;
        while (start <= msg.size()) {
            size_t nl = msg.find('\n', start);
            std::string line = msg.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) {
                std::string logLine;
                const std::string reply = model_.handleRequest(line, clock_(), logLine);
                if (!logLine.empty()) log_.info(logLine);
                if (!writeAll(reply + "\n")) { alive = false; break; }
            }
            if (nl == std::string::npos) break;
            start = nl + 1;
        }
        msg.clear();
    }

    if (reading) {
        CancelIoEx(p, &ro);
        DWORD n = 0;
        GetOverlappedResult(p, &ro, &n, TRUE);   // buffer must outlive the I/O
    }
    DisconnectNamedPipe(p);
    CloseHandle(p);
    {
        std::lock_guard<std::mutex> lk(c->mu);
        c->done = true;
        CloseHandle(c->pushEv);
        c->pushEv = nullptr;
    }
    CloseHandle(rEv);
    CloseHandle(wEv);
    clients_.fetch_sub(1);
}

// ── window probe ────────────────────────────────────────────────────────────

namespace {
struct WinScan {
    const std::vector<unsigned long>* pids;
    bool found = false;
    bool hung = false;
};
BOOL CALLBACK scanWindow(HWND h, LPARAM lp) {
    auto* s = reinterpret_cast<WinScan*>(lp);
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    for (unsigned long want : *s->pids) {
        if (pid != want) continue;
        if (!IsWindowVisible(h) || GetWindow(h, GW_OWNER) != nullptr) break;
        s->found = true;
        if (IsHungAppWindow(h)) s->hung = true;
        break;
    }
    return TRUE;
}
}  // namespace

int windowResponding(const std::vector<unsigned long>& pids) {
    if (pids.empty()) return -1;
    WinScan s;
    s.pids = &pids;
    EnumWindows(scanWindow, reinterpret_cast<LPARAM>(&s));
    if (s.hung) return 0;
    return s.found ? 1 : -1;
}

// ── watched PIDs ────────────────────────────────────────────────────────────

WatchedSet::~WatchedSet() {
    for (auto& x : e_)
        if (x.h) CloseHandle(static_cast<HANDLE>(x.h));
}

bool WatchedSet::add(unsigned long pid, std::string& exe, std::string& why) {
    for (const auto& x : e_)
        if (x.pid == pid) return true;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!h) {
        why = "OpenProcess error " + std::to_string(GetLastError());
        return false;
    }
    FILETIME cr, ex, k, u;
    std::uint64_t created = 0;
    if (GetProcessTimes(h, &cr, &ex, &k, &u))
        created = (static_cast<std::uint64_t>(cr.dwHighDateTime) << 32) | cr.dwLowDateTime;
    wchar_t path[MAX_PATH * 2];
    DWORD len = MAX_PATH * 2;
    if (QueryFullProcessImageNameW(h, 0, path, &len)) {
        std::string full = narrow(path);
        const size_t slash = full.find_last_of("\\/");
        exe = slash == std::string::npos ? full : full.substr(slash + 1);
    }
    Entry e;
    e.pid = pid;
    e.h = h;
    e.created = created;
    e_.push_back(e);
    return true;
}

void WatchedSet::remove(unsigned long pid) {
    for (auto it = e_.begin(); it != e_.end(); ++it) {
        if (it->pid != pid) continue;
        if (it->h) CloseHandle(static_cast<HANDLE>(it->h));
        e_.erase(it);
        return;
    }
}

void WatchedSet::sample(std::vector<Sample>& out) {
    out.clear();
    for (auto& x : e_) {
        Sample s;
        s.pid = x.pid;
        s.obs.pid = x.pid;
        s.obs.identity = x.created;
        if (!x.dead && WaitForSingleObject(static_cast<HANDLE>(x.h), 0) == WAIT_OBJECT_0) {
            x.dead = true;
            CloseHandle(static_cast<HANDLE>(x.h));
            x.h = nullptr;
        }
        if (x.dead) {
            s.obs.present = false;
            out.push_back(s);
            continue;
        }
        s.obs.present = true;
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(static_cast<HANDLE>(x.h), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            s.obs.privateMb = static_cast<double>(pmc.PrivateUsage) / 1048576.0;
            s.obs.rssMb = static_cast<double>(pmc.WorkingSetSize) / 1048576.0;
        }
        DWORD hc = 0;
        if (GetProcessHandleCount(static_cast<HANDLE>(x.h), &hc)) s.obs.handles = hc;
        out.push_back(s);
    }
}

}  // namespace ev
