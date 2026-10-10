#include "edgevitals/SystemSampler.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace ev {
namespace {

std::string toLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::uint64_t toU64(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

constexpr double kMb = 1024.0 * 1024.0;

}  // namespace

std::uint64_t monotonicNs() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

void nowLocal(std::string& iso, Date& date) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[40];  // flawfinder: ignore -- written only by snprintf(buf, sizeof(buf), ...)
    (void)std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03d", st.wYear, st.wMonth,
                  st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    iso = buf;
    date.y = st.wYear;
    date.m = st.wMonth;
    date.d = st.wDay;
}

SystemSampler::SystemSampler() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    cores_ = si.dwNumberOfProcessors > 0 ? static_cast<int>(si.dwNumberOfProcessors) : 1;
}

SystemSample SystemSampler::sample(const std::string& diskPathHint) {
    SystemSample s;
    s.cores = cores_;

    FILETIME idle{}, kern{}, user{};
    if (GetSystemTimes(&idle, &kern, &user)) {
        const std::uint64_t i = toU64(idle), k = toU64(kern), u = toU64(user);
        if (primed_) {
            // GetSystemTimes folds idle INTO kernel, so busy is
            // (kernel - idle) + user, not kernel + user. Getting this wrong
            // reports an idle machine as ~100% busy.
            const double di = static_cast<double>(i - lastIdle_);
            const double dk = static_cast<double>(k - lastKernel_);
            const double du = static_cast<double>(u - lastUser_);
            const double total = dk + du;
            if (total > 0.0) s.cpuPct = (total - di) / total * 100.0;
            if (s.cpuPct < 0.0) s.cpuPct = 0.0;
        }
        lastIdle_ = i;
        lastKernel_ = k;
        lastUser_ = u;
        primed_ = true;
    }

    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        s.availMb = static_cast<double>(ms.ullAvailPhys) / kMb;
        s.totalMb = static_cast<double>(ms.ullTotalPhys) / kMb;
        const double totalCommit = static_cast<double>(ms.ullTotalPageFile);
        const double availCommit = static_cast<double>(ms.ullAvailPageFile);
        if (totalCommit > 0.0) s.commitPct = (totalCommit - availCommit) / totalCommit * 100.0;
    }

    ULARGE_INTEGER freeAvail{}, total{}, freeTotal{};
    std::string dir = diskPathHint.empty() ? std::string(".") : diskPathHint;
    if (GetDiskFreeSpaceExA(dir.c_str(), &freeAvail, &total, &freeTotal))
        s.diskFreeMb = static_cast<double>(freeAvail.QuadPart) / kMb;

    return s;
}

double Win32DiskSpace::freeMbAt(const std::string& dir) {
    ULARGE_INTEGER freeAvail{}, total{}, freeTotal{};
    // The directory may not exist yet on first run; fall back to the volume
    // the process is running from rather than reporting a scary zero.
    std::string probe = dir;
    std::error_code ec;
    if (!fs::exists(probe, ec)) probe = ".";
    if (!GetDiskFreeSpaceExA(probe.c_str(), &freeAvail, &total, &freeTotal)) return 0.0;
    return static_cast<double>(freeAvail.QuadPart) / kMb;
}

// ── discovery ────────────────────────────────────────────────────────────
DiscoveryLog::DiscoveryLog(std::string pathTemplate, const std::vector<std::string>& systemAllowlist,
                           const std::vector<std::string>& trackedExe, int chainEvery)
    : template_(std::move(pathTemplate)), out_(new ChainedFile(chainEvery)) {
    for (const auto& a : systemAllowlist) allow_.insert(toLower(a));
    for (const auto& t : trackedExe) tracked_.insert(toLower(t));
}

void DiscoveryLog::openFor(const Date& d) {
    out_->close();   // seals the outgoing day, if one was open
    day_ = d;
    haveDay_ = true;
    // "unknown-processes.csv" -> "unknown-processes-YYYY-MM-DD.csv": the name
    // the retention classifier already recognises.
    const size_t slash = template_.find_last_of("/\\");
    const size_t dot = template_.rfind('.');
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
        path_ = template_.substr(0, dot) + "-" + d.iso() + template_.substr(dot);
    else
        path_ = template_ + "-" + d.iso();
    seen_.clear();
    loadExisting();
    // The file itself opens on the first new row: a day with no unknown
    // binaries leaves no file, as before.
}

void DiscoveryLog::loadExisting() {
    std::ifstream in(path_);
    if (!in) return;
    std::string line;
    bool first = true;
    while (std::getline(in, line)) {
        if (first) { first = false; continue; }  // header
        // key is the 4th field (first_seen,name,path,key) -- but parsing CSV
        // properly for one column is not worth it, so the key is written last
        // and unquoted by construction.
        const size_t last = line.find_last_of(',');
        if (last != std::string::npos && last + 1 < line.size())
            seen_.insert(line.substr(last + 1));
    }
}

bool DiscoveryLog::isKnown(const ProcInfo& p) const {
    // Our own PID, whatever the binary was renamed to for this drop. On
    // 20 Aug edgevitals_v2.1.exe recorded itself as an unknown binary, which
    // is noise in the one file a bank reviewer is most likely to open.
    if (p.pid == GetCurrentProcessId()) return true;
    if (allow_.count(p.exeName)) return true;
    if (tracked_.count(p.exeName)) return true;
    return false;
}

int DiscoveryLog::record(const std::vector<ProcInfo>& all, const std::string& nowIso,
                         const Date& today) {
    if (!haveDay_ || day_ != today) openFor(today);
    std::vector<const ProcInfo*> fresh;
    for (const auto& p : all) {
        if (p.pid == 0 || p.pid == 4) continue;  // System Idle / System
        if (isKnown(p)) continue;
        const std::string key = toLower(p.exePath.empty() ? p.exeName : p.exePath);
        if (key.empty() || seen_.count(key)) continue;
        seen_.insert(key);
        fresh.push_back(&p);
    }
    if (fresh.empty()) return 0;

    std::error_code ec;
    const fs::path parent = fs::path(path_).parent_path();
    if (!parent.empty()) fs::create_directories(parent, ec);

    const bool existed = fs::exists(path_, ec) && fs::file_size(path_, ec) > 0;
    if (!out_->isOpen()) {
        std::string err;
        if (!out_->open(path_, err)) return 0;
    }
    // Chained like the other two streams: every byte, header included.
    if (!existed) out_->append("first_seen,exe_name,exe_path,parent_pid,note,key\n");

    for (const ProcInfo* p : fresh) {
        // An unreadable path is recorded as a note rather than dropped.
        // "Could not read PID 4312" is information; a missing row is not.
        const std::string note = p->exePath.empty() ? "path unreadable" : "";
        std::ostringstream line;
        line << nowIso << ',' << csvEscape(p->exeName) << ',' << csvEscape(p->exePath) << ','
             << p->parentPid << ',' << note << ','
             << toLower(p->exePath.empty() ? p->exeName : p->exePath) << '\n';
        out_->append(line.str());
    }
    return static_cast<int>(fresh.size());
}

}  // namespace ev
