#include "edgevitals/ProcessSampler.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cctype>

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

ProcessSampler::ProcessSampler(const Config& cfg) : cfg_(cfg) {}

ProcessSampler::~ProcessSampler() {
    for (auto& kv : bound_)
        for (auto& t : kv.second) closeHandle(t);
}

void ProcessSampler::closeHandle(Tracked& t) {
    if (t.handle) {
        CloseHandle(static_cast<HANDLE>(t.handle));
        t.handle = nullptr;
    }
}

std::vector<ProcInfo> ProcessSampler::enumerate() {
    std::vector<ProcInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcInfo pi;
            pi.pid = pe.th32ProcessID;
            pi.parentPid = pe.th32ParentProcessID;
            pi.threads = pe.cntThreads;

            // WideCharToMultiByte rather than a narrow snapshot: exe names on
            // an ATM can carry non-ASCII from vendor installers, and a narrow
            // API would mangle them into a name that never matches config.
            char narrow[MAX_PATH * 2] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow, sizeof(narrow) - 1,
                                nullptr, nullptr);
            pi.exeName = toLower(narrow);

            // Full path needs a handle. Many processes refuse even to an
            // elevated caller (protected processes); an empty path is a fact
            // to record, not a failure to hide.
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.pid);
            if (h) {
                wchar_t buf[MAX_PATH * 2];
                DWORD n = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
                if (QueryFullProcessImageNameW(h, 0, buf, &n)) {
                    char p[MAX_PATH * 4] = {0};
                    WideCharToMultiByte(CP_UTF8, 0, buf, -1, p, sizeof(p) - 1, nullptr, nullptr);
                    pi.exePath = p;
                }
                CloseHandle(h);
            }
            out.push_back(std::move(pi));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

void ProcessSampler::bindRoles(const std::vector<ProcInfo>& all) {
    // Enumeration is ground truth. A role found here is running, so clear any
    // backoff immediately -- a process that just started must not wait out a
    // 5-minute timer set while it was absent.
    for (auto& kv : bound_) {
        for (auto& t : kv.second) { t.openFails = 0; t.retryAtTick = 0; }
    }
    const unsigned long selfPid = GetCurrentProcessId();
    for (const auto& tp : cfg_.tracked) {
        std::vector<unsigned long> pids;
        std::unordered_map<unsigned long, unsigned long> threadsByPid;
        if (tp.self) {
            // Bind by PID. Matching our own image name fails the moment the
            // binary is renamed for a drop, which is exactly what happened on
            // 20 Aug: edgevitals_v2.1.exe left vitals_* empty and put the
            // agent in its own discovery log.
            pids.push_back(selfPid);
            for (const auto& pi : all)
                if (pi.pid == selfPid) threadsByPid[selfPid] = pi.threads;
        }
        for (const auto& pi : all) {
            if (tp.self && pi.pid == selfPid) continue;
            for (const auto& want : tp.exe) {
                if (pi.exeName == toLower(want)) {
                    pids.push_back(pi.pid);
                    threadsByPid[pi.pid] = pi.threads;
                    break;
                }
            }
        }

        auto& slots = bound_[tp.role];

        // Drop instances that have exited. Closing the handle here is what
        // keeps the cache from leaking one handle per short-lived Piper run --
        // which over a week of an ATM speaking is thousands.
        slots.erase(std::remove_if(slots.begin(), slots.end(),
                                   [&](Tracked& t) {
                                       const bool gone = std::find(pids.begin(), pids.end(),
                                                                   t.pid) == pids.end();
                                       if (gone) closeHandle(t);
                                       return gone;
                                   }),
                    slots.end());

        for (unsigned long pid : pids) {
            auto it = std::find_if(slots.begin(), slots.end(),
                                   [&](const Tracked& t) { return t.pid == pid; });
            if (it != slots.end()) {
                it->threads = threadsByPid[pid];
                continue;
            }
            Tracked t;
            t.pid = pid;
            t.gui = tp.gui;
            t.threads = threadsByPid[pid];
            slots.push_back(t);
        }
    }
}

bool ProcessSampler::openIfNeeded(Tracked& t) {
    if (t.handle) return true;
    // GetGuiResources needs PROCESS_QUERY_INFORMATION, so try that first --
    // but fall back to LIMITED, which is granted far more often and is
    // enough for times, memory and IO. Losing GDI counts is much better
    // than losing the process entirely.
    HANDLE h = nullptr;
    t.fullAccess = false;
    if (t.gui) {
        h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, t.pid);
        if (h) t.fullAccess = true;
    }
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, t.pid);
    if (!h) return false;
    t.handle = h;
    t.primed = false;  // counters restart against a fresh handle
    t.createTime = 0;
    return true;
}

bool ProcessSampler::isAlive(const Tracked& t) const {
    if (!t.handle) return false;
    // WaitForSingleObject rather than GetExitCodeProcess: a process that exits
    // with code 259 is indistinguishable from a running one under
    // STILL_ACTIVE, and that is the same class of bug as the one this fixes.
    // Costs a SYNCHRONIZE right on the handle and roughly a microsecond.
    const DWORD r = WaitForSingleObject(static_cast<HANDLE>(t.handle), 0);
    if (r == WAIT_OBJECT_0) return false;      // signalled == exited
    if (r == WAIT_TIMEOUT) return true;        // still running
    // WAIT_FAILED means the handle lacks SYNCHRONIZE (a process we could only
    // open with LIMITED rights on an older OS). Fall back rather than
    // declaring a live process dead.
    DWORD code = 0;
    if (GetExitCodeProcess(static_cast<HANDLE>(t.handle), &code))
        return code == STILL_ACTIVE;
    return false;
}

const char* ProcessSampler::priorityName(void* handle) {
    if (!handle) return "";
    const DWORD p = GetPriorityClass(static_cast<HANDLE>(handle));
    switch (p) {
        case IDLE_PRIORITY_CLASS:         return "idle";
        case BELOW_NORMAL_PRIORITY_CLASS: return "below";
        case NORMAL_PRIORITY_CLASS:       return "normal";
        case ABOVE_NORMAL_PRIORITY_CLASS: return "above";
        case HIGH_PRIORITY_CLASS:         return "high";
        case REALTIME_PRIORITY_CLASS:     return "realtime";
        default:                          return "";   // 0 == call failed
    }
}

void ProcessSampler::resetCounters(Tracked& t) {
    t.lastKernel100ns = 0;
    t.lastUser100ns = 0;
    t.lastReadBytes = 0;
    t.lastWriteBytes = 0;
    t.lastReadOps = 0;
    t.lastWriteOps = 0;
    t.lastPageFaults = 0;
    t.cpuSeconds = 0.0;
    t.openFails = 0;
    t.retryAtTick = 0;
    t.primed = false;
}

bool ProcessSampler::sampleOne(Tracked& t, std::uint64_t elapsedNs, ProcSample& out) {
    // Backoff: after repeated failures, stop retrying every tick. Doubles from
    // 2 ticks to a 30-tick ceiling (5 minutes at the standing rate), so a role
    // that is simply not installed costs one open attempt per 5 minutes rather
    // than one per 10 seconds. Enumeration still rebinds it the moment it
    // appears, so nothing is missed -- only the pointless retries go away.
    if (!t.handle && t.openFails > 0 && tick_ < t.retryAtTick) {
        out.note = "not running";
        return false;
    }
    if (!openIfNeeded(t)) {
        int delay = 2;
        for (int k = 1; k < t.openFails && delay < 30; ++k) delay *= 2;
        if (delay > 30) delay = 30;
        ++t.openFails;
        t.retryAtTick = tick_ + delay;
        out.note = "open failed";
        return false;
    }
    t.openFails = 0;

    // Liveness is checked EVERY sample, not every enumeration. The old
    // gone-detection tested membership of the enumerated PID list, which
    // refreshes every 6th tick -- so a dead process reported zeros for up to
    // four ticks and looked like a running application using no memory.
    if (!isAlive(t)) {
        closeHandle(t);
        resetCounters(t);
        out.note = "exited";
        return false;                       // invalid => cells stay EMPTY
    }

    HANDLE h = static_cast<HANDLE>(t.handle);

    FILETIME cre{}, ex{}, ker{}, usr{};
    if (!GetProcessTimes(h, &cre, &ex, &ker, &usr)) {
        closeHandle(t);
        out.note = "GetProcessTimes failed";
        return false;
    }
    const std::uint64_t k = toU64(ker), u = toU64(usr);

    // Identity check. The creation time is already in hand from the call
    // above -- it was previously discarded -- so this costs nothing but the
    // comparison. A changed value means the PID was reused by a different
    // process and every accumulated counter belongs to the previous one.
    const std::uint64_t created = toU64(cre);
    if (t.createTime != 0 && created != t.createTime) {
        resetCounters(t);
        out.note = "pid reused";
    }
    t.createTime = created;

    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (!GetProcessMemoryInfo(h, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        closeHandle(t);
        out.note = "GetProcessMemoryInfo failed";
        return false;
    }

    IO_COUNTERS io{};
    const bool haveIo = GetProcessIoCounters(h, &io) != 0;

    DWORD handles = 0;
    GetProcessHandleCount(h, &handles);

    out.pid = t.pid;
    out.rssMb = static_cast<double>(pmc.WorkingSetSize) / kMb;
    out.privateMb = static_cast<double>(pmc.PrivateUsage) / kMb;
    out.peakRssMb = static_cast<double>(pmc.PeakWorkingSetSize) / kMb;
    out.handles = handles;
    out.threads = t.threads;
    if (t.gui && t.fullAccess) {
        // Qt applications leak these, and an ATM runs for weeks. A slow
        // upward ramp here is the tell long before anything looks wrong.
        out.gdiObjects = GetGuiResources(h, GR_GDIOBJECTS);
        out.userObjects = GetGuiResources(h, GR_USEROBJECTS);
    }

    if (!t.primed) {
        // First observation of this handle. Emit the levels, but no rates --
        // a delta against zero would report a CPU spike that never happened.
        t.lastKernel100ns = k;
        t.lastUser100ns = u;
        t.lastPageFaults = pmc.PageFaultCount;
        if (haveIo) {
            t.lastReadBytes = io.ReadTransferCount;
            t.lastWriteBytes = io.WriteTransferCount;
            t.lastReadOps = io.ReadOperationCount;
            t.lastWriteOps = io.WriteOperationCount;
        }
        t.primed = true;
        out.valid = true;
        out.note = "primed";
        return true;
    }

    const double elapsed100ns = static_cast<double>(elapsedNs) / 100.0;
    if (elapsed100ns > 0.0) {
        const double dk = static_cast<double>(k - t.lastKernel100ns);
        const double du = static_cast<double>(u - t.lastUser100ns);
        out.cpuPct = (dk + du) / elapsed100ns * 100.0;
        // Kernel time separated on purpose: a high kernel fraction points at
        // IO or driver work (camera, audio, XFS), a high user fraction at our
        // own code. They call for opposite fixes and the combined number hides
        // which one you are looking at.
        out.cpuKernelPct = dk / elapsed100ns * 100.0;
        // Accumulate the same deltas as seconds. 100 ns units -> seconds.
        t.cpuSeconds += (dk + du) / 1.0e7;
    }
    out.cpuSeconds = t.cpuSeconds;
    out.priority = priorityName(t.handle);

    out.pageFaultDelta = static_cast<double>(pmc.PageFaultCount - t.lastPageFaults);

    if (haveIo) {
        const double secs = static_cast<double>(elapsedNs) / 1e9;
        if (secs > 0.0) {
            out.ioReadMbs = static_cast<double>(io.ReadTransferCount - t.lastReadBytes) / kMb / secs;
            out.ioWriteMbs = static_cast<double>(io.WriteTransferCount - t.lastWriteBytes) / kMb / secs;
            out.ioReadOps = static_cast<double>(io.ReadOperationCount - t.lastReadOps) / secs;
            out.ioWriteOps = static_cast<double>(io.WriteOperationCount - t.lastWriteOps) / secs;
        }
        t.lastReadBytes = io.ReadTransferCount;
        t.lastWriteBytes = io.WriteTransferCount;
        t.lastReadOps = io.ReadOperationCount;
        t.lastWriteOps = io.WriteOperationCount;
    }

    t.lastKernel100ns = k;
    t.lastUser100ns = u;
    t.lastPageFaults = pmc.PageFaultCount;

    out.valid = true;
    return true;
}

std::unordered_map<std::string, ProcSample> ProcessSampler::sampleAll(std::uint64_t elapsedNs) {
    std::unordered_map<std::string, ProcSample> out;

    for (auto& kv : bound_) {
        ProcSample agg;
        int live = 0;
        std::string firstNote;

        for (auto& t : kv.second) {
            ProcSample s;
            if (!sampleOne(t, elapsedNs, s)) {
                if (firstNote.empty()) firstNote = s.note;
                continue;
            }
            ++live;
            // Aggregate across instances of a role. Rates and memory sum;
            // PID reports the first, which is what a human wants to see.
            if (live == 1) agg.pid = s.pid;
            agg.cpuPct += s.cpuPct;
            agg.cpuKernelPct += s.cpuKernelPct;
            agg.rssMb += s.rssMb;
            agg.privateMb += s.privateMb;
            agg.peakRssMb = (std::max)(agg.peakRssMb, s.peakRssMb);
            agg.pageFaultDelta += s.pageFaultDelta;
            agg.handles += s.handles;
            agg.threads += s.threads;
            agg.gdiObjects += s.gdiObjects;
            agg.userObjects += s.userObjects;
            agg.ioReadMbs += s.ioReadMbs;
            agg.ioWriteMbs += s.ioWriteMbs;
            agg.ioReadOps += s.ioReadOps;
            agg.ioWriteOps += s.ioWriteOps;
            // cpuSeconds SUMS across instances -- total processor time for the
            // role, matching how memory and CPU rate are aggregated.
            agg.cpuSeconds += s.cpuSeconds;
            // priority takes the FIRST live instance. Summing a class makes no
            // sense, and the instances of one role are started the same way.
            // Missing this pair is what left cpu_seconds reading 0.0 and
            // priority empty for the whole GFF event: sampleOne filled them in
            // and the aggregation dropped them on the floor, so the row carried
            // a default-constructed zero rather than an honest empty.
            if (live == 1) agg.priority = s.priority;
            if (s.note == "primed" && firstNote.empty()) firstNote = "primed";
        }

        // valid stays false when nothing is running. The row then carries
        // EMPTY cells, so "not licensed" and "idle" never both read as 0.
        agg.valid = live > 0;
        agg.note = firstNote;
        out[kv.first] = agg;
    }
    return out;
}

size_t ProcessSampler::liveCount(const std::string& role) const {
    auto it = bound_.find(role);
    return it == bound_.end() ? 0 : it->second.size();
}

}  // namespace ev
