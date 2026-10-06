// Per-process sampling, direct Win32.
//
// NOT WMI and NOT PDH. A WMI query can take tens of milliseconds; at that cost
// the instrument disturbs what it measures, and the frame-time percentiles
// this agent collects would become partly an artifact of collecting them. The
// calls used here -- GetProcessTimes, GetProcessMemoryInfo,
// GetProcessIoCounters -- are microseconds.
//
// Two optimisations matter on the CPU budget:
//   1. Handles are cached across ticks. OpenProcess is the expensive call, and
//      reopening 11 processes every 10 s for the life of an ATM is waste.
//   2. Full enumeration runs every Nth tick, not every tick. Process churn is
//      not a 10-second phenomenon.
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edgevitals/Config.h"

namespace ev {

// One sample of one process, already differenced against the previous tick.
struct ProcSample {
    bool valid = false;          // false => leave the row cells EMPTY, not zero
    unsigned long pid = 0;
    double cpuPct = 0.0;         // % of one core, 0-100*ncores
    double cpuKernelPct = 0.0;
    double rssMb = 0.0;
    double privateMb = 0.0;
    double peakRssMb = 0.0;
    double pageFaultDelta = 0.0;
    double handles = 0.0;
    double threads = 0.0;
    double gdiObjects = 0.0;     // UI processes only; 0 elsewhere
    double userObjects = 0.0;
    // Whether handles / gdi+user were actually READ. A failed
    // GetProcessHandleCount or GetGuiResources leaves 0 in the value, and 0
    // written to the CSV says "holds no handles" -- the opposite of "could not
    // ask". For a multi-PID role these are true only when EVERY live instance
    // was read: a sum that silently omits one instance is a wrong number, not
    // a partial one.
    bool handlesValid = false;
    bool guiValid = false;
    // Order-independent signature of the live (pid, creation time) set. Changes
    // on restart, PID reuse, or an instance that could not be read this tick.
    // The handle probe uses it to refuse comparing across two process sets.
    std::uint64_t identity = 0;
    double ioReadMbs = 0.0;
    double ioWriteMbs = 0.0;
    double ioReadOps = 0.0;
    double ioWriteOps = 0.0;
    // Total processor time since the role bound. A rate answers "is this bad
    // right now"; a total answers "where is optimisation effort worth
    // spending", which is a different and often more useful question.
    double cpuSeconds = 0.0;
    const char* priority = "";   // "" when unreadable -- never a default
    // Set when the process was seen but could not be fully read. Logged rather
    // than dropped: "could not read PID 4312" is information.
    std::string note;
};

// A process discovered on the machine, whether tracked or not.
struct ProcInfo {
    unsigned long pid = 0;
    unsigned long parentPid = 0;
    std::string exeName;         // lowercased file name
    std::string exePath;         // full path, empty if unreadable
    unsigned long threads = 0;
};

class ProcessSampler {
public:
    explicit ProcessSampler(const Config& cfg);
    ~ProcessSampler();

    ProcessSampler(const ProcessSampler&) = delete;
    ProcessSampler& operator=(const ProcessSampler&) = delete;

    // Full machine enumeration. Call every enumerate_every_ticks, not every
    // tick -- this is the expensive operation in the whole agent.
    std::vector<ProcInfo> enumerate();

    // Advanced by the Agent each tick so open-retry backoff can be expressed
    // in ticks rather than duplicating the clock down here. PUBLIC: the Agent
    // calls it every tick -- it landed in the private section first time and
    // the Win32 build caught it.
    void setTick(long long t) { tick_ = t; }

    // Re-resolve which PIDs match which tracked role, from an enumeration.
    // A role with several live PIDs (spawned Piper instances) aggregates them.
    void bindRoles(const std::vector<ProcInfo>& all);

    // Sample every bound role. elapsedNs is wall time since the previous call
    // and is what CPU percentages are computed against -- using the nominal
    // interval instead would misreport whenever a tick runs late.
    std::unordered_map<std::string, ProcSample> sampleAll(std::uint64_t elapsedNs);

    // Number of live PIDs currently bound to a role.
    size_t liveCount(const std::string& role) const;

    // PIDs of a role's instances that hold an open handle -- i.e. that were
    // sampled successfully on the last sampleAll. These are the PIDs whose
    // handle-count sum the row reports, so a probe tallied over them matches.
    void livePids(const std::string& role, std::vector<unsigned long>& out) const;

private:
    struct Tracked {
        void* handle = nullptr;              // HANDLE, cached across ticks
        unsigned long pid = 0;
        // Process identity is (pid, createTime), never pid alone. Windows
        // reuses PIDs, and a reused PID silently continues the previous
        // process's column series -- which a trend detector then reads as a
        // continuous history across two unrelated processes.
        std::uint64_t createTime = 0;
        // Total processor time consumed since this role bound, in seconds.
        // Reset with the counters on exit or PID reuse, because carrying a
        // total across two different processes is meaningless.
        double cpuSeconds = 0.0;
        // Consecutive failed opens, and the tick to retry on. A role that is
        // not running costs FAR more per tick than one that is: measured on
        // the terminal, sample ticks with a role absent were 3.68 ms p95
        // against 0.39 ms with it present, because a failing OpenProcess is
        // slower than querying a cached handle. With ten roles unbound that
        // is the dominant sampling cost, so back off instead of retrying
        // every tick.
        int openFails = 0;
        long long retryAtTick = 0;
        std::uint64_t lastKernel100ns = 0;
        std::uint64_t lastUser100ns = 0;
        std::uint64_t lastReadBytes = 0;
        std::uint64_t lastWriteBytes = 0;
        std::uint64_t lastReadOps = 0;
        std::uint64_t lastWriteOps = 0;
        std::uint64_t lastPageFaults = 0;
        unsigned long threads = 0;           // from the last enumeration
        bool gui = false;                    // emit GDI/USER for this role
        bool fullAccess = false;             // got PROCESS_QUERY_INFORMATION
        bool primed = false;                 // first tick yields no delta
    };

    bool openIfNeeded(Tracked& t);
    void closeHandle(Tracked& t);
    // True while the process behind this handle is still running. A cached
    // handle stays valid after exit and Windows answers queries with zeros,
    // so without this a dead process reports 0 MB and looks like a live one
    // using no memory.
    bool isAlive(const Tracked& t) const;
    void resetCounters(Tracked& t);
    // PRIORITY_CLASS as a short lowercase word. Empty when it cannot be read,
    // never a default -- "we could not ask" and "it is normal" are different
    // facts and a bank reviewer will ask which one they are looking at.
    static const char* priorityName(void* handle);
    bool sampleOne(Tracked& t, std::uint64_t elapsedNs, ProcSample& out);

    const Config& cfg_;
    long long tick_ = 0;
    // role -> live instances. A vector because Piper and Rhubarb may briefly
    // have more than one, and dropping the second would understate the peak.
    std::unordered_map<std::string, std::vector<Tracked>> bound_;
};

}  // namespace ev
