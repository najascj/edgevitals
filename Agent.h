// Orchestration: builds the schema, runs the tick loop, writes rows.
//
// Everything platform-specific lives behind ProcessSampler, SystemSampler and
// IpcServer. Agent itself only decides WHAT to record and WHEN.
#pragma once
#include <atomic>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "edgevitals/Config.h"
#include "edgevitals/CsvSink.h"
#include "edgevitals/HandleProbe.h"
#include "edgevitals/Health.h"
#include "edgevitals/HealthServer.h"
#include "edgevitals/WinEventWatcher.h"
#include "edgevitals/WinEvents.h"
#include "edgevitals/IpcServer.h"
#include "edgevitals/PostureCollect.h"
#include "edgevitals/IntegrityCollect.h"
#include "edgevitals/IntegrityMonitor.h"
#include "edgevitals/IntegrityMonitor.h"
#include "edgevitals/PostureMonitor.h"
#include "edgevitals/ProcessSampler.h"
#include "edgevitals/Row.h"
#include "edgevitals/SystemSampler.h"

namespace ev {

// Where the agent reports its own state. The service writes to the event log,
// the console build writes to stderr; Agent does not care which.
class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void info(const std::string& msg) = 0;
    virtual void warn(const std::string& msg) = 0;
    virtual void error(const std::string& msg) = 0;
};

class Agent {
public:
    Agent(Config cfg, ILogger& log);
    ~Agent();

    bool start();
    // Blocks until stop(). Safe to call from a service worker thread.
    void run();
    void stop();

    const Schema& schema() const { return schema_; }
    long long ticks() const { return tick_; }

private:
    void buildSchema();
    void doTick();
    std::string snapshotJson(const Row& r) const;
    // Observes the probed roles' handle counts for the trigger, and runs the
    // handle-type probe if it is due. Separate from doTick so the one edit to
    // that function is a single call.
    void runHandleProbe(const std::unordered_map<std::string, ProcSample>& samples, Row& row,
                        double nowSec);
    // Health link (3.2): keep this tick's samples, then evaluate after the
    // system sample. Two calls so doTick gains two lines, not a block.
    void stashForHealth(const std::unordered_map<std::string, ProcSample>& samples,
                        std::uint64_t elapsedNs);
    void runHealth(Row& row, double commitPct, double diskFreeMb, double nowSec);
    // Windows Event Log watcher (3.3): read, filter, record, count.
    void runWinEvents(Row& row, const Date& today, double nowSec);
    // Reads up to the remaining per-interval budget of events, records what the
    // filter admits, and routes SCM / RDP-session events to the posture monitor.
    // Called from the tick AND between ticks, so a routed event is acted on in
    // seconds; the budget keeps the total per interval at max_per_tick.
    void drainWinEvents(const Date& today, double nowSec);
    void routeToPosture(const WinEvent& e, const Date& today, double nowSec);

    // Remote-access posture (3.4). Runs only between ticks -- the slow tier --
    // never inside doTick, so sample_cost_ms is untouched by it.
    void setupIntegrity();
    void runIntegrityFull(const std::string& trigger, bool interval, double nowSec, const Date& today);
    void writeIntegrity(const IntegrityRunOutput& out, const Date& today);
    void setupPosture();
    bool postureSlowTier(double nowSec, double msToNextTick);
    void runPostureFull(const std::string& trigger, bool interval, double nowSec, const Date& today);
    void writePosture(const PostureRunOutput& out, const Date& today);
    double nowSec() const;

    Config cfg_;
    ILogger& log_;
    Schema schema_;

    std::unique_ptr<ProcessSampler> proc_;
    std::unique_ptr<SystemSampler> sys_;
    std::unique_ptr<CsvSink> sink_;
    std::unique_ptr<IpcServer> ipc_;
    std::unique_ptr<DiscoveryLog> discovery_;

    std::atomic<bool> running_{false};
    void* wakeEvent_ = nullptr;  // HANDLE, so stop() interrupts the wait

    long long tick_ = 0;
    std::uint64_t lastTickNs_ = 0;
    std::uint64_t startNs_ = 0;
    // Distinguishes two runs inside one day file. Without it, seq restarts at
    // 0 on every start and a day with two runs carries duplicate sequence
    // numbers -- so anything that differences or sorts on seq silently
    // interleaves two unrelated series.
    std::string runId_;
    // Eight hex characters over the applied config. Two files with different
    // hashes were produced under different rules, which is worth knowing
    // before comparing their numbers.
    std::string cfgHash_;
    double lastEnumCostMs_ = 0.0;
    // Wall time of this tick's handle probe, or negative when none ran. Taken
    // out of sample_cost_ms for the same reason enumeration is: conflated, the
    // per-tick budget becomes uncheckable on exactly the ticks that matter.
    double tickProbeMs_ = -1.0;
    Date lastPurgeDate_;
    bool warnedSuppressed_ = false;

    // Cached column indices. Looked up once at startup so the hot path does
    // no string hashing -- the whole point is that sampling costs under 2 ms.
    struct Cols {
        size_t ts = Schema::npos, seq = Schema::npos, uptime = Schema::npos;
        size_t runId = Schema::npos, agentVer = Schema::npos;
        size_t runNote = Schema::npos, cfgHash = Schema::npos;
        size_t tickSkew = Schema::npos;
        size_t sampleCost = Schema::npos, enumCost = Schema::npos;
        size_t handleProbeMs = Schema::npos;
        size_t sysCpu = Schema::npos, sysAvail = Schema::npos, sysCommit = Schema::npos;
        size_t sysTotal = Schema::npos;
        size_t diskFree = Schema::npos, cores = Schema::npos;
        size_t unknownNew = Schema::npos, budgetBreaches = Schema::npos;
        // Contention accounting. txn/bg are this tick; contention is the
        // running total of ticks where both conditions held.
        size_t txnCpu = Schema::npos, bgCpu = Schema::npos, contention = Schema::npos;
    } col_;

    struct RoleCols {
        size_t pid, cpu, cpuKernel, rss, priv, peak, faults, handles, threads;
        size_t ioRead, ioWrite, ioReadOps, ioWriteOps;
        size_t gdi = Schema::npos, user = Schema::npos;
        size_t cpuSeconds = Schema::npos, priority = Schema::npos;
    };
    std::vector<std::pair<std::string, RoleCols>> roleCols_;
    // Cumulative ticks in which a background-tier role held CPU while a
    // transaction-tier role was active. Survives across ticks, resets never --
    // the point is the running count over a session.
    long long contentionTicks_ = 0;

    // Summed across every live role in the group. NOT a copy of the per-role
    // columns: only quantities that add correctly are here.
    //
    // private_mb sums because private bytes are private by definition.
    // rss_mb deliberately does NOT appear -- working sets include shared
    // pages, so summing them counts every shared DLL once per process and
    // would be the one arithmetically wrong number in the file. Sum
    // private_mb for memory; use the per-role rss columns if you need
    // resident figures.
    struct GroupCols {
        size_t priv, cpu, cpuKernel, handles, threads, cpuSeconds, live;
    };
    std::vector<std::pair<std::string, GroupCols>> groupCols_;

    // Handle-type probe. One entry per role with handle_probe set; empty when
    // none are (and then the source is never created).
    struct ProbeRole {
        std::string role;
        size_t growType = Schema::npos, growDelta = Schema::npos;
        size_t topType = Schema::npos, topCount = Schema::npos;
        // This tick.
        bool measured = false;
        double count = 0.0;
        std::uint64_t identity = 0;
        // Previous successful probe of this role, for growth. Compared only
        // when the process set is the same one.
        bool havePrev = false;
        std::uint64_t prevIdentity = 0;
        TypeCounts prev;
    };
    std::vector<ProbeRole> probeRoles_;
    std::unique_ptr<IHandleSource> probe_;
    std::unique_ptr<ProbeTrigger> trigger_;
    int probeFails_ = 0;
    bool probeDisabled_ = false;

    std::unique_ptr<HealthModel> health_;
    std::unique_ptr<HealthServer> healthSrv_;
    std::unique_ptr<WatchedSet> watched_;
    std::unordered_map<std::string, ProcSample> lastSamples_;
    double lastElapsedSec_ = 0.0;
    std::map<std::string, std::pair<std::uint64_t, double>> lastCpuSec_;
    std::map<std::string, size_t> healthCols_;
    size_t healthAdvCol_ = Schema::npos;

    std::unique_ptr<WinEventWatcher> wevWatch_;
    std::unique_ptr<WinEventFilter> wevFilter_;
    std::unique_ptr<WinEventLog> wevLog_;
    size_t wevRecCol_ = Schema::npos, wevSupCol_ = Schema::npos;

    std::unique_ptr<PostureMonitor> posture_;
    std::unique_ptr<PostureScheduler> postureSched_;
    std::unique_ptr<WinEventLog> postureLog_;
    std::vector<std::string> postureWatched_;     // service key names / patterns that trigger a run
    std::vector<std::string> postureStartTypes_;
    size_t postureFailCol_ = Schema::npos, postureFlagsCol_ = Schema::npos;
    // The agent's own enumeration, kept for RA-013 and listener owners.
    std::vector<std::string> lastProcNames_;
    std::map<unsigned long, std::string> lastPidNames_;
    std::string lastListenerSig_;
    Date postureDay_{};
    int wevBudget_ = 0;   // events still readable in this interval
    bool haveProcNames_ = false;
    bool haveListenerSig_ = false;
    bool havePostureDay_ = false;

    // Endpoint integrity (3.5).
    std::unique_ptr<IntegrityMonitor> integrity_;
    std::unique_ptr<PostureScheduler> integritySched_;
    std::unique_ptr<WinEventLog> integrityLog_;
    std::vector<std::string> integrityFiles_;
    long long integrityMaxBytes_ = 64LL * 1024 * 1024;
    size_t integrityFailCol_ = Schema::npos, integrityFlagsCol_ = Schema::npos;
    Date integrityDay_{};
    bool haveIntegrityDay_ = false;

    // Agent liveness beacon (3.5): a monotonic beat number in the CSV and a
    // periodic agent-log line, so a gap means the agent was down.
    size_t livenessCol_ = Schema::npos;
    long long livenessBeat_ = 0;
};

}  // namespace ev
