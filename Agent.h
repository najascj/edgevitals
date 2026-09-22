// Orchestration: builds the schema, runs the tick loop, writes rows.
//
// Everything platform-specific lives behind ProcessSampler, SystemSampler and
// IpcServer. Agent itself only decides WHAT to record and WHEN.
#pragma once
#include <atomic>
#include <memory>
#include <string>

#include "edgevitals/Config.h"
#include "edgevitals/CsvSink.h"
#include "edgevitals/IpcServer.h"
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
};

}  // namespace ev
