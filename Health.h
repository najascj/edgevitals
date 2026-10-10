// Health model -- the platform-neutral half of the EdgeBastion recovery link.
//
// EdgeVitals' charter does not change: it OBSERVES and ANSWERS. It never
// reboots, kills, restarts or suspends anything, never decides commit or
// rollback, never opens an XFS session, never touches transaction or cash
// state. EdgeBastion asks questions and receives advisories; EdgeBastion
// decides and acts. An "advisory" here is a message, never an action, and
// "suggested_action" is a hint EdgeBastion is free to ignore.
//
// Everything that DECIDES lives here, in the core, so it is tested off-target
// (evhealthtest): per-process state with hysteresis, absolute thresholds,
// slope-based trends, advisory rate limiting, and the request/response
// contract (query, all_healthy, watch, unwatch, ping, ack). The Win32 side
// (HealthServerWin.cpp) only moves bytes over a pipe and reads OS state.
//
// Time: every call takes nowSec (monotonic seconds) and, where an event
// needs a wall-clock stamp, wallMs. Tests drive both synthetically.
#pragma once
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace ev {

class Json;

// Thresholds for one critical process. A zero (or negative) value disables
// that check. Defaults are the EdgeBastion brief's (6 Oct 2026, section 4.2).
struct HealthLimits {
    double ceilingMb = 0;               // private-bytes ceiling; 0 => role ram_budget_mb
    double ceilingPct = 80;             // condition when private > pct% of ceiling
    double handlesMax = 10000;
    double handleGrowthPctPerHour = 5;  // sustained growth => leak
    double gdiMax = 8000;               // GDI or USER objects
    double gdiGrowthPerHour = 50;       // growth without plateau => leak
    double faultsPerSecMax = 20000;     // soft page faults per second
    double faultsHoldSec = 60;          // "sustained"
    double cpuPctMax = 90;
    double cpuHoldSec = 300;
    double leakWindowSec = 1800;        // history kept for memory trend
    double leakMinSpanSec = 600;        // evidence needed before calling a leak
    double leakMinMbPerHour = 20;
    double leakMinGrowthMb = 10;
    double hangHoldSec = 30;
    int hangMinSamples = 3;
    int absentMinSamples = 2;
    int thresholdMinSamples = 3;        // hysteresis for absolute thresholds
    double heartbeatMaxAgeSec = 10;     // two missed 5 s beats
    bool cpuStallHang = false;          // "no CPU accrued" counts as hung (opt-in:
                                        // idle services sit at 0 CPU legitimately)
};

struct CriticalProcess {
    std::string role;                   // a tracked role
    std::string process;                // display / query name, e.g. EdgeTerminal.exe
    std::string heartbeatRole;          // role key EdgeTerminal sends with {"hb":1}
    std::vector<std::string> aliases;   // every name a query may use: role, process, exes
    HealthLimits limits;
};

struct HealthConfig {
    bool enabled = true;
    // Its own pipe. \\.\pipe\edgevitals is the EdgeTerminal metrics pipe,
    // which has a different audience and ACL; one name cannot carry both.
    std::string pipe = "\\\\.\\pipe\\edgevitals-health";
    // Who may connect besides SYSTEM. Account names, resolved to SIDs at start.
    std::vector<std::string> allowedAccounts{"NT SERVICE\\EdgeBastion"};
    int maxClients = 4;
    double advisoryMinIntervalSec = 60; // per class, per process
    // After EdgeVitals starts, a critical process not yet seen raises no
    // "absent" advisory for this long: on boot, EdgeTerminal and the XFS
    // stack start minutes after us. all_healthy still answers false.
    double startupGraceSec = 180;
    int watchMaxPids = 32;
    double commitPctMax = 90;
    double diskFreeMbMin = 2048;
    double diskShrinkMbPerHour = 100;
    double diskTrendWindowSec = 3600;
    HealthLimits defaults;
    std::vector<CriticalProcess> critical;
};

// Parses the "health" object (h may be null => defaults). roleExists checks
// that every critical role is tracked: a critical role that can never be
// present would fail every health gate forever, so it is refused loudly.
bool parseHealthConfig(const Json& h, const std::vector<std::string>& trackedRoles,
                       const std::vector<std::vector<std::string>>& trackedExes,
                       HealthConfig& out, std::string& err);

// One process (or role) as seen this tick. Negative = not measured.
struct ProcObs {
    bool present = false;
    unsigned long pid = 0;
    std::uint64_t identity = 0;          // process-set signature
    double cpuPct = -1;
    double privateMb = -1;
    double rssMb = -1;
    double handles = -1;
    double gdi = -1;                     // max of GDI and USER
    double faultsPerSec = -1;
    double cpuSecondsDelta = -1;
    int windowResponding = -1;           // -1 unknown (always, in service mode), 0 no, 1 yes
    double heartbeatAtSec = -1;          // model time of last heartbeat; <0 none
};

// Least-squares trend over a sliding window.
class TrendSeries {
public:
    explicit TrendSeries(double windowSec = 1800) : window_(windowSec) {}
    void add(double t, double v);
    void clear() { pts_.clear(); }
    double spanSec() const;
    double slopePerHour() const;        // 0 when < 2 points
    double growth() const;              // last - first
    double mean() const;
    double nonDecreasingFraction(double tolerance) const;
    // Share of variance the trend line explains: ~1 for a steady leak under
    // jitter, ~0 for noise around a flat level.
    double r2() const;
    size_t size() const { return pts_.size(); }
    void setWindow(double w) { window_ = w; }

private:
    double window_;
    std::deque<std::pair<double, double>> pts_;
};

// A condition with hysteresis: raw this tick, confirmed once held long enough.
struct Condition {
    bool raw = false;
    bool confirmed = false;
    double since = 0;
    int samples = 0;
    std::string cls;                     // advisory class
    std::string severity;
    std::string evidence;                // JSON object body, without braces
    void update(bool now, double t, double holdSec, int minSamples);
};

class HealthModel {
public:
    HealthModel(HealthConfig cfg, std::string agentVersion);

    // ── agent thread ────────────────────────────────────────────────────
    // ceilingFallbackMb: the role's ram_budget_mb, used when limits.ceilingMb is 0.
    void observe(const std::string& role, const ProcObs& o, double ceilingFallbackMb,
                 double nowSec);
    void observeWatched(unsigned long pid, const std::string& exe, const ProcObs& o,
                        double nowSec);
    void observeSystem(double commitPct, double diskFreeMb, double nowSec);
    // Advisories due now (rate-limited) and crossing events (confirm/clear
    // transitions), as JSON lines. Advisories go to EdgeBastion and the log;
    // crossings go to the log.
    void collect(double nowSec, std::int64_t wallMs, std::vector<std::string>& advisories,
                 std::vector<std::string>& crossings);
    // PIDs EdgeBastion asked to watch / unwatch since the last call.
    void takeWatchRequests(std::vector<unsigned long>& add, std::vector<unsigned long>& remove);
    // CSV cell for a critical role: ok | absent | hung | thrash | leak.
    std::string stateOf(const std::string& role) const;

    // ── any thread (pipe clients) ───────────────────────────────────────
    // One request line in, one reply line out (no trailing newline).
    // logLine is set when the request should be recorded (ack, watch).
    std::string handleRequest(const std::string& line, double nowSec, std::string& logLine);

    const HealthConfig& config() const { return cfg_; }
    size_t watchedCount() const;

private:
    struct Tracker {
        std::string name;                // query name
        std::string role;                // empty for watched pids
        unsigned long pid = 0;
        HealthLimits lim;
        ProcObs last;
        double lastAt = -1;
        bool everSeen = false;
        std::uint64_t identity = 0;
        double identitySince = 0;
        bool heartbeatArmed = false;
        TrendSeries mem{1800}, handles{3600}, gdi{3600};
        std::map<std::string, Condition> cond;  // key -> condition
        bool dead = false;               // watched pid that exited
        bool deadReported = false;
    };
    void evaluate(Tracker& t, const ProcObs& o, double ceilingMb, double nowSec);
    std::string statusJson(const Tracker& t, double nowSec) const;
    std::string stateOfLocked(const Tracker& t) const;
    bool healthyLocked(const Tracker& t) const;
    const Tracker* findLocked(const std::string& name) const;

    HealthConfig cfg_;
    std::string version_;
    mutable std::mutex mu_;
    std::map<std::string, Tracker> roles_;           // by role
    std::map<unsigned long, Tracker> watched_;       // by pid
    std::map<std::string, std::string> alias_;       // lowercased name -> role
    Tracker system_;
    double diskAt_ = -1;
    std::map<std::string, double> lastAdvisory_;     // class|process -> nowSec
    std::vector<unsigned long> watchAdd_, watchRemove_;
    std::set<std::string> confirmedBefore_;          // for crossing transitions
    std::uint64_t advisorySeq_ = 0;
};

}  // namespace ev
