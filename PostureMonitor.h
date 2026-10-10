// Remote-access posture monitor (3.4): config, scheduling, change detection,
// upstream rate limit. Platform-neutral and tested on any host
// (evposturetest); the Win32 collector is PostureCollect.h.
//
// EdgeVitals' part of the posture work, as opposed to ATMProbe's: ATMProbe
// takes a one-time baseline, EdgeVitals keeps watching and reports WHEN
// SOMETHING CHANGES. Observe only -- it reports; it never switches anything off.
#pragma once
#include "edgevitals/CsvSink.h"
#include "edgevitals/PostureFacts.h"
#include "edgevitals/WinEvents.h"

#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ev {

class Json;

struct PostureConfig {
    bool enabled = true;
    int intervalMinutes = 15;          // full run on the slow tier
    int listenerPollSeconds = 60;      // TCP listener re-read; 0 = off
    bool onServiceChange = true;       // SCM 7036/7040 for a watched service -> run within 5 s
    // RDP session evidence (TerminalServices LocalSessionManager 21/24/25,
    // RemoteConnectionManager 1149). Off unless the bank allows those channels.
    bool rdpSessionEvents = false;
    // The source address of an RDP session. Off: the 3.3 privacy rule keeps IP
    // addresses out of every record. On only with the bank's written approval.
    bool rdpSessionSourceIp = false;
    int maxEventsPerHour = 12;         // upstream posture events
    std::string profilePath = "config/posture-profile.json";
    // Services whose state change triggers a run (key names, lower-cased).
    std::vector<std::string> watchedServices;
};
// h may be null (defaults). Clamps instead of refusing: a posture typo must
// not cost the terminal its telemetry.
bool parsePostureConfig(const Json& h, PostureConfig& out, std::string& err);
std::vector<std::string> defaultWatchedServices();

// When to run. Times are agent-monotonic seconds.
class PostureScheduler {
public:
    PostureScheduler(double intervalSec, double listenerPollSec, double quietSec = 1.5, double maxDelaySec = 4.0);

    // A watched service changed. Debounced: due after quietSec without a
    // further event, and never later than maxDelaySec after the first one --
    // so a burst (stop, start, start-type change) costs one run, inside 5 s.
    void serviceEvent(double now, const std::string& what);
    void listenerChanged(double now);
    void dayChanged(double now);

    // A full run is due now. trigger: start | interval | scm <service> |
    // listener | midnight. interval = this is the scheduled run (heartbeat on no change).
    bool fullDue(double now, std::string& trigger, bool& interval) const;
    void fullRan(double now);
    bool listenerPollDue(double now) const;
    void listenerPolled(double now);
    // Seconds until the next thing is due (0 if due now); for the wait.
    double secondsUntilNext(double now) const;

private:
    double interval_, poll_, quiet_, maxDelay_;
    double lastFull_ = -1.0;
    double lastPoll_ = -1.0;
    double svcFirst_ = -1.0, svcLast_ = -1.0;
    std::string svcWhat_;
    bool listener_ = false, midnight_ = false;
};

// One run's output: records for posture-YYYY-MM-DD.jsonl and lines for the
// agent log (level 0 info, 1 warn). "event: " lines are the upstream path
// until the leaf-node publisher lands, as for health and winevents.
struct PostureRunOutput {
    std::vector<std::string> records;
    std::vector<std::pair<int, std::string>> log;
    bool changed = false;
};

class PostureMonitor {
public:
    PostureMonitor(PostureProfile profile, std::string profileLabel, std::string profileHash,
                   std::string agentVersion, int maxEventsPerHour);

    // Evaluates and decides what to write. The first run of a session, and the
    // first run in each new day, write a full baseline record; later runs write
    // a change record when any check changed (status or key), a heartbeat when
    // it was the interval run and nothing changed, and nothing otherwise.
    void process(const PostureFacts& f, const std::string& trigger, bool intervalRun, double nowSec,
                 const Date& today, double costMs, double cpuMs, PostureRunOutput& out);

    // RDP session evidence from a routed Windows event. False when the event
    // is not one of the four.
    bool rdpSession(const WinEvent& e, bool includeSourceIp, double nowSec, PostureRunOutput& out);

    bool haveResult() const { return !last_.empty(); }
    int failCount() const { return failCount_; }
    const std::string& flags() const { return flags_; }
    const std::vector<PostureResult>& last() const { return last_; }
    long long upstreamSent() const { return upstreamSent_; }
    long long upstreamSuppressed() const { return upstreamSuppressedTotal_; }

private:
    bool upstream(double nowSec);   // rate limit: true = may send
    std::string baselineRecord(const PostureFacts& f, const std::string& trigger, double costMs, double cpuMs) const;

    PostureProfile profile_;
    std::string profileLabel_, profileHash_, agentVersion_;
    int maxPerHour_;
    std::vector<PostureResult> last_, baseline_;
    std::map<std::string, double> deviatedSince_;
    Date lastDay_{};
    bool haveDay_ = false;
    int failCount_ = 0;
    std::string flags_;
    std::deque<double> sentTimes_;
    int suppressedSinceReport_ = 0;
    long long upstreamSent_ = 0, upstreamSuppressedTotal_ = 0;
};

// Reads and parses the profile file (at most 256 KB). Never fails the caller:
// on a missing or rejected file it returns the built-in default -- the strict
// one, so a broken profile can only make findings louder -- with label saying
// why, and err set. hash is "sha256:<hex>" of the file bytes, or "none".
void loadPostureProfile(const std::string& path, PostureProfile& out, std::string& label, std::string& hash,
                        std::string& err);

// "2 h 27 min", "12 min", "45 s".
std::string humanDuration(double seconds);

}  // namespace ev
