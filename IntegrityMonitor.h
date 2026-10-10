// Endpoint integrity monitor (3.5): config, scheduling, change detection.
// Platform-neutral and tested on any host (evintegritytest).
//
// EdgeVitals' part: a baseline at start, a full re-check on a slow cadence,
// and a change record when a watched file's hash or the persistence set
// differs from the last run. Observe-only: it reports; it never restores a
// file or removes an autostart.
#pragma once
#include "edgevitals/CsvSink.h"   // Date
#include "edgevitals/IntegrityFacts.h"

#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ev {

class Json;

struct IntegrityConfig {
    bool enabled = true;
    int interval_minutes = 60;          // full re-hash + persistence read
    int max_events_per_hour = 12;       // upstream integrity events
    int max_files = 256;                // cap on the watched set
    long long max_file_mb = 64;         // skip a file larger than this (logged)
    std::string baseline = "config/integrity-baseline.json";
};
bool parseIntegrityConfig(const Json& h, IntegrityConfig& out, std::string& err);

// Reads and parses config/integrity-baseline.json (<= 1 MB). Never fails the
// caller: a missing or rejected file yields the built-in default (which
// approves nothing, so findings can only get louder) with label/err set.
// hash is "sha256:<hex>" of the file bytes, or "none".
void loadIntegrityBaseline(const std::string& path, IntegrityBaseline& out, std::string& label,
                           std::string& hash, std::string& err);

// One run's output: records for integrity-YYYY-MM-DD.jsonl and agent-log lines.
struct IntegrityRunOutput {
    std::vector<std::string> records;
    std::vector<std::pair<int, std::string>> log;   // (level 0 info / 1 warn, text)
    bool changed = false;
};

class IntegrityMonitor {
public:
    IntegrityMonitor(IntegrityBaseline baseline, std::string label, std::string hash,
                     std::string agentVersion, int maxEventsPerHour);

    // Session baseline on the first run and at each new day; a change record
    // when any result changed (status or key); a heartbeat on an interval run
    // with no change.
    void process(const IntegrityFacts& f, const std::string& trigger, bool intervalRun, double nowSec,
                 const Date& today, double costMs, IntegrityRunOutput& out);

    bool haveResult() const { return !last_.empty(); }
    int failCount() const { return failCount_; }
    const std::string& flags() const { return flags_; }
    long long upstreamSent() const { return upstreamSent_; }
    long long upstreamSuppressed() const { return upstreamSuppressedTotal_; }

private:
    bool upstream(double nowSec);
    std::string baselineRecord(const IntegrityFacts& f, const std::string& trigger, double costMs) const;

    IntegrityBaseline baseline_;
    std::string label_, hash_, agentVersion_;
    int maxPerHour_;
    std::vector<IntegrityResult> last_, baseRun_;
    std::map<std::string, double> deviatedSince_;
    Date lastDay_{};
    bool haveDay_ = false;
    int failCount_ = 0;
    std::string flags_;
    std::deque<double> sentTimes_;
    int suppressedSinceReport_ = 0;
    long long upstreamSent_ = 0, upstreamSuppressedTotal_ = 0;
};

std::string integrityHumanDuration(double seconds);

}  // namespace ev
