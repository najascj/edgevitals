// Windows Event Log watcher -- the platform-neutral half (3.3).
//
// EdgeVitals reads selected Windows event channels and records CURATED
// events into its own chained daily stream (winevents-YYYY-MM-DD.jsonl).
// Observe only: nothing here acts on what it reads.
//
// PRIVACY RULE, enforced here and tested: a record carries event id, source,
// time, level and key fields ONLY. No user names, no file or registry paths,
// no SIDs, no e-mail addresses, no IP addresses. Field values are filtered by
// name (deny words) AND by shape (path-like, SID-like, address-like values
// are dropped even under a harmless name), so an event with unexpected fields
// cannot leak them.
//
// VOLUME RULE: per-key hourly limit, global per-minute and per-day caps.
// What is suppressed is counted and written as a periodic summary record, so
// suppression is never silent. The same caps bound the uplink, because the
// leaf-node publisher (next block) will send exactly these records.
//
// Split as elsewhere: everything that decides lives here (evwineventtest);
// WinEventsWin.cpp only subscribes to channels and keeps bookmarks.
#pragma once
#include "edgevitals/ChainedFile.h"
#include "edgevitals/CsvSink.h"

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ev {

class Json;

struct WinEventChannel {
    std::string name;                 // e.g. "System"
    bool enabled = false;
    // Also record events NOT covered by a rule when their level is 1..N
    // (1 critical, 2 error, 3 warning). 0 = rules only.
    int forwardUnlistedMaxLevel = 0;
};

struct WinEventRule {
    std::string name;                 // label carried in the record, e.g. "bugcheck"
    std::string channel;              // empty = any watched channel
    std::string provider;             // matches provider Name or EventSourceName
    std::vector<int> ids;
    std::string severity = "warning"; // critical | error | warning | info
    // Field allow-list for this rule (3.4). Empty = the general privacy
    // filter alone decides. Set when an event carries a person's name under
    // a harmless field name: RDP 1149 puts the user name in "Param1", which
    // no deny word and no value shape can tell from a service name. ["-"] =
    // record no fields at all.
    std::vector<std::string> fields = {};
};

struct WinEventsConfig {
    bool enabled = true;
    std::vector<WinEventChannel> channels;
    std::vector<WinEventRule> rules;
    // Route-only selections (3.4): read so another component can react (the
    // posture monitor watches SCM 7036/7040), never recorded by this filter.
    // Added to the channel XPath; admit() ignores them.
    std::vector<WinEventRule> routes;
    int backfillHours = 24;           // first start / stale bookmark: look back this far
    int maxPerTick = 200;             // events read per 10 s tick
    // Volume limits.
    int perKeyPerHour = 20;           // same channel/provider/id
    int perMinute = 30;               // all keys together
    int perDay = 5000;                // all keys together
    double summaryEverySec = 300;     // suppression summary cadence
    // Privacy limits.
    int maxFields = 8;
    int maxValueLen = 128;
    std::vector<std::string> deniedFieldWords;
};

// h may be null: defaults (System + Application on, Security off, built-in rules).
bool parseWinEventsConfig(const Json& h, WinEventsConfig& out, std::string& err);
WinEventsConfig defaultWinEventsConfig();

// One event as parsed from the XML Windows renders.
struct WinEvent {
    std::string channel;
    std::string provider;             // Provider/@Name
    std::string sourceName;           // Provider/@EventSourceName (classic sources)
    int id = -1;
    int level = -1;
    std::string timeUtc;              // TimeCreated/@SystemTime
    std::uint64_t recordId = 0;
    std::vector<std::pair<std::string, std::string>> data;   // EventData / UserData leaves
    // EventData/<Binary> as hex text, at most 512 characters. Never recorded:
    // used only for routing (SCM 7036 carries the service key name here).
    std::string binary;
};

// Tolerant extractor for the event XML Windows renders. Never reads past the
// input; returns false only when the essentials (provider, id) are missing.
bool parseEventXml(const std::string& xml, WinEvent& out);

// XPath filter for one channel: rule ids + level-based forwarding, bounded to
// the backfill window. Empty when the channel has nothing to collect.
std::string buildChannelXPath(const WinEventsConfig& c, const WinEventChannel& ch);

// Field filter: true if this name/value pair may leave the terminal.
bool fieldAllowed(const std::string& name, const std::string& value,
                  const std::vector<std::string>& deniedWords);

class WinEventFilter {
public:
    // exeToRole: lower-cased tracked executable name -> EdgeVitals role, so an
    // "Application Error" for EdgeTerminal.exe is tagged role "ui".
    WinEventFilter(WinEventsConfig cfg, std::map<std::string, std::string> exeToRole);

    // True and record set when the event is recorded; false when it is not
    // collected (no rule, below level) or suppressed by a limit (counted).
    bool admit(const WinEvent& e, double nowSec, std::string& record);
    // A suppression summary when one is due and anything was suppressed.
    bool summaryDue(double nowSec, const std::string& tsUtc, std::string& record);

    // Per-tick counters for the CSV, reset on read.
    void takeCounts(int& recorded, int& suppressed);
    // Severity of the last admitted record (for mirroring criticals).
    const std::string& lastSeverity() const { return lastSeverity_; }

private:
    const WinEventRule* match(const WinEvent& e) const;
    WinEventsConfig cfg_;
    std::map<std::string, std::string> exeToRole_;
    std::map<std::string, std::pair<double, int>> perKey_;   // key -> (window start, count)
    std::deque<double> lastMinute_;
    double dayStart_ = -1;
    int dayCount_ = 0;
    std::map<std::string, int> suppressed_;
    double lastSummary_ = 0;
    int tickRecorded_ = 0, tickSuppressed_ = 0;
    std::string lastSeverity_;
};

// Daily, chained JSON-lines stream: <prefix>YYYY-MM-DD.jsonl (+ .chain).
// winevents- (3.3) and posture- (3.4). Same lifecycle as the other streams
// (sealed at midnight and on shutdown, archived after archive_after_days,
// deleted at retention_days).
class WinEventLog {
public:
    WinEventLog(std::string dir, int chainEvery, std::string prefix = "winevents-")
        : dir_(std::move(dir)), prefix_(std::move(prefix)), file_(chainEvery) {}
    bool write(const std::string& line, const Date& today);
    void close() { file_.close(); }
    const std::string& path() const { return file_.path(); }

private:
    std::string dir_;
    std::string prefix_;
    ChainedFile file_;
    Date day_{};
    bool haveDay_ = false;
};

}  // namespace ev
