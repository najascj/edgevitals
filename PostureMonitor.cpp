#include "edgevitals/PostureMonitor.h"

#include "edgevitals/Digest.h"
#include "edgevitals/Json.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <fstream>

namespace ev {
namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string fmtMs(double ms) {
    char b[32];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), ...)
    (void)std::snprintf(b, sizeof(b), "%.2f", ms < 0 ? 0.0 : ms);
    return b;
}

bool looksLikeIp(const std::string& v) {
    if (v.empty() || v.size() > 45) return false;
    for (char c : v)
        if (!std::isxdigit(static_cast<unsigned char>(c)) && c != '.' && c != ':') return false;
    return v.find('.') != std::string::npos || v.find(':') != std::string::npos;
}

}  // namespace

std::vector<std::string> defaultWatchedServices() {
    // The services the catalogue judges. MpsSvc too: the firewall service
    // stopping is as much a posture change as RDP starting.
    return {"termservice", "tlntsvr", "sshd", "winrm", "lanmanserver", "remoteregistry",
            "snmp", "ftpsvc", "msftpsvc", "tftpd", "mpssvc"};
}

// err is unused today: every posture value is clamped, none refused. Kept so
// the signature matches parseWinEventsConfig and parseHealthConfig.
// cppcheck-suppress constParameterReference
bool parsePostureConfig(const Json& h, PostureConfig& out, std::string& err) {
    (void)err;
    PostureConfig c;
    c.watchedServices = defaultWatchedServices();
    if (h.isObject()) {
        c.enabled = h["enabled"].asBool(c.enabled);
        c.intervalMinutes = static_cast<int>(h["interval_minutes"].asInt(c.intervalMinutes));
        c.listenerPollSeconds = static_cast<int>(h["listener_poll_seconds"].asInt(c.listenerPollSeconds));
        c.onServiceChange = h["on_service_change"].asBool(c.onServiceChange);
        c.rdpSessionEvents = h["rdp_session_events"].asBool(c.rdpSessionEvents);
        c.rdpSessionSourceIp = h["rdp_session_source_ip"].asBool(c.rdpSessionSourceIp);
        c.maxEventsPerHour = static_cast<int>(h["max_events_per_hour"].asInt(c.maxEventsPerHour));
        c.profilePath = h["profile"].asString(c.profilePath);
        if (h.has("watched_services")) {
            // Additive, like the privacy deny-words: config can watch more, never fewer.
            const Json& a = h["watched_services"];
            for (size_t i = 0; i < a.size(); ++i) {
                const std::string s = lower(a[i].asString());
                if (!s.empty() && std::find(c.watchedServices.begin(), c.watchedServices.end(), s) == c.watchedServices.end())
                    c.watchedServices.push_back(s);
            }
        }
    }
    c.intervalMinutes = std::max(1, std::min(c.intervalMinutes, 1440));
    if (c.listenerPollSeconds != 0) c.listenerPollSeconds = std::max(10, std::min(c.listenerPollSeconds, 3600));
    c.maxEventsPerHour = std::max(1, std::min(c.maxEventsPerHour, 600));
    if (c.rdpSessionSourceIp && !c.rdpSessionEvents) c.rdpSessionSourceIp = false;
    out = std::move(c);
    return true;
}

void loadPostureProfile(const std::string& path, PostureProfile& out, std::string& label, std::string& hash,
                        std::string& err) {
    out = defaultPostureProfile();
    hash = "none";
    err.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + path;
        label = "default (built-in; " + err + ")";
        return;
    }
    std::string text;
    char buf[4096];  // flawfinder: ignore -- filled only by in.read(buf, sizeof(buf))
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
        text.append(buf, static_cast<size_t>(in.gcount()));
        if (text.size() > 256 * 1024) {
            err = path + " is larger than 256 KB";
            label = "default (built-in; profile too large)";
            return;
        }
    }
    hash = "sha256:" + sha256Hex(text);
    Json root;
    std::string perr;
    if (!Json::parse(text, root, perr)) {
        err = path + ": " + perr;
        label = "default (built-in; profile rejected)";
        return;
    }
    PostureProfile p;
    if (!parsePostureProfile(root, p, perr)) {
        err = path + ": " + perr;
        label = "default (built-in; profile rejected)";
        return;
    }
    out = std::move(p);
    label = out.name;
}

std::string humanDuration(double s) {
    if (s < 0) s = 0;
    const long long t = std::llround(s);
    if (t < 60) return std::to_string(t) + " s";
    const long long m = t / 60;
    if (m < 60) return std::to_string(m) + " min";
    const long long h = m / 60;
    if (h < 48) return std::to_string(h) + " h " + std::to_string(m % 60) + " min";
    return std::to_string(h / 24) + " d " + std::to_string(h % 24) + " h";
}

// ── scheduler ───────────────────────────────────────────────────────────────

PostureScheduler::PostureScheduler(double intervalSec, double listenerPollSec, double quietSec, double maxDelaySec)
    : interval_(intervalSec), poll_(listenerPollSec), quiet_(quietSec), maxDelay_(maxDelaySec) {}

void PostureScheduler::serviceEvent(double now, const std::string& what) {
    if (svcFirst_ < 0) {
        svcFirst_ = now;
        svcWhat_ = what;
    } else if (svcWhat_.find(what) == std::string::npos && svcWhat_.size() < 120) {
        svcWhat_ += "," + what;
    }
    svcLast_ = now;
}

void PostureScheduler::listenerChanged(double) { listener_ = true; }
void PostureScheduler::dayChanged(double) { midnight_ = true; }

bool PostureScheduler::fullDue(double now, std::string& trigger, bool& interval) const {
    interval = false;
    if (lastFull_ < 0) { trigger = "start"; return true; }
    if (midnight_) { trigger = "midnight"; return true; }
    if (svcFirst_ >= 0 && (now - svcLast_ >= quiet_ || now - svcFirst_ >= maxDelay_)) {
        trigger = "scm " + svcWhat_;
        return true;
    }
    if (listener_) { trigger = "listener"; return true; }
    if (now - lastFull_ >= interval_) {
        trigger = "interval";
        interval = true;
        return true;
    }
    return false;
}

void PostureScheduler::fullRan(double now) {
    lastFull_ = now;
    lastPoll_ = now;   // a full run read the listener table too
    svcFirst_ = svcLast_ = -1.0;
    svcWhat_.clear();
    listener_ = midnight_ = false;
}

bool PostureScheduler::listenerPollDue(double now) const {
    return poll_ > 0 && lastFull_ >= 0 && now - lastPoll_ >= poll_;
}

void PostureScheduler::listenerPolled(double now) { lastPoll_ = now; }

double PostureScheduler::secondsUntilNext(double now) const {
    if (lastFull_ < 0 || midnight_ || listener_) return 0.0;
    double next = lastFull_ + interval_;
    if (svcFirst_ >= 0) next = std::min(next, std::min(svcLast_ + quiet_, svcFirst_ + maxDelay_));
    if (poll_ > 0) next = std::min(next, lastPoll_ + poll_);
    return std::max(0.0, next - now);
}

// ── monitor ─────────────────────────────────────────────────────────────────

PostureMonitor::PostureMonitor(PostureProfile profile, std::string profileLabel, std::string profileHash,
                               std::string agentVersion, int maxEventsPerHour)
    : profile_(std::move(profile)), profileLabel_(std::move(profileLabel)), profileHash_(std::move(profileHash)),
      agentVersion_(std::move(agentVersion)), maxPerHour_(maxEventsPerHour < 1 ? 1 : maxEventsPerHour) {}

bool PostureMonitor::upstream(double now) {
    while (!sentTimes_.empty() && now - sentTimes_.front() >= 3600.0) sentTimes_.pop_front();
    if (static_cast<int>(sentTimes_.size()) >= maxPerHour_) {
        ++suppressedSinceReport_;
        ++upstreamSuppressedTotal_;
        return false;
    }
    sentTimes_.push_back(now);
    ++upstreamSent_;
    return true;
}

std::string PostureMonitor::baselineRecord(const PostureFacts& f, const std::string& trigger, double costMs, double cpuMs) const {
    return "{\"type\":\"baseline\",\"schema\":" + jsonQuote(kPostureSchema) + ",\"taken_at\":" + jsonQuote(f.takenAtUtc) +
           ",\"trigger\":" + jsonQuote(trigger) + ",\"agent\":\"edgevitals\",\"agent_version\":" + jsonQuote(agentVersion_) +
           ",\"profile\":" + jsonQuote(profileLabel_) + ",\"profile_hash\":" + jsonQuote(profileHash_) +
           ",\"elevated\":" + (f.elevated ? "true" : "false") + ",\"cost_ms\":" + fmtMs(costMs) +
           ",\"cpu_ms\":" + fmtMs(cpuMs) + ",\"summary\":" + summaryJson(summarize(last_)) + ",\"digest\":" + jsonQuote(postureDigest(last_)) +
           ",\"checks\":" + checksJson(last_) + "}";
}

void PostureMonitor::process(const PostureFacts& f, const std::string& trigger, bool intervalRun, double now,
                             const Date& today, double costMs, double cpuMs, PostureRunOutput& out) {
    out = PostureRunOutput();
    std::vector<PostureResult> prev = std::move(last_);
    last_ = evaluatePosture(f, profile_);
    const PostureSummary sum = summarize(last_);
    failCount_ = sum.fail;
    flags_ = failFlags(last_);

    const bool sessionStart = baseline_.empty();
    const bool newDay = !haveDay_ || lastDay_ != today;
    lastDay_ = today;
    haveDay_ = true;

    char counts[96];  // flawfinder: ignore -- written only by snprintf(counts, sizeof(counts), ...)
    (void)std::snprintf(counts, sizeof(counts), "%d FAIL %d WARN %d PASS %d INFO %d UNKNOWN", sum.fail, sum.warn, sum.pass,
                        sum.info, sum.unknown);

    if (sessionStart) {
        // The session baseline: what "back to normal" means for this run.
        baseline_ = last_;
        out.records.push_back(baselineRecord(f, trigger, costMs, cpuMs));
        out.log.emplace_back(0, std::string("[posture] baseline: ") + counts + " (profile " + profileLabel_ + ", " +
                                    (f.elevated ? "elevated" : "NOT elevated") + ", " + fmtMs(costMs) + " ms, cpu " +
                                    fmtMs(cpuMs) + " ms)");
        for (const auto& r : last_)
            if (r.status == PStatus::Fail || r.status == PStatus::Warn || r.status == PStatus::Unknown)
                out.log.emplace_back(r.status == PStatus::Fail ? 1 : 0,
                                     "[posture] " + r.id + " " + statusName(r.status) + ": " + r.summary);
        out.changed = true;
        return;
    }

    // Change detection against the previous run: status or key.
    std::string changes;
    int nChanges = 0;
    for (size_t i = 0; i < last_.size() && i < prev.size(); ++i) {
        const PostureResult& a = prev[i];
        const PostureResult& b = last_[i];
        if (a.status == b.status && a.key == b.key) continue;
        ++nChanges;
        const PostureResult& base = baseline_[i];
        const bool backToBase = b.status == base.status && b.key == base.key;
        double since = -1.0;
        if (backToBase) {
            auto it = deviatedSince_.find(b.id);
            if (it != deviatedSince_.end()) since = now - it->second;
            deviatedSince_.erase(b.id);
        } else if (!deviatedSince_.count(b.id)) {
            deviatedSince_[b.id] = now;
        }

        std::string c = "{\"id\":" + jsonQuote(b.id) + ",\"from\":" + jsonQuote(statusName(a.status)) +
                        ",\"to\":" + jsonQuote(statusName(b.status)) + ",\"severity\":" + jsonQuote(b.severity) +
                        ",\"summary\":" + jsonQuote(b.summary);
        if (a.status == b.status) c += ",\"key_changed\":true";
        if (backToBase) c += ",\"back_to_baseline\":true" + (since >= 0 ? ",\"after_s\":" + std::to_string(static_cast<long long>(since)) : std::string());
        c += ",\"observed\":" + (b.observed.empty() ? std::string("{}") : b.observed) + "}";
        changes += (changes.empty() ? "" : ",") + c;

        std::string line = "[posture] " + b.id + " " + statusName(a.status) + " -> " + statusName(b.status) + ": " + b.summary;
        if (backToBase) line += " - back to baseline" + (since >= 0 ? " after " + humanDuration(since) : std::string());
        line += " (trigger: " + trigger + ")";
        const bool worse = b.status == PStatus::Fail || b.status == PStatus::Warn || b.status == PStatus::Unknown;
        out.log.emplace_back(worse && !backToBase ? 1 : 0, line);

        // Upstream: critical on a move to FAIL at high severity -- including a
        // new reason while already failing (a second listener, a tool that
        // started) -- and info on the return to baseline.
        const bool critical = b.status == PStatus::Fail && b.severity == "high" && !backToBase;
        if (critical || (backToBase && a.status != b.status)) {
            if (upstream(now)) {
                std::string ev = "{\"type\":\"posture_event\",\"severity\":" + jsonQuote(critical ? "critical" : "info") +
                                 ",\"taken_at\":" + jsonQuote(f.takenAtUtc) + ",\"id\":" + jsonQuote(b.id) +
                                 ",\"from\":" + jsonQuote(statusName(a.status)) + ",\"to\":" + jsonQuote(statusName(b.status)) +
                                 ",\"summary\":" + jsonQuote(b.summary) + ",\"trigger\":" + jsonQuote(trigger);
                if (backToBase && since >= 0) ev += ",\"after_s\":" + std::to_string(static_cast<long long>(since));
                ev += "}";
                out.log.emplace_back(critical ? 1 : 0, "event: " + ev);
            }
        }
    }

    std::string extra;
    if (suppressedSinceReport_ > 0) {
        extra = ",\"upstream_suppressed\":" + std::to_string(suppressedSinceReport_);
        out.log.emplace_back(1, "[posture] upstream: " + std::to_string(suppressedSinceReport_) +
                                    " event(s) held back by max_events_per_hour=" + std::to_string(maxPerHour_) +
                                    " (all recorded in the posture file)");
        suppressedSinceReport_ = 0;
    }

    if (newDay) {
        // Each day file opens with a full document, so a day file read alone
        // (or an archived one) says what the posture was, not only what changed.
        out.records.push_back(baselineRecord(f, trigger, costMs, cpuMs));
        out.log.emplace_back(0, std::string("[posture] daily baseline: ") + counts);
    }
    if (nChanges > 0) {
        out.records.push_back("{\"type\":\"change\",\"taken_at\":" + jsonQuote(f.takenAtUtc) + ",\"trigger\":" + jsonQuote(trigger) +
                              ",\"cost_ms\":" + fmtMs(costMs) + ",\"cpu_ms\":" + fmtMs(cpuMs) + ",\"changes\":[" + changes + "],\"summary\":" + summaryJson(sum) +
                              ",\"digest\":" + jsonQuote(postureDigest(last_)) + extra + "}");
        out.changed = true;
    } else if (intervalRun && !newDay) {
        out.records.push_back("{\"type\":\"heartbeat\",\"taken_at\":" + jsonQuote(f.takenAtUtc) + ",\"cost_ms\":" + fmtMs(costMs) +
                              ",\"cpu_ms\":" + fmtMs(cpuMs) + ",\"summary\":" + summaryJson(sum) + ",\"digest\":" + jsonQuote(postureDigest(last_)) + extra + "}");
    }
}

bool PostureMonitor::rdpSession(const WinEvent& e, bool includeIp, double now, PostureRunOutput& out) {
    out = PostureRunOutput();
    const std::string prov = lower(e.provider);
    const char* kind = nullptr;
    std::string addr;
    auto field = [&](const char* name) {
        for (const auto& kv : e.data)
            if (lower(kv.first) == name) return kv.second;
        return std::string();
    };
    if (prov == "microsoft-windows-terminalservices-localsessionmanager") {
        if (e.id == 21) kind = "logon";
        else if (e.id == 24) kind = "disconnect";
        else if (e.id == 25) kind = "reconnect";
        addr = field("address");
    } else if (prov == "microsoft-windows-terminalservices-remoteconnectionmanager" && e.id == 1149) {
        kind = "auth_ok";
        addr = field("param3");
    }
    if (!kind) return false;
    // "LOCAL" is the console. Anything else that looks like an address is a
    // remote session. The address itself is recorded only when allowed.
    const bool remote = !addr.empty() && lower(addr) != "local";
    std::string rec = "{\"type\":\"rdp_session\",\"taken_at\":" + jsonQuote(e.timeUtc) + ",\"event_id\":" + std::to_string(e.id) +
                      ",\"kind\":" + jsonQuote(kind) + ",\"remote\":" + (remote ? "true" : "false");
    if (includeIp && remote && looksLikeIp(addr)) rec += ",\"source_ip\":" + jsonQuote(addr);
    rec += "}";
    out.records.push_back(rec);
    out.changed = true;
    if (remote) {
        out.log.emplace_back(1, std::string("[posture] RDP session ") + kind + " at " + e.timeUtc +
                                    (includeIp && looksLikeIp(addr) ? " from " + addr : std::string(" (remote)")));
        if (std::string(kind) == "logon" || std::string(kind) == "auth_ok" || std::string(kind) == "reconnect") {
            if (upstream(now))
                out.log.emplace_back(1, "event: {\"type\":\"posture_event\",\"severity\":\"critical\",\"taken_at\":" +
                                            jsonQuote(e.timeUtc) + ",\"id\":\"RA-001\",\"summary\":" +
                                            jsonQuote(std::string("RDP session ") + kind + " (remote)") + "}");
        }
    }
    return true;
}

}  // namespace ev
