#include "edgevitals/IntegrityMonitor.h"

#include "edgevitals/Digest.h"
#include "edgevitals/Json.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>

namespace ev {
namespace {

std::string fmtMs(double ms) {
    char b[32];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), ...)
    (void)std::snprintf(b, sizeof(b), "%.2f", ms < 0 ? 0.0 : ms);
    return b;
}

}  // namespace

// err is unused: every integrity value is clamped, none refused. Kept so the
// signature matches the other parse*Config functions.
// cppcheck-suppress constParameterReference
bool parseIntegrityConfig(const Json& h, IntegrityConfig& out, std::string& err) {
    (void)err;
    IntegrityConfig c;
    if (h.isObject()) {
        c.enabled = h["enabled"].asBool(c.enabled);
        c.interval_minutes = static_cast<int>(h["interval_minutes"].asInt(c.interval_minutes));
        c.max_events_per_hour = static_cast<int>(h["max_events_per_hour"].asInt(c.max_events_per_hour));
        c.max_files = static_cast<int>(h["max_files"].asInt(c.max_files));
        c.max_file_mb = h["max_file_mb"].asInt(c.max_file_mb);
        c.baseline = h["baseline"].asString(c.baseline);
    }
    c.interval_minutes = std::max(1, std::min(c.interval_minutes, 1440));
    c.max_events_per_hour = std::max(1, std::min(c.max_events_per_hour, 600));
    c.max_files = std::max(1, std::min(c.max_files, 4096));
    c.max_file_mb = std::max<long long>(1, std::min<long long>(c.max_file_mb, 1024));
    out = std::move(c);
    return true;
}

std::string integrityHumanDuration(double s) {
    if (s < 0) s = 0;
    const long long t = std::llround(s);
    if (t < 60) return std::to_string(t) + " s";
    const long long m = t / 60;
    if (m < 60) return std::to_string(m) + " min";
    const long long h = m / 60;
    if (h < 48) return std::to_string(h) + " h " + std::to_string(m % 60) + " min";
    return std::to_string(h / 24) + " d " + std::to_string(h % 24) + " h";
}

// Reads and parses the baseline file (<= 1 MB). Never fails the caller: on a
// missing or rejected file it returns the built-in default (which approves
// nothing, so findings can only get louder), with label and err set. hash is
// sha256 of the bytes, or "none".
void loadIntegrityBaseline(const std::string& path, IntegrityBaseline& out, std::string& label,
                           std::string& hash, std::string& err) {
    out = defaultIntegrityBaseline();
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
        if (text.size() > 1024 * 1024) {
            err = path + " is larger than 1 MB";
            label = "default (built-in; baseline too large)";
            return;
        }
    }
    hash = "sha256:" + sha256Hex(text);
    Json root;
    std::string perr;
    if (!Json::parse(text, root, perr)) {
        err = path + ": " + perr;
        label = "default (built-in; baseline rejected)";
        return;
    }
    IntegrityBaseline b;
    if (!parseIntegrityBaseline(root, b, perr)) {
        err = path + ": " + perr;
        label = "default (built-in; baseline rejected)";
        return;
    }
    out = std::move(b);
    label = out.name;
}

IntegrityMonitor::IntegrityMonitor(IntegrityBaseline baseline, std::string label, std::string hash,
                                   std::string agentVersion, int maxEventsPerHour)
    : baseline_(std::move(baseline)), label_(std::move(label)), hash_(std::move(hash)),
      agentVersion_(std::move(agentVersion)), maxPerHour_(maxEventsPerHour < 1 ? 1 : maxEventsPerHour) {}

bool IntegrityMonitor::upstream(double now) {
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

std::string IntegrityMonitor::baselineRecord(const IntegrityFacts& f, const std::string& trigger, double costMs) const {
    return "{\"type\":\"baseline\",\"schema\":" + iJsonQuote(kIntegritySchema) + ",\"taken_at\":" + iJsonQuote(f.takenAtUtc) +
           ",\"trigger\":" + iJsonQuote(trigger) + ",\"agent\":\"edgevitals\",\"agent_version\":" + iJsonQuote(agentVersion_) +
           ",\"baseline\":" + iJsonQuote(label_) + ",\"baseline_hash\":" + iJsonQuote(hash_) +
           ",\"elevated\":" + (f.elevated ? "true" : "false") + ",\"cost_ms\":" + fmtMs(costMs) +
           ",\"summary\":" + integritySummaryJson(summarizeIntegrity(last_)) + ",\"digest\":" + iJsonQuote(integrityDigest(last_)) +
           ",\"checks\":" + integrityChecksJson(last_) + "}";
}

void IntegrityMonitor::process(const IntegrityFacts& f, const std::string& trigger, bool intervalRun, double now,
                               const Date& today, double costMs, IntegrityRunOutput& out) {
    out = IntegrityRunOutput();
    std::vector<IntegrityResult> prev = std::move(last_);
    last_ = evaluateIntegrity(f, baseline_);
    const IntegritySummary sum = summarizeIntegrity(last_);
    failCount_ = sum.fail;
    flags_ = integrityFlags(last_);

    const bool sessionStart = baseRun_.empty();
    const bool newDay = !haveDay_ || lastDay_ != today;
    lastDay_ = today;
    haveDay_ = true;

    char counts[96];  // flawfinder: ignore -- written only by snprintf(counts, sizeof(counts), ...)
    (void)std::snprintf(counts, sizeof(counts), "%d FAIL %d WARN %d PASS %d INFO %d UNKNOWN", sum.fail, sum.warn, sum.pass, sum.info, sum.unknown);

    if (sessionStart) {
        baseRun_ = last_;
        out.records.push_back(baselineRecord(f, trigger, costMs));
        out.log.emplace_back(0, std::string("[integrity] baseline: ") + counts + " (baseline " + label_ + ", " +
                                    (f.elevated ? "elevated" : "NOT elevated") + ", " + fmtMs(costMs) + " ms)");
        for (const auto& r : last_)
            if (r.status == IStatus::Fail || r.status == IStatus::Warn || r.status == IStatus::Unknown)
                out.log.emplace_back(r.status == IStatus::Fail ? 1 : 0,
                                     "[integrity] " + r.id + " " + iStatusName(r.status) + ": " + r.summary);
        out.changed = true;
        return;
    }

    std::string changes;
    int nChanges = 0;
    for (size_t i = 0; i < last_.size() && i < prev.size(); ++i) {
        const IntegrityResult& a = prev[i];
        const IntegrityResult& b = last_[i];
        if (a.status == b.status && a.key == b.key) continue;
        ++nChanges;
        const IntegrityResult& base = baseRun_[i];
        const bool backToBase = b.status == base.status && b.key == base.key;
        double since = -1.0;
        if (backToBase) {
            auto it = deviatedSince_.find(b.id);
            if (it != deviatedSince_.end()) since = now - it->second;
            deviatedSince_.erase(b.id);
        } else if (!deviatedSince_.count(b.id)) {
            deviatedSince_[b.id] = now;
        }

        std::string c = "{\"id\":" + iJsonQuote(b.id) + ",\"from\":" + iJsonQuote(iStatusName(a.status)) +
                        ",\"to\":" + iJsonQuote(iStatusName(b.status)) + ",\"severity\":" + iJsonQuote(b.severity) +
                        ",\"summary\":" + iJsonQuote(b.summary);
        if (a.status == b.status) c += ",\"key_changed\":true";
        if (backToBase) c += ",\"back_to_baseline\":true" + (since >= 0 ? ",\"after_s\":" + std::to_string(static_cast<long long>(since)) : std::string());
        c += ",\"observed\":" + (b.observed.empty() ? std::string("{}") : b.observed) + "}";
        changes += (changes.empty() ? "" : ",") + c;

        std::string line = "[integrity] " + b.id + " " + iStatusName(a.status) + " -> " + iStatusName(b.status) + ": " + b.summary;
        if (backToBase) line += " - back to baseline" + (since >= 0 ? " after " + integrityHumanDuration(since) : std::string());
        line += " (trigger: " + trigger + ")";
        const bool worse = b.status == IStatus::Fail || b.status == IStatus::Warn || b.status == IStatus::Unknown;
        out.log.emplace_back(worse && !backToBase ? 1 : 0, line);

        const bool critical = b.status == IStatus::Fail && b.severity == "high" && !backToBase;
        if (critical || (backToBase && a.status != b.status)) {
            if (upstream(now)) {
                std::string ev = "{\"type\":\"integrity_event\",\"severity\":" + iJsonQuote(critical ? "critical" : "info") +
                                 ",\"taken_at\":" + iJsonQuote(f.takenAtUtc) + ",\"id\":" + iJsonQuote(b.id) +
                                 ",\"from\":" + iJsonQuote(iStatusName(a.status)) + ",\"to\":" + iJsonQuote(iStatusName(b.status)) +
                                 ",\"summary\":" + iJsonQuote(b.summary) + ",\"trigger\":" + iJsonQuote(trigger);
                if (backToBase && since >= 0) ev += ",\"after_s\":" + std::to_string(static_cast<long long>(since));
                ev += "}";
                out.log.emplace_back(critical ? 1 : 0, "event: " + ev);
            }
        }
    }

    std::string extra;
    if (suppressedSinceReport_ > 0) {
        extra = ",\"upstream_suppressed\":" + std::to_string(suppressedSinceReport_);
        out.log.emplace_back(1, "[integrity] upstream: " + std::to_string(suppressedSinceReport_) +
                                    " event(s) held back by max_events_per_hour=" + std::to_string(maxPerHour_) +
                                    " (all recorded in the integrity file)");
        suppressedSinceReport_ = 0;
    }

    if (newDay) {
        out.records.push_back(baselineRecord(f, trigger, costMs));
        out.log.emplace_back(0, std::string("[integrity] daily baseline: ") + counts);
    }
    if (nChanges > 0) {
        out.records.push_back("{\"type\":\"change\",\"taken_at\":" + iJsonQuote(f.takenAtUtc) + ",\"trigger\":" + iJsonQuote(trigger) +
                              ",\"cost_ms\":" + fmtMs(costMs) + ",\"changes\":[" + changes + "],\"summary\":" + integritySummaryJson(sum) +
                              ",\"digest\":" + iJsonQuote(integrityDigest(last_)) + extra + "}");
        out.changed = true;
    } else if (intervalRun && !newDay) {
        out.records.push_back("{\"type\":\"heartbeat\",\"taken_at\":" + iJsonQuote(f.takenAtUtc) + ",\"cost_ms\":" + fmtMs(costMs) +
                              ",\"summary\":" + integritySummaryJson(sum) + ",\"digest\":" + iJsonQuote(integrityDigest(last_)) + extra + "}");
    }
}

}  // namespace ev
