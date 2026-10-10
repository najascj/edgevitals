#include "edgevitals/Health.h"

#include "edgevitals/Json.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace ev {
namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string esc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), "\\u%04x", ...)
                    (void)std::snprintf(b, sizeof(b), "\\u%04x", c);
                    o += b;
                } else {
                    o.push_back(static_cast<char>(c));
                }
        }
    }
    return o;
}

std::string q(const std::string& s) { return "\"" + esc(s) + "\""; }

std::string num(double v, int prec = 2) {
    if (!std::isfinite(v)) return "null";
    char b[48];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), ...)
    const int n = std::snprintf(b, sizeof(b), "%.*f", prec, v);
    if (n < 0 || n >= static_cast<int>(sizeof(b))) {
        // Too large for fixed notation: exponent form (valid JSON), untrimmed.
        (void)std::snprintf(b, sizeof(b), "%.*e", prec, v);
        return std::string(b);
    }
    // Trim trailing zeros for readability; keeps integers integral.
    std::string s = b;
    if (s.find('.') != std::string::npos) {
        while (!s.empty() && s.back() == '0') s.pop_back();
        if (!s.empty() && s.back() == '.') s.pop_back();
    }
    return s;
}

std::string i64(long long v) { return std::to_string(v); }

void readLimits(const Json& j, HealthLimits& l) {
    if (!j.isObject()) return;
    auto n = [&](const char* k, double& v) { if (j.has(k)) v = j[k].asNumber(v); };
    auto i = [&](const char* k, int& v) { if (j.has(k)) v = static_cast<int>(j[k].asInt(v)); };
    n("ceiling_mb", l.ceilingMb);
    n("ceiling_pct", l.ceilingPct);
    n("handles_max", l.handlesMax);
    n("handle_growth_pct_per_hour", l.handleGrowthPctPerHour);
    n("gdi_max", l.gdiMax);
    n("gdi_growth_per_hour", l.gdiGrowthPerHour);
    n("faults_per_sec_max", l.faultsPerSecMax);
    n("faults_hold_s", l.faultsHoldSec);
    n("cpu_pct_max", l.cpuPctMax);
    n("cpu_hold_s", l.cpuHoldSec);
    n("leak_window_s", l.leakWindowSec);
    n("leak_min_span_s", l.leakMinSpanSec);
    n("leak_min_mb_per_hour", l.leakMinMbPerHour);
    n("leak_min_growth_mb", l.leakMinGrowthMb);
    n("hang_hold_s", l.hangHoldSec);
    i("hang_min_samples", l.hangMinSamples);
    i("absent_min_samples", l.absentMinSamples);
    i("threshold_min_samples", l.thresholdMinSamples);
    n("heartbeat_max_age_s", l.heartbeatMaxAgeSec);
    if (j.has("cpu_stall_hang")) l.cpuStallHang = j["cpu_stall_hang"].asBool(l.cpuStallHang);
    // Floors: a typo must not turn hysteresis off.
    if (l.hangMinSamples < 1) l.hangMinSamples = 1;
    if (l.absentMinSamples < 1) l.absentMinSamples = 1;
    if (l.thresholdMinSamples < 1) l.thresholdMinSamples = 1;
    if (l.hangHoldSec < 0) l.hangHoldSec = 0;
    if (l.leakWindowSec < 60) l.leakWindowSec = 60;
    if (l.leakMinSpanSec > l.leakWindowSec) l.leakMinSpanSec = l.leakWindowSec;
}

const char* suggestedAction(const std::string& cls) {
    if (cls == "absent") return "restart_process";
    if (cls == "hang") return "controlled_restart";
    if (cls == "leak") return "schedule_restart";
    if (cls == "disk") return "free_disk";
    if (cls == "commit") return "controlled_reboot";
    return "observe";
}

}  // namespace

// ── config ──────────────────────────────────────────────────────────────────

bool parseHealthConfig(const Json& h, const std::vector<std::string>& trackedRoles,
                       const std::vector<std::vector<std::string>>& trackedExes,
                       HealthConfig& out, std::string& err) {
    HealthConfig c;
    if (h.isObject()) {
        c.enabled = h["enabled"].asBool(c.enabled);
        c.pipe = h["pipe"].asString(c.pipe);
        if (h.has("allowed_accounts")) {
            c.allowedAccounts.clear();
            const Json& a = h["allowed_accounts"];
            for (size_t i = 0; i < a.size(); ++i)
                if (!a[i].asString().empty()) c.allowedAccounts.push_back(a[i].asString());
        }
        c.maxClients = static_cast<int>(h["max_clients"].asInt(c.maxClients));
        c.advisoryMinIntervalSec = h["advisory_min_interval_s"].asNumber(c.advisoryMinIntervalSec);
        c.startupGraceSec = h["startup_grace_s"].asNumber(c.startupGraceSec);
        c.watchMaxPids = static_cast<int>(h["watch_max_pids"].asInt(c.watchMaxPids));
        const Json& s = h["system"];
        if (s.isObject()) {
            c.commitPctMax = s["commit_pct_max"].asNumber(c.commitPctMax);
            c.diskFreeMbMin = s["disk_free_mb_min"].asNumber(c.diskFreeMbMin);
            c.diskShrinkMbPerHour = s["disk_shrink_mb_per_hour"].asNumber(c.diskShrinkMbPerHour);
        }
        readLimits(h["defaults"], c.defaults);
    }
    if (c.pipe.rfind("\\\\.\\pipe\\", 0) != 0) {
        err = "health.pipe must start with \\\\.\\pipe\\";
        return false;
    }
    if (c.maxClients < 1) c.maxClients = 1;
    if (c.maxClients > 16) c.maxClients = 16;
    if (c.advisoryMinIntervalSec < 5) c.advisoryMinIntervalSec = 5;
    if (c.startupGraceSec < 0) c.startupGraceSec = 0;
    if (c.watchMaxPids < 1) c.watchMaxPids = 1;
    if (c.watchMaxPids > 256) c.watchMaxPids = 256;

    auto roleIndex = [&](const std::string& r) -> int {
        for (size_t i = 0; i < trackedRoles.size(); ++i)
            if (trackedRoles[i] == r) return static_cast<int>(i);
        return -1;
    };
    auto finish = [&](CriticalProcess& cp, int idx) {
        const auto& exes = trackedExes[static_cast<size_t>(idx)];
        if (cp.process.empty()) {
            cp.process = exes.empty() ? cp.role : exes.front();
            // EdgeTerminal ships under two names; prefer the production one.
            for (const auto& e : exes)
                if (lower(e) == "edgeterminal.exe") cp.process = e;
        }
        cp.aliases.clear();
        cp.aliases.push_back(cp.role);
        cp.aliases.push_back(cp.process);
        for (const auto& e : exes) cp.aliases.push_back(e);
    };

    const Json crit = h.isObject() ? h["critical"] : Json();
    if (crit.isArray()) {
        for (size_t i = 0; i < crit.size(); ++i) {
            const Json& e = crit[i];
            CriticalProcess cp;
            cp.role = e["role"].asString();
            const int idx = roleIndex(cp.role);
            if (cp.role.empty() || idx < 0) {
                // Refused, not skipped: a critical role that can never be
                // present would fail every health gate, silently, forever.
                err = "health.critical[" + std::to_string(i) + "]: role '" + cp.role +
                      "' is not a tracked process role";
                return false;
            }
            cp.process = e["process"].asString();
            cp.heartbeatRole = e["heartbeat_role"].asString();
            cp.limits = c.defaults;
            readLimits(e, cp.limits);
            finish(cp, idx);
            c.critical.push_back(std::move(cp));
        }
    } else {
        // Brief's default critical set: EdgeTerminal, XFS SPs and broker, the
        // NATS leaf, EdgeBastion -- whichever of them this config tracks.
        const char* defaults[][2] = {{"ui", "ui"}, {"xfs", ""}, {"broker", ""}, {"nats", ""}, {"bastion", ""}};
        for (const auto& d : defaults) {
            const int idx = roleIndex(d[0]);
            if (idx < 0) continue;
            CriticalProcess cp;
            cp.role = d[0];
            cp.heartbeatRole = d[1];
            cp.limits = c.defaults;
            finish(cp, idx);
            c.critical.push_back(std::move(cp));
        }
    }
    out = std::move(c);
    return true;
}

// ── trend ───────────────────────────────────────────────────────────────────

void TrendSeries::add(double t, double v) {
    pts_.emplace_back(t, v);
    while (!pts_.empty() && t - pts_.front().first > window_) pts_.pop_front();
}

double TrendSeries::spanSec() const {
    return pts_.size() < 2 ? 0.0 : pts_.back().first - pts_.front().first;
}

double TrendSeries::slopePerHour() const {
    const size_t n = pts_.size();
    if (n < 2) return 0.0;
    double mt = 0, mv = 0;
    for (const auto& p : pts_) { mt += p.first; mv += p.second; }
    mt /= static_cast<double>(n);
    mv /= static_cast<double>(n);
    double num = 0, den = 0;
    for (const auto& p : pts_) {
        num += (p.first - mt) * (p.second - mv);
        den += (p.first - mt) * (p.first - mt);
    }
    return den <= 0 ? 0.0 : num / den * 3600.0;
}

double TrendSeries::growth() const { return pts_.size() < 2 ? 0.0 : pts_.back().second - pts_.front().second; }

double TrendSeries::mean() const {
    if (pts_.empty()) return 0.0;
    double s = 0;
    for (const auto& p : pts_) s += p.second;
    return s / static_cast<double>(pts_.size());
}

double TrendSeries::r2() const {
    const size_t n = pts_.size();
    if (n < 3) return 0.0;
    double mt = 0, mv = 0;
    for (const auto& p : pts_) { mt += p.first; mv += p.second; }
    mt /= static_cast<double>(n);
    mv /= static_cast<double>(n);
    double stt = 0, svv = 0, stv = 0;
    for (const auto& p : pts_) {
        stt += (p.first - mt) * (p.first - mt);
        svv += (p.second - mv) * (p.second - mv);
        stv += (p.first - mt) * (p.second - mv);
    }
    if (stt <= 0 || svv <= 0) return 0.0;
    return (stv * stv) / (stt * svv);
}

double TrendSeries::nonDecreasingFraction(double tolerance) const {
    if (pts_.size() < 2) return 0.0;
    size_t ok = 0;
    for (size_t i = 1; i < pts_.size(); ++i)
        if (pts_[i].second >= pts_[i - 1].second - tolerance) ++ok;
    return static_cast<double>(ok) / static_cast<double>(pts_.size() - 1);
}

// ── condition ───────────────────────────────────────────────────────────────

void Condition::update(bool now, double t, double holdSec, int minSamples) {
    if (!now) {
        raw = false;
        confirmed = false;
        samples = 0;
        return;
    }
    if (!raw) {
        since = t;
        samples = 1;
    } else {
        ++samples;
    }
    raw = true;
    confirmed = (t - since >= holdSec) && samples >= minSamples;
}

// ── model ───────────────────────────────────────────────────────────────────

HealthModel::HealthModel(HealthConfig cfg, std::string agentVersion)
    : cfg_(std::move(cfg)), version_(std::move(agentVersion)) {
    for (const auto& cp : cfg_.critical) {
        Tracker t;
        t.name = cp.process;
        t.role = cp.role;
        t.lim = cp.limits;
        t.mem.setWindow(cp.limits.leakWindowSec);
        roles_[cp.role] = std::move(t);
        for (const auto& a : cp.aliases) alias_[lower(a)] = cp.role;
    }
    system_.name = "system";
    system_.lim = cfg_.defaults;
}

void HealthModel::evaluate(Tracker& t, const ProcObs& o, double ceilingMb, double now) {
    const HealthLimits& L = t.lim;
    t.lastAt = now;
    t.everSeen = t.everSeen || o.present;

    if (o.present && (o.identity != t.identity || !t.last.present)) {
        // A new process set: nothing measured about the old one applies.
        if (o.identity != t.identity) {
            t.mem.clear();
            t.handles.clear();
            t.gdi.clear();
            for (auto& kv : t.cond)
                if (kv.first != "absent") kv.second.update(false, now, 0, 1);
            t.heartbeatArmed = false;
            t.identitySince = now;
        }
        t.identity = o.identity;
    }
    t.last = o;

    Condition& ab = t.cond["absent"];
    ab.cls = "absent";
    ab.severity = "critical";
    ab.update(!o.present, now, 0, t.role.empty() ? 1 : L.absentMinSamples);
    ab.evidence = "\"samples\":" + std::to_string(ab.samples);
    if (!o.present) {
        for (auto& kv : t.cond)
            if (kv.first != "absent") kv.second.update(false, now, 0, 1);
        return;
    }

    // Heartbeat arms once one arrives from THIS instance; until then (or if
    // EdgeTerminal has not implemented it yet) its absence proves nothing.
    if (o.heartbeatAtSec >= 0 && o.heartbeatAtSec >= t.identitySince) t.heartbeatArmed = true;
    const double hbAge = (t.heartbeatArmed && o.heartbeatAtSec >= 0) ? now - o.heartbeatAtSec : -1;

    auto set = [&](const char* key, const char* cls, const char* sev, bool raw, double hold,
                   int minS, const std::string& ev) {
        Condition& c = t.cond[key];
        c.cls = cls;
        c.severity = sev;
        c.update(raw, now, hold, minS);
        c.evidence = ev;
    };

    {   // hang
        const bool hbStale = L.heartbeatMaxAgeSec > 0 && hbAge >= L.heartbeatMaxAgeSec;
        const bool winHung = o.windowResponding == 0;
        const bool stalled = L.cpuStallHang && o.cpuSecondsDelta == 0.0;
        Condition& c = t.cond["hang"];
        const bool raw = hbStale || winHung || stalled;
        set("hang", "hang", "critical", raw, L.hangHoldSec, L.hangMinSamples, "");
        c.evidence = "\"samples\":" + std::to_string(c.samples) + ",\"window_responding\":" +
                     (o.windowResponding < 0 ? std::string("null") : (o.windowResponding ? "true" : "false")) +
                     ",\"heartbeat_age_ms\":" + (hbAge < 0 ? std::string("null") : i64(static_cast<long long>(hbAge * 1000))) +
                     ",\"cpu_stall\":" + (stalled ? "true" : "false");
    }

    const double ceiling = L.ceilingMb > 0 ? L.ceilingMb : ceilingMb;
    {   // memory against ceiling
        const bool raw = ceiling > 0 && o.privateMb >= 0 && o.privateMb > ceiling * L.ceilingPct / 100.0;
        const bool over = ceiling > 0 && o.privateMb > ceiling;
        set("memory", "thrash", over ? "critical" : "warning", raw, 0, L.thresholdMinSamples,
            "\"private_mb\":" + num(o.privateMb) + ",\"ceiling_mb\":" + num(ceiling) +
                ",\"ceiling_pct\":" + num(L.ceilingPct));
    }
    set("handles", "thrash", "warning", L.handlesMax > 0 && o.handles > L.handlesMax, 0,
        L.thresholdMinSamples, "\"handles\":" + num(o.handles, 0) + ",\"max\":" + num(L.handlesMax, 0));
    set("gdi", "thrash", "warning", L.gdiMax > 0 && o.gdi > L.gdiMax, 0, L.thresholdMinSamples,
        "\"gdi_user_objects\":" + num(o.gdi, 0) + ",\"max\":" + num(L.gdiMax, 0));
    set("cpu", "thrash", "warning", L.cpuPctMax > 0 && o.cpuPct > L.cpuPctMax, L.cpuHoldSec,
        L.thresholdMinSamples, "\"cpu_pct\":" + num(o.cpuPct) + ",\"max\":" + num(L.cpuPctMax));
    set("faults", "thrash", "warning", L.faultsPerSecMax > 0 && o.faultsPerSec > L.faultsPerSecMax,
        L.faultsHoldSec, L.thresholdMinSamples,
        "\"soft_faults_per_s\":" + num(o.faultsPerSec, 0) + ",\"max\":" + num(L.faultsPerSecMax, 0));

    {   // memory trend
        if (o.privateMb >= 0) t.mem.add(now, o.privateMb);
        const double slope = t.mem.slopePerHour();
        const bool raw = L.leakMinMbPerHour > 0 && t.mem.spanSec() >= L.leakMinSpanSec &&
                         slope >= L.leakMinMbPerHour && t.mem.growth() >= L.leakMinGrowthMb &&
                         t.mem.r2() >= 0.5;
        set("leak_memory", "leak", "warning", raw, 0, L.thresholdMinSamples,
            "\"private_mb\":" + num(o.privateMb) + ",\"slope_mb_per_hour\":" + num(slope) +
                ",\"window_s\":" + num(t.mem.spanSec(), 0) + ",\"r2\":" + num(t.mem.r2()));
    }
    {   // handle trend: sustained relative growth
        if (o.handles >= 0) t.handles.add(now, o.handles);
        const double m = t.handles.mean();
        const double pct = m > 0 ? t.handles.slopePerHour() / m * 100.0 : 0.0;
        const bool raw = L.handleGrowthPctPerHour > 0 && t.handles.spanSec() >= 1800 &&
                         pct >= L.handleGrowthPctPerHour && t.handles.nonDecreasingFraction(2.0) >= 0.7;
        set("leak_handles", "leak", "warning", raw, 0, L.thresholdMinSamples,
            "\"handles\":" + num(o.handles, 0) + ",\"growth_pct_per_hour\":" + num(pct));
    }
    {   // GDI/USER trend: growth without plateau
        if (o.gdi >= 0) t.gdi.add(now, o.gdi);
        const double slope = t.gdi.slopePerHour();
        const bool raw = L.gdiGrowthPerHour > 0 && t.gdi.spanSec() >= 1800 &&
                         slope >= L.gdiGrowthPerHour && t.gdi.nonDecreasingFraction(1.0) >= 0.8;
        set("leak_gdi", "leak", "warning", raw, 0, L.thresholdMinSamples,
            "\"gdi_user_objects\":" + num(o.gdi, 0) + ",\"slope_per_hour\":" + num(slope));
    }
}

void HealthModel::observe(const std::string& role, const ProcObs& o, double ceilingFallbackMb,
                          double nowSec) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = roles_.find(role);
    if (it == roles_.end()) return;
    evaluate(it->second, o, ceilingFallbackMb, nowSec);
}

void HealthModel::observeWatched(unsigned long pid, const std::string& exe, const ProcObs& o,
                                 double nowSec) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = watched_.find(pid);
    if (it == watched_.end()) {
        Tracker t;
        t.name = "pid:" + std::to_string(pid);
        t.pid = pid;
        t.lim = cfg_.defaults;
        it = watched_.emplace(pid, std::move(t)).first;
    }
    // Named "pid:N" for queries; the image name is recorded once, in the log,
    // by the agent when the watch is opened.
    (void)exe;
    evaluate(it->second, o, 0, nowSec);
    if (!o.present) it->second.dead = true;
}

void HealthModel::observeSystem(double commitPct, double diskFreeMb, double nowSec) {
    std::lock_guard<std::mutex> lk(mu_);
    Tracker& t = system_;
    t.lastAt = nowSec;
    t.everSeen = true;
    t.last.present = true;
    const int m = cfg_.defaults.thresholdMinSamples;
    auto set = [&](const char* key, const char* cls, const char* sev, bool raw, const std::string& ev) {
        Condition& c = t.cond[key];
        c.cls = cls;
        c.severity = sev;
        c.update(raw, nowSec, 0, m);
        c.evidence = ev;
    };
    set("commit", "commit", "critical", cfg_.commitPctMax > 0 && commitPct > cfg_.commitPctMax,
        "\"commit_pct\":" + num(commitPct) + ",\"max\":" + num(cfg_.commitPctMax));
    set("disk_low", "disk", "critical", cfg_.diskFreeMbMin > 0 && diskFreeMb >= 0 && diskFreeMb < cfg_.diskFreeMbMin,
        "\"free_mb\":" + num(diskFreeMb, 0) + ",\"min_mb\":" + num(cfg_.diskFreeMbMin, 0));
    if (diskFreeMb >= 0) {
        t.mem.setWindow(cfg_.diskTrendWindowSec);
        t.mem.add(nowSec, diskFreeMb);
    }
    const double slope = t.mem.slopePerHour();
    set("disk_shrink", "disk", "warning",
        cfg_.diskShrinkMbPerHour > 0 && t.mem.spanSec() >= 1800 && -slope >= cfg_.diskShrinkMbPerHour,
        "\"free_mb\":" + num(diskFreeMb, 0) + ",\"shrink_mb_per_hour\":" + num(-slope));
}

void HealthModel::collect(double nowSec, std::int64_t wallMs, std::vector<std::string>& advisories,
                          std::vector<std::string>& crossings) {
    std::lock_guard<std::mutex> lk(mu_);
    std::set<std::string> confirmedNow;
    std::set<std::string> advisedThisTick;

    auto visit = [&](Tracker& t) {
        if (t.lastAt < 0) return;
        for (const auto& kv : t.cond) {
            const Condition& c = kv.second;
            const std::string ck = t.name + "|" + kv.first;
            if (c.confirmed) {
                confirmedNow.insert(ck);
                if (!confirmedBefore_.count(ck)) {
                    crossings.push_back("{\"type\":\"crossing\",\"ts_ms\":" + i64(wallMs) +
                                        ",\"edge\":\"raised\",\"process\":" + q(t.name) +
                                        ",\"condition\":" + q(kv.first) + ",\"class\":" + q(c.cls) +
                                        ",\"severity\":" + q(c.severity) + ",\"evidence\":{" + c.evidence + "}}");
                }
            }
            if (!c.confirmed) continue;
            // A watched PID that died is reported once; it cannot recover.
            if (t.dead && t.deadReported) continue;
            // Boot: not started yet is not the same as died.
            if (kv.first == "absent" && !t.role.empty() && !t.everSeen && nowSec < cfg_.startupGraceSec) continue;
            const std::string lk2 = c.cls + "|" + t.name;
            if (advisedThisTick.count(lk2)) continue;
            auto last = lastAdvisory_.find(lk2);
            if (last != lastAdvisory_.end() && nowSec - last->second < cfg_.advisoryMinIntervalSec) continue;
            lastAdvisory_[lk2] = nowSec;
            advisedThisTick.insert(lk2);
            char id[40];  // flawfinder: ignore -- written only by snprintf(id, sizeof(id), ...)
            (void)std::snprintf(id, sizeof(id), "%012llx%04llx",
                          static_cast<unsigned long long>(wallMs) & 0xFFFFFFFFFFFFull,
                          static_cast<unsigned long long>(++advisorySeq_ & 0xFFFF));
            std::string a = "{\"type\":\"advisory\",\"advisory_id\":\"" + std::string(id) +
                            "\",\"ts_ms\":" + i64(wallMs) + ",\"severity\":" + q(c.severity) +
                            ",\"class\":" + q(c.cls) + ",\"process\":" + q(t.name);
            if (!t.role.empty()) a += ",\"role\":" + q(t.role);
            const unsigned long pid = t.pid ? t.pid : t.last.pid;
            a += ",\"pid\":" + (pid ? std::to_string(pid) : std::string("null"));
            a += ",\"held_for_ms\":" + i64(static_cast<long long>((nowSec - c.since) * 1000));
            a += ",\"evidence\":{" + c.evidence + "}";
            a += ",\"suggested_action\":" + q(suggestedAction(c.cls)) + "}";
            advisories.push_back(std::move(a));
            if (t.dead) t.deadReported = true;
        }
    };
    for (auto& kv : roles_) visit(kv.second);
    for (auto& kv : watched_) visit(kv.second);
    visit(system_);

    for (const auto& ck : confirmedBefore_) {
        if (confirmedNow.count(ck)) continue;
        const size_t bar = ck.find('|');
        crossings.push_back("{\"type\":\"crossing\",\"ts_ms\":" + i64(wallMs) +
                            ",\"edge\":\"cleared\",\"process\":" + q(ck.substr(0, bar)) +
                            ",\"condition\":" + q(ck.substr(bar + 1)) + "}");
    }
    confirmedBefore_.swap(confirmedNow);
}

void HealthModel::takeWatchRequests(std::vector<unsigned long>& add, std::vector<unsigned long>& remove) {
    std::lock_guard<std::mutex> lk(mu_);
    add.swap(watchAdd_);
    remove.swap(watchRemove_);
    watchAdd_.clear();
    watchRemove_.clear();
    for (unsigned long p : remove) watched_.erase(p);
}

size_t HealthModel::watchedCount() const {
    std::lock_guard<std::mutex> lk(mu_);
    return watched_.size();
}

std::string HealthModel::stateOfLocked(const Tracker& t) const {
    if (t.lastAt < 0) return "";
    if (!t.last.present) return "absent";
    auto conf = [&](const char* k) {
        auto it = t.cond.find(k);
        return it != t.cond.end() && it->second.confirmed;
    };
    if (conf("hang")) return "hung";
    for (const auto& kv : t.cond)
        if (kv.second.confirmed && kv.second.cls == "thrash") return "thrash";
    for (const auto& kv : t.cond)
        if (kv.second.confirmed && kv.second.cls == "leak") return "leak";
    return "ok";
}

std::string HealthModel::stateOf(const std::string& role) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = roles_.find(role);
    return it == roles_.end() ? std::string() : stateOfLocked(it->second);
}

bool HealthModel::healthyLocked(const Tracker& t) const {
    if (t.lastAt < 0 || !t.last.present) return false;   // never seen, or gone NOW
    for (const auto& kv : t.cond)
        if (kv.second.confirmed) return false;
    return true;
}

const HealthModel::Tracker* HealthModel::findLocked(const std::string& name) const {
    const std::string n = lower(name);
    if (n.rfind("pid:", 0) == 0) {
        char* end = nullptr;
        const unsigned long pid = std::strtoul(n.c_str() + 4, &end, 10);
        auto it = watched_.find(pid);
        return it == watched_.end() ? nullptr : &it->second;
    }
    if (n == "system") return system_.lastAt < 0 ? nullptr : &system_;
    auto a = alias_.find(n);
    if (a == alias_.end()) return nullptr;
    auto it = roles_.find(a->second);
    return it == roles_.end() ? nullptr : &it->second;
}

std::string HealthModel::statusJson(const Tracker& t, double nowSec) const {
    const ProcObs& o = t.last;
    bool within = true;
    std::string conds;
    for (const auto& kv : t.cond) {
        if (!kv.second.confirmed) continue;
        if (kv.second.cls == "thrash" || kv.second.cls == "leak") within = false;
        conds += (conds.empty() ? "" : ",") + q(kv.first);
    }
    const double hbAge = (t.heartbeatArmed && o.heartbeatAtSec >= 0) ? nowSec - o.heartbeatAtSec : -1;
    std::string s = "{\"name\":" + q(t.name) + ",\"present\":" + (o.present ? "true" : "false") +
                    ",\"state\":" + q(stateOfLocked(t));
    if (o.present) {
        s += ",\"pid\":" + std::to_string(o.pid);
        s += ",\"cpu_pct\":" + (o.cpuPct < 0 ? std::string("null") : num(o.cpuPct));
        s += ",\"rss_bytes\":" + (o.rssMb < 0 ? std::string("null") : i64(static_cast<long long>(o.rssMb * 1048576.0)));
        s += ",\"private_bytes\":" + (o.privateMb < 0 ? std::string("null") : i64(static_cast<long long>(o.privateMb * 1048576.0)));
        s += ",\"handles\":" + (o.handles < 0 ? std::string("null") : num(o.handles, 0));
    }
    s += ",\"within_thresholds\":" + std::string(within ? "true" : "false");
    s += ",\"heartbeat_age_ms\":" + (hbAge < 0 ? std::string("null") : i64(static_cast<long long>(hbAge * 1000)));
    s += ",\"window_responding\":" +
         (o.windowResponding < 0 ? std::string("null") : (o.windowResponding ? "true" : "false"));
    // How old the answer is: queries are served from the last tick, never
    // sampled on demand, which is what keeps them inside the 100 ms budget.
    s += ",\"sample_age_ms\":" + i64(static_cast<long long>((nowSec - t.lastAt) * 1000));
    s += ",\"conditions\":[" + conds + "]}";
    return s;
}

std::string HealthModel::handleRequest(const std::string& line, double nowSec, std::string& logLine) {
    logLine.clear();
    if (line.size() > 64 * 1024) return "{\"ok\":false,\"err\":\"request too large\"}";
    Json j;
    std::string perr;
    if (!Json::parse(line, j, perr) || !j.isObject()) return "{\"ok\":false,\"err\":\"bad json\"}";
    const std::string idPart = j.has("id") && j["id"].type() == Json::Type::Number
                                   ? "\"id\":" + i64(j["id"].asInt()) + ","
                                   : std::string();
    const std::string op = j["op"].asString();
    auto fail = [&](const std::string& e) { return "{" + idPart + "\"ok\":false,\"err\":" + q(e) + "}"; };

    if (op == "ping") {
        return "{" + idPart + "\"ok\":true,\"version\":" + q(version_) +
               ",\"uptime_ms\":" + i64(static_cast<long long>(nowSec * 1000)) + "}";
    }
    if (op == "query" || op == "all_healthy") {
        const Json& p = j["processes"];
        if (!p.isArray() || p.size() == 0) return fail("processes must be a non-empty array");
        if (p.size() > 64) return fail("too many processes");
        std::lock_guard<std::mutex> lk(mu_);
        bool all = true;
        std::string results;
        for (size_t i = 0; i < p.size(); ++i) {
            const std::string name = p[i].asString();
            const Tracker* t = findLocked(name);
            if (!t) {
                all = false;   // unknown names fail safe
                results += (results.empty() ? "" : ",") + std::string("{\"name\":") + q(name) +
                           ",\"present\":false,\"state\":\"unknown\",\"within_thresholds\":false}";
                continue;
            }
            all = all && healthyLocked(*t);
            results += (results.empty() ? "" : ",") + statusJson(*t, nowSec);
        }
        if (op == "all_healthy")
            return "{" + idPart + "\"ok\":true,\"healthy\":" + (all ? "true" : "false") + "}";
        return "{" + idPart + "\"ok\":true,\"results\":[" + results + "]}";
    }
    if (op == "watch" || op == "unwatch") {
        const Json& p = j["pids"];
        if (!p.isArray() || p.size() == 0) return fail("pids must be a non-empty array");
        std::vector<unsigned long> pids;
        for (size_t i = 0; i < p.size(); ++i) {
            const long long v = p[i].asInt(-1);
            if (p[i].type() != Json::Type::Number || v <= 0 || v > 0xFFFFFFFFLL) return fail("invalid pid");
            pids.push_back(static_cast<unsigned long>(v));
        }
        std::lock_guard<std::mutex> lk(mu_);
        if (op == "watch") {
            std::set<unsigned long> fresh;
            for (unsigned long x : pids)
                if (!watched_.count(x)) fresh.insert(x);
            for (unsigned long x : watchAdd_) fresh.erase(x);
            if (watched_.size() + watchAdd_.size() + fresh.size() > static_cast<size_t>(cfg_.watchMaxPids))
                return fail("watch limit reached");
            for (unsigned long x : fresh) watchAdd_.push_back(x);
        } else {
            for (unsigned long x : pids) watchRemove_.push_back(x);
        }
        std::string list;
        for (unsigned long x : pids) list += (list.empty() ? "" : ",") + std::to_string(x);
        logLine = "health: " + op + " pids=" + list;
        return "{" + idPart + "\"ok\":true}";
    }
    if (op == "ack") {
        const std::string aid = j["advisory_id"].asString();
        if (aid.empty()) return fail("advisory_id required");
        // EdgeBastion reports what it decided; recorded beside the advisory so
        // the chain holds both halves.
        logLine = "event: {\"type\":\"advisory_ack\",\"advisory_id\":" + q(aid) +
                  ",\"action\":" + q(j["action"].asString("none")) +
                  ",\"detail\":" + q(j["detail"].asString()) + "}";
        return "{" + idPart + "\"ok\":true}";
    }
    return fail("unknown op");
}

}  // namespace ev
