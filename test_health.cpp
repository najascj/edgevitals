// EdgeVitals health-model tests (evhealthtest).
//
// The decision logic behind the EdgeBastion recovery link, driven with
// synthetic time so every hysteresis window is exact. Maps to the acceptance
// table in the EdgeBastion handoff (6 Oct 2026, section 6) wherever a test can
// be run off-target; the rest are hardware tests listed in the release notes.
#include "edgevitals/Health.h"
#include "edgevitals/Json.h"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

using namespace ev;

namespace {
int g_pass = 0, g_fail = 0;
void check(const char* name, bool ok, const std::string& d = "") {
    std::printf("  %-60s %s%s%s\n", name, ok ? "PASS" : "FAIL", d.empty() ? "" : "   ", d.c_str());
    (ok ? g_pass : g_fail)++;
}
bool has(const std::string& s, const std::string& sub) { return s.find(sub) != std::string::npos; }

HealthConfig cfgFor(const char* extra = "") {
    std::string text = std::string("{\"critical\":[{\"role\":\"ui\",\"process\":\"EdgeTerminal.exe\",\"heartbeat_role\":\"ui\"") +
                       extra + "},{\"role\":\"xfs\"}]}";
    Json j;
    std::string e;
    Json::parse(text, j, e);
    HealthConfig c;
    std::string err;
    parseHealthConfig(j, {"ui", "xfs"}, {{"EdgeTerminalDemo.exe", "EdgeTerminal.exe"}, {"pertocdmspimanager.exe"}}, c, err);
    return c;
}

ProcObs live(double privateMb = 300, double handles = 1200) {
    ProcObs o;
    o.present = true;
    o.pid = 4120;
    o.identity = 77;
    o.cpuPct = 3;
    o.privateMb = privateMb;
    o.rssMb = 256;
    o.handles = handles;
    o.gdi = 600;
    o.faultsPerSec = 100;
    o.cpuSecondsDelta = 0.2;
    return o;
}

struct Out {
    std::vector<std::string> adv, cross;
};
Out collect(HealthModel& m, double t) {
    Out o;
    m.collect(t, 1791234567890LL + static_cast<long long>(t * 1000), o.adv, o.cross);
    return o;
}
std::string req(HealthModel& m, const std::string& line, double t) {
    std::string log;
    return m.handleRequest(line, t, log);
}
}  // namespace

void testConfig() {
    std::printf("\nconfig\n");
    Json j;
    std::string e, err;
    HealthConfig c;
    Json::parse("{}", j, e);
    bool ok = parseHealthConfig(j, {"ui", "nats", "vision"}, {{"EdgeTerminal.exe"}, {"nats-server.exe"}, {"x.exe"}}, c, err);
    check("default critical set keeps only tracked roles", ok && c.critical.size() == 2 &&
          c.critical[0].role == "ui" && c.critical[1].role == "nats");
    check("default pipe is its own, not the metrics pipe", c.pipe == "\\\\.\\pipe\\edgevitals-health");
    Json::parse("{\"critical\":[{\"role\":\"ghost\"}]}", j, e);
    check("critical role that is not tracked is refused", !parseHealthConfig(j, {"ui"}, {{"a.exe"}}, c, err), err);
    Json::parse("{\"pipe\":\"edgevitals\"}", j, e);
    check("pipe outside \\\\.\\pipe\\ refused", !parseHealthConfig(j, {"ui"}, {{"a.exe"}}, c, err));
    Json::parse("{\"defaults\":{\"hang_min_samples\":0,\"absent_min_samples\":-3}}", j, e);
    ok = parseHealthConfig(j, {"ui"}, {{"a.exe"}}, c, err);
    check("hysteresis cannot be configured away", ok && c.defaults.hangMinSamples == 1 && c.defaults.absentMinSamples == 1);
}

void testAbsent() {
    std::printf("\nF1 absent  (accept: absent within 2 samples; all_healthy false)\n");
    HealthModel m(cfgFor(), "3.2.0-health");
    m.observe("ui", live(), 400, 0);
    collect(m, 0);
    check("healthy while present", has(req(m, "{\"id\":1,\"op\":\"all_healthy\",\"processes\":[\"EdgeTerminal.exe\"]}", 0), "\"healthy\":true"));
    ProcObs gone;
    m.observe("ui", gone, 400, 10);
    Out o1 = collect(m, 10);
    check("all_healthy false immediately once gone", has(req(m, "{\"id\":2,\"op\":\"all_healthy\",\"processes\":[\"EdgeTerminal.exe\"]}", 10), "\"healthy\":false"));
    check("single missing sample: NO advisory", o1.adv.empty());
    m.observe("ui", gone, 400, 20);
    Out o2 = collect(m, 20);
    check("second sample: absent advisory, critical", o2.adv.size() == 1 && has(o2.adv[0], "\"class\":\"absent\"") &&
          has(o2.adv[0], "\"severity\":\"critical\"") && has(o2.adv[0], "\"suggested_action\":\"restart_process\""),
          o2.adv.empty() ? "" : o2.adv[0].substr(0, 90));
    m.observe("ui", gone, 400, 30);
    check("rate limit: no repeat within 60 s", collect(m, 30).adv.empty());
    m.observe("ui", gone, 400, 80);
    check("repeats while the condition holds, after 60 s", collect(m, 80).adv.size() == 1);
    m.observe("ui", live(), 400, 90);
    Out back = collect(m, 90);
    bool cleared = false;
    for (auto& c : back.cross) cleared = cleared || (has(c, "\"edge\":\"cleared\"") && has(c, "absent"));
    check("recovery emits a cleared crossing", cleared);
}

void testGrace() {
    std::printf("\nF1 start-up grace (boot: processes start after EdgeVitals)\n");
    HealthConfig c = cfgFor();
    c.startupGraceSec = 180;
    HealthModel m(c, "v");
    ProcObs gone;
    bool early = false;
    for (int t = 0; t < 180; t += 10) { m.observe("ui", gone, 400, t); early = early || !collect(m, t).adv.empty(); }
    check("not yet started within grace: no absent advisory", !early);
    check("...but all_healthy is still false", has(req(m, "{\"op\":\"all_healthy\",\"processes\":[\"ui\"]}", 170), "\"healthy\":false"));
    m.observe("ui", gone, 400, 180);
    check("after grace, never started: absent advisory", collect(m, 180).adv.size() == 1);
    HealthModel s(c, "v");
    s.observe("ui", live(), 400, 10);
    collect(s, 10);
    Out r;
    for (int t = 20; t <= 30; t += 10) { s.observe("ui", gone, 400, t); r = collect(s, t); }
    check("seen, then gone, inside grace: advisory as normal", r.adv.size() == 1);
}

void testHang() {
    std::printf("\nF1 hang  (accept: heartbeat-age hang within hysteresis; one miss is not a hang)\n");
    HealthModel m(cfgFor(), "v");
    ProcObs o = live();
    // No heartbeat ever: absence of a heartbeat proves nothing.
    for (int t = 0; t <= 120; t += 10) { m.observe("ui", o, 400, t); collect(m, t); }
    check("never-heartbeating process is not called hung", m.stateOf("ui") == "ok");

    HealthModel h(cfgFor(), "v");
    double hb = 0;
    for (int t = 0; t <= 30; t += 10) { o.heartbeatAtSec = hb = t; h.observe("ui", o, 400, t); collect(h, t); }
    // Business thread deadlocks at t=30: window still painting, heartbeats stop.
    o.heartbeatAtSec = hb;
    o.windowResponding = 1;
    std::vector<std::string> advAt;
    double firstAdv = -1;
    for (int t = 40; t <= 120; t += 10) {
        h.observe("ui", o, 400, t);
        Out r = collect(h, t);
        for (auto& a : r.adv) if (has(a, "\"class\":\"hang\"") && firstAdv < 0) { firstAdv = t; advAt.push_back(a); }
    }
    check("hang advisory raised from heartbeat age", firstAdv > 0, "at t=" + std::to_string(static_cast<int>(firstAdv)) + " s");
    check("not before max age + hold (10 + 30 s)", firstAdv >= 70);
    check("evidence carries heartbeat_age_ms and window_responding", !advAt.empty() &&
          has(advAt[0], "\"heartbeat_age_ms\":") && has(advAt[0], "\"window_responding\":true"));
    check("state reads hung", h.stateOf("ui") == "hung");

    HealthModel g(cfgFor(), "v");
    o = live();
    bool late = false;
    for (int t = 0; t <= 100; t += 10) {
        // Beats stall for 20 s (t=50, 60 see the t=40 beat), then resume.
        o.heartbeatAtSec = (t == 50 || t == 60) ? 40 : t;
        g.observe("ui", o, 400, t);
        for (auto& a : collect(g, t).adv) late = late || has(a, "\"hang\"");
    }
    check("heartbeat gap shorter than the hold: no advisory", !late);
}

void testIdleIsNotHung() {
    std::printf("\nF1 CPU stall is opt-in\n");
    HealthModel m(cfgFor(), "v");
    ProcObs o = live();
    o.cpuSecondsDelta = 0;
    for (int t = 0; t <= 120; t += 10) { m.observe("xfs", o, 0, t); collect(m, t); }
    check("idle SP at 0 CPU is not hung by default", m.stateOf("xfs") == "ok");
    HealthModel s(cfgFor(",\"cpu_stall_hang\":true"), "v");
    for (int t = 0; t <= 120; t += 10) { s.observe("ui", o, 400, t); collect(s, t); }
    check("opted-in process with no CPU accrual is hung", s.stateOf("ui") == "hung");
}

void testWindowUnknown() {
    std::printf("\nF1 window unknown in service mode\n");
    HealthModel m(cfgFor(), "v");
    ProcObs o = live();
    o.windowResponding = -1;
    for (int t = 0; t <= 60; t += 10) { m.observe("ui", o, 400, t); collect(m, t); }
    check("unknown window state never raises hang", m.stateOf("ui") == "ok");
    o.windowResponding = 0;
    double first = -1;
    for (int t = 70; t <= 130; t += 10) {
        m.observe("ui", o, 400, t);
        for (auto& a : collect(m, t).adv) if (has(a, "\"hang\"") && first < 0) first = t;
    }
    check("not-responding window raises hang after hold", first >= 100 && first <= 110);
}

void testThresholds() {
    std::printf("\nF2 absolute thresholds with hysteresis\n");
    HealthModel m(cfgFor(), "v");
    ProcObs o = live(330);   // 82.5% of a 400 MB ceiling
    m.observe("ui", o, 400, 0);
    check("one sample over 80% of ceiling: not yet confirmed", collect(m, 0).adv.empty());
    m.observe("ui", o, 400, 10);
    collect(m, 10);
    m.observe("ui", o, 400, 20);
    Out r = collect(m, 20);
    check("third sample: thrash warning", r.adv.size() == 1 && has(r.adv[0], "\"thrash\"") && has(r.adv[0], "\"warning\""));
    check("within_thresholds false in query", has(req(m, "{\"op\":\"query\",\"processes\":[\"ui\"]}", 20), "\"within_thresholds\":false"));
    HealthModel c(cfgFor(), "v");
    ProcObs big = live(420);
    for (int t = 0; t <= 20; t += 10) { c.observe("ui", big, 400, t); r = collect(c, t); }
    check("over the ceiling itself: critical", !r.adv.empty() && has(r.adv[0], "\"critical\""));

    HealthModel f(cfgFor(), "v");
    ProcObs pf = live();
    pf.faultsPerSec = 62070;   // the measured camera defect
    double first = -1;
    for (int t = 0; t <= 120; t += 10) {
        f.observe("ui", pf, 400, t);
        for (auto& a : collect(f, t).adv) if (has(a, "soft_faults_per_s") && first < 0) first = t;
    }
    check("62,070 soft faults/s caught once sustained 60 s", first >= 60 && first <= 70,
          "at t=" + std::to_string(static_cast<int>(first)));

    HealthModel cpu(cfgFor(), "v");
    ProcObs hot = live();
    hot.cpuPct = 95;
    first = -1;
    for (int t = 0; t <= 400; t += 10) {
        cpu.observe("ui", hot, 400, t);
        for (auto& a : collect(cpu, t).adv) if (has(a, "\"cpu_pct\"") && first < 0) first = t;
    }
    check("CPU > 90% only after 5 minutes", first >= 300 && first <= 310);
}

void testLeak() {
    std::printf("\nF2 trends  (accept: 50 MB / 10 min leak advised before the absolute threshold)\n");
    HealthModel m(cfgFor(), "v");
    double firstLeak = -1, firstAbs = -1;
    for (int t = 0; t <= 3600; t += 10) {
        // 200 MB baseline, +50 MB per 10 minutes, plus +-1 MB jitter.
        const double mb = 200 + 50.0 * t / 600.0 + ((t / 10) % 3 - 1);
        ProcObs o = live(mb);
        m.observe("ui", o, 600, t);   // ceiling 600 => absolute at 480 MB, t ~ 3360 s
        for (auto& a : collect(m, t).adv) {
            if (has(a, "\"leak\"") && firstLeak < 0) firstLeak = t;
            if (has(a, "\"ceiling_mb\"") && firstAbs < 0) firstAbs = t;
        }
    }
    check("leak advisory raised", firstLeak > 0, "at t=" + std::to_string(static_cast<int>(firstLeak)) + " s");
    check("before the absolute threshold", firstLeak > 0 && (firstAbs < 0 || firstLeak < firstAbs),
          "absolute at t=" + std::to_string(static_cast<int>(firstAbs)) + " s");
    check("needs at least 10 minutes of evidence", firstLeak >= 600);

    HealthModel flat(cfgFor(), "v");
    for (int t = 0; t <= 3600; t += 10) {
        ProcObs o = live(300 + ((t / 10) % 7) - 3);   // noisy but flat
        flat.observe("ui", o, 600, t);
        collect(flat, t);
    }
    check("noisy flat memory is not a leak", flat.stateOf("ui") == "ok");

    HealthModel h(cfgFor(), "v");
    double firstH = -1;
    for (int t = 0; t <= 7200; t += 10) {
        ProcObs o = live(300, 1200 + 1200.0 * 0.08 * t / 3600.0);   // +8%/hour
        h.observe("ui", o, 600, t);
        for (auto& a : collect(h, t).adv) if (has(a, "growth_pct_per_hour") && firstH < 0) firstH = t;
    }
    check("handle growth > 5%/hour sustained is a leak", firstH >= 1800, "at t=" + std::to_string(static_cast<int>(firstH)) + " s");

    HealthModel restart(cfgFor(), "v");
    for (int t = 0; t <= 500; t += 10) { ProcObs o = live(200 + t * 0.1); restart.observe("ui", o, 600, t); collect(restart, t); }
    ProcObs fresh = live(200);
    fresh.identity = 78;
    restart.observe("ui", fresh, 600, 510);
    collect(restart, 510);
    check("restart resets the trend window", restart.stateOf("ui") == "ok");
}

void testSystem() {
    std::printf("\nF2 system  (accept: disk < 2 GB => critical disk advisory)\n");
    HealthModel m(cfgFor(), "v");
    Out r;
    for (int t = 0; t <= 20; t += 10) { m.observeSystem(40, 1500, t); r = collect(m, t); }
    bool disk = false;
    for (auto& a : r.adv) disk = disk || (has(a, "\"class\":\"disk\"") && has(a, "\"critical\"") && has(a, "\"process\":\"system\""));
    check("disk below 2 GB: critical disk advisory", disk);
    HealthModel c(cfgFor(), "v");
    for (int t = 0; t <= 20; t += 10) { c.observeSystem(95, 50000, t); r = collect(c, t); }
    check("commit above 90%: critical commit advisory", !r.adv.empty() && has(r.adv[0], "\"commit\"") && has(r.adv[0], "controlled_reboot"));
    HealthModel s(cfgFor(), "v");
    double first = -1;
    for (int t = 0; t <= 3600; t += 60) {
        s.observeSystem(40, 20000 - 150.0 * t / 3600.0, t);
        for (auto& a : collect(s, t).adv) if (has(a, "shrink_mb_per_hour") && first < 0) first = t;
    }
    check("disk shrinking 150 MB/h: warning after 30 min of evidence", first >= 1800);
}

void testIpc() {
    std::printf("\nF3 contract\n");
    HealthModel m(cfgFor(), "3.2.0-health");
    m.observe("ui", live(), 400, 5);
    m.observe("xfs", live(), 0, 5);
    collect(m, 5);
    std::string r = req(m, "{\"id\":17,\"op\":\"query\",\"processes\":[\"EdgeTerminal.exe\"]}", 7);
    check("query echoes id and returns results", has(r, "\"id\":17") && has(r, "\"ok\":true") && has(r, "\"results\":["));
    check("result carries present, state, cpu, rss_bytes, handles", has(r, "\"present\":true") && has(r, "\"state\":\"ok\"") &&
          has(r, "\"cpu_pct\":3") && has(r, "\"rss_bytes\":268435456") && has(r, "\"handles\":1200"));
    check("result says how old the sample is", has(r, "\"sample_age_ms\":2000"));
    Json j;
    std::string e;
    check("reply is valid JSON", Json::parse(r, j, e) && j["results"][0]["name"].asString() == "EdgeTerminal.exe");
    check("role, display name and any tracked exe all resolve",
          has(req(m, "{\"op\":\"all_healthy\",\"processes\":[\"ui\",\"edgeterminaldemo.exe\",\"PertoCdmSpiManager.exe\"]}", 7), "\"healthy\":true"));
    check("unknown name fails safe: healthy false", has(req(m, "{\"op\":\"all_healthy\",\"processes\":[\"nope.exe\"]}", 7), "\"healthy\":false"));
    check("ping returns version and uptime", has(req(m, "{\"id\":20,\"op\":\"ping\"}", 912.334), "\"version\":\"3.2.0-health\",\"uptime_ms\":912334"));
    check("bad JSON answered, not crashed", has(req(m, "{oops", 7), "bad json"));
    check("unknown op refused", has(req(m, "{\"op\":\"reboot\"}", 7), "unknown op"));
    check("oversized request refused", has(req(m, std::string(70000, ' '), 7), "too large"));
    check("empty process list refused", has(req(m, "{\"op\":\"query\",\"processes\":[]}", 7), "non-empty"));
    std::string log;
    std::string a = m.handleRequest("{\"id\":3,\"op\":\"ack\",\"advisory_id\":\"a1f4\",\"action\":\"controlled_restart\"}", 7, log);
    check("ack is recorded as an event beside the advisory", has(a, "\"ok\":true") && has(log, "advisory_ack") && has(log, "controlled_restart"));
}

void testWatch() {
    std::printf("\nF8 watch\n");
    HealthModel m(cfgFor(), "v");
    std::string log;
    check("watch accepted", has(m.handleRequest("{\"id\":19,\"op\":\"watch\",\"pids\":[3312,3340]}", 1, log), "\"ok\":true") &&
          has(log, "3312,3340"));
    std::vector<unsigned long> add, rem;
    m.takeWatchRequests(add, rem);
    check("agent receives the PIDs to open", add.size() == 2 && add[0] == 3312);
    check("invalid pid refused", has(req(m, "{\"op\":\"watch\",\"pids\":[-1]}", 1), "invalid pid"));
    ProcObs o = live();
    o.pid = 3312;
    m.observeWatched(3312, "edgebastion.exe", o, 10);
    collect(m, 10);
    check("watched pid answers queries as pid:N", has(req(m, "{\"op\":\"all_healthy\",\"processes\":[\"pid:3312\"]}", 10), "\"healthy\":true"));
    ProcObs dead;
    m.observeWatched(3312, "", dead, 20);
    Out r = collect(m, 20);
    check("death reported at once (exit is certain)", r.adv.size() == 1 && has(r.adv[0], "\"absent\"") && has(r.adv[0], "\"pid\":3312"));
    m.observeWatched(3312, "", dead, 200);
    check("...and only once", collect(m, 200).adv.empty());
    HealthConfig small = cfgFor();
    small.watchMaxPids = 2;
    HealthModel lim(small, "v");
    req(lim, "{\"op\":\"watch\",\"pids\":[1,2]}", 0);
    check("watch limit enforced", has(req(lim, "{\"op\":\"watch\",\"pids\":[3]}", 0), "watch limit"));
}

void testCost() {
    std::printf("\nlatency (host CPU; target < 100 ms p99 end to end)\n");
    HealthModel m(cfgFor(), "v");
    m.observe("ui", live(), 400, 1);
    m.observe("xfs", live(), 0, 1);
    collect(m, 1);
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 10000; ++i) req(m, "{\"id\":1,\"op\":\"query\",\"processes\":[\"EdgeTerminal.exe\",\"xfs\"]}", 2);
    const double us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count() / 10000;
    char d[64];
    std::snprintf(d, sizeof(d), "%.1f us per query", us);
    check("query handled well inside budget", us < 1000, d);
}

int main() {
    std::printf("EdgeVitals health-model tests\n");
    testConfig();
    testAbsent();
    testGrace();
    testHang();
    testIdleIsNotHung();
    testWindowUnknown();
    testThresholds();
    testLeak();
    testSystem();
    testIpc();
    testWatch();
    testCost();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
