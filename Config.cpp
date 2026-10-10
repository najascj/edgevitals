#include "edgevitals/Config.h"

#include <fstream>
#include <sstream>

#include "edgevitals/Json.h"

namespace ev {

Config Config::defaults() {
    Config c{};
    // Fallback only -- used when the config file is missing or unreadable. Every
    // field is spelled out, including tier: an aggregate initialiser that stops
    // short leaves the rest default-constructed, which is correct but produces
    // a -Wmissing-field-initializers warning per row and hides the day someone
    // adds a field that should NOT default.
    //
    // Tier matters even here. If the config is gone and the agent falls back to
    // this table, contention accounting should still work rather than silently
    // going dark.
    c.tracked = {
        //  role        exe                                            label                  ram   cpu  gui    group          self   tier           hprobe
        {"ui",       {"EdgeTerminalDemo.exe", "EdgeTerminal.exe"}, "EdgeTerminal",         260,  20, true,  "bosach",      false, "transaction", true },
        {"vision",   {"edgesignal-vision.exe"},                    "EdgeSignal-Vision",    220,  60, false, "bosach",      false, "background",  false},
        {"piper",    {"piper.exe"},                                "Piper TTS",            150, 100, false, "bosach",      false, "interactive", false},
        {"rhubarb",  {"rhubarb.exe"},                              "Rhubarb lip-sync",      60, 100, false, "bosach",      false, "interactive", false},
        {"content",  {"edgesignal-content.exe"},                   "EdgeSignal-Content",    60,  20, false, "bosach",      false, "background",  false},
        {"campaign", {"edgecampaign.exe"},                         "EdgeCampaign",          50,  10, false, "bosach",      false, "background",  false},
        {"monitor",  {"edgemonitor.exe", "apex-edge.exe"},         "EdgeMonitor",          260,  60, false, "bosach",      false, "background",  false},
        {"nats",     {"nats-server.exe"},                          "NATS leaf",             45,   5, false, "bosach",      false, "transaction", false},
        {"bastion",  {"edgebastion.exe"},                          "EdgeBastion",           40,  10, false, "bosach",      false, "transaction", false},
        {"clamd",    {"clamd.exe", "clamscan.exe"},                "ClamAV",                 0,   0, false, "environment", false, "background",  false},
        {"vitals",   {"edgevitals.exe"},                           "EdgeVitals (self)",     15,   1, false, "bosach",      true,  "interactive", false},
    };
    c.extraColumns = {
        {"state",             0, true},
        {"persona",           0, true},
        {"theme",             0, true},
        {"frame_p50_ms",      2, false},
        {"frame_p95_ms",      2, false},
        {"frame_p99_ms",      2, false},
        {"frame_max_ms",      2, false},
        {"frames_total",      0, false},
        {"frames_over_33ms",  0, false},
        {"tts_synth_ms",      1, false},
        {"tts_chars",         0, false},
        {"rhubarb_ms",        1, false},
        {"asr_partial_ms",    1, false},
        {"audio_underruns",   0, false},
        {"cam_face_fps",      1, false},
        {"cam_slot_fps",      1, false},
        {"cam_lobby_fps",     1, false},
        {"cam_drops",         0, false},
        {"vision_proc_p95_ms", 2, false},
        {"feed_mbs",          2, false},
        {"feed_queue_depth",  0, false},
    };
    c.systemAllowlist = {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe",
        "dwm.exe", "fontdrvhost.exe", "spoolsv.exe", "taskhostw.exe",
        "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "conhost.exe",
        "registry", "memory compression", "dllhost.exe", "searchindexer.exe",
    };
    {
        // Health defaults follow whatever roles the defaults track, so a
        // critical role can never name a process this config cannot see.
        std::vector<std::string> roles;
        std::vector<std::vector<std::string>> exes;
        for (const auto& t : c.tracked) {
            roles.push_back(t.role);
            exes.push_back(t.exe);
        }
        std::string herr;
        parseHealthConfig(Json(), roles, exes, c.health, herr);
    }
    c.winevents = defaultWinEventsConfig();
    {
        std::string perr;
        parsePostureConfig(Json(), c.posture, perr);
        parseIntegrityConfig(Json(), c.integrity, perr);
    }
    return c;
}

// A config larger than this is refused unread. The shipped file is ~9 KB and
// the parser allocates roughly an order of magnitude more than the input for a
// deeply-keyed document, so an unbounded read is an out-of-memory condition
// waiting for a corrupt or hostile file. 1 MB is over a hundred times what we
// ship and still nothing on a 4 GB terminal.
static constexpr std::streamsize kMaxConfigBytes = 1024 * 1024;

static std::string readFile(const std::string& path, bool& ok, std::string& why) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { ok = false; why = "cannot open"; return {}; }

    // Size first, then read. Checking after the fact means the allocation has
    // already happened, which is the thing being guarded against.
    in.seekg(0, std::ios::end);
    const std::streamsize n = in.tellg();
    if (n < 0) { ok = false; why = "cannot size file"; return {}; }
    if (n > kMaxConfigBytes) {
        ok = false;
        why = "config is " + std::to_string(n / 1024) + " KB, limit is " +
              std::to_string(kMaxConfigBytes / 1024) + " KB";
        return {};
    }
    in.seekg(0, std::ios::beg);

    std::string text;
    text.resize(static_cast<size_t>(n));
    if (n > 0 && !in.read(&text[0], n)) { ok = false; why = "short read"; return {}; }
    ok = true;
    return text;
}

void Config::resolvePaths() {
    if (exeDir.empty()) return;
    auto anchor = [&](std::string& v) {
        if (v.empty()) return;
        const bool drive = v.size() > 1 && v[1] == ':';
        const bool unc   = v.size() > 1 && (v[0] == '\\' || v[0] == '/') &&
                                           (v[1] == '\\' || v[1] == '/');
        const bool posix = v[0] == '/';
        if (drive || unc || posix) return;
        std::string base = exeDir;
        if (!base.empty() && base.back() != '\\' && base.back() != '/') base += '\\';
        v = base + v;
    };
    anchor(logDir);
    anchor(posture.profilePath);
    anchor(integrity.baseline);
}

bool Config::load(const std::string& path, std::string& err) {
    sourcePath = path;
    bool ok = false;
    std::string why;
    const std::string text = readFile(path, ok, why);
    if (!ok) { err = why.empty() ? ("cannot open " + path) : (path + ": " + why); return false; }

    Json root;
    std::string perr;
    if (!Json::parse(text, root, perr)) { err = path + ": " + perr; return false; }
    if (!root.isObject()) { err = path + ": top level must be an object"; return false; }

    // Build into a scratch copy so a failure part-way leaves *this untouched.
    Config c = Config::defaults();

    const Json& s = root["sampling"];
    c.intervalMs = static_cast<int>(s["interval_ms"].asInt(c.intervalMs));
    c.enumerateEveryTicks =
        static_cast<int>(s["enumerate_every_ticks"].asInt(c.enumerateEveryTicks));
    if (c.intervalMs < 1000) { err = "sampling.interval_ms below 1000 is not supported"; return false; }
    if (c.enumerateEveryTicks < 1) c.enumerateEveryTicks = 1;

    // Clamped rather than refused: a probe setting out of range must not cost
    // the terminal its telemetry. The floors keep a typo from turning a
    // triggered probe into one that runs on (or near) every tick.
    c.handleProbeEnabled = s["handle_probe_enabled"].asBool(c.handleProbeEnabled);
    c.handleProbeDelta = s["handle_probe_delta"].asInt(c.handleProbeDelta);
    c.handleProbeMinSeconds = s["handle_probe_min_seconds"].asNumber(c.handleProbeMinSeconds);
    c.handleProbeMaxMb = static_cast<int>(s["handle_probe_max_mb"].asInt(c.handleProbeMaxMb));
    if (c.handleProbeDelta < 10) c.handleProbeDelta = 10;
    if (c.handleProbeMinSeconds < 10.0) c.handleProbeMinSeconds = 10.0;
    if (c.handleProbeMinSeconds > 86400.0) c.handleProbeMinSeconds = 86400.0;
    if (c.handleProbeMaxMb < 1) c.handleProbeMaxMb = 1;
    if (c.handleProbeMaxMb > 64) c.handleProbeMaxMb = 64;

    const Json& o = root["output"];
    c.logDir = o["dir"].asString(c.logDir);
    c.filePrefix = o["prefix"].asString(c.filePrefix);
    c.retentionDays = static_cast<int>(o["retention_days"].asInt(c.retentionDays));
    c.archiveAfterDays = static_cast<int>(o["archive_after_days"].asInt(c.archiveAfterDays));
    c.archiveMaxMb = static_cast<int>(o["archive_max_mb"].asInt(c.archiveMaxMb));
    c.txnActivePct = o["txn_active_pct"].asNumber(c.txnActivePct);
    c.bgLimitPct = o["bg_limit_pct"].asNumber(c.bgLimitPct);
    c.chainEveryRows = static_cast<int>(o["chain_every_rows"].asInt(c.chainEveryRows));
    c.chainEveryLogLines =
        static_cast<int>(o["chain_every_log_lines"].asInt(c.chainEveryLogLines));
    c.diskFloorMb = o["disk_floor_mb"].asNumber(c.diskFloorMb);
    c.flushEveryTick = o["flush_every_tick"].asBool(c.flushEveryTick);
    if (c.retentionDays < 1) c.retentionDays = 1;

    const Json& d = root["discovery"];
    c.discoverUnknown = d["enabled"].asBool(c.discoverUnknown);
    c.discoveryFile = d["file"].asString(c.discoveryFile);
    if (d["system_allowlist"].isArray()) {
        c.systemAllowlist.clear();
        for (size_t i = 0; i < d["system_allowlist"].size(); ++i)
            c.systemAllowlist.push_back(d["system_allowlist"][i].asString());
    }

    const Json& ipc = root["ipc"];
    c.ipcEnabled = ipc["enabled"].asBool(c.ipcEnabled);
    c.pipeName = ipc["pipe"].asString(c.pipeName);
    c.ipcClientSid = ipc["client_sid"].asString(c.ipcClientSid);
    c.ipcMaxClients = static_cast<int>(ipc["max_clients"].asInt(c.ipcMaxClients));
    c.ipcAllowSnapshot = ipc["allow_snapshot"].asBool(c.ipcAllowSnapshot);
    if (ipc["extra_columns"].isArray()) {
        c.extraColumns.clear();
        for (size_t i = 0; i < ipc["extra_columns"].size(); ++i) {
            const Json& e = ipc["extra_columns"][i];
            ExtraColumn col;
            col.name = e["name"].asString();
            col.precision = static_cast<int>(e["precision"].asInt(2));
            col.text = e["text"].asBool(false);
            if (!col.name.empty()) c.extraColumns.push_back(col);
        }
    }

    if (root["processes"].isArray()) {
        c.tracked.clear();
        for (size_t i = 0; i < root["processes"].size(); ++i) {
            const Json& p = root["processes"][i];
            TrackedProcess t;
            t.role = p["role"].asString();
            t.label = p["label"].asString(t.role);
            t.ramBudgetMb = p["ram_budget_mb"].asNumber(0.0);
            t.cpuBudgetPct = p["cpu_budget_pct"].asNumber(0.0);
            t.gui = p["gui"].asBool(false);
            t.group = p["group"].asString();
            t.self = p["self"].asBool(false);
            t.tier = p["tier"].asString();
            t.handleProbe = p["handle_probe"].asBool(false);
            const Json& ex = p["exe"];
            if (ex.isArray())
                for (size_t k = 0; k < ex.size(); ++k) t.exe.push_back(ex[k].asString());
            else if (!ex.asString().empty())
                t.exe.push_back(ex.asString());
            if (t.role.empty()) { err = "processes[" + std::to_string(i) + "] has no role"; return false; }
            if (t.exe.empty()) { err = "process role '" + t.role + "' has no exe list"; return false; }
            c.tracked.push_back(std::move(t));
        }
    }

    {
        std::vector<std::string> roles;
        std::vector<std::vector<std::string>> exes;
        for (const auto& t : c.tracked) {
            roles.push_back(t.role);
            exes.push_back(t.exe);
        }
        if (!parseHealthConfig(root["health"], roles, exes, c.health, err)) return false;
    }
    if (!parseWinEventsConfig(root["winevents"], c.winevents, err)) return false;
    if (!parsePostureConfig(root["posture"], c.posture, err)) return false;
    if (!parseIntegrityConfig(root["integrity"], c.integrity, err)) return false;
    c.livenessBeaconSec = static_cast<int>(root["integrity"]["liveness_beacon_s"].asInt(c.livenessBeaconSec));
    if (c.livenessBeaconSec != 0) { if (c.livenessBeaconSec < 30) c.livenessBeaconSec = 30; if (c.livenessBeaconSec > 3600) c.livenessBeaconSec = 3600; }

    // The scratch copy came from defaults() and does not know where it was
    // loaded from. Carry the path across the swap, or config_hash ends up
    // hashing nothing and every file reports the same value.
    c.sourcePath = path;
    *this = std::move(c);
    return true;
}

}  // namespace ev
