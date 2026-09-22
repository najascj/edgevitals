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
        //  role        exe                                            label                  ram   cpu  gui    group          self   tier
        {"ui",       {"EdgeTerminalDemo.exe", "EdgeTerminal.exe"}, "EdgeTerminal",         260,  20, true,  "bosach",      false, "transaction"},
        {"vision",   {"edgesignal-vision.exe"},                    "EdgeSignal-Vision",    220,  60, false, "bosach",      false, "background"},
        {"piper",    {"piper.exe"},                                "Piper TTS",            150, 100, false, "bosach",      false, "interactive"},
        {"rhubarb",  {"rhubarb.exe"},                              "Rhubarb lip-sync",      60, 100, false, "bosach",      false, "interactive"},
        {"content",  {"edgesignal-content.exe"},                   "EdgeSignal-Content",    60,  20, false, "bosach",      false, "background"},
        {"campaign", {"edgecampaign.exe"},                         "EdgeCampaign",          50,  10, false, "bosach",      false, "background"},
        {"monitor",  {"edgemonitor.exe", "apex-edge.exe"},         "EdgeMonitor",          260,  60, false, "bosach",      false, "background"},
        {"nats",     {"nats-server.exe"},                          "NATS leaf",             45,   5, false, "bosach",      false, "transaction"},
        {"bastion",  {"edgebastion.exe"},                          "EdgeBastion",           40,  10, false, "bosach",      false, "transaction"},
        {"clamd",    {"clamd.exe", "clamscan.exe"},                "ClamAV",                 0,   0, false, "environment", false, "background"},
        {"vitals",   {"edgevitals.exe"},                           "EdgeVitals (self)",     15,   1, false, "bosach",      true,  "interactive"},
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
    return c;
}

static std::string readFile(const std::string& path, bool& ok) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { ok = false; return {}; }
    std::ostringstream ss;
    ss << in.rdbuf();
    ok = true;
    return ss.str();
}

bool Config::load(const std::string& path, std::string& err) {
    sourcePath = path;
    bool ok = false;
    const std::string text = readFile(path, ok);
    if (!ok) { err = "cannot open " + path; return false; }

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

    const Json& o = root["output"];
    c.logDir = o["dir"].asString(c.logDir);
    c.filePrefix = o["prefix"].asString(c.filePrefix);
    c.retentionDays = static_cast<int>(o["retention_days"].asInt(c.retentionDays));
    c.archiveAfterDays = static_cast<int>(o["archive_after_days"].asInt(c.archiveAfterDays));
    c.archiveMaxMb = static_cast<int>(o["archive_max_mb"].asInt(c.archiveMaxMb));
    c.txnActivePct = o["txn_active_pct"].asNumber(c.txnActivePct);
    c.bgLimitPct = o["bg_limit_pct"].asNumber(c.bgLimitPct);
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

    // The scratch copy came from defaults() and does not know where it was
    // loaded from. Carry the path across the swap, or config_hash ends up
    // hashing nothing and every file reports the same value.
    c.sourcePath = path;
    *this = std::move(c);
    return true;
}

}  // namespace ev
