#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "edgevitals/Health.h"

namespace ev {

// Written into every row. A CSV read months later must be able to say which
// build produced it -- a schema change between drops silently redefines
// columns otherwise, and the file carries no other clue.
constexpr const char* kAgentVersion = "3.2.1-lifecycle";

// One process EdgeVitals is asked to track by name. Role becomes the column
// prefix, so it must be a valid identifier fragment: ui_cpu_pct, vision_rss_mb.
struct TrackedProcess {
    std::string role;               // "ui", "vision", "nats", ...
    std::vector<std::string> exe;   // matched case-insensitively on file name
    std::string label;              // human-readable, for the discovery log
    double ramBudgetMb = 0.0;       // 0 = no budget
    double cpuBudgetPct = 0.0;      // % of one core; 0 = no budget
    // GDI/USER object counts are only meaningful for a process with a
    // window. Adding them to all 13 roles would be 26 permanently-empty
    // columns, so they are opt-in.
    bool gui = false;
    // Roles sharing a group get a summed rollup column set. Empty means the
    // role is in no group and contributes to no total. A group exists so the
    // question "what does BOSACH software cost on this terminal" is answered
    // by reading one column rather than by summing eleven correctly.
    std::string group;
    // Binds to this process by PID, ignoring exe entirely. The 20 Aug run
    // shipped as edgevitals_v2.1.exe, did not match "edgevitals.exe", and so
    // recorded ITSELF in the discovery log while leaving vitals_* empty --
    // the agent could not measure its own cost. A name is a rename away from
    // wrong; the PID is not.
    bool self = false;
    // Scheduling tier. "transaction" is the MVS-to-Switch path and anything
    // it depends on; "background" is work that must yield to it -- content,
    // campaign, vision. Empty means untiered and excluded from contention
    // accounting. This is a LABEL: EdgeVitals reports contention, it does not
    // enforce priority. Enforcement is a CREATE_SUSPENDED priority class or a
    // Job Object CPU cap at launch, and it belongs to whatever starts these
    // processes.
    std::string tier;
    // Handle-type probe for this role: four columns saying which KIND of
    // handle it holds most of and which kind grew most since the last probe.
    // Opt-in per role, like gui -- four columns on all 17 roles would be 68,
    // nearly all permanently empty. Has no effect unless
    // sampling.handle_probe_enabled is also true.
    bool handleProbe = false;
};

struct Config {
    // ── sampling ────────────────────────────────────────────────────────
    int intervalMs = 10000;         // 10 s standing rate
    int enumerateEveryTicks = 6;    // full process enumeration every 60 s.
                                    // Process churn is not a 10 s phenomenon
                                    // and enumeration is the expensive part.

    // Handle-type probe. TRIGGERED, never on cadence: the snapshot is the whole
    // machine's handle table (~2 MB, ~50k entries on the lab terminal) and
    // cannot fit the per-tick budget. It runs when a probed role's handle count
    // has risen by handleProbeDelta above its baseline, or once to take a
    // baseline when a role's process set has been stable for
    // handleProbeMinSeconds -- and never twice within handleProbeMinSeconds.
    // On a healthy terminal that is one probe per process start, then nothing.
    bool handleProbeEnabled = true;
    long long handleProbeDelta = 200;
    double handleProbeMinSeconds = 300.0;
    // Refuse the snapshot rather than allocate past this. 6, not the 16 first
    // proposed: the self-budget is vitals_private_mb max under 8 MB against a
    // 1.4 MB baseline, and 16 would let the probe alone breach it.
    int handleProbeMaxMb = 6;

    // ── output ──────────────────────────────────────────────────────────
    // Relative by design, resolved against the EXE directory rather than the
    // working directory. The SCM sets a service's CWD to system32, so a bare
    // "logs" would otherwise put telemetry in C:\\Windows\\System32\\logs.
    std::string logDir = "logs";
    std::string exeDir;                 // set by main before resolvePaths()

    // Makes every relative path absolute against exeDir. Idempotent: an
    // already-absolute path is left alone, so "D:\\EdgeVitals\\logs" still works.
    void resolvePaths();
    std::string filePrefix = "telemetry";
    int retentionDays = 30;
    // Files older than this are compressed to <name>.csv.zip and the raw .csv
    // removed. Only the most recent archiveAfterDays remain readable without
    // unzipping, which is what a field engineer actually needs; everything
    // behind that is for retrospective analysis and can afford a decompress.
    // 0 disables archiving entirely and keeps every file raw until purge.
    int archiveAfterDays = 7;
    int archiveMaxMb = 64;   // refuse to compress a file larger than this
    // A transaction-tier role above this counts as "the terminal is busy
    // transacting"; a background-tier role above its own limit at the same
    // moment counts as contention. Percent of ONE core, matching the budgets.
    double txnActivePct = 5.0;
    double bgLimitPct = 5.0;

    // How often a chain checkpoint is written, in rows for the telemetry CSV
    // and lines for the agent log. Everything after the last checkpoint is
    // unverified until the next one lands, so this sets how much of a LIVE
    // file EdgeSentinel must ingest on trust -- and how much an abrupt kill
    // leaves unchained. 30 rows at a 10 s interval is five minutes.
    //
    // Cost per checkpoint is one SHA-256 finalisation (microseconds) and a
    // ~300 byte sidecar line. The CPU is free; the sidecar is NOT, and the
    // earlier estimate of "about 430 KB over 180 days" was wrong by two orders
    // of magnitude. Measured properly, at a 10 s interval:
    //
    //   30 rows -> 288 checkpoints/day,   84 KB/day,   15 MB over 180 days
    //    6 rows -> 1,440 checkpoints/day, 422 KB/day,  74 MB over 180 days
    //
    // 74 MB against a ~900 MB total log footprint is roughly 8% -- worth
    // paying to cut the unverified tail from five minutes to one, but a real
    // trade rather than a free one.
    //
    // 0 disables chaining entirely, which also disables tamper evidence.
    int chainEveryRows = 30;
    int chainEveryLogLines = 50;
    // Stop writing below this and say so once. A telemetry log that fills the
    // disk and takes the terminal out of service is a self-inflicted outage.
    double diskFloorMb = 500.0;
    bool flushEveryTick = true;

    // ── discovery ───────────────────────────────────────────────────────
    bool discoverUnknown = true;
    std::string discoveryFile = "unknown-processes.csv";
    // Never flagged as unknown. Not a security allowlist -- purely noise
    // suppression for the OS surface. Enforcement belongs in EdgeBastion.
    std::vector<std::string> systemAllowlist;

    // ── IPC ─────────────────────────────────────────────────────────────
    bool ipcEnabled = true;
    std::string pipeName = "\\\\.\\pipe\\edgevitals";
    // SID allowed to push columns, in SDDL form. Default S-1-5-11
    // (Authenticated Users) is the loosest thing that still works and should
    // be narrowed to the account EdgeTerminal runs as before production.
    // Free text from --note, written to every row. Every diagnosis so far has
    // stalled on "what was the terminal doing during this run" -- whether the
    // camera was on, whether a probe was looping. A CSV that cannot answer that
    // needs a human who remembers, and by the next week nobody does.
    std::string runNote;
    // Path the config was loaded from, so the hash covers what was actually
    // applied rather than whatever happens to sit next to the exe.
    std::string sourcePath;
    std::string ipcClientSid = "AU";
    // Concurrent pipe clients. Unbounded lets one local process exhaust
    // threads; the real client count is 1.
    int ipcMaxClients = 4;
    // The snapshot command returns the whole current row. That is a complete
    // process inventory of the terminal, so it is off unless asked for.
    bool ipcAllowSnapshot = false;
    // Columns clients may push. Declared here so the schema is fixed before
    // the first row is written -- a column appearing mid-file would
    // desynchronise every row already on disk.
    struct ExtraColumn {
        std::string name;
        int precision = 2;
        bool text = false;
    };
    std::vector<ExtraColumn> extraColumns;

    // ── tracked processes ───────────────────────────────────────────────
    std::vector<TrackedProcess> tracked;

    // ── health link for EdgeBastion (3.2) ───────────────────────────────
    // Critical-process liveness, thresholds with trend, and the pipe
    // EdgeBastion queries. Observe and answer only: advisories are messages,
    // never actions. See Health.h.
    HealthConfig health;

    // Loads from path. On any failure returns false with err set and leaves
    // *this at defaults -- a bad config must not produce a half-applied one.
    bool load(const std::string& path, std::string& err);

    // Defaults matching the BOSACH edge portfolio.
    static Config defaults();
};

}  // namespace ev
