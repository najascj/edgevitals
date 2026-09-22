#include "edgevitals/Agent.h"

#include <algorithm>
#include <fstream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>

namespace ev {

Agent::Agent(Config cfg, ILogger& log) : cfg_(std::move(cfg)), log_(log) {}

Agent::~Agent() {
    stop();
    if (wakeEvent_) {
        CloseHandle(static_cast<HANDLE>(wakeEvent_));
        wakeEvent_ = nullptr;
    }
}

void Agent::buildSchema() {
    col_.ts = schema_.add("ts", 0);
    col_.seq = schema_.add("seq", 0);
    col_.runId = schema_.add("run_id", 0);
    col_.agentVer = schema_.add("agent_version", 0);
    col_.cfgHash = schema_.add("config_hash", 0);
    // Only present when --note was given. An empty column costs one comma per
    // row; a run nobody can identify costs an afternoon.
    if (!cfg_.runNote.empty()) col_.runNote = schema_.add("run_note", 0);
    col_.uptime = schema_.add("uptime_s", 0);
    // Actual interval minus nominal. Rates are computed from the real elapsed
    // time so they stay correct, but a loop that slips is a loop competing for
    // CPU, and nothing on the row said so. Empty on the first tick of a run.
    col_.tickSkew = schema_.add("tick_skew_ms", 1);
    col_.sampleCost = schema_.add("sample_cost_ms", 3);
    // Split from sample_cost_ms. Conflated, a 0.43 ms distribution and a 25 ms
    // one averaged into a single number that could not be checked against
    // either budget -- and whose p95 depended on where the enumeration tick
    // happened to land.
    col_.enumCost = schema_.add("enum_cost_ms", 3);

    // Extra columns come BEFORE the per-process block so state, persona and
    // theme sit near the front of the file where a human scrolling the CSV
    // will actually see them.
    for (const auto& e : cfg_.extraColumns) schema_.add(e.name, e.precision);

    for (const auto& tp : cfg_.tracked) {
        RoleCols rc{};
        const std::string p = tp.role + "_";
        rc.pid = schema_.add(p + "pid", 0);
        rc.cpu = schema_.add(p + "cpu_pct", 2);
        rc.cpuKernel = schema_.add(p + "cpu_kernel_pct", 2);
        rc.rss = schema_.add(p + "rss_mb", 1);
        rc.priv = schema_.add(p + "private_mb", 1);
        rc.peak = schema_.add(p + "peak_rss_mb", 1);
        rc.faults = schema_.add(p + "pagefault_delta", 0);
        rc.handles = schema_.add(p + "handles", 0);
        rc.threads = schema_.add(p + "threads", 0);
        if (tp.gui) {
            rc.gdi = schema_.add(p + "gdi_objects", 0);
            rc.user = schema_.add(p + "user_objects", 0);
        }
        rc.ioRead = schema_.add(p + "io_read_mbs", 3);
        rc.ioWrite = schema_.add(p + "io_write_mbs", 3);
        rc.ioReadOps = schema_.add(p + "io_read_ops", 1);
        rc.ioWriteOps = schema_.add(p + "io_write_ops", 1);
        rc.cpuSeconds = schema_.add(p + "cpu_seconds", 1);
        rc.priority = schema_.add(p + "priority", 0);
        roleCols_.emplace_back(tp.role, rc);
    }

    // Group rollups sit after the per-role block and before the system-wide
    // columns: they are an aggregate of what precedes them, and a reader
    // scrolling right meets the parts before the total.
    {
        std::vector<std::string> seen;
        for (const auto& tp : cfg_.tracked) {
            if (tp.group.empty()) continue;
            if (std::find(seen.begin(), seen.end(), tp.group) != seen.end()) continue;
            seen.push_back(tp.group);
            GroupCols gc{};
            const std::string p = tp.group + "_total_";
            gc.priv = schema_.add(p + "private_mb", 1);
            gc.cpu = schema_.add(p + "cpu_pct", 2);
            gc.cpuKernel = schema_.add(p + "cpu_kernel_pct", 2);
            gc.handles = schema_.add(p + "handles", 0);
            gc.threads = schema_.add(p + "threads", 0);
            // How many roles in the group were actually live this tick. A
            // total of 300 MB from two roles and from nine are different
            // facts, and without this the reader cannot tell them apart.
            gc.cpuSeconds = schema_.add(p + "cpu_seconds", 1);
            gc.live = schema_.add(p + "live_roles", 0);
            groupCols_.emplace_back(tp.group, gc);
        }
    }

    // Contention accounting sits with the system-wide columns because it is a
    // statement about the machine, not about any one role.
    col_.txnCpu = schema_.add("txn_cpu_pct", 2);
    col_.bgCpu = schema_.add("bg_cpu_pct", 2);
    col_.contention = schema_.add("contention_ticks", 0);

    col_.sysCpu = schema_.add("sys_cpu_pct", 2);
    col_.sysAvail = schema_.add("sys_avail_mb", 1);
    // Without the denominator on the row, every percentage computed later is
    // uninterpretable: 1840 MB available is a 4 GB terminal in trouble or a
    // 32 GB workstation idling, and a CSV read in six months cannot tell.
    col_.sysTotal = schema_.add("sys_total_mb", 1);
    col_.sysCommit = schema_.add("sys_commit_pct", 2);
    col_.diskFree = schema_.add("disk_free_mb", 0);
    col_.cores = schema_.add("cores", 0);
    col_.unknownNew = schema_.add("unknown_new", 0);
    col_.budgetBreaches = schema_.add("budget_breaches", 0);

    // Frozen before the first row. A column appearing mid-file would
    // desynchronise every row already on disk today.
    schema_.freeze();
}

bool Agent::start() {
    // Generated before the schema so the first row already carries it. Derived
    // from the start time and the process id: unique enough to group by, short
    // enough not to bloat every row, and sortable by start order.
    {
        const std::uint64_t t = monotonicNs() ^ (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32);
        char buf[20];
        std::snprintf(buf, sizeof(buf), "%08llx",
                      static_cast<unsigned long long>((t >> 12) & 0xFFFFFFFFull));
        runId_ = buf;
    }

    // Config hash. FNV-1a over the raw file: two runs with different hashes
    // were produced under different rules, and comparing their numbers without
    // knowing that is how a "regression" turns out to be a config change.
    {
        std::uint32_t h = 2166136261u;
        std::ifstream cf(cfg_.sourcePath, std::ios::binary);
        char ch;
        while (cf.get(ch)) { h ^= static_cast<unsigned char>(ch); h *= 16777619u; }
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%08x", h);
        cfgHash_ = buf;
    }

    buildSchema();

    proc_.reset(new ProcessSampler(cfg_));
    sys_.reset(new SystemSampler());

    CsvSink::Options o;
    o.dir = cfg_.logDir;
    o.prefix = cfg_.filePrefix;
    o.retentionDays = cfg_.retentionDays;
    o.archiveAfterDays = cfg_.archiveAfterDays;
    o.archiveMaxMb = cfg_.archiveMaxMb;
    o.diskFloorMb = cfg_.diskFloorMb;
    o.flushEveryTick = cfg_.flushEveryTick;
    sink_.reset(new CsvSink(o, schema_, std::make_shared<Win32DiskSpace>()));

    if (cfg_.discoverUnknown) {
        std::vector<std::string> trackedExe;
        for (const auto& tp : cfg_.tracked)
            for (const auto& e : tp.exe) trackedExe.push_back(e);
        std::string dpath = cfg_.discoveryFile;
        if (dpath.find('/') == std::string::npos && dpath.find('\\') == std::string::npos)
            dpath = cfg_.logDir + "/" + dpath;
        discovery_.reset(new DiscoveryLog(dpath, cfg_.systemAllowlist, trackedExe));
        discovery_->loadExisting();
        log_.info("discovery: " + std::to_string(discovery_->knownCount()) +
                  " binaries already recorded");
    }

    if (cfg_.ipcEnabled) {
        std::vector<std::string> keys;
        for (const auto& e : cfg_.extraColumns) keys.push_back(e.name);
        ipc_.reset(new IpcServer(cfg_.pipeName, keys));
        // Set before start(): the DACL is built inside the listener thread,
        // so anything applied afterwards would arrive too late.
        ipc_->setSecurity(cfg_.ipcClientSid, cfg_.ipcMaxClients, cfg_.ipcAllowSnapshot);
        if (!ipc_->start())
            log_.warn("IPC did not start (" + ipc_->lastError() +
                      ") -- sampling continues without client metrics");
        else
            log_.info("IPC listening on " + cfg_.pipeName);
    }

    wakeEvent_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    startNs_ = monotonicNs();
    lastTickNs_ = 0;
    running_.store(true);

    log_.info("EdgeVitals started: interval " + std::to_string(cfg_.intervalMs) + " ms, " +
              std::to_string(cfg_.tracked.size()) + " tracked roles, " +
              std::to_string(schema_.size()) + " columns, log dir " + cfg_.logDir);
    return true;
}

void Agent::run() {
    while (running_.load()) {
        const std::uint64_t t0 = monotonicNs();
        doTick();
        const std::uint64_t spent = monotonicNs() - t0;

        // Subtract the work from the sleep so ticks stay on a cadence rather
        // than drifting later by the sampling cost every single time.
        const std::uint64_t budgetNs = static_cast<std::uint64_t>(cfg_.intervalMs) * 1000000ull;
        DWORD waitMs = 0;
        if (spent < budgetNs) waitMs = static_cast<DWORD>((budgetNs - spent) / 1000000ull);

        if (WaitForSingleObject(static_cast<HANDLE>(wakeEvent_), waitMs) == WAIT_OBJECT_0) break;
    }
    log_.info("EdgeVitals stopped after " + std::to_string(tick_) + " ticks");
}

void Agent::stop() {
    if (!running_.exchange(false)) return;
    if (wakeEvent_) SetEvent(static_cast<HANDLE>(wakeEvent_));
    if (ipc_) ipc_->stop();
}

void Agent::doTick() {
    const std::uint64_t t0 = monotonicNs();
    std::string iso;
    Date today;
    nowLocal(iso, today);

    // Monotonic, not wall clock: an NTP step must not make one tick report an
    // impossible CPU percentage.
    const std::uint64_t now = monotonicNs();
    const std::uint64_t elapsedNs = lastTickNs_ ? (now - lastTickNs_) : 0;
    lastTickNs_ = now;

    // Enumeration is the expensive call, so it runs every Nth tick. Its cost
    // is timed separately and reported in its own column -- averaging it into
    // sample_cost_ms made both numbers uncheckable.
    int newUnknown = 0;
    bool enumerated = false;
    if (tick_ % cfg_.enumerateEveryTicks == 0) {
        const std::uint64_t e0 = monotonicNs();
        const auto all = proc_->enumerate();
        proc_->bindRoles(all);
        if (discovery_) newUnknown = discovery_->record(all, iso);
        lastEnumCostMs_ = static_cast<double>(monotonicNs() - e0) / 1e6;
        enumerated = true;
    }

    Row row(schema_);
    row.setText(col_.ts, iso);
    row.setNumber(col_.seq, static_cast<double>(tick_));
    row.setText(col_.runId, runId_);
    row.setText(col_.agentVer, kAgentVersion);
    row.setText(col_.cfgHash, cfgHash_);
    if (col_.runNote != Schema::npos) row.setText(col_.runNote, cfg_.runNote);
    row.setNumber(col_.uptime, static_cast<double>((now - startNs_) / 1000000000ull));
    if (elapsedNs > 0) {
        const double skewMs = (static_cast<double>(elapsedNs) / 1.0e6) -
                              static_cast<double>(cfg_.intervalMs);
        row.setNumber(col_.tickSkew, skewMs);
    }

    // Client-pushed columns. Drain-on-read: a client that stops pushing leaves
    // its cells empty rather than repeating a stale value forever.
    if (ipc_) {
        for (const auto& kv : ipc_->drain()) {
            if (kv.second.isText)
                row.setText(kv.first, kv.second.txt);
            else
                row.setNumber(kv.first, kv.second.num);
        }
    }

    int breaches = 0;
    // Accumulated per group as roles are written. Kept parallel to
    // groupCols_ so no lookup by name is needed in the hot path.
    struct GroupAcc { double priv = 0, cpu = 0, cpuKernel = 0, handles = 0, threads = 0, cpuSeconds = 0; int live = 0; };
    std::vector<GroupAcc> gacc(groupCols_.size());
    // Tier totals for this tick. Separate from groups on purpose: a role can
    // be BOSACH and background at the same time, and the two are unrelated
    // questions.
    double txnCpu = 0.0, bgCpu = 0.0;
    bool anyTiered = false;

    if (elapsedNs > 0) {
        proc_->setTick(tick_);
        auto samples = proc_->sampleAll(elapsedNs);
        for (const auto& rc : roleCols_) {
            auto it = samples.find(rc.first);
            // Absent or not running leaves every cell EMPTY. "Not licensed"
            // and "idle" must never both render as 0.
            if (it == samples.end() || !it->second.valid) continue;
            const ProcSample& s = it->second;
            const RoleCols& c = rc.second;
            row.setNumber(c.pid, static_cast<double>(s.pid));
            row.setNumber(c.cpu, s.cpuPct);
            row.setNumber(c.cpuKernel, s.cpuKernelPct);
            row.setNumber(c.rss, s.rssMb);
            row.setNumber(c.priv, s.privateMb);
            row.setNumber(c.peak, s.peakRssMb);
            row.setNumber(c.faults, s.pageFaultDelta);
            row.setNumber(c.handles, s.handles);
            row.setNumber(c.threads, s.threads);
            if (c.gdi != Schema::npos) {
                row.setNumber(c.gdi, s.gdiObjects);
                row.setNumber(c.user, s.userObjects);
            }
            row.setNumber(c.ioRead, s.ioReadMbs);
            row.setNumber(c.ioWrite, s.ioWriteMbs);
            row.setNumber(c.ioReadOps, s.ioReadOps);
            row.setNumber(c.ioWriteOps, s.ioWriteOps);
            row.setNumber(c.cpuSeconds, s.cpuSeconds);
            // Empty rather than a placeholder when GetPriorityClass failed:
            // "could not read" and "normal" must not look the same.
            if (s.priority && s.priority[0]) row.setText(c.priority, s.priority);

            for (const auto& tp : cfg_.tracked) {
                if (tp.role != rc.first) continue;
                if (tp.ramBudgetMb > 0 && s.privateMb > tp.ramBudgetMb) ++breaches;
                if (tp.cpuBudgetPct > 0 && s.cpuPct > tp.cpuBudgetPct) ++breaches;
                if (tp.tier == "transaction") { txnCpu += s.cpuPct; anyTiered = true; }
                else if (tp.tier == "background") { bgCpu += s.cpuPct; anyTiered = true; }
                if (!tp.group.empty()) {
                    for (size_t gi = 0; gi < groupCols_.size(); ++gi) {
                        if (groupCols_[gi].first != tp.group) continue;
                        gacc[gi].priv += s.privateMb;
                        gacc[gi].cpu += s.cpuPct;
                        gacc[gi].cpuKernel += s.cpuKernelPct;
                        gacc[gi].handles += s.handles;
                        gacc[gi].threads += s.threads;
                        gacc[gi].cpuSeconds += s.cpuSeconds;
                        ++gacc[gi].live;
                        break;
                    }
                }
                break;
            }
        }
    }

    // A group with nothing live leaves EVERY cell empty, including
    // live_roles. Zero would assert that nine BOSACH processes were running
    // and consuming nothing, which is the opposite of the truth.
    for (size_t gi = 0; gi < groupCols_.size(); ++gi) {
        if (gacc[gi].live == 0) continue;
        const GroupCols& g = groupCols_[gi].second;
        row.setNumber(g.priv, gacc[gi].priv);
        row.setNumber(g.cpu, gacc[gi].cpu);
        row.setNumber(g.cpuKernel, gacc[gi].cpuKernel);
        row.setNumber(g.handles, gacc[gi].handles);
        row.setNumber(g.threads, gacc[gi].threads);
        row.setNumber(g.cpuSeconds, gacc[gi].cpuSeconds);
        row.setNumber(g.live, gacc[gi].live);
    }

    // Contention: a background-tier role holding CPU at the same moment a
    // transaction-tier role is busy. CIRCUMSTANTIAL -- the true measure is
    // thread ready time, which Win32 does not expose without ETW. What this
    // says is "background work ran while the transaction path was active",
    // which is the question worth asking even though it is not proof.
    if (anyTiered) {
        row.setNumber(col_.txnCpu, txnCpu);
        row.setNumber(col_.bgCpu, bgCpu);
        if (txnCpu > cfg_.txnActivePct && bgCpu > cfg_.bgLimitPct) ++contentionTicks_;
        row.setNumber(col_.contention, static_cast<double>(contentionTicks_));
    }

    const SystemSample ss = sys_->sample(cfg_.logDir);
    row.setNumber(col_.sysCpu, ss.cpuPct);
    row.setNumber(col_.sysAvail, ss.availMb);
    row.setNumber(col_.sysTotal, ss.totalMb);
    row.setNumber(col_.sysCommit, ss.commitPct);
    row.setNumber(col_.diskFree, ss.diskFreeMb);
    row.setNumber(col_.cores, ss.cores);
    row.setNumber(col_.unknownNew, newUnknown);
    row.setNumber(col_.budgetBreaches, breaches);

    // Measured last so it reflects the whole tick. If this ever approaches
    // the 2 ms budget, the instrument has started disturbing the measurement.
    const double costMs = static_cast<double>(monotonicNs() - t0) / 1e6;
    // Enumeration cost is subtracted so sample_cost_ms measures only sampling
    // and can be checked against the 2 ms budget on every row, including the
    // 6th. enum_cost_ms is EMPTY on ticks that did not enumerate -- empty,
    // not zero, because "did not run" and "ran instantly" are different facts.
    row.setNumber(col_.sampleCost, enumerated ? (costMs - lastEnumCostMs_) : costMs);
    if (enumerated) row.setNumber(col_.enumCost, lastEnumCostMs_);

    if (!sink_->write(row, today)) {
        if (sink_->suppressed() && !warnedSuppressed_) {
            warnedSuppressed_ = true;
            log_.error(sink_->lastError());
        } else if (!sink_->suppressed() && !sink_->lastError().empty()) {
            log_.error(sink_->lastError());
        }
    } else if (warnedSuppressed_) {
        warnedSuppressed_ = false;
        log_.info("disk space recovered -- telemetry writing resumed");
    }

    if (ipc_) ipc_->publishSnapshot(snapshotJson(row));

    if (!(lastPurgeDate_ == today)) {
        lastPurgeDate_ = today;
        // Purge FIRST, then archive. The other order compresses files that
        // are about to be deleted, spending CPU on nothing. archiveOldFiles
        // also refuses past-retention files on its own, so the ordering is a
        // saving rather than a correctness requirement -- but it is free.
        const int removed = sink_->purgeOldFiles(today);
        if (removed > 0)
            log_.info("retention: permanently removed " + std::to_string(removed) +
                      " file(s) older than " + std::to_string(cfg_.retentionDays) + " days");
        const int archived = sink_->archiveOldFiles(today);
        if (archived > 0)
            log_.info("retention: archived " + std::to_string(archived) + " file(s) older than " +
                      std::to_string(cfg_.archiveAfterDays) + " days");
        log_.info("retention: telemetry footprint now " +
                  std::to_string(sink_->bytesOnDisk() / 1048576) + " MB");
    }

    if (newUnknown > 0)
        log_.info("discovery: " + std::to_string(newUnknown) + " new binary/binaries recorded");

    ++tick_;
}

std::string Agent::snapshotJson(const Row& r) const {
    // The panel reads this rather than sampling for itself, so the panel and
    // the CSV can never disagree, and opening the panel cannot change what
    // gets logged.
    std::string out = "{";
    bool first = true;
    for (size_t i = 0; i < schema_.size(); ++i) {
        const Cell& c = r.at(i);
        if (c.empty()) continue;
        if (!first) out.push_back(',');
        first = false;
        out += '"' + schema_.name(i) + "\":";
        if (c.kind() == Cell::Kind::Text) {
            out.push_back('"');
            for (char ch : c.txt()) {
                if (ch == '"' || ch == '\\') out.push_back('\\');
                out.push_back(ch);
            }
            out.push_back('"');
        } else {
            out += c.toCsv(schema_.precision(i));
        }
    }
    out.push_back('}');
    return out;
}

}  // namespace ev
