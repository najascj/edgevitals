#pragma once
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include <memory>

#include "edgevitals/ChainedFile.h"
#include "edgevitals/Config.h"
#include "edgevitals/CsvSink.h"
#include "edgevitals/ProcessSampler.h"

namespace ev {

struct SystemSample {
    double cpuPct = 0.0;        // machine-wide, 0-100
    double availMb = 0.0;       // available physical
    double totalMb = 0.0;
    double commitPct = 0.0;     // commit charge / commit limit
    double diskFreeMb = 0.0;
    int cores = 1;
};

// System-wide counters. commitPct is the number that predicts trouble on a
// 4 GB box: a process can look healthy at 300 MB while the machine swaps
// because Windows plus the vendor device runtime plus vision took the rest.
class SystemSampler {
public:
    SystemSampler();
    SystemSample sample(const std::string& diskPathHint);
    int cores() const { return cores_; }

private:
    int cores_ = 1;
    std::uint64_t lastIdle_ = 0, lastKernel_ = 0, lastUser_ = 0;
    bool primed_ = false;
};

// Win32 implementation of the disk-space port CsvSink depends on.
class Win32DiskSpace : public IDiskSpace {
public:
    double freeMbAt(const std::string& dir) override;
};

// Records binaries seen running that are not in the tracked list and not in
// the system allowlist.
//
// SCOPE BOUNDARY, deliberate: this OBSERVES. It never blocks, alerts or
// enforces. Unknown-binary detection on an ATM is EdgeBastion's territory;
// two detection paths in one portfolio is a confused story in front of a
// bank. If a finding needs teeth, it belongs there, not here.
class DiscoveryLog {
public:
    // pathTemplate is undated (logs/unknown-processes.csv); the day is
    // inserted per file. chainEvery > 0 chains the file like the agent log.
    DiscoveryLog(std::string pathTemplate, const std::vector<std::string>& systemAllowlist,
                 const std::vector<std::string>& trackedExe, int chainEvery);
    // Switches to the file for day d -- sealing the previous day -- and loads
    // what d's file already holds, so a restart does not re-log the machine.
    // Before 3.2.1 the file was dated once at start-up and never rotated: a
    // 24x7 agent wrote every day into its start-day file, which retention
    // then archived and deleted while it was still being appended to.
    void openFor(const Date& d);

    // Appends any newly-seen unknown binary. Dedup is by lowercased full path
    // (or name when the path is unreadable), so a chatty updater produces one
    // row, not one per sighting. Returns how many new rows were written.
    int record(const std::vector<ProcInfo>& all, const std::string& nowIso, const Date& today);

    size_t knownCount() const { return seen_.size(); }

private:
    bool isKnown(const ProcInfo& p) const;
    void loadExisting();
    std::string template_;
    std::string path_;
    Date day_{};
    bool haveDay_ = false;
    std::unique_ptr<ChainedFile> out_;
    std::set<std::string> allow_;    // lowercased
    std::set<std::string> tracked_;  // lowercased
    std::set<std::string> seen_;     // lowercased path or name
};

// Local time as ISO-8601 plus the calendar date, taken together so a tick
// spanning midnight cannot log a timestamp from one day into the other's file.
void nowLocal(std::string& iso, Date& date);

// Monotonic nanoseconds. Not wall time: the interval must not jump when NTP
// steps the clock, or one tick reports an impossible CPU percentage.
std::uint64_t monotonicNs();

}  // namespace ev
