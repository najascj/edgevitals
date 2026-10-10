// Handle-type probe -- the platform-neutral half.
//
// Question this answers: a role's handle count is climbing (EdgeTerminal has
// measured +49 to +152 per hour across five sessions) -- WHICH KIND of handle?
// The count alone says how many; it never says Event versus Key versus Thread,
// and the fix for each lives in a different part of the code.
//
// Split, like the rest of the agent, so the logic can be tested off-target:
//
//   HERE (edgevitals_core, tested by evhandletest):
//     - ranking a tally into top-by-count and top-by-GROWTH
//     - the trigger that decides when a probe is worth its cost
//     - parsing of the Windows NT buffer layouts, done on raw bytes with
//       memcpy so a malformed or truncated buffer is a refused parse, never
//       an out-of-bounds read, and so the layout rules can be exercised on
//       synthetic buffers on any host
//     - IHandleSource, the one interface each platform implements
//
//   PER PLATFORM (only the snapshot itself):
//     - Windows: HandleProbeWin.cpp, NtQuerySystemInformation(
//       SystemExtendedHandleInformation) + NtQueryObject(ObjectTypesInformation)
//     - Linux / Android (not written yet): /proc/<pid>/fd, classifying each
//       readlink() target by its PREFIX only -- "socket:", "pipe:",
//       "anon_inode:[eventfd]", "/dev/...", "/..." -> "file" -- and discarding
//       the remainder. Same rule as here: types, never names or paths. On
//       Android, SELinux denies another app's fd directory unless the agent
//       runs as that app's uid or as a privileged system component; the source
//       must report that as "unavailable", exactly as the Windows one does when
//       ntdll lacks an export.
//
// OBSERVE ONLY. Nothing here opens, duplicates, closes or names another
// process's handle. A snapshot is read, tallied by type, and released.
#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ev {

// Type name -> handle count, for one role at one probe. std::map so the log
// line is deterministic: two probes of the same state print the same text.
using TypeCounts = std::map<std::string, std::uint64_t>;

std::uint64_t totalOf(const TypeCounts& c);

// "Event:612,Key:291,..." -- count descending, then name ascending.
std::string formatTally(const TypeCounts& c);

struct HandleRank {
    // Largest absolute count. Context, not the answer: a Qt process holds
    // hundreds of Events in steady state.
    bool haveTop = false;
    std::string topType;
    std::uint64_t topCount = 0;

    // Largest INCREASE since the previous probe of the same process set. This
    // is the column that answers "what is leaking".
    //
    //   haveGrow == false   no comparable previous probe (first probe, or the
    //                       process restarted in between). Cells stay EMPTY.
    //   haveGrow == true,
    //   growType empty      compared, and no type increased. growDelta is 0
    //                       and that zero is a measurement, not a default.
    bool haveGrow = false;
    std::string growType;
    long long growDelta = 0;
};

// prev == nullptr means "nothing comparable", and haveGrow stays false. Ties
// break by name so the result never depends on iteration order.
HandleRank rankHandles(const TypeCounts& now, const TypeCounts* prev);

// Decides WHEN to probe. The handle table is the whole machine (~2 MB, ~50k
// entries on the lab terminal), so this never runs on cadence. Rules:
//
//   1. Baseline. A role whose current process set has never been probed needs
//      a baseline -- growth cannot be read without one. It becomes due once
//      that set has been observed unchanged for minSeconds, which also keeps
//      the baseline out of the target's own startup allocation burst.
//   2. Delta. A role whose count has risen by >= delta above its baseline.
//      The baseline FOLLOWS DROPS (min of baseline and current) so a fall
//      followed by a new climb is caught from the low point, not from the
//      old peak.
//   3. Never two probes within minSeconds of each other, for any reason.
//
// A process-set change (restart, PID reuse, an instance of a multi-PID role
// that could not be read) resets the baseline instead of comparing across it.
// That trades a missed reading for never firing on an artefact.
class ProbeTrigger {
public:
    ProbeTrigger(std::vector<std::string> roleNames, long long delta, double minSeconds);

    // One role's handle count this tick. measured == false when the count
    // could not be read; the role's state is then left untouched.
    void observe(size_t role, bool measured, double count, std::uint64_t identity,
                 double nowSec);

    // True if a probe should run now. reason names which rule fired.
    bool due(double nowSec, std::string& reason) const;

    // A probe ran at nowSec. On success, every role measured this tick is
    // rebased to its current count and marked probed for its current set.
    // A failed probe still counts against minSeconds.
    void probed(double nowSec, bool ok);

    size_t roles() const { return st_.size(); }

private:
    struct RoleState {
        bool measured = false;      // this tick
        double count = 0.0;
        std::uint64_t identity = 0;
        double identitySince = 0.0; // when this identity was first observed
        bool haveIdentity = false;
        bool haveBaseline = false;
        double baseline = 0.0;
        bool probedThisIdentity = false;
    };
    std::vector<std::string> names_;
    std::vector<RoleState> st_;
    long long delta_;
    double minSeconds_;
    bool everProbed_ = false;
    double lastProbe_ = 0.0;
};

// Implemented once per platform. The Agent depends only on this.
class IHandleSource {
public:
    virtual ~IHandleSource() = default;

    // False when the platform mechanism is missing or failed its startup
    // self-check. status() then says why, in one line, for the log.
    virtual bool available() const = 0;
    virtual const std::string& status() const = 0;

    struct Stats {
        double costMs = 0.0;
        std::uint64_t bufferBytes = 0;   // peak transient allocation
        std::uint64_t entries = 0;       // handles in the whole snapshot
    };

    // pidToSlot maps a process id to an index into out (out is resized to
    // slots). Only those PIDs are tallied; everything else in the snapshot is
    // skipped. Returns false with err set on failure; out is then unspecified.
    virtual bool snapshot(const std::unordered_map<std::uint64_t, size_t>& pidToSlot,
                          size_t slots, std::vector<TypeCounts>& out, Stats& stats,
                          std::string& err) = 0;
};

struct HandleSourceOptions {
    // Refuse a snapshot whose buffer would exceed this. Same guard shape as
    // archive_max_mb: a transient allocation must not breach the self-budget.
    int maxMb = 6;
};

// Defined by exactly one platform source file. Never returns null: an
// unavailable source is returned with available() == false.
std::unique_ptr<IHandleSource> makePlatformHandleSource(const HandleSourceOptions& o);

// ── Windows NT buffer layouts, parsed portably ──────────────────────────────
//
// These describe what ntdll returns. They live in the core, not in the Win32
// file, because a layout mistake here produces PLAUSIBLE WRONG type names --
// the worst failure this feature can have -- and the core is where tests run.
namespace ntlayout {

// How an entry's ObjectTypeIndex maps onto the ObjectTypesInformation array.
//   Field:         Windows 8.1+ fills OBJECT_TYPE_INFORMATION.TypeIndex.
//   PositionPlus2: before 8.1 the field is reserved; index = position + 2
//                  (0 and 1 are never valid object types).
// The Win32 source does not trust either by OS version: it tries both against
// handles of known type and keeps the one that resolves correctly.
enum class IndexMode { Field, PositionPlus2 };

// Parse an OBJECT_TYPES_INFORMATION buffer into index -> type name. baseAddr
// is the address the buffer had when the kernel filled it: the UNICODE_STRING
// Buffer pointers inside are absolute and are translated back to offsets.
// Names are reduced to [A-Za-z0-9_]; anything else becomes '?'.
bool parseObjectTypes(const std::uint8_t* buf, size_t len, std::uint64_t baseAddr,
                      bool ptr64, IndexMode mode, std::vector<std::string>& byIndex,
                      std::string& err);

// Header of SYSTEM_HANDLE_INFORMATION_EX: entry count, validated against len.
bool handleCount(const std::uint8_t* buf, size_t len, bool ptr64, std::uint64_t& n,
                 std::string& err);

// Tally every entry whose PID is in pidToSlot, by type name. Indexes with no
// name become "type#N" rather than being dropped -- a count that does not add
// up to the total would be its own kind of wrong.
bool tallyHandles(const std::uint8_t* buf, size_t len, bool ptr64,
                  const std::vector<std::string>& byIndex,
                  const std::unordered_map<std::uint64_t, size_t>& pidToSlot, size_t slots,
                  std::vector<TypeCounts>& out, std::string& err);

// Find the ObjectTypeIndex of one (pid, handle value). Used only by the
// startup self-check, against handles the agent created itself.
bool findHandleType(const std::uint8_t* buf, size_t len, bool ptr64, std::uint64_t pid,
                    std::uint64_t value, std::uint16_t& typeIndex);

// Sizes, exposed for the tests.
size_t typeInfoSize(bool ptr64);    // sizeof(OBJECT_TYPE_INFORMATION)
size_t handleEntrySize(bool ptr64); // sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
size_t handleHeaderSize(bool ptr64);

}  // namespace ntlayout
}  // namespace ev
