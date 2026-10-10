// Endpoint integrity (3.5): facts, baseline, results.
//
// Two observe-only checks a bank's security review asks for on an ATM:
//   - File-Integrity Monitoring (FIM): has a watched file changed since the
//     baseline the bank signed off? (PCI DSS 11.5)
//   - Persistence watch: has a new auto-start, service or scheduled task
//     appeared that was not in the baseline? (the common malware foothold)
//
// Same discipline as the rest of EdgeVitals. It REPORTS a change; it never
// restores a file, removes an autostart or stops a service. It reads only:
// file bytes (to hash) and the registry / service manager. No child
// processes, no network, no personal data.
//
// Shape mirrors PostureFacts: a pure evaluator over collected facts, so the
// logic is unit-tested on Linux with real files and hand-built registry facts.
#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ev {

// Read outcome of one fact (same vocabulary as posture).
enum class IRd : std::uint8_t { Ok, Absent, Denied, Error };
const char* irdName(IRd r);

// One file as hashed this run. path is the configured path (a label); the
// bytes are never recorded, only the digest and size.
struct FileHash {
    std::string path;        // as configured, forward slashes; shown in records
    IRd rd = IRd::Error;     // Ok = hashed, Absent = not present, Denied/Error
    std::string sha256;      // lowercase hex when rd == Ok
    std::uint64_t size = 0;
};

// One persistence entry (autostart, service or scheduled task), normalised.
// value is the command/target with any user/path specifics already stripped
// by the collector to a stable, non-identifying token (file name + args kind).
struct PersistEntry {
    std::string kind;        // run | run_once | service | task
    std::string name;        // the value name / service key / task name (lower-cased)
    std::string target;      // lower-cased exe file name only (no path, no args)
};

struct IntegrityFacts {
    std::string takenAtUtc;
    bool elevated = false;

    // FIM
    IRd filesRd = IRd::Error;     // overall: could the fileset be enumerated at all
    std::vector<FileHash> files;

    // Persistence
    IRd persistRd = IRd::Error;
    std::vector<PersistEntry> persistence;

    const FileHash* file(const std::string& path) const;
};

// ── baseline: config/integrity-baseline.json (what the bank approved) ──────

struct FileBaseline {
    std::string path;
    std::string sha256;       // expected digest; empty = "watch, no pinned hash"
    bool required = true;     // true: absence is a FAIL; false: absence is INFO
};

struct IntegrityBaseline {
    std::string name = "default";
    std::vector<FileBaseline> files;          // the watched set and pinned hashes
    std::vector<std::string> persistAllow;    // "kind:name" or "kind:name:target" tokens the bank permits
    bool strictPersistence = true;            // true: any entry not in persistAllow is a FAIL; false: WARN
};
IntegrityBaseline defaultIntegrityBaseline();

// ── results ─────────────────────────────────────────────────────────────────

enum class IStatus : std::uint8_t { Pass, Info, Warn, Fail, Unknown };
const char* iStatusName(IStatus s);

struct IntegrityResult {
    std::string id;          // FI-001 (fileset) ... or P-xxx; here grouped
    std::string title;
    IStatus status = IStatus::Unknown;
    std::string severity;    // high | medium | low | info
    std::string summary;
    std::string flag;        // CSV code: FIM, FIMMISS, PERSIST, ...
    std::string key;         // canonical: a change is a change of status OR key
    std::string observed;    // JSON object text
};

// Pure: same facts + baseline -> same results.
std::vector<IntegrityResult> evaluateIntegrity(const IntegrityFacts& f, const IntegrityBaseline& b);

struct IntegritySummary { int fail = 0, warn = 0, pass = 0, info = 0, unknown = 0; };
IntegritySummary summarizeIntegrity(const std::vector<IntegrityResult>& r);
std::string integrityFlags(const std::vector<IntegrityResult>& r);

// Token helpers (exposed for tests).
std::string persistToken(const PersistEntry& e);          // "service:sshd:sshd.exe"
bool persistAllowed(const PersistEntry& e, const std::vector<std::string>& allow);

// ── JSON (IntegrityJson.cpp) ────────────────────────────────────────────────

class Json;
bool parseIntegrityBaseline(const Json& h, IntegrityBaseline& out, std::string& err);
std::string iJsonQuote(const std::string& s);
std::string integritySummaryJson(const IntegritySummary& s);
std::string integrityChecksJson(const std::vector<IntegrityResult>& r);
std::string integrityDigest(const std::vector<IntegrityResult>& r);

constexpr const char* kIntegritySchema = "edgestack.integrity.endpoint/1";

}  // namespace ev
