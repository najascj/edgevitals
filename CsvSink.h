// Day-rotated CSV writer.
//
// Platform-independent by design: the one OS-specific thing it needs -- free
// space on the log volume -- comes in through IDiskSpace. That keeps rotation
// and retention logic testable off-Windows, which is where their bugs live.
#pragma once
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "edgevitals/Digest.h"
#include "edgevitals/Row.h"

namespace ev {

struct Date {
    int y = 0, m = 0, d = 0;
    bool operator==(const Date& o) const { return y == o.y && m == o.m && d == o.d; }
    bool operator!=(const Date& o) const { return !(*this == o); }
    std::string iso() const;                       // 2026-07-31
    static bool parseIso(const std::string& s, Date& out);
    // Days since 1970-01-01. Only used for retention age, so the epoch is
    // arbitrary -- what matters is that differences are correct.
    long long serial() const;
};

class IDiskSpace {
public:
    virtual ~IDiskSpace() = default;
    virtual double freeMbAt(const std::string& dir) = 0;
};

class CsvSink {
public:
    struct Options {
        std::string dir = "logs";
        std::string prefix = "telemetry";
        int retentionDays = 30;
        int archiveAfterDays = 7;      // 0 = never archive
        // Refuse to compress a file larger than this. Compression peaks at
        // roughly 3x the file size in transient memory, so an unbounded day
        // file would blow the agent's own budget on a 4 GB terminal. An
        // oversized file is left raw and reported, not silently skipped.
        int archiveMaxMb = 64;
        // Apply an explicit DACL to the log directory on creation. Telemetry
        // is not cardholder data, but it does enumerate every process on the
        // terminal including the security stack, which is reconnaissance.
        // Inheriting whatever the exe was unpacked into is not a decision.
        bool restrictLogAcl = true;
        double diskFloorMb = 500.0;
        bool flushEveryTick = true;
        // Tamper-evidence. A rolling SHA-256 chain over the bytes written,
        // with a checkpoint every N rows into <file>.chain. 0 disables it.
        // 30 rows is 5 minutes at the standing 10 s interval -- the window in
        // which a local edit is still undetectable.
        int chainEveryRows = 30;
    };

    CsvSink(Options opts, const Schema& schema, std::shared_ptr<IDiskSpace> disk);
    ~CsvSink();

    CsvSink(const CsvSink&) = delete;
    CsvSink& operator=(const CsvSink&) = delete;

    // Writes one row, rotating first if the date changed. Returns false if
    // the row was suppressed (disk floor) or the file could not be opened;
    // lastError() explains which.
    bool write(const Row& row, const Date& today);

    // True while writing is suppressed by the disk floor.
    bool suppressed() const { return suppressed_; }
    const std::string& lastError() const { return lastError_; }
    const std::string& currentPath() const { return path_; }

    // Deletes prefix-YYYY-MM-DD.csv AND prefix-YYYY-MM-DD.csv.zip older than
    // retentionDays. Returns how many were removed. Never touches a file it
    // cannot date from its own name -- an unparseable name is somebody else's
    // file. Permanent: fs::remove, no recycle bin, no tombstone.
    int purgeOldFiles(const Date& today);

    // One maintenance sweep for EVERY stream in the log directory, not just
    // the telemetry CSV. Archives past archiveAfterDays and deletes past
    // retentionDays, for:
    //     <prefix>-YYYY-MM-DD.csv          telemetry
    //     unknown-processes-YYYY-MM-DD.csv discovery
    //     edgevitals-YYYY-MM-DD.log        the agent's own log
    // and each one's .chain sidecar, which is moved and deleted with its file
    // so a verifier never meets an orphan.
    //
    // Runs on rotation, so once a day.
    int maintainAllStreams(const Date& today);

    // Compress one file to <path>.zip. Shared by archiveOldFiles and the
    // all-stream sweep so both honour the same size cap.
    bool archiveFile(const std::string& src, const std::string& dstZip, std::string& err);

    // SYSTEM and Administrators only, inheritable, protected from inherited
    // ACEs. Best-effort: a failure is recorded in lastError() and does not
    // stop telemetry, because losing the log is worse than a loose ACL.
    // No-op off Windows so the core stays testable.
    void applyLogDirAcl();

    // Compresses prefix-YYYY-MM-DD.csv older than archiveAfterDays into
    // prefix-YYYY-MM-DD.csv.zip and removes the raw file. Returns how many
    // were archived.
    //
    // Ordering contract: the .zip is written to a .tmp name, fsync'd, renamed
    // into place, and only then is the .csv deleted. A power cut at any point
    // leaves either the original or a complete archive, never neither.
    int archiveOldFiles(const Date& today);

    // Total bytes currently held by this sink's own files (.csv + .csv.zip).
    // Lets the agent report its own footprint rather than the operator
    // discovering it.
    long long bytesOnDisk() const;

    double freeMb() const { return freeMb_; }

private:
    bool openFor(const Date& d);
    void close();

    Options opts_;
    const Schema& schema_;
    std::shared_ptr<IDiskSpace> disk_;
    std::FILE* fp_ = nullptr;
    Date openDate_;
    std::string path_;
    // One chain per open file; recreated on rotation so each day stands alone
    // and can be verified without the previous day's sidecar.
    std::unique_ptr<HashChain> chain_;
    std::string chainPath_;
    int sinceCheckpoint_ = 0;
    void chainFeed(const std::string& bytes);
    void chainCheckpoint();
    std::string lastError_;
    bool schemaRolled_ = false;
    bool suppressed_ = false;
    double freeMb_ = 0.0;
};

}  // namespace ev
