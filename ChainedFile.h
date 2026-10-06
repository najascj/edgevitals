// A day file with a tamper-evidence chain beside it: the one shared shape
// behind every stream the agent writes.
//
// Same rules as the telemetry sink and the agent log, in one place:
//   - every byte appended is fed to a running SHA-256 (HashChain);
//   - a checkpoint record lands in <path>.chain every N appends;
//   - close() SEALS the file ("final":1) -- nothing may follow;
//   - opening a file that already has a sealed chain (same-day restart)
//     writes a "reopen" record first, resuming from the file's current size
//     and the last recorded hash, so a legitimate restart never fails
//     verification.
// evverify checks these sidecars exactly as it checks the other two streams.
#pragma once
#include "edgevitals/Digest.h"

#include <cstdio>
#include <memory>
#include <string>

namespace ev {

class ChainedFile {
public:
    // checkpointEvery <= 0 disables chaining (plain append).
    explicit ChainedFile(int checkpointEvery) : every_(checkpointEvery) {}
    ~ChainedFile() { close(); }
    ChainedFile(const ChainedFile&) = delete;
    ChainedFile& operator=(const ChainedFile&) = delete;

    // Seals any file already open, then opens path for append.
    bool open(const std::string& path, std::string& err);
    // Appends and chains. Each call counts as one line towards a checkpoint.
    bool append(const std::string& bytes);
    // Seals and closes. Safe to call twice.
    void close();

    bool isOpen() const { return fp_ != nullptr; }
    const std::string& path() const { return path_; }

private:
    void writeRecord(const std::string& rec);
    int every_;
    std::FILE* fp_ = nullptr;
    std::string path_, chainPath_;
    std::unique_ptr<HashChain> chain_;
    int since_ = 0;
};

// Shared sidecar readers (also used by tests).
bool chainSidecarIsSealed(const std::string& sidecar);
std::string chainSidecarLastHash(const std::string& sidecar);

}  // namespace ev
