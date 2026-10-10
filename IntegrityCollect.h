// Endpoint integrity collection.
//   - hashFiles(): portable (std::ifstream + Sha256), compiled into the core
//     so FIM is unit-tested on Linux with real files.
//   - collectIntegrity(): Win32 only -- adds the persistence read (registry
//     Run/RunOnce, services, scheduled-task cache) and fills takenAt/elevated.
// Read-only throughout: file bytes to hash, registry/SCM to enumerate. No
// child processes, no network.
#pragma once
#include "edgevitals/IntegrityFacts.h"

#include <string>
#include <vector>

namespace ev {

// Hashes each path with SHA-256. A path over maxBytes is reported Error (too
// large) rather than read. rd is Ok when the set could be processed at all.
// Portable: no Windows calls.
void hashFiles(const std::vector<std::string>& paths, long long maxBytes,
               std::vector<FileHash>& out, IRd& rd);

struct IntegrityCollectInput {
    std::vector<std::string> files;   // paths to hash (from the baseline)
    long long maxBytes = 64LL * 1024 * 1024;
};

// Win32: fills takenAt/elevated, hashes the fileset, and reads persistence.
void collectIntegrity(const IntegrityCollectInput& in, IntegrityFacts& out);

}  // namespace ev
