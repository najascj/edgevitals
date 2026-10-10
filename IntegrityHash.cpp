// Portable file hashing for FIM (compiled into edgevitals_core; tested on Linux).
#include "edgevitals/IntegrityCollect.h"

#include "edgevitals/Digest.h"

#include <fstream>

namespace ev {

void hashFiles(const std::vector<std::string>& paths, long long maxBytes,
               std::vector<FileHash>& out, IRd& rd) {
    out.clear();
    rd = IRd::Ok;   // the set could be processed; per-file outcomes carry the rest
    for (const auto& p : paths) {
        FileHash h;
        h.path = p;
        std::ifstream in(p, std::ios::binary);
        if (!in) {
            // Absent vs denied is not distinguishable portably; the Win32
            // collector refines this. Here: treat an unopenable path as Absent,
            // which FIM reports as "required file missing" when the baseline
            // marks it required.
            h.rd = IRd::Absent;
            out.push_back(std::move(h));
            continue;
        }
        in.seekg(0, std::ios::end);
        const std::streamoff n = in.tellg();
        if (n < 0) {
            h.rd = IRd::Error;
            out.push_back(std::move(h));
            continue;
        }
        if (maxBytes > 0 && static_cast<long long>(n) > maxBytes) {
            h.rd = IRd::Error;   // too large: skipped, not hashed
            h.size = static_cast<std::uint64_t>(n);
            out.push_back(std::move(h));
            continue;
        }
        in.seekg(0, std::ios::beg);
        Sha256 sha;
        char buf[64 * 1024];  // flawfinder: ignore -- filled only by in.read(buf, sizeof(buf)); gcount bounds the update
        std::uint64_t total = 0;
        bool ok = true;
        while (in) {
            in.read(buf, sizeof(buf));
            const std::streamsize got = in.gcount();
            if (got > 0) {
                sha.update(buf, static_cast<std::size_t>(got));
                total += static_cast<std::uint64_t>(got);
            }
            if (!in && !in.eof()) {
                ok = false;
                break;
            }
        }
        if (!ok) {
            h.rd = IRd::Error;
        } else {
            h.rd = IRd::Ok;
            h.sha256 = sha.hex();
            h.size = total;
        }
        out.push_back(std::move(h));
    }
}

}  // namespace ev
