// evverify - check a telemetry CSV against its .chain sidecar.
//
//     evverify logs\telemetry-2026-09-22.csv
//     evverify logs\*.csv
//
// Run it on the ATM, on the analyst's workstation, or on the EdgeSentinel
// server -- it needs nothing but the two files and reaches no network. That
// portability is the point: evidence a third party cannot check independently
// is not evidence.
//
// Exit 0 = every checkpoint verified. Non-zero = the file does not match its
// chain, and the output names the first checkpoint that failed.
//
// WHAT A PASS MEANS, PRECISELY
//   The bytes covered by each checkpoint are unchanged since it was written,
//   and the checkpoints form an unbroken chain back to genesis.
//
// WHAT IT DOES NOT MEAN
//   It does not prove WHO wrote the file. An attacker holding SYSTEM can edit
//   the CSV and regenerate the whole chain. Detection comes from comparing
//   against the copy EdgeSentinel already holds, or from a signature once the
//   "sig" field is populated -- the envelope carries it, it is null today.
#include "edgevitals/Digest.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Checkpoint {
    unsigned long long seq = 0, bytes = 0, rows = 0;
    std::string prev, hash, alg, sig, file;
    bool final = false;
    unsigned long long start = 0;
    bool hasStart = false;
};

// Deliberately not the JSON parser: the verifier must be buildable on its own,
// against nothing but Digest.cpp, so it can be handed to an auditor.
std::string field(const std::string& line, const std::string& key) {
    const std::string k = "\"" + key + "\":";
    const size_t p = line.find(k);
    if (p == std::string::npos) return {};
    size_t i = p + k.size();
    while (i < line.size() && (line[i] == ' ')) ++i;
    if (i < line.size() && line[i] == '"') {
        const size_t e = line.find('"', ++i);
        return e == std::string::npos ? std::string() : line.substr(i, e - i);
    }
    const size_t e = line.find_first_of(",}", i);
    return line.substr(i, e - i);
}

bool loadChain(const std::string& path, std::vector<Checkpoint>& out, std::string& err,
               bool& lastWasSeal) {
    lastWasSeal = false;
    std::ifstream f(path);
    if (!f) { err = "cannot open " + path; return false; }
    std::string line;
    while (std::getline(f, line)) {
        // A reopen record carries no hash: it only says the sealed file was
        // legitimately continued by a later agent run.
        if (line.find("\"event\":\"reopen\"") != std::string::npos) {
            // Order matters, not mere presence. An early reopen must not
            // excuse an append after a LATER seal -- tracking a single boolean
            // for the whole file disabled the check entirely.
            lastWasSeal = false;
            continue;
        }
        if (line.find("\"hash\"") == std::string::npos) continue;
        // v1 had no "start" field and assumed segments were contiguous from
        // zero; v2 records each segment's own offset. Both are read here so a
        // chain written before the fix still verifies as far as it can.
        Checkpoint c;
        c.file = field(line, "file");
        c.prev = field(line, "prev");
        c.hash = field(line, "hash");
        c.alg  = field(line, "alg");
        c.sig  = field(line, "sig");
        c.seq   = std::strtoull(field(line, "seq").c_str(), nullptr, 10);
        c.bytes = std::strtoull(field(line, "bytes").c_str(), nullptr, 10);
        // Segment start offset. Absent in chains written before the fix, in
        // which case segments were assumed contiguous from zero -- which broke
        // the moment the agent restarted mid-day and appended to the file.
        const std::string st = field(line, "start");
        c.hasStart = !st.empty();
        c.start = c.hasStart ? std::strtoull(st.c_str(), nullptr, 10) : 0;
        c.rows  = std::strtoull(field(line, "rows").c_str(), nullptr, 10);
        c.final = line.find("\"final\":1") != std::string::npos;
        lastWasSeal = c.final;
        out.push_back(c);
    }
    if (out.empty()) { err = "no checkpoints in " + path; return false; }
    return true;
}

int verify(const std::string& csv) {
    const std::string chain = csv + ".chain";
    std::printf("\n%s\n", csv.c_str());

    std::vector<Checkpoint> cps;
    std::string err;
    bool lastWasSeal = false;
    if (!loadChain(chain, cps, err, lastWasSeal)) {
        std::printf("  UNVERIFIABLE  %s\n", err.c_str());
        std::printf("  A file with no sidecar is not evidence of anything.\n");
        return 2;
    }

    std::ifstream f(csv, std::ios::binary);
    if (!f) { std::printf("  FAIL  cannot open the CSV\n"); return 2; }
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string data = ss.str();

    // Truncation check first: it is the failure a per-segment hash cannot see,
    // because the missing bytes simply never get hashed.
    const Checkpoint& last = cps.back();
    if (data.size() < last.bytes) {
        std::printf("  FAIL  TRUNCATED: file is %llu bytes, checkpoint %llu claims %llu\n",
                    (unsigned long long)data.size(), last.seq, last.bytes);
        std::printf("        %llu bytes are missing from the end.\n",
                    (unsigned long long)(last.bytes - data.size()));
        return 1;
    }

    std::string prev = "genesis";
    unsigned long long off = 0;
    int bad = 0;
    for (const auto& c : cps) {
        if (c.alg != "sha256") {
            std::printf("  FAIL  checkpoint %llu uses unknown alg '%s'\n", c.seq, c.alg.c_str());
            ++bad; break;
        }
        if (c.prev != prev) {
            std::printf("  FAIL  checkpoint %llu: chain broken (prev=%s, expected %s)\n",
                        c.seq, c.prev.c_str(), prev.c_str());
            std::printf("        A checkpoint was removed, reordered, or inserted.\n");
            ++bad; break;
        }
        if (c.bytes > data.size()) {
            std::printf("  FAIL  checkpoint %llu claims %llu bytes, file has %llu\n",
                        c.seq, c.bytes, (unsigned long long)data.size());
            ++bad; break;
        }
        ev::Sha256 seg;
        // Trust the recorded start when present. A restart mid-day makes the
        // segments non-contiguous, and assuming otherwise hashes the wrong
        // bytes and reports a tamper that never happened.
        const unsigned long long from = c.hasStart ? c.start : off;
        if (from > c.bytes || c.bytes > data.size()) {
            std::printf("  FAIL  checkpoint %llu: range %llu-%llu is outside a %llu-byte file\n",
                        c.seq, from, c.bytes, (unsigned long long)data.size());
            return 1;
        }
        seg.update(data.data() + from, static_cast<size_t>(c.bytes - from));
        ev::Sha256 link;
        link.update(prev);
        link.update(seg.hex());
        const std::string got = link.hex();
        if (got != c.hash) {
            std::printf("  FAIL  checkpoint %llu: CONTENT ALTERED between byte %llu and %llu\n",
                        c.seq, from, c.bytes);
            std::printf("        expected %s\n        got      %s\n", c.hash.c_str(), got.c_str());
            ++bad; break;
        }
        prev = c.hash;
        off = c.bytes;
    }

    if (bad) return 1;

    // Was the last checkpoint a seal? A sealed file is finished: anything
    // after the final checkpoint was appended once the agent had stopped, and
    // that is the upward-poisoning case -- forge rows onto yesterday's closed
    // file and let the server ingest them. Before this check an appended row
    // verified OK with exit 0.
    // Sealed AND not subsequently reopened. A same-day restart writes a
    // reopen record before appending, so its trailing bytes are the normal
    // live-file case, not an append-after-close.
    const bool sealed = lastWasSeal;
    const bool trailing = data.size() > off;
    if (trailing && sealed) {
        std::printf("  FAIL  APPENDED AFTER CLOSE: %llu bytes were added after the\n"
                    "        file was sealed at byte %llu. Rows written once the agent\n"
                    "        had stopped. Do not ingest.\n",
                    static_cast<unsigned long long>(data.size() - off),
                    static_cast<unsigned long long>(off));
        return 1;          // int, not bool: 'false' here meant PASS
    }
    std::printf("  OK  %zu checkpoints, %llu rows, %llu bytes covered%s\n",
                cps.size(), last.rows, last.bytes,
                trailing ? "" : "");
    if (trailing)
        std::printf("      %llu trailing bytes after the last checkpoint are NOT covered\n"
                    "      (normal for a file still being written)\n",
                    (unsigned long long)(data.size() - off));
    if (last.sig == "null" || last.sig.empty())
        std::printf("      unsigned: proves integrity, not authorship\n");
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: evverify <telemetry.csv> [more.csv ...]\n");
        return 2;
    }
    int worst = 0;
    for (int i = 1; i < argc; ++i) {
        const int r = verify(argv[i]);
        worst = r > worst ? r : worst;
    }
    std::printf("\n%s\n", worst == 0 ? "all files verified" : "VERIFICATION FAILED");
    return worst;
}
