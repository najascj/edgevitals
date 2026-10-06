// EdgeVitals log-lifecycle tests (evlifecycletest).
//
// Daily rotation, seal at cutover, reopen on same-day restart, archive after
// archive_after_days, purge at retention_days -- for all three streams, with
// dates injected so every boundary is exact. Runs on any host.
//
// Chain CONTENT is verified separately by evverify (it reimplements the rule
// and shares no code with the writers); here we check the lifecycle around it.
#include "edgevitals/ChainedFile.h"
#include "edgevitals/CsvSink.h"
#include "edgevitals/Row.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

namespace fs = std::filesystem;
using namespace ev;

namespace {
int g_pass = 0, g_fail = 0;
void check(const char* n, bool ok, const std::string& d = "") {
    std::printf("  %-64s %s%s%s\n", n, ok ? "PASS" : "FAIL", d.empty() ? "" : "   ", d.c_str());
    (ok ? g_pass : g_fail)++;
}
std::string slurp(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
int count(const std::string& s, const std::string& sub) {
    int n = 0;
    for (size_t p = s.find(sub); p != std::string::npos; p = s.find(sub, p + 1)) ++n;
    return n;
}
void touch(const fs::path& p, const std::string& body = "x\n") {
    std::ofstream o(p, std::ios::binary);
    o << body;
}
struct BigDisk : IDiskSpace {
    double freeMbAt(const std::string&) override { return 1e9; }
};
Date day(const char* iso) {
    Date d{};
    Date::parseIso(iso, d);
    return d;
}
fs::path fresh(const char* name) {
    fs::path d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d);
    return d;
}
}  // namespace

void testChainedFile() {
    std::printf("\nChainedFile (discovery stream's chain)\n");
    const fs::path dir = fresh("evlc_cf");
    const std::string f = (dir / "unknown-processes-2026-10-05.csv").string();
    std::string err;
    {
        ChainedFile cf(2);
        check("opens", cf.open(f, err), err);
        for (int i = 0; i < 5; ++i) cf.append("line " + std::to_string(i) + "\n");
        cf.close();
    }
    const std::string side = slurp(f + ".chain");
    check("checkpoint every 2 appends (5 lines -> 2 checkpoints + seal)", count(side, "\"hash\"") == 3, std::to_string(count(side, "\"hash\"")) + " records");
    check("close seals: last record carries final:1", chainSidecarIsSealed(f + ".chain"));
    {
        ChainedFile cf(2);
        cf.open(f, err);   // same-day restart
        cf.append("after restart\n");
    }   // destructor seals
    const std::string side2 = slurp(f + ".chain");
    check("same-day reopen writes a reopen record before new bytes", side2.find("\"event\":\"reopen\"") != std::string::npos);
    check("...and the file is sealed again on close", chainSidecarIsSealed(f + ".chain"));
    check("bytes appended, nothing lost", count(slurp(f), "\n") == 6);
    ChainedFile off(0);
    const std::string g = (dir / "plain.csv").string();
    off.open(g, err);
    off.append("a\n");
    off.close();
    check("chaining disabled: no sidecar", !fs::exists(g + ".chain"));
}

void testCutover() {
    std::printf("\ntelemetry cutover at midnight\n");
    const fs::path dir = fresh("evlc_cut");
    Schema s;
    const size_t a = s.add("a", 0);
    s.freeze();
    CsvSink::Options o;
    o.dir = dir.string();
    o.chainEveryRows = 2;
    o.restrictLogAcl = false;
    const fs::path d1 = dir / "telemetry-2026-10-05.csv";
    {
        CsvSink sink(o, s, std::make_shared<BigDisk>());
        Row r(s);
        r.setNumber(a, 1);
        for (int i = 0; i < 3; ++i) sink.write(r, day("2026-10-05"));
        sink.write(r, day("2026-10-06"));   // first row after midnight
        check("day 1 file exists", fs::exists(d1));
        check("day 1 sealed at cutover (final:1)", chainSidecarIsSealed(d1.string() + ".chain"));
        check("day 2 file opened", fs::exists(dir / "telemetry-2026-10-06.csv"));
        check("day 2 not sealed while open", !chainSidecarIsSealed((dir / "telemetry-2026-10-06.csv.chain").string()));
    }   // agent shutdown
    check("shutdown seals day 2", chainSidecarIsSealed((dir / "telemetry-2026-10-06.csv.chain").string()));
}

void testHousekeeping() {
    std::printf("\nhousekeeping: all three streams (archive after 7 days, purge after 180)\n");
    const fs::path dir = fresh("evlc_hk");
    const char* days[] = {"2026-10-06", "2026-09-29", "2026-09-28", "2026-04-09", "2026-04-08"};
    for (const char* d : days) {
        for (const std::string base : {std::string("telemetry-") + d + ".csv", std::string("unknown-processes-") + d + ".csv",
                                       std::string("edgevitals-") + d + ".log"}) {
            touch(dir / base, "row,row,row\n");
            touch(dir / (base + ".chain"), "{\"hash\":\"x\",\"final\":1}\n");
        }
    }
    // An archive past retention, and an orphan sidecar left by an older build.
    touch(dir / "telemetry-2026-03-01.csv.zip", "PK");
    touch(dir / "telemetry-2026-03-01.csv.chain", "{}\n");
    touch(dir / "edgevitals-2026-02-01.log.chain", "{}\n");

    Schema s;
    s.add("a", 0);
    s.freeze();
    CsvSink::Options o;
    o.dir = dir.string();
    o.retentionDays = 180;
    o.archiveAfterDays = 7;
    o.restrictLogAcl = false;
    CsvSink sink(o, s, std::make_shared<BigDisk>());
    sink.maintainAllStreams(day("2026-10-06"));

    auto ex = [&](const std::string& n) { return fs::exists(dir / n); };
    for (const std::string p : {"telemetry-", "unknown-processes-", "edgevitals-"}) {
        const std::string ext = p == "edgevitals-" ? ".log" : ".csv";
        const std::string lbl = p.substr(0, p.size() - 1);
        check((lbl + ": today untouched").c_str(), ex(p + "2026-10-06" + ext));
        check((lbl + ": exactly 7 days old stays raw").c_str(), ex(p + "2026-09-29" + ext) && !ex(p + "2026-09-29" + ext + ".zip"));
        check((lbl + ": 8 days old archived to .zip, raw removed").c_str(), ex(p + "2026-09-28" + ext + ".zip") && !ex(p + "2026-09-28" + ext));
        check((lbl + ": archived day keeps its .chain beside the zip").c_str(), ex(p + "2026-09-28" + ext + ".chain"));
        check((lbl + ": exactly 180 days old kept").c_str(), ex(p + "2026-04-09" + ext + ".zip") || ex(p + "2026-04-09" + ext));
        check((lbl + ": 181 days old deleted with its sidecar").c_str(), !ex(p + "2026-04-08" + ext) && !ex(p + "2026-04-08" + ext + ".zip") && !ex(p + "2026-04-08" + ext + ".chain"));
    }
    check("archive past retention: zip AND its sidecar deleted", !ex("telemetry-2026-03-01.csv.zip") && !ex("telemetry-2026-03-01.csv.chain"));
    check("orphan sidecar past retention deleted", !ex("edgevitals-2026-02-01.log.chain"));

    // Archive bytes round-trip is covered by the Archive tests; check the zip
    // names the original file so an analyst can extract it beside its chain.
    const std::string z = slurp(dir / "unknown-processes-2026-09-28.csv.zip");
    check("zip entry is the original file name", z.find("unknown-processes-2026-09-28.csv") != std::string::npos);
}

int main() {
    std::printf("EdgeVitals log-lifecycle tests\n");
    testChainedFile();
    testCutover();
    testHousekeeping();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
