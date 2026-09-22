// Tests for the platform-independent core: JSON, Row/Schema, CSV rotation
// and retention. These build and run anywhere, which is the point -- the
// rotation and retention bugs are date-arithmetic bugs, and those do not need
// Windows to reproduce.
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "edgevitals/Archive.h"
#include "edgevitals/Config.h"
#include "edgevitals/CsvSink.h"
#include "edgevitals/Json.h"
#include "edgevitals/Row.h"

namespace fs = std::filesystem;
using namespace ev;

static int failures = 0;
static int checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        ++checks;                                                            \
        if (!(cond)) {                                                       \
            ++failures;                                                      \
            std::cout << "  FAIL " << (what) << "  [" << __LINE__ << "]\n";  \
        }                                                                    \
    } while (0)

#define CHECK_EQ(a, b, what)                                                 \
    do {                                                                     \
        ++checks;                                                            \
        auto _a = (a);                                                       \
        auto _b = (b);                                                       \
        if (!(_a == _b)) {                                                   \
            ++failures;                                                      \
            std::cout << "  FAIL " << (what) << " -- got [" << _a            \
                      << "] want [" << _b << "]  [" << __LINE__ << "]\n";    \
        }                                                                    \
    } while (0)

static void testJson() {
    std::cout << "[json]\n";
    Json j;
    std::string err;

    const std::string src = R"({
        // a comment, which strict JSON would reject
        "sampling": { "interval_ms": 10000, "enumerate_every_ticks": 6 },
        "output": { "retention_days": 30, "disk_floor_mb": 500.5, "flush_every_tick": true },
        "processes": [
            { "role": "ui", "exe": ["EdgeTerminalDemo.exe"], "ram_budget_mb": 260 },
            { "role": "vision", "exe": "edgesignal-vision.exe" }
        ],
        "esc": "a\"b\\c\td",
        "neg": -12.5,
        "exp": 1.5e3,
        "nul": null,
        "no": false
    })";

    CHECK(Json::parse(src, j, err), "parses config-shaped document");
    CHECK_EQ(j["sampling"]["interval_ms"].asInt(0), 10000LL, "nested int");
    CHECK_EQ(j["output"]["disk_floor_mb"].asNumber(0), 500.5, "double");
    CHECK(j["output"]["flush_every_tick"].asBool(false), "bool true");
    CHECK(!j["no"].asBool(true), "bool false");
    CHECK_EQ(j["processes"].size(), size_t(2), "array size");
    CHECK_EQ(j["processes"][0]["exe"][0].asString(), std::string("EdgeTerminalDemo.exe"), "nested array string");
    CHECK_EQ(j["processes"][1]["exe"].asString(), std::string("edgesignal-vision.exe"), "scalar exe");
    CHECK_EQ(j["esc"].asString(), std::string("a\"b\\c\td"), "escapes");
    CHECK_EQ(j["neg"].asNumber(0), -12.5, "negative");
    CHECK_EQ(j["exp"].asNumber(0), 1500.0, "exponent");
    CHECK(j["nul"].isNull(), "null");

    // Absent keys must give the fallback, never throw -- a service has no
    // console to throw at.
    CHECK_EQ(j["nope"]["deeper"].asInt(42), 42LL, "missing key -> fallback");
    CHECK_EQ(j["processes"][99]["role"].asString("none"), std::string("none"), "OOR index -> fallback");
    CHECK_EQ(j["sampling"].asInt(7), 7LL, "wrong type -> fallback");

    Json bad;
    CHECK(!Json::parse("{ \"a\": }", bad, err), "rejects missing value");
    CHECK(!Json::parse("{ \"a\": 1 ", bad, err), "rejects unterminated object");
    CHECK(!Json::parse("{ \"a\": \"x }", bad, err), "rejects unterminated string");
    CHECK(!Json::parse("{} junk", bad, err), "rejects trailing content");
    CHECK(err.compare(0, 5, "line ") == 0, "error carries a line number");
}

static void testRow() {
    std::cout << "[row]\n";
    Schema s;
    const size_t ts = s.add("ts", 0);
    const size_t cpu = s.add("ui_cpu_pct", 2);
    const size_t rss = s.add("ui_rss_mb", 1);
    const size_t st = s.add("state", 0);
    s.add("vision_rss_mb", 1);
    s.add("note", 0);
    CHECK_EQ(s.size(), size_t(6), "schema size");
    CHECK_EQ(s.indexOf("ui_rss_mb"), rss, "indexOf");
    CHECK_EQ(s.indexOf("absent"), Schema::npos, "indexOf missing");
    CHECK_EQ(s.headerCsv(), std::string("ts,ui_cpu_pct,ui_rss_mb,state,vision_rss_mb,note"), "header");

    s.freeze();
    CHECK_EQ(s.add("too_late", 0), Schema::npos, "frozen schema rejects new columns");

    Row r(s);
    r.setText(ts, "2026-07-31T14:22:10");
    r.setNumber(cpu, 12.345);
    r.setNumber(rss, 248.0);
    r.setText(st, "pin");
    // vision deliberately left EMPTY -- not licensed.
    r.setText("note", "has,comma and \"quote\"");

    const std::string csv = r.toCsv();
    // The empty vision cell must render as nothing between commas, NOT 0.
    CHECK_EQ(csv,
             std::string("2026-07-31T14:22:10,12.35,248,pin,,\"has,comma and \"\"quote\"\"\""),
             "row csv: empty stays empty, quoting, precision, integer trim");

    CHECK(!r.setNumber("no_such_column", 1.0), "unknown named column is ignored, not fatal");

    Row r2(s);
    r2.setNumber(cpu, std::nan(""));
    r2.setNumber(rss, 1.0 / 0.0);
    const std::string c2 = r2.toCsv();
    CHECK_EQ(c2, std::string(",,,,,"), "nan and inf render empty, not 'nan'/'inf'");
}

static void testDate() {
    std::cout << "[date]\n";
    Date a{2026, 7, 31}, b{2026, 8, 1};
    CHECK_EQ(b.serial() - a.serial(), 1LL, "month boundary is one day");
    Date c{2024, 2, 28}, d{2024, 3, 1};
    CHECK_EQ(d.serial() - c.serial(), 2LL, "leap year February has a 29th");
    Date e{2023, 2, 28}, f{2023, 3, 1};
    CHECK_EQ(f.serial() - e.serial(), 1LL, "non-leap February does not");
    Date g{2024, 12, 31}, h{2025, 1, 1};
    CHECK_EQ(h.serial() - g.serial(), 1LL, "year boundary");
    Date p;
    CHECK(Date::parseIso("2026-07-31", p), "parses iso");
    CHECK(p == (Date{2026, 7, 31}), "parsed value");
    CHECK(!Date::parseIso("2026-7-31", p), "rejects short month");
    CHECK(!Date::parseIso("2026-13-01", p), "rejects month 13");
    CHECK(!Date::parseIso("not-a-date", p), "rejects garbage");
}

class FakeDisk : public IDiskSpace {
public:
    double mb = 100000.0;
    double freeMbAt(const std::string&) override { return mb; }
};

static void testSink() {
    std::cout << "[sink]\n";
    const fs::path dir = fs::temp_directory_path() / "ev_sink_test";
    fs::remove_all(dir);

    Schema s;
    s.add("ts", 0);
    s.add("v", 1);
    s.freeze();

    auto disk = std::make_shared<FakeDisk>();
    CsvSink::Options o;
    o.dir = dir.string();
    o.prefix = "telemetry";
    o.retentionDays = 3;
    o.diskFloorMb = 500.0;

    {
        CsvSink sink(o, s, disk);
        Row r(s);
        r.setText(0, "t1");
        r.setNumber(1, 1.5);
        CHECK(sink.write(r, Date{2026, 7, 31}), "writes first row");
        r.setText(0, "t2");
        CHECK(sink.write(r, Date{2026, 7, 31}), "writes second row same day");
        r.setText(0, "t3");
        CHECK(sink.write(r, Date{2026, 8, 1}), "rotates to next day");
    }

    CHECK(fs::exists(dir / "telemetry-2026-07-31.csv"), "day 1 file exists");
    CHECK(fs::exists(dir / "telemetry-2026-08-01.csv"), "day 2 file exists");

    {
        std::ifstream in(dir / "telemetry-2026-07-31.csv");
        std::string l1, l2, l3, l4;
        std::getline(in, l1);
        std::getline(in, l2);
        std::getline(in, l3);
        const bool extra = static_cast<bool>(std::getline(in, l4));
        CHECK_EQ(l1, std::string("ts,v"), "header written once");
        CHECK_EQ(l2, std::string("t1,1.5"), "row 1");
        CHECK_EQ(l3, std::string("t2,1.5"), "row 2");
        CHECK(!extra, "no trailing rows");
    }

    // Reopen mid-day: must append, not write a second header.
    {
        CsvSink sink(o, s, disk);
        Row r(s);
        r.setText(0, "t4");
        r.setNumber(1, 2.0);
        CHECK(sink.write(r, Date{2026, 7, 31}), "reopen writes");
    }
    {
        std::ifstream in(dir / "telemetry-2026-07-31.csv");
        std::string line;
        int headers = 0, lines = 0;
        while (std::getline(in, line)) {
            ++lines;
            if (line == "ts,v") ++headers;
        }
        CHECK_EQ(headers, 1, "restart mid-day does not duplicate the header");
        CHECK_EQ(lines, 4, "restart appends");
    }

    // Disk floor.
    {
        disk->mb = 100.0;
        CsvSink sink(o, s, disk);
        Row r(s);
        r.setText(0, "nope");
        CHECK(!sink.write(r, Date{2026, 8, 2}), "suppressed below disk floor");
        CHECK(sink.suppressed(), "suppressed flag set");
        CHECK(!sink.lastError().empty(), "explains why");
        CHECK(!fs::exists(dir / "telemetry-2026-08-02.csv"), "no file created while suppressed");
        disk->mb = 100000.0;
        CHECK(sink.write(r, Date{2026, 8, 2}), "resumes when space returns");
        CHECK(!sink.suppressed(), "suppressed flag cleared");
    }

    // Retention: 3 days, today 2026-08-10 -> cutoff 2026-08-07.
    {
        for (const char* n : {"telemetry-2026-08-01.csv", "telemetry-2026-08-06.csv",
                              "telemetry-2026-08-08.csv", "telemetry-2026-08-09.csv"}) {
            std::ofstream f(dir / n);
            f << "ts,v\n";
        }
        std::ofstream keep(dir / "notes.txt");
        keep << "not ours\n";
        std::ofstream keep2(dir / "telemetry-garbage.csv");
        keep2 << "undateable\n";

        CsvSink sink(o, s, disk);
        Row r(s);
        r.setText(0, "t");
        sink.write(r, Date{2026, 8, 10});
        const int removed = sink.purgeOldFiles(Date{2026, 8, 10});

        CHECK(!fs::exists(dir / "telemetry-2026-08-01.csv"), "purged old");
        CHECK(!fs::exists(dir / "telemetry-2026-08-06.csv"), "purged just-past-cutoff");
        CHECK(fs::exists(dir / "telemetry-2026-08-08.csv"), "kept within retention");
        CHECK(fs::exists(dir / "telemetry-2026-08-10.csv"), "kept today");
        CHECK(fs::exists(dir / "notes.txt"), "left a foreign file alone");
        CHECK(fs::exists(dir / "telemetry-garbage.csv"), "left an undateable name alone");
        CHECK(removed >= 2, "reported the removals");
    }

    fs::remove_all(dir);
}

static void testConfig() {
    std::cout << "[config]\n";
    const fs::path p = fs::temp_directory_path() / "ev_cfg_test.json";
    {
        std::ofstream f(p);
        f << R"({
            "sampling": { "interval_ms": 5000 },
            "output": { "dir": "C:/logs", "retention_days": 7 },
            "processes": [ { "role": "ui", "exe": ["A.exe","B.exe"], "ram_budget_mb": 300 } ]
        })";
    }
    Config c;
    std::string err;
    CHECK(c.load(p.string(), err), "loads");
    CHECK_EQ(c.intervalMs, 5000, "interval overridden");
    CHECK_EQ(c.retentionDays, 7, "retention overridden");
    CHECK_EQ(c.logDir, std::string("C:/logs"), "dir overridden");
    CHECK_EQ(c.enumerateEveryTicks, 6, "unspecified field keeps its default");
    CHECK_EQ(c.tracked.size(), size_t(1), "processes replaced, not merged");
    CHECK_EQ(c.tracked[0].exe.size(), size_t(2), "exe list");
    CHECK(!c.extraColumns.empty(), "extra columns keep defaults when unspecified");

    // A bad config must leave the object at defaults, not half-applied.
    {
        std::ofstream f(p);
        f << R"({ "sampling": { "interval_ms": 9000 }, "processes": [ { "exe": ["X.exe"] } ] })";
    }
    Config c2 = Config::defaults();
    const int before = c2.intervalMs;
    CHECK(!c2.load(p.string(), err), "rejects a process with no role");
    CHECK_EQ(c2.intervalMs, before, "failed load leaves config untouched");
    CHECK(err.find("role") != std::string::npos, "error names the problem");

    {
        std::ofstream f(p);
        f << R"({ "sampling": { "interval_ms": 100 } })";
    }
    CHECK(!c2.load(p.string(), err), "rejects an interval below 1 s");

    CHECK(!c2.load("/no/such/file.json", err), "missing file is an error, not a crash");
    fs::remove(p);
}


// ── Archive: compression correctness and the retention/archive interaction ──
static void testArchive() {
    std::cout << "archive\n";

    // CRC32 against the canonical check value from the zlib documentation.
    const std::string chk = "123456789";
    CHECK_EQ(crc32Of(reinterpret_cast<const std::uint8_t*>(chk.data()), chk.size()),
             0xCBF43926u, "crc32 of \"123456789\"");

    // Deflate must produce a stream a real decompressor accepts. We cannot
    // inflate here, so the structural guarantees are what we can assert:
    // the container is well formed and the sizes are consistent.
    {
        std::string body;
        for (int i = 0; i < 2000; ++i) body += "ts,seq,run_id,cpu,mem\n2026-08-19,1,abc,0.4,283.1\n";
        ZipEntry e;
        e.name = "telemetry-2026-08-12.csv";
        e.data.assign(body.begin(), body.end());
        e.year = 2026; e.month = 8; e.day = 12;
        const auto z = buildZip({e});

        CHECK(z.size() > 22, "zip is non-trivial");
        CHECK(z.size() < body.size(), "repetitive CSV actually got smaller");
        // Local file header signature.
        CHECK(z[0] == 0x50 && z[1] == 0x4B && z[2] == 0x03 && z[3] == 0x04, "local header sig");
        // End of central directory, last 22 bytes with no comment.
        const size_t eo = z.size() - 22;
        CHECK(z[eo] == 0x50 && z[eo+1] == 0x4B && z[eo+2] == 0x05 && z[eo+3] == 0x06, "EOCD sig");
        const unsigned nEnt = static_cast<unsigned>(z[eo+10]) | (static_cast<unsigned>(z[eo+11]) << 8);
        CHECK_EQ(nEnt, 1u, "one entry in the central directory");
    }

    // Empty input must still produce a valid single-entry archive rather than
    // a zero-byte file that looks like a failed write.
    {
        ZipEntry e;
        e.name = "telemetry-2026-08-12.csv";
        e.year = 2026; e.month = 8; e.day = 12;
        const auto z = buildZip({e});
        CHECK(z.size() > 22, "empty entry still yields a valid archive");
    }

    // Incompressible input must fall back to stored, never grow unboundedly.
    {
        std::string noise;
        noise.reserve(4096);
        unsigned x = 12345;
        for (int i = 0; i < 4096; ++i) { x = x * 1103515245u + 12345u; noise.push_back(static_cast<char>(x >> 16)); }
        ZipEntry e;
        e.name = "noise.csv";
        e.data.assign(noise.begin(), noise.end());
        const auto z = buildZip({e});
        CHECK(z.size() < noise.size() + 200, "incompressible input does not balloon");
    }
}

static void testArchiveRetention() {
    std::cout << "archive + retention\n";
    const fs::path dir = fs::temp_directory_path() / "ev_arch_test";
    fs::remove_all(dir);
    fs::create_directories(dir);

    auto makeFile = [&](const std::string& name, int lines) {
        std::ofstream f(dir / name);
        for (int i = 0; i < lines; ++i)
            f << "2026-08-01T00:00:0" << (i % 10) << ",1,abc,0.43,283.1,216.2\n";
    };

    // today = 2026-08-20, archive after 7 days, retention 30 days.
    makeFile("telemetry-2026-08-20.csv", 50);   // today
    makeFile("telemetry-2026-08-18.csv", 50);   // 2 days -- raw
    makeFile("telemetry-2026-08-14.csv", 50);   // 6 days -- raw (boundary)
    makeFile("telemetry-2026-08-12.csv", 400);  // 8 days -- archive
    makeFile("telemetry-2026-08-01.csv", 400);  // 19 days -- archive
    makeFile("telemetry-2026-07-01.csv", 50);   // 50 days -- purge
    makeFile("notes.txt", 5);                   // foreign, never touched

    Schema sch;
    sch.add("ts", 0);
    sch.freeze();

    CsvSink::Options o;
    o.dir = dir.string();
    o.prefix = "telemetry";
    o.retentionDays = 30;
    o.archiveAfterDays = 7;
    o.diskFloorMb = 0.0;
    CsvSink sink(o, sch, nullptr);

    const Date today{2026, 8, 20};
    // Open today's file so it is excluded by name, matching real operation.
    Row r(sch);
    r.setText(0, "2026-08-20T00:00:00");
    sink.write(r, today);

    const int archived = sink.archiveOldFiles(today);
    CHECK_EQ(archived, 2, "archived exactly the two files past the raw window");
    CHECK(!fs::exists(dir / "telemetry-2026-08-12.csv"), "raw removed after archiving");
    CHECK(fs::exists(dir / "telemetry-2026-08-12.csv.zip"), "archive written");
    CHECK(!fs::exists(dir / "telemetry-2026-08-01.csv"), "second raw removed");
    CHECK(fs::exists(dir / "telemetry-2026-08-01.csv.zip"), "second archive written");

    CHECK(fs::exists(dir / "telemetry-2026-08-14.csv"), "6-day file stays raw");
    CHECK(fs::exists(dir / "telemetry-2026-08-18.csv"), "2-day file stays raw");
    CHECK(fs::exists(dir / "telemetry-2026-08-20.csv"), "today stays raw");
    CHECK(fs::exists(dir / "notes.txt"), "foreign file untouched by archiving");

    // The archive must be smaller than what it replaced.
    CHECK(fs::file_size(dir / "telemetry-2026-08-12.csv.zip") < 400 * 40,
          "archive is smaller than the source it replaced");

    // No temp files survive a successful run.
    int tmps = 0;
    for (const auto& e : fs::directory_iterator(dir))
        if (e.path().extension() == ".tmp") ++tmps;
    CHECK_EQ(tmps, 0, "no .tmp left behind");

    // Idempotent: a second pass finds nothing new.
    CHECK_EQ(sink.archiveOldFiles(today), 0, "archiving is idempotent");

    // Purge must delete BOTH .csv and .csv.zip past retention.
    makeFile("telemetry-2026-06-01.csv", 10);
    {
        std::ofstream f(dir / "telemetry-2026-06-02.csv.zip");
        f << "PK\x03\x04 fake";
    }
    const int removed = sink.purgeOldFiles(today);
    CHECK(!fs::exists(dir / "telemetry-2026-07-01.csv"), "purged old raw");
    CHECK(!fs::exists(dir / "telemetry-2026-06-01.csv"), "purged very old raw");
    CHECK(!fs::exists(dir / "telemetry-2026-06-02.csv.zip"), "purged old ARCHIVE too");
    CHECK(fs::exists(dir / "telemetry-2026-08-01.csv.zip"), "kept archive inside retention");
    CHECK(fs::exists(dir / "notes.txt"), "foreign file untouched by purge");
    CHECK(removed >= 3, "reported the removals");

    CHECK(sink.bytesOnDisk() > 0, "reports its own footprint");

    // archiveAfterDays = 0 disables archiving entirely.
    {
        CsvSink::Options o2 = o;
        o2.archiveAfterDays = 0;
        CsvSink s2(o2, sch, nullptr);
        makeFile("telemetry-2026-08-05.csv", 20);
        CHECK_EQ(s2.archiveOldFiles(today), 0, "archiveAfterDays=0 disables archiving");
        CHECK(fs::exists(dir / "telemetry-2026-08-05.csv"), "file left raw when disabled");
    }

    fs::remove_all(dir);
}

static void testLogAcl() {
    std::cout << "log dir acl\n";
    // applyLogDirAcl is a no-op off Windows. What is testable everywhere is
    // that it never throws, never blocks writing, and that a failure is
    // recorded rather than swallowed -- losing telemetry to a permissions
    // problem would be worse than the loose ACL it is trying to fix.
    const fs::path dir = fs::temp_directory_path() / "ev_acl_test";
    fs::remove_all(dir);

    Schema sch;
    sch.add("ts", 0);
    sch.freeze();

    CsvSink::Options o;
    o.dir = dir.string();
    o.prefix = "telemetry";
    o.diskFloorMb = 0.0;
    o.restrictLogAcl = true;
    CsvSink sink(o, sch, nullptr);

    Row r(sch);
    r.setText(0, "2026-08-22T09:00:00.000");
    CHECK(sink.write(r, Date{2026, 8, 22}), "writes after applying the ACL");
    CHECK(fs::exists(dir / "telemetry-2026-08-22.csv"), "file landed");

    // Disabled must also be safe.
    fs::remove_all(dir);
    CsvSink::Options o2 = o;
    o2.restrictLogAcl = false;
    CsvSink s2(o2, sch, nullptr);
    CHECK(s2.write(r, Date{2026, 8, 22}), "writes with the ACL step disabled");

    fs::remove_all(dir);
}

int main() {
    testJson();
    testRow();
    testDate();
    testSink();
    testConfig();
    testArchive();
    testArchiveRetention();
    testLogAcl();
    std::cout << "\n" << (checks - failures) << "/" << checks << " checks passed\n";
    if (failures) std::cout << failures << " FAILURES\n";
    return failures ? 1 : 0;
}
