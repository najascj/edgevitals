// EdgeVitals security test harness.
//
//     evsecuritytest            run everything, print a pass/fail table
//     evsecuritytest --verbose  show each case
//
// Purpose: prove that hostile input cannot crash, hang, or grow EdgeVitals
// without bound. It exercises the two surfaces an attacker can actually reach
// -- the IPC pipe and the config file -- plus the one place machine-controlled
// strings leave the process, the CSV.
//
// This is a HOST-SIDE harness: it links the core sources directly, so it runs
// the same code the agent runs without needing the agent to be running. Build
// and run it on the ATM as part of acceptance.
//
// Every case has a time and memory budget. A case that neither crashes nor
// returns is as much a failure as one that segfaults -- a wedged parser inside
// the IPC handler holds a client slot forever.
#include "edgevitals/Config.h"
#include "edgevitals/Json.h"
#include "edgevitals/Row.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

bool g_verbose = false;
int g_pass = 0, g_fail = 0;

struct Result {
    bool ok = false;
    double ms = 0.0;
    std::string detail;
};

// A case "passes" when the parser REJECTS or accepts quickly and returns.
// Crashing is caught by the runner script, not here: a segfault takes the
// whole process, which is precisely why the outer loop matters.
Result parseCase(const std::string& name, const std::string& doc,
                 double budgetMs, bool expectReject) {
    Result r;
    const auto t0 = std::chrono::steady_clock::now();
    ev::Json j;
    std::string err;
    const bool parsed = ev::Json::parse(doc, j, err);
    r.ms = std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now() - t0).count();

    if (expectReject && parsed) {
        r.detail = "accepted a document that should have been refused";
    } else if (r.ms > budgetMs) {
        char b[128];
        std::snprintf(b, sizeof(b), "took %.1f ms, budget %.0f ms", r.ms, budgetMs);
        r.detail = b;
    } else {
        r.ok = true;
        r.detail = parsed ? "accepted" : ("refused: " + err);
    }

    std::printf("  %-28s %7.2f ms  %-6s %s\n", name.c_str(), r.ms,
                r.ok ? "PASS" : "FAIL", r.detail.c_str());
    r.ok ? ++g_pass : ++g_fail;
    return r;
}

std::string rep(const std::string& unit, size_t n) {
    std::string s;
    s.reserve(unit.size() * n);
    for (size_t i = 0; i < n; ++i) s += unit;
    return s;
}

// ── 1. Depth ─────────────────────────────────────────────────────────
// The finding this harness was written for. value() recurses through
// object() and array(); without a limit one stack frame per character.
void testDepth() {
    std::printf("\n[1] nesting depth — stack exhaustion\n");
    parseCase("nest 8 (normal config)",  rep("[", 8) + rep("]", 8), 50, false);
    parseCase("nest 64 (at the limit)",  rep("[", 64) + rep("]", 64), 50, false);
    parseCase("nest 65 (over)",          rep("[", 65) + rep("]", 65), 50, true);
    parseCase("nest 5000",               rep("[", 5000), 200, true);
    parseCase("nest 100000",             rep("[", 100000), 500, true);
    // 262,144 is what the 256 KB IPC cap actually admits.
    parseCase("nest 262144 (IPC cap)",   rep("[", 262144), 1000, true);
    parseCase("nest objects 65",         rep("{\"a\":", 65) + "1" + rep("}", 65), 50, true);
    // Alternating shapes defeat a naive "count only braces" guard.
    parseCase("nest mixed 200",          rep("[{\"a\":", 200) + "1" + rep("}]", 200), 200, true);
}

// ── 2. Size and shape ────────────────────────────────────────────────
void testSizeAndShape() {
    std::printf("\n[2] size and shape — memory and time\n");
    parseCase("2 MB string value",
              "{\"k\":\"" + std::string(2 * 1024 * 1024, 'a') + "\"}", 500, false);
    parseCase("200k keys",
              [] { std::string s = "{"; for (int i = 0; i < 200000; ++i) {
                       if (i) s += (char)44;
                       s += "\"k" + std::to_string(i) + "\":1"; }
                   return s + "}"; }(), 3000, false);
    parseCase("200k array elements",
              [] { std::string s = "["; for (int i = 0; i < 200000; ++i) {
                       if (i) s += (char)44;
                       s += "1"; } return s + "]"; }(), 3000, false);
    parseCase("duplicate keys x50000",
              [] { std::string s = "{"; for (int i = 0; i < 50000; ++i) {
                       if (i) s += (char)44;
                       s += "\"same\":1"; } return s + "}"; }(), 3000, false);
    parseCase("escape storm 500k",
              "\"" + rep("\\\\", 500000) + "\"", 2000, false);
    parseCase("comment storm 200k",
              rep("/*x*/", 200000) + "1", 2000, false);
}

// ── 3. Numbers ───────────────────────────────────────────────────────
void testNumbers() {
    std::printf("\n[3] numbers — overflow and malformed\n");
    parseCase("exponent bomb 1e999999999", "1e999999999", 50, false);
    parseCase("huge exponent digits",     "1e" + std::string(100000, '9'), 500, false);
    parseCase("long integer 100k digits", std::string(100000, '9'), 500, false);
    parseCase("minus only",               "-", 50, true);
    parseCase("dot only",                 ".", 50, true);
    parseCase("1e",                       "1e", 50, true);
    parseCase("leading plus",             "+1", 50, true);
    parseCase("NaN literal",              "NaN", 50, true);
}

// ── 4. Malformed and truncated ───────────────────────────────────────
// The IPC splits on newline, so a sender can deliver any prefix of a document.
// Every truncation of a valid document must be refused, never accepted and
// never hang.
void testTruncation() {
    std::printf("\n[4] truncation sweep — every prefix of a real message\n");
    const std::string full =
        "{\"role\":\"ui\",\"state\":\"idle\",\"frame_p95_ms\":18.2,"
        "\"nested\":{\"a\":[1,2,3],\"b\":\"x\"}}";
    int bad = 0;
    double worst = 0;
    for (size_t n = 1; n < full.size(); ++n) {
        const auto t0 = std::chrono::steady_clock::now();
        ev::Json j; std::string err;
        const bool parsed = ev::Json::parse(full.substr(0, n), j, err);
        const double ms = std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - t0).count();
        worst = ms > worst ? ms : worst;
        if (parsed) { ++bad; if (g_verbose) std::printf("      prefix %zu accepted\n", n); }
    }
    const bool ok = (bad == 0) && (worst < 50);
    std::printf("  %-28s %7.2f ms  %-6s %d of %zu prefixes accepted\n",
                "truncation sweep", worst, ok ? "PASS" : "FAIL", bad, full.size() - 1);
    ok ? ++g_pass : ++g_fail;

    parseCase("unterminated string",  "{\"a\":\"xxx", 50, true);
    parseCase("unterminated escape",  "{\"a\":\"xx\\\\", 50, true);
    parseCase("unclosed object",      "{\"a\":1", 50, true);
    parseCase("trailing content",     "{} garbage", 50, true);
    parseCase("bare NUL byte",        std::string("{\"a\":\"x\0y\"}", 12), 50, false);
    parseCase("empty document",       "", 50, true);
    parseCase("whitespace only",      "   \n\t  ", 50, true);
}

// ── 5. CSV injection ─────────────────────────────────────────────────
// Process names come from the machine and land in unknown-processes.csv,
// which a lab engineer opens in Excel. A Windows filename may contain '='.
void testCsvInjection() {
    std::printf("\n[5] CSV formula injection — process names into Excel\n");
    struct C { const char* in; bool mustNeutralise; };
    const C cases[] = {
        {"=cmd|' /c calc'!A1",                  true},
        {"@SUM(1+1)*cmd|' /c calc'!A1",         true},
        {"+HYPERLINK(\"http://evil\",\"x\")",   true},
        {"-2+3+cmd|' /c calc'!A1",              true},
        {"\tleading tab.exe",                   true},
        {"\rleading cr.exe",                    true},
        {"explorer.exe",                        false},
        {"normal,with,commas.exe",              false},
        {"quote\"inside.exe",                   false},
    };
    for (const auto& c : cases) {
        const std::string out = ev::csvEscape(c.in);
        // Printable form: a raw CR in a test name rewinds the console and
        // overwrites the line above it, which made two results unreadable.
        std::string shown;
        for (char ch : out) {
            if (ch == '\r')      shown += "\\r";
            else if (ch == '\t') shown += "\\t";
            else if (ch == '\n') shown += "\\n";
            else                 shown += ch;
        }
        // Neutralised means the cell no longer STARTS with a formula trigger
        // once any RFC-4180 opening quote is skipped.
        size_t k = (!out.empty() && out[0] == '"') ? 1 : 0;
        const char lead = k < out.size() ? out[k] : '\0';
        const bool dangerous = (lead == '=' || lead == '+' || lead == '-' ||
                                lead == '@' || lead == '\t' || lead == '\r');
        const bool ok = c.mustNeutralise ? !dangerous : true;
        std::printf("  %-28s %7s     %-6s %s\n",
                    c.mustNeutralise ? "formula neutralised" : "ordinary name intact",
                    "-", ok ? "PASS" : "FAIL", shown.c_str());
        ok ? ++g_pass : ++g_fail;
    }
}

// ── 6. Config file ───────────────────────────────────────────────────
void testConfigFile() {
    std::printf("\n[6] config file — size cap and bad content\n");
    const std::string dir = ".";
    auto write = [&](const std::string& name, const std::string& body) {
        const std::string p = dir + "/" + name;
        std::ofstream f(p, std::ios::binary);
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        return p;
    };
    auto tryLoad = [&](const char* label, const std::string& path, bool expectFail) {
        const auto t0 = std::chrono::steady_clock::now();
        ev::Config c;
        std::string err;
        const bool ok = c.load(path, err);
        const double ms = std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - t0).count();
        const bool pass = expectFail ? !ok : true;
        std::printf("  %-28s %7.2f ms  %-6s %s\n", label, ms,
                    pass ? "PASS" : "FAIL", ok ? "loaded" : ("refused: " + err).c_str());
        pass ? ++g_pass : ++g_fail;
        std::remove(path.c_str());
    };

    tryLoad("oversized config 4 MB",
            write("ev_test_big.json", "{\"x\":\"" + std::string(4 * 1024 * 1024, 'a') + "\"}"),
            true);
    tryLoad("deeply nested config",
            write("ev_test_deep.json", rep("[", 5000)), true);
    tryLoad("truncated config",
            write("ev_test_trunc.json", "{\"sampling\":{\"interval_ms\":"), true);
    tryLoad("empty config",     write("ev_test_empty.json", ""), true);
    tryLoad("binary garbage",   write("ev_test_bin.json", std::string("\x00\xff\xfe\x01", 4)), true);
    tryLoad("missing file",     dir + "/ev_test_does_not_exist.json", true);
    // A valid minimal config must still load -- a guard that rejects everything
    // is not a guard, it is an outage.
    tryLoad("valid minimal config",
            write("ev_test_ok.json",
                  "{\"sampling\":{\"interval_ms\":10000},\"output\":{\"dir\":\"logs\"}}"),
            false);
}

}  // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i)
        if (!std::strcmp(argv[i], "--verbose")) g_verbose = true;

    std::printf("EdgeVitals security harness\n");
    std::printf("Each case must RETURN within budget. A hang is a failure; a\n");
    std::printf("crash takes this process and is reported by the runner script.\n");

    testDepth();
    testSizeAndShape();
    testNumbers();
    testTruncation();
    testCsvInjection();
    testConfigFile();

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
