// EdgeVitals handle-probe tests.
//
//     evhandletest            run everything, print a pass/fail table
//
// Covers the platform-neutral half of the probe: ranking, the trigger, and
// parsing of the Windows NT buffer layouts. The layouts are exercised on
// SYNTHETIC buffers built here, in both pointer widths, so the walk rules
// (pointer alignment, MaximumLength not Length, absolute name pointers) are
// checked on any host -- and on adversarial buffers, because this parser
// reads data shaped by the kernel and a bad walk is an out-of-bounds read.
//
// Kept separate from evsecuritytest so that harness stays at its declared
// 46 cases. Like it, this is meant to be runnable on the ATM.
//
// What this does NOT cover: the live ntdll calls and the index mapping on
// real Windows. Those are checked at runtime by the agent's own self-check
// and can only be accepted on hardware.
#include "edgevitals/HandleProbe.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace ev;
using ev::ntlayout::IndexMode;

namespace {

int g_pass = 0, g_fail = 0;

void check(const char* name, bool ok, const std::string& detail = std::string()) {
    std::printf("  %-52s %s%s%s\n", name, ok ? "PASS" : "FAIL", detail.empty() ? "" : "   ",
                detail.c_str());
    (ok ? g_pass : g_fail)++;
}

size_t alignUp(size_t v, size_t a) { return (v + a - 1) / a * a; }

void put(std::vector<std::uint8_t>& b, size_t off, std::uint64_t v, size_t n) {
    if (b.size() < off + n) b.resize(off + n, 0);
    for (size_t i = 0; i < n; ++i) b[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
}

// Builds an OBJECT_TYPES_INFORMATION buffer the way the kernel lays it out:
// name storage directly after each fixed entry, MaximumLength = Length + 2,
// next entry pointer-aligned. fieldIndex[i] goes into TypeIndex.
std::vector<std::uint8_t> makeTypes(const std::vector<std::string>& names, bool ptr64,
                                    std::uint64_t base, const std::vector<int>& fieldIndex,
                                    size_t* dataEnd = nullptr) {
    const size_t ps = ptr64 ? 8 : 4;
    const size_t us = ptr64 ? 16 : 8;
    const size_t tis = ntlayout::typeInfoSize(ptr64);
    std::vector<std::uint8_t> b;
    put(b, 0, names.size(), 4);
    size_t off = alignUp(4, ps);
    for (size_t i = 0; i < names.size(); ++i) {
        const size_t len = names[i].size() * 2, max = len + 2;
        put(b, off, len, 2);
        put(b, off + 2, max, 2);
        put(b, off + (ptr64 ? 8 : 4), base + off + tis, ps);
        put(b, off + us + 13 * 4 + 16 + 4 + 2, static_cast<std::uint64_t>(fieldIndex[i]), 1);
        for (size_t c = 0; c < names[i].size(); ++c)
            put(b, off + tis + 2 * c, static_cast<unsigned char>(names[i][c]), 2);
        put(b, off + tis + len, 0, 2);
        if (dataEnd) *dataEnd = off + tis + max;
        off = alignUp(off + tis + max, ps);
    }
    b.resize(off, 0);
    return b;
}

struct Entry { std::uint64_t pid, value; std::uint16_t type; };

std::vector<std::uint8_t> makeHandles(const std::vector<Entry>& es, bool ptr64) {
    const size_t ps = ptr64 ? 8 : 4;
    const size_t hs = ntlayout::handleHeaderSize(ptr64), esz = ntlayout::handleEntrySize(ptr64);
    std::vector<std::uint8_t> b(hs + es.size() * esz, 0);
    put(b, 0, es.size(), ps);
    for (size_t i = 0; i < es.size(); ++i) {
        const size_t o = hs + i * esz;
        put(b, o, 0xFFFF800000001000ull + i, ps);  // Object: never read
        put(b, o + ps, es[i].pid, ps);
        put(b, o + 2 * ps, es[i].value, ps);
        put(b, o + 3 * ps + 4 + 2, es[i].type, 2);
    }
    return b;
}

// Deterministic, so a failure reproduces.
struct Rng {
    std::uint64_t s;
    std::uint64_t next() {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        return s;
    }
};

const std::vector<std::string> kNames = {"Type", "Directory", "Event", "Semaphore", "Key", "Thread"};
// Position+2 indexes for kNames: Type=2 ... Thread=7.

// ── ranking ─────────────────────────────────────────────────────────────────

void testRanking() {
    std::printf("\nranking\n");
    TypeCounts now{{"Event", 612}, {"Key", 291}, {"Thread", 40}};
    HandleRank r = rankHandles(now, nullptr);
    check("top is the largest count", r.haveTop && r.topType == "Event" && r.topCount == 612);
    check("no previous -> growth stays empty", !r.haveGrow && r.growType.empty());

    TypeCounts prev{{"Event", 600}, {"Key", 104}, {"Thread", 40}};
    r = rankHandles(now, &prev);
    check("growth picks the largest INCREASE, not the largest count",
          r.haveGrow && r.growType == "Key" && r.growDelta == 187 && r.topType == "Event");

    TypeCounts withNew{{"Event", 600}, {"Section", 50}};
    TypeCounts before{{"Event", 600}};
    r = rankHandles(withNew, &before);
    check("a type absent before grew from zero", r.growType == "Section" && r.growDelta == 50);

    TypeCounts shrank{{"Event", 500}, {"Key", 100}};
    r = rankHandles(shrank, &prev);
    check("nothing grew -> measured zero, empty type",
          r.haveGrow && r.growType.empty() && r.growDelta == 0);

    TypeCounts tie{{"Mutant", 10}, {"Event", 10}};
    r = rankHandles(tie, nullptr);
    check("count tie breaks by name", r.topType == "Event");

    TypeCounts g1{{"Key", 5}, {"Event", 5}};
    r = rankHandles(g1, &before);  // Event 600 -> 5 is a drop; Key 0 -> 5
    check("growth ignores drops", r.growType == "Key" && r.growDelta == 5);

    check("empty tally has no top", !rankHandles(TypeCounts{}, nullptr).haveTop);
    check("format: count desc then name",
          formatTally(TypeCounts{{"b", 2}, {"a", 2}, {"c", 9}}) == "c:9,a:2,b:2");
    check("total", totalOf(now) == 943);
}

// ── trigger ─────────────────────────────────────────────────────────────────

void testTrigger() {
    std::printf("\ntrigger\n");
    std::string why;
    {
        ProbeTrigger t({"ui"}, 200, 300);
        t.observe(0, true, 1000, 7, 0);
        check("baseline waits for a stable process set", !t.due(10, why));
        t.observe(0, true, 1000, 7, 299);
        check("still waiting at 299 s", !t.due(299, why));
        t.observe(0, true, 1000, 7, 300);
        check("baseline due at min_seconds", t.due(300, why) && why == "baseline ui");
        t.probed(300, true);
        t.observe(0, true, 1150, 7, 900);
        check("rise below delta does not fire", !t.due(900, why));
        t.observe(0, true, 1200, 7, 910);
        check("rise of exactly delta fires", t.due(910, why) && why == "delta ui +200");
        t.probed(910, true);
        t.observe(0, true, 1450, 7, 1000);
        check("min spacing holds even with a large rise", !t.due(1000, why));
        check("and releases after min_seconds", t.due(1210, why));
    }
    {
        ProbeTrigger t({"ui"}, 200, 300);
        t.observe(0, true, 1000, 1, 0);
        t.probed(400, true);  // baseline 1000
        t.observe(0, true, 400, 1, 800);   // drop: baseline follows to 400
        t.observe(0, true, 650, 1, 900);   // +250 from the low point
        check("baseline follows drops", t.due(900, why) && why == "delta ui +250");
    }
    {
        ProbeTrigger t({"ui"}, 200, 300);
        t.observe(0, true, 1000, 1, 0);
        t.probed(400, true);
        t.observe(0, true, 5000, 2, 800);  // restart with a big count
        check("process-set change does not fire delta", !t.due(800, why));
        t.observe(0, true, 5000, 2, 1100);
        check("it re-baselines once the new set is stable", t.due(1100, why) && why == "baseline ui");
    }
    {
        ProbeTrigger t({"ui"}, 200, 300);
        t.observe(0, true, 1000, 1, 0);
        t.probed(300, true);
        t.observe(0, true, 1300, 1, 700);
        t.observe(0, false, 0, 0, 710);
        check("unmeasured tick never fires", !t.due(710, why));
        t.observe(0, true, 1300, 1, 720);
        check("state survives an unmeasured tick", t.due(720, why));
        t.probed(720, false);
        check("failed probe still counts against spacing", !t.due(800, why));
        check("failed probe does not rebase", t.due(1020, why) && why == "delta ui +300");
    }
    {
        ProbeTrigger t({"ui", "xfs"}, 200, 300);
        t.observe(0, true, 100, 1, 0);
        t.observe(1, true, 100, 9, 0);
        t.probed(300, true);
        t.observe(0, true, 100, 1, 700);
        t.observe(1, true, 400, 9, 700);
        check("second role's rise is named in the reason", t.due(700, why) && why == "delta xfs +300");
    }
}

// ── layouts ─────────────────────────────────────────────────────────────────

void testSizes() {
    std::printf("\nlayout sizes (against the documented Windows structures)\n");
    check("OBJECT_TYPE_INFORMATION x64 = 0x68", ntlayout::typeInfoSize(true) == 0x68);
    check("OBJECT_TYPE_INFORMATION x86 = 0x60", ntlayout::typeInfoSize(false) == 0x60);
    check("SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX x64 = 40", ntlayout::handleEntrySize(true) == 40);
    check("SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX x86 = 28", ntlayout::handleEntrySize(false) == 28);
    check("SYSTEM_HANDLE_INFORMATION_EX header x64 = 16", ntlayout::handleHeaderSize(true) == 16);
}

void testTypes(bool ptr64) {
    const char* w = ptr64 ? "x64" : "x86";
    std::printf("\nobject types, %s\n", w);
    const std::uint64_t base = ptr64 ? 0x000001A2B3C40000ull : 0x00C40000ull;
    const std::vector<int> field = {2, 3, 4, 5, 6, 7};
    size_t dataEnd = 0;
    auto buf = makeTypes(kNames, ptr64, base, field, &dataEnd);

    std::vector<std::string> t;
    std::string err;
    bool ok = ntlayout::parseObjectTypes(buf.data(), buf.size(), base, ptr64, IndexMode::Field, t, err);
    check("field mapping parses", ok && t.size() == 8 && t[4] == "Event" && t[5] == "Semaphore", err);
    ok = ntlayout::parseObjectTypes(buf.data(), buf.size(), base, ptr64, IndexMode::PositionPlus2, t, err);
    check("position+2 mapping parses", ok && t[2] == "Type" && t[7] == "Thread", err);

    // Pre-8.1: TypeIndex reserved (zero). Field mode must refuse, not map
    // everything to index 0.
    auto zero = makeTypes(kNames, ptr64, base, std::vector<int>(kNames.size(), 0));
    check("field mode refuses an unpopulated TypeIndex",
          !ntlayout::parseObjectTypes(zero.data(), zero.size(), base, ptr64, IndexMode::Field, t, err));

    auto dup = makeTypes(kNames, ptr64, base, {2, 3, 4, 4, 6, 7});
    check("duplicate index refused",
          !ntlayout::parseObjectTypes(dup.data(), dup.size(), base, ptr64, IndexMode::Field, t, err));

    check("wrong base address -> names outside buffer, refused",
          !ntlayout::parseObjectTypes(buf.data(), buf.size(), base + 0x100000, ptr64,
                                      IndexMode::Field, t, err));

    auto hostile = makeTypes({"Ev\x01nt;rm"}, ptr64, base, {2});
    ok = ntlayout::parseObjectTypes(hostile.data(), hostile.size(), base, ptr64, IndexMode::Field, t, err);
    check("non-identifier characters reduced to '?'", ok && t[2] == "Ev?nt?rm", ok ? t[2] : err);

    // Every cut into declared data must be a clean refusal. Only the last
    // entry's trailing ALIGNMENT PADDING may be absent -- nothing is read there.
    int crashedOrAccepted = 0;
    for (size_t n = 0; n < dataEnd; ++n) {
        std::vector<std::uint8_t> cut(buf.begin(), buf.begin() + static_cast<long>(n));
        if (ntlayout::parseObjectTypes(cut.empty() ? nullptr : cut.data(), n, base, ptr64,
                                       IndexMode::Field, t, err))
            ++crashedOrAccepted;
    }
    check("every cut into declared data refused", crashedOrAccepted == 0,
          std::to_string(dataEnd) + " lengths tried");

    std::vector<std::uint8_t> huge(64, 0);
    put(huge, 0, 0xFFFFFFFFull, 4);
    check("absurd type count refused",
          !ntlayout::parseObjectTypes(huge.data(), huge.size(), base, ptr64, IndexMode::Field, t, err));
}

void testHandles(bool ptr64) {
    const char* w = ptr64 ? "x64" : "x86";
    std::printf("\nhandle table, %s\n", w);
    std::vector<std::string> byIndex = {"", "", "Type", "Directory", "Event", "Semaphore", "Key", "Thread"};
    std::vector<Entry> es = {
        {4, 0x4, 7}, {4, 0x8, 4},                          // System: not tracked
        {100, 0x10, 4}, {100, 0x14, 4}, {100, 0x18, 6},     // ui
        {200, 0x20, 4},                                     // xfs instance 1
        {201, 0x24, 6}, {201, 0x28, 99},                    // xfs instance 2, unknown type 99
        {100, 0x2C, 4},                                     // ui again, non-contiguous
    };
    auto buf = makeHandles(es, ptr64);
    std::unordered_map<std::uint64_t, size_t> slots = {{100, 0}, {200, 1}, {201, 1}};
    std::vector<TypeCounts> out;
    std::string err;
    const bool ok = ntlayout::tallyHandles(buf.data(), buf.size(), ptr64, byIndex, slots, 2, out, err);
    check("tally parses", ok, err);
    check("ui counted by type", ok && out[0]["Event"] == 3 && out[0]["Key"] == 1 && totalOf(out[0]) == 4);
    check("role sums across its PIDs", ok && out[1]["Event"] == 1 && out[1]["Key"] == 1);
    check("unknown index kept as type#N, not dropped", ok && out[1]["type#99"] == 1 && totalOf(out[1]) == 3);

    std::uint16_t ti = 0;
    check("find own handle", ntlayout::findHandleType(buf.data(), buf.size(), ptr64, 201, 0x28, ti) && ti == 99);
    check("find misses cleanly", !ntlayout::findHandleType(buf.data(), buf.size(), ptr64, 201, 0x99, ti));

    auto lie = buf;
    put(lie, 0, 1000000, ptr64 ? 8 : 4);
    check("count larger than buffer refused",
          !ntlayout::tallyHandles(lie.data(), lie.size(), ptr64, byIndex, slots, 2, out, err), err);

    int accepted = 0;
    for (size_t n = 0; n < buf.size(); ++n)
        if (ntlayout::tallyHandles(n ? buf.data() : nullptr, n, ptr64, byIndex, slots, 2, out, err))
            ++accepted;
    check("every truncation refused", accepted == 0, std::to_string(buf.size()) + " lengths tried");

    std::unordered_map<std::uint64_t, size_t> badSlot = {{100, 7}};
    check("slot index beyond slots is ignored, not written",
          ntlayout::tallyHandles(buf.data(), buf.size(), ptr64, byIndex, badSlot, 2, out, err) &&
              totalOf(out[0]) == 0 && totalOf(out[1]) == 0);
}

void testFuzz() {
    std::printf("\nfuzz\n");
    Rng r{0x5EED0FED17A15ull};
    const auto t0 = std::chrono::steady_clock::now();
    std::vector<std::string> t;
    std::vector<TypeCounts> out;
    std::string err;
    std::unordered_map<std::uint64_t, size_t> slots = {{1, 0}, {2, 0}};
    long parsed = 0;
    for (int i = 0; i < 20000; ++i) {
        const size_t n = static_cast<size_t>(r.next() % 4096);
        std::vector<std::uint8_t> b(n);
        for (auto& c : b) c = static_cast<std::uint8_t>(r.next());
        // Small counts sometimes, so the walk gets past the header check.
        if (n >= 8 && (i & 1)) put(b, 0, r.next() % 40, 4);
        const bool p64 = (i & 2) != 0;
        const std::uint64_t base = r.next() & 0xFFFFFFFFFFF0ull;
        parsed += ntlayout::parseObjectTypes(n ? b.data() : nullptr, n, base, p64,
                                             (i & 4) ? IndexMode::Field : IndexMode::PositionPlus2, t, err);
        ntlayout::tallyHandles(n ? b.data() : nullptr, n, p64, {"", "", "A"}, slots, 1, out, err);
    }
    const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    check("20,000 random buffers: no crash, bounded time", ms < 5000,
          std::to_string(static_cast<long>(ms)) + " ms, " + std::to_string(parsed) + " parsed");
}

void testCost() {
    std::printf("\ncost (host CPU, indicative only)\n");
    std::vector<std::string> byIndex(70);
    for (size_t i = 2; i < byIndex.size(); ++i) byIndex[i] = "T" + std::to_string(i);
    std::vector<Entry> es;
    Rng r{42};
    for (std::uint64_t pid = 4; es.size() < 50000; pid += 4)
        for (int k = 0; k < 400 && es.size() < 50000; ++k)
            es.push_back({pid, static_cast<std::uint64_t>(k * 4), static_cast<std::uint16_t>(2 + r.next() % 68)});
    auto buf = makeHandles(es, true);
    std::unordered_map<std::uint64_t, size_t> slots = {{40, 0}, {44, 1}};
    std::vector<TypeCounts> out;
    std::string err;
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = ntlayout::tallyHandles(buf.data(), buf.size(), true, byIndex, slots, 2, out, err);
    const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    char d[96];
    std::snprintf(d, sizeof(d), "%.2f ms for 50,000 entries, %zu KB buffer", ms, buf.size() / 1024);
    check("tally of a 50k-entry table under 5 ms", ok && ms < 5.0 && totalOf(out[0]) == 400, d);
}

}  // namespace

int main() {
    std::printf("EdgeVitals handle-probe tests\n");
    testRanking();
    testTrigger();
    testSizes();
    testTypes(true);
    testTypes(false);
    testHandles(true);
    testHandles(false);
    testFuzz();
    testCost();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
