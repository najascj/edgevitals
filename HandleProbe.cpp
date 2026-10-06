#include "edgevitals/HandleProbe.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace ev {

// ── tally helpers ───────────────────────────────────────────────────────────

std::uint64_t totalOf(const TypeCounts& c) {
    std::uint64_t t = 0;
    for (const auto& kv : c) t += kv.second;
    return t;
}

std::string formatTally(const TypeCounts& c) {
    std::vector<std::pair<std::string, std::uint64_t>> v(c.begin(), c.end());
    std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out.push_back(',');
        out += v[i].first;
        out.push_back(':');
        out += std::to_string(v[i].second);
    }
    return out;
}

HandleRank rankHandles(const TypeCounts& now, const TypeCounts* prev) {
    HandleRank r;
    // std::map iterates by name ascending; a strict '>' keeps the first name
    // on a tie, so ties resolve alphabetically without a second pass.
    for (const auto& kv : now) {
        if (!r.haveTop || kv.second > r.topCount) {
            r.haveTop = true;
            r.topType = kv.first;
            r.topCount = kv.second;
        }
    }
    if (!prev) return r;

    r.haveGrow = true;
    r.growDelta = 0;
    // A type present now and absent before grew from zero; a type that
    // vanished cannot be the largest increase, so only 'now' is walked.
    for (const auto& kv : now) {
        auto it = prev->find(kv.first);
        const long long before = it == prev->end() ? 0 : static_cast<long long>(it->second);
        const long long d = static_cast<long long>(kv.second) - before;
        if (d > r.growDelta) {
            r.growDelta = d;
            r.growType = kv.first;
        }
    }
    return r;
}

// ── trigger ─────────────────────────────────────────────────────────────────

ProbeTrigger::ProbeTrigger(std::vector<std::string> names, long long delta, double minSeconds)
    : names_(std::move(names)), st_(names_.size()), delta_(delta < 1 ? 1 : delta),
      minSeconds_(minSeconds < 0 ? 0 : minSeconds) {}

void ProbeTrigger::observe(size_t role, bool measured, double count, std::uint64_t identity,
                           double nowSec) {
    if (role >= st_.size()) return;
    RoleState& s = st_[role];
    s.measured = measured;
    if (!measured) return;
    if (!s.haveIdentity || identity != s.identity) {
        // New process set. Everything known belongs to the old one.
        s.identity = identity;
        s.identitySince = nowSec;
        s.haveIdentity = true;
        s.baseline = count;
        s.probedThisIdentity = false;
    } else if (count < s.baseline) {
        s.baseline = count;
    }
    s.count = count;
}

bool ProbeTrigger::due(double nowSec, std::string& reason) const {
    if (everProbed_ && nowSec - lastProbe_ < minSeconds_) return false;
    // Delta first: if a role is both rising and another needs a baseline, the
    // reason recorded should be the one that matters.
    for (size_t i = 0; i < st_.size(); ++i) {
        const RoleState& s = st_[i];
        if (!s.measured || !s.probedThisIdentity) continue;
        const double rise = s.count - s.baseline;
        if (rise >= static_cast<double>(delta_)) {
            reason = "delta " + names_[i] + " +" + std::to_string(static_cast<long long>(rise));
            return true;
        }
    }
    for (size_t i = 0; i < st_.size(); ++i) {
        const RoleState& s = st_[i];
        if (!s.measured || s.probedThisIdentity) continue;
        if (nowSec - s.identitySince >= minSeconds_) {
            reason = "baseline " + names_[i];
            return true;
        }
    }
    return false;
}

void ProbeTrigger::probed(double nowSec, bool ok) {
    everProbed_ = true;
    lastProbe_ = nowSec;
    if (!ok) return;
    for (auto& s : st_) {
        if (!s.measured) continue;
        s.baseline = s.count;
        s.probedThisIdentity = true;
    }
}

// ── NT layouts ──────────────────────────────────────────────────────────────
//
// Little-endian decode by byte, not by cast: no alignment assumption, no
// aliasing question, and the same answer on any host the tests run on.

namespace ntlayout {
namespace {

std::uint64_t rd(const std::uint8_t* p, size_t n) {
    std::uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
    return v;
}

size_t ptrSize(bool ptr64) { return ptr64 ? 8 : 4; }

size_t alignUp(size_t v, size_t a) { return (v + a - 1) / a * a; }

// UNICODE_STRING: USHORT Length, USHORT MaximumLength, [pad], PWSTR Buffer.
size_t unicodeStringSize(bool ptr64) { return ptr64 ? 16 : 8; }

// Upper bounds. Generous against any Windows build seen (Win7 has ~42 object
// types, Win10/11 ~70) but finite, so a garbage count cannot drive a loop.
constexpr std::uint64_t kMaxTypes = 1024;
constexpr size_t kMaxNameChars = 128;

}  // namespace

size_t typeInfoSize(bool ptr64) {
    // UNICODE_STRING, 13 ULONG counters, GENERIC_MAPPING (4 ULONG),
    // ValidAccessMask, SecurityRequired, MaintainHandleCount, TypeIndex,
    // ReservedByte, PoolType, DefaultPagedPoolCharge, DefaultNonPagedPoolCharge.
    // 0x68 on x64, 0x60 on x86.
    return unicodeStringSize(ptr64) + 13 * 4 + 16 + 4 + 4 + 4 + 4 + 4;
}

size_t handleEntrySize(bool ptr64) {
    // Object, UniqueProcessId, HandleValue (pointer-sized each), GrantedAccess,
    // CreatorBackTraceIndex, ObjectTypeIndex, HandleAttributes, Reserved.
    return 3 * ptrSize(ptr64) + 4 + 2 + 2 + 4 + 4;
}

size_t handleHeaderSize(bool ptr64) { return 2 * ptrSize(ptr64); }

bool parseObjectTypes(const std::uint8_t* buf, size_t len, std::uint64_t baseAddr,
                      bool ptr64, IndexMode mode, std::vector<std::string>& byIndex,
                      std::string& err) {
    byIndex.clear();
    const size_t ps = ptrSize(ptr64);
    if (!buf || len < 4) { err = "type buffer too short"; return false; }
    const std::uint64_t n = rd(buf, 4);
    if (n == 0 || n > kMaxTypes) { err = "implausible type count " + std::to_string(n); return false; }

    const size_t tis = typeInfoSize(ptr64);
    const size_t typeIndexOff = unicodeStringSize(ptr64) + 13 * 4 + 16 + 4 + 2;
    size_t off = alignUp(4, ps);

    for (std::uint64_t i = 0; i < n; ++i) {
        if (off > len || len - off < tis) { err = "type entry " + std::to_string(i) + " truncated"; return false; }
        const std::uint8_t* e = buf + off;
        const size_t nameBytes = static_cast<size_t>(rd(e, 2));
        const size_t maxBytes = static_cast<size_t>(rd(e + 2, 2));
        const std::uint64_t namePtr = rd(e + (ptr64 ? 8 : 4), ps);

        if ((nameBytes & 1) || nameBytes > maxBytes) { err = "type name length invalid"; return false; }
        // The entry declares MaximumLength bytes of name storage after its fixed
        // part. All of it must be inside the buffer, not just the bytes read:
        // a buffer that ends inside declared storage is truncated, full stop.
        if (len - off - tis < maxBytes) { err = "type entry " + std::to_string(i) + " name storage truncated"; return false; }
        std::string name;
        if (nameBytes) {
            if (namePtr < baseAddr) { err = "type name outside buffer"; return false; }
            const std::uint64_t nOff = namePtr - baseAddr;
            if (nOff > len || len - nOff < nameBytes) { err = "type name outside buffer"; return false; }
            const size_t chars = (std::min)(nameBytes / 2, kMaxNameChars);
            name.reserve(chars);
            for (size_t c = 0; c < chars; ++c) {
                const std::uint64_t u = rd(buf + nOff + 2 * c, 2);
                const bool ok = (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') ||
                                (u >= '0' && u <= '9') || u == '_';
                name.push_back(ok ? static_cast<char>(u) : '?');
            }
        }

        std::uint64_t index = 0;
        if (mode == IndexMode::Field) {
            index = e[typeIndexOff];
            if (index < 2) { err = "TypeIndex field not populated"; return false; }
        } else {
            index = i + 2;
        }
        if (index >= kMaxTypes + 2) { err = "type index out of range"; return false; }
        if (byIndex.size() <= index) byIndex.resize(static_cast<size_t>(index) + 1);
        if (!byIndex[index].empty()) { err = "duplicate type index " + std::to_string(index); return false; }
        byIndex[index] = name.empty() ? "?" : name;

        // Next entry: past the fixed part AND the name storage, pointer
        // aligned. MaximumLength, not Length -- the kernel reserves the
        // terminator, and getting this wrong shifts every later type by two
        // bytes into nonsense.
        const size_t next = alignUp(off + tis + maxBytes, ps);
        if (next <= off) { err = "type walk did not advance"; return false; }
        off = next;
    }
    return true;
}

bool handleCount(const std::uint8_t* buf, size_t len, bool ptr64, std::uint64_t& n,
                 std::string& err) {
    const size_t hs = handleHeaderSize(ptr64), es = handleEntrySize(ptr64);
    if (!buf || len < hs) { err = "handle buffer too short"; return false; }
    n = rd(buf, ptrSize(ptr64));
    if (n > (len - hs) / es) {
        err = "handle count " + std::to_string(n) + " exceeds buffer";
        return false;
    }
    return true;
}

bool tallyHandles(const std::uint8_t* buf, size_t len, bool ptr64,
                  const std::vector<std::string>& byIndex,
                  const std::unordered_map<std::uint64_t, size_t>& pidToSlot, size_t slots,
                  std::vector<TypeCounts>& out, std::string& err) {
    std::uint64_t n = 0;
    if (!handleCount(buf, len, ptr64, n, err)) return false;
    const size_t hs = handleHeaderSize(ptr64), es = handleEntrySize(ptr64), ps = ptrSize(ptr64);
    const size_t typeOff = 3 * ps + 4 + 2;

    // Counted by numeric index first: the per-handle work is one hash lookup
    // (skipped when the PID repeats, which is the common case -- the table is
    // grouped by process) and one increment. Names are attached once per
    // slot at the end, not 50,000 times.
    std::vector<std::vector<std::uint64_t>> counts(slots);
    std::vector<std::map<std::uint32_t, std::uint64_t>> overflow(slots);
    std::uint64_t lastPid = ~0ull;
    size_t lastSlot = static_cast<size_t>(-1);

    for (std::uint64_t i = 0; i < n; ++i) {
        const std::uint8_t* e = buf + hs + static_cast<size_t>(i) * es;
        const std::uint64_t pid = rd(e + ps, ps);
        if (pid != lastPid) {
            lastPid = pid;
            auto it = pidToSlot.find(pid);
            lastSlot = (it == pidToSlot.end() || it->second >= slots) ? static_cast<size_t>(-1)
                                                                       : it->second;
        }
        if (lastSlot == static_cast<size_t>(-1)) continue;
        const std::uint32_t ti = static_cast<std::uint32_t>(rd(e + typeOff, 2));
        if (ti < byIndex.size() && !byIndex[ti].empty()) {
            auto& v = counts[lastSlot];
            if (v.size() <= ti) v.resize(byIndex.size(), 0);
            ++v[ti];
        } else {
            ++overflow[lastSlot][ti];
        }
    }

    out.assign(slots, TypeCounts{});
    for (size_t s = 0; s < slots; ++s) {
        for (size_t ti = 0; ti < counts[s].size(); ++ti)
            if (counts[s][ti]) out[s][byIndex[ti]] += counts[s][ti];
        for (const auto& kv : overflow[s])
            out[s]["type#" + std::to_string(kv.first)] += kv.second;
    }
    return true;
}

bool findHandleType(const std::uint8_t* buf, size_t len, bool ptr64, std::uint64_t pid,
                    std::uint64_t value, std::uint16_t& typeIndex) {
    std::uint64_t n = 0;
    std::string err;
    if (!handleCount(buf, len, ptr64, n, err)) return false;
    const size_t hs = handleHeaderSize(ptr64), es = handleEntrySize(ptr64), ps = ptrSize(ptr64);
    for (std::uint64_t i = 0; i < n; ++i) {
        const std::uint8_t* e = buf + hs + static_cast<size_t>(i) * es;
        if (rd(e + ps, ps) != pid || rd(e + 2 * ps, ps) != value) continue;
        typeIndex = static_cast<std::uint16_t>(rd(e + 3 * ps + 4 + 2, 2));
        return true;
    }
    return false;
}

}  // namespace ntlayout
}  // namespace ev
