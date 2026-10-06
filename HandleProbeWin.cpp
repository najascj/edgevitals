// Windows handle source for the handle-type probe.
//
// Mechanism: NtQuerySystemInformation(SystemExtendedHandleInformation) -- the
// call Process Explorer and handle.exe make -- returns every handle on the
// machine with its owning PID and an ObjectTypeIndex. NtQueryObject(
// ObjectTypesInformation), called ONCE here at construction, maps those
// indexes to names. Per probe the work is one snapshot and a tally.
//
// Both are resolved from ntdll with GetProcAddress. They are semi-documented
// ("may be altered or unavailable in future versions"); that is acceptable
// because the use is read-only, a snapshot, changes nothing, and every failure
// path ends in available() == false and one log line -- never in the agent
// failing to start.
//
// WHAT THIS DELIBERATELY DOES NOT DO
//   - It never calls NtQueryObject(ObjectNameInformation). Per-handle name
//     queries can block indefinitely on some object types (the known hang in
//     naive handle tools), and would put file and registry paths into
//     telemetry that currently contains none.
//   - It never opens, duplicates or closes another process's handle.
//   - The Object field (a kernel address) is never read, stored or logged.
//
// SELF-CHECK. A wrong index-to-name mapping does not fail -- it produces
// plausible wrong names, which is the worst outcome this feature can have.
// So at construction the source creates one Event and one Semaphore of its
// own, finds them in a real snapshot by (own PID, handle value), and accepts
// a mapping only if both resolve to the right names. Two distinct types, so a
// constant offset error cannot pass by coincidence. Both candidate mappings
// are tried (TypeIndex field on 8.1+, position+2 before it) rather than
// choosing by OS version. The same check proves the agent's token -- console
// or the restricted service token -- can actually read the table.
#include "edgevitals/HandleProbe.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ev {
namespace {

using NtStatus = LONG;
using NtQuerySystemInformationFn = NtStatus(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObjectFn = NtStatus(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

constexpr ULONG kSystemExtendedHandleInformation = 64;
constexpr ULONG kObjectTypesInformation = 3;
constexpr NtStatus kStatusInfoLengthMismatch = static_cast<NtStatus>(0xC0000004L);
constexpr NtStatus kStatusBufferTooSmall = static_cast<NtStatus>(0xC0000023L);
constexpr NtStatus kStatusBufferOverflow = static_cast<NtStatus>(0x80000005L);

bool isSizeError(NtStatus s) {
    return s == kStatusInfoLengthMismatch || s == kStatusBufferTooSmall ||
           s == kStatusBufferOverflow;
}

std::string hex32(NtStatus s) {
    char b[16];
    std::snprintf(b, sizeof(b), "0x%08lX", static_cast<unsigned long>(s));
    return b;
}

// VirtualAlloc, not the heap. A heap would usually return a block this large
// to the OS on free, but "usually" is allocator behaviour; MEM_RELEASE is a
// guarantee, and the self-budget is the point. Also page-aligned, which the
// type-walk alignment rule relies on (offsets and addresses align together).
class PageBuffer {
public:
    PageBuffer() = default;
    ~PageBuffer() { release(); }
    PageBuffer(const PageBuffer&) = delete;
    PageBuffer& operator=(const PageBuffer&) = delete;

    bool allocate(size_t bytes) {
        release();
        p_ = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        size_ = p_ ? bytes : 0;
        return p_ != nullptr;
    }
    void release() {
        if (p_) VirtualFree(p_, 0, MEM_RELEASE);
        p_ = nullptr;
        size_ = 0;
    }
    std::uint8_t* data() const { return static_cast<std::uint8_t*>(p_); }
    size_t size() const { return size_; }

private:
    void* p_ = nullptr;
    size_t size_ = 0;
};

// Closes on scope exit. The self-check must not leave its two handles behind:
// a handle-counting feature that leaks handles discredits itself.
struct ScopedHandle {
    HANDLE h = nullptr;
    explicit ScopedHandle(HANDLE v) : h(v) {}
    ~ScopedHandle() { if (h) CloseHandle(h); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
};

class Win32HandleSource : public IHandleSource {
public:
    explicit Win32HandleSource(const HandleSourceOptions& o) {
        capBytes_ = static_cast<size_t>(o.maxMb > 0 ? o.maxMb : 1) * 1048576u;
        init();
    }

    bool available() const override { return available_; }
    const std::string& status() const override { return status_; }

    bool snapshot(const std::unordered_map<std::uint64_t, size_t>& pidToSlot, size_t slots,
                  std::vector<TypeCounts>& out, Stats& stats, std::string& err) override {
        if (!available_) { err = status_; return false; }
        const auto t0 = std::chrono::steady_clock::now();
        PageBuffer buf;
        size_t used = 0;
        if (!readHandleTable(buf, used, err)) return false;
        stats.bufferBytes = buf.size();
        std::uint64_t n = 0;
        if (!ntlayout::handleCount(buf.data(), used, kPtr64, n, err)) return false;
        stats.entries = n;
        const bool ok = ntlayout::tallyHandles(buf.data(), used, kPtr64, byIndex_, pidToSlot,
                                               slots, out, err);
        buf.release();  // before the clock stops: the release is part of the cost
        stats.costMs = std::chrono::duration<double, std::milli>(
                           std::chrono::steady_clock::now() - t0).count();
        return ok;
    }

private:
    static constexpr bool kPtr64 = sizeof(void*) == 8;
    static constexpr int kMaxAttempts = 5;

    void init() {
        status_ = "disabled: not initialised";
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");  // always mapped; no load, no search path
        if (!nt) { status_ = "disabled: ntdll.dll not mapped"; return; }
        qsi_ = reinterpret_cast<NtQuerySystemInformationFn>(
            reinterpret_cast<void*>(GetProcAddress(nt, "NtQuerySystemInformation")));
        qo_ = reinterpret_cast<NtQueryObjectFn>(
            reinterpret_cast<void*>(GetProcAddress(nt, "NtQueryObject")));
        if (!qsi_ || !qo_) {
            status_ = "disabled: ntdll does not export NtQuerySystemInformation/NtQueryObject";
            return;
        }

        // ── type table, once ──
        PageBuffer types;
        ULONG size = 64 * 1024, ret = 0;
        NtStatus s = kStatusInfoLengthMismatch;
        for (int i = 0; i < kMaxAttempts; ++i) {
            if (size > 1024u * 1024u) break;  // the real table is ~10 KB
            if (!types.allocate(size)) { status_ = "disabled: cannot allocate type table"; return; }
            ret = 0;
            s = qo_(nullptr, kObjectTypesInformation, types.data(), size, &ret);
            if (!isSizeError(s)) break;
            size = (ret > size ? ret : size * 2) + 4096;
        }
        if (s < 0) { status_ = "disabled: NtQueryObject(ObjectTypesInformation) " + hex32(s); return; }

        const std::uint64_t base = reinterpret_cast<std::uintptr_t>(types.data());
        std::vector<std::string> byField, byPos;
        std::string errField, errPos;
        const bool okField = ntlayout::parseObjectTypes(types.data(), types.size(), base, kPtr64,
                                                        ntlayout::IndexMode::Field, byField, errField);
        const bool okPos = ntlayout::parseObjectTypes(types.data(), types.size(), base, kPtr64,
                                                      ntlayout::IndexMode::PositionPlus2, byPos, errPos);
        types.release();
        if (!okField && !okPos) {
            status_ = "disabled: type table unparseable (field: " + errField + "; position: " + errPos + ")";
            return;
        }

        // ── self-check against handles of known type ──
        ScopedHandle ev(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        ScopedHandle sem(CreateSemaphoreW(nullptr, 0, 1, nullptr));
        if (!ev.h || !sem.h) { status_ = "disabled: self-check could not create test objects"; return; }

        PageBuffer table;
        size_t used = 0;
        std::string err;
        if (!readHandleTable(table, used, err)) { status_ = "disabled: " + err; return; }
        const std::uint64_t self = GetCurrentProcessId();
        std::uint16_t tiEv = 0, tiSem = 0;
        const bool foundEv = ntlayout::findHandleType(table.data(), used, kPtr64, self,
                                                      reinterpret_cast<std::uintptr_t>(ev.h), tiEv);
        const bool foundSem = ntlayout::findHandleType(table.data(), used, kPtr64, self,
                                                       reinterpret_cast<std::uintptr_t>(sem.h), tiSem);
        lastSnapshotBytes_ = table.size();
        table.release();
        if (!foundEv || !foundSem) {
            status_ = "disabled: self-check could not find its own handles in the snapshot "
                      "(token cannot see the handle table?)";
            return;
        }

        auto resolves = [&](const std::vector<std::string>& t) {
            return tiEv < t.size() && tiSem < t.size() && t[tiEv] == "Event" &&
                   t[tiSem] == "Semaphore";
        };
        if (okField && resolves(byField)) {
            byIndex_ = std::move(byField);
            mode_ = "typeindex-field";
        } else if (okPos && resolves(byPos)) {
            byIndex_ = std::move(byPos);
            mode_ = "position+2";
        } else {
            status_ = "disabled: self-check failed -- own Event resolved to index " +
                      std::to_string(tiEv) + ", Semaphore to " + std::to_string(tiSem) +
                      ", and neither mapping names them correctly. Refusing to report "
                      "type names that may be wrong.";
            return;
        }

        size_t named = 0;
        for (const auto& n : byIndex_) if (!n.empty()) ++named;
        available_ = true;
        status_ = "ok: " + std::to_string(named) + " object types, mapping " + mode_ +
                  ", self-check Event/Semaphore passed, first snapshot " +
                  std::to_string(lastSnapshotBytes_ / 1024) + " KB, cap " +
                  std::to_string(capBytes_ / 1048576) + " MB";
    }

    // Reads the whole-machine handle table into buf. Grows on a size error,
    // bounded both by attempt count and by the cap. The table changes between
    // calls, so the size the kernel reports is a floor, not an answer: grow
    // past it with headroom.
    bool readHandleTable(PageBuffer& buf, size_t& used, std::string& err) {
        size_t size = lastSnapshotBytes_ ? lastSnapshotBytes_ : 512u * 1024u;
        if (size > capBytes_) size = capBytes_;
        for (int i = 0; i < kMaxAttempts; ++i) {
            if (!buf.allocate(size)) {
                err = "VirtualAlloc of " + std::to_string(size / 1024) + " KB failed";
                return false;
            }
            ULONG ret = 0;
            const NtStatus s = qsi_(kSystemExtendedHandleInformation, buf.data(),
                                    static_cast<ULONG>(size), &ret);
            if (s >= 0) {
                used = (ret && ret <= size) ? ret : size;
                lastSnapshotBytes_ = size;
                return true;
            }
            if (!isSizeError(s)) {
                buf.release();
                err = "NtQuerySystemInformation " + hex32(s);
                return false;
            }
            size_t want = (static_cast<size_t>(ret) > size ? static_cast<size_t>(ret) : size) ;
            want = want + want / 4 + 64 * 1024;
            buf.release();
            if (want > capBytes_) {
                err = "handle table needs " + std::to_string(want / 1024) +
                      " KB, over the handle_probe_max_mb cap of " +
                      std::to_string(capBytes_ / 1048576) + " MB -- snapshot refused";
                return false;
            }
            size = want;
        }
        err = "handle table kept growing across " + std::to_string(kMaxAttempts) + " attempts";
        return false;
    }

    NtQuerySystemInformationFn qsi_ = nullptr;
    NtQueryObjectFn qo_ = nullptr;
    std::vector<std::string> byIndex_;
    std::string mode_;
    std::string status_;
    bool available_ = false;
    size_t capBytes_ = 0;
    size_t lastSnapshotBytes_ = 0;
};

}  // namespace

std::unique_ptr<IHandleSource> makePlatformHandleSource(const HandleSourceOptions& o) {
    return std::unique_ptr<IHandleSource>(new Win32HandleSource(o));
}

}  // namespace ev
