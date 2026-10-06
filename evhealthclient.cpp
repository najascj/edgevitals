// evhealthclient -- speaks the EdgeBastion health contract, for acceptance
// testing on a terminal without EdgeBastion installed.
//
//   evhealthclient [--pipe NAME] [--listen SECONDS] [--repeat N] <json-line>...
//
// Sends each request line, prints the reply and its round-trip latency, then
// (with --listen) prints unsolicited advisories for the given time. --repeat
// sends the requests N times and prints p50/p99 latency.
//
// Exit codes: 0 all replies ok, 1 a reply was ok:false or missing,
// 2 usage, 3 cannot connect (access denied prints as such -- the expected
// result when run by a non-privileged user).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

bool readMessage(HANDLE p, std::string& out, DWORD timeoutMs) {
    out.clear();
    const auto t0 = std::chrono::steady_clock::now();
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(p, nullptr, 0, nullptr, &avail, nullptr)) return false;
        if (avail) break;
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        if (ms >= static_cast<long long>(timeoutMs)) return false;
        Sleep(1);
    }
    char buf[65536];
    for (;;) {
        DWORD got = 0;
        const BOOL ok = ReadFile(p, buf, sizeof(buf), &got, nullptr);
        out.append(buf, got);
        if (ok) break;
        if (GetLastError() != ERROR_MORE_DATA) return false;
    }
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::string pipe = "\\\\.\\pipe\\edgevitals-health";
    int listenSec = 0, repeat = 1;
    std::vector<std::string> reqs;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--pipe") && i + 1 < argc) pipe = argv[++i];
        else if (!std::strcmp(argv[i], "--listen") && i + 1 < argc) listenSec = std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--repeat") && i + 1 < argc) repeat = std::max(1, std::atoi(argv[++i]));
        else reqs.push_back(argv[i]);
    }
    if (reqs.empty() && listenSec == 0) {
        std::fprintf(stderr, "usage: evhealthclient [--pipe NAME] [--listen S] [--repeat N] <json-line>...\n");
        return 2;
    }

    HANDLE p = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 50; ++attempt) {
        p = CreateFileA(pipe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (p != INVALID_HANDLE_VALUE) break;
        const DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED) {
            std::printf("connect: ACCESS DENIED (%s)\n", pipe.c_str());
            return 3;
        }
        if (e != ERROR_PIPE_BUSY) {
            std::printf("connect: error %lu (%s) -- is EdgeVitals running?\n", e, pipe.c_str());
            return 3;
        }
        WaitNamedPipeA(pipe.c_str(), 200);
    }
    if (p == INVALID_HANDLE_VALUE) {
        std::printf("connect: pipe busy\n");
        return 3;
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(p, &mode, nullptr, nullptr);

    int bad = 0;
    std::vector<double> lat;
    for (int r = 0; r < repeat; ++r) {
        for (const auto& q : reqs) {
            const std::string line = q + "\n";
            const auto t0 = std::chrono::steady_clock::now();
            DWORD wrote = 0;
            if (!WriteFile(p, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr)) {
                std::printf("write failed: %lu\n", GetLastError());
                return 1;
            }
            std::string reply;
            // Skip unsolicited advisories that arrive between request and reply.
            for (;;) {
                if (!readMessage(p, reply, 5000)) {
                    std::printf("no reply within 5 s\n");
                    return 1;
                }
                if (reply.find("\"type\":\"advisory\"") == std::string::npos) break;
                std::printf("ADVISORY %s\n", reply.c_str());
            }
            const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
            lat.push_back(ms);
            if (reply.find("\"ok\":true") == std::string::npos) ++bad;
            if (repeat == 1) std::printf("%7.2f ms  %s\n", ms, reply.c_str());
        }
    }
    if (repeat > 1 && !lat.empty()) {
        std::sort(lat.begin(), lat.end());
        const double p50 = lat[lat.size() / 2];
        const double p99 = lat[std::min(lat.size() - 1, lat.size() * 99 / 100)];
        std::printf("%zu requests: p50 %.2f ms, p99 %.2f ms, max %.2f ms, failures %d\n", lat.size(), p50, p99, lat.back(), bad);
    }
    if (listenSec > 0) {
        std::printf("listening %d s for advisories...\n", listenSec);
        const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(listenSec);
        while (std::chrono::steady_clock::now() < end) {
            std::string m;
            if (readMessage(p, m, 500)) std::printf("ADVISORY %s\n", m.c_str());
        }
    }
    CloseHandle(p);
    return bad ? 1 : 0;
}
