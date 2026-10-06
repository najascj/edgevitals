# EdgeVitals 3.2.1-lifecycle — source package

Full source of EdgeVitals 3.2.1-lifecycle (3.0.7 + 3.1.0-handleprobe + 3.2.0-health +
3.2.1-lifecycle),
for building and testing as a standalone project. C++17, Windows SDK, no
third-party libraries. Target: 64-bit Windows 10 and 11.

## Build (Windows, release)

    build.bat

Clean configure and build, static-import check on every executable, then the
four test suites (evsecuritytest must be 46/0, evhandletest 66/0,
evhealthtest 61/0, evlifecycletest 33/0), then prints `agent_version`. Toolchain paths default to
`D:\Qt\Tools\mingw1310_64\bin` and `D:\Qt\Tools\Ninja`; override with
`EV_MINGW` and `EV_NINJA`.

Manual build:

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build

## Build from Linux (cross-compile, as used to verify this package)

    # mingw.cmake
    set(CMAKE_SYSTEM_NAME Windows)
    set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc-posix)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++-posix)
    set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)
    set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=mingw.cmake
    cmake --build build

## Outputs

| Executable | Purpose |
|---|---|
| edgevitals.exe | The agent |
| evsecuritytest.exe | 46 hostile-input cases |
| evhandletest.exe | 66 handle-probe cases |
| evhealthtest.exe | 61 health-model cases (new in 3.2) |
| evhealthclient.exe | Speaks the EdgeBastion health contract (new in 3.2) |
| evlifecycletest.exe | 33 log-lifecycle cases (new in 3.2.1) |
| evverify.exe | Independent chain verifier |

## Quick run (console, from the build folder)

    copy ..\config\edgevitals.json config\edgevitals.json   (or run from the source root)
    edgevitals.exe --version
    edgevitals.exe --once
    edgevitals.exe --console
    evhealthclient.exe "{\"id\":1,\"op\":\"ping\"}" "{\"id\":2,\"op\":\"all_healthy\",\"processes\":[\"EdgeTerminal.exe\"]}"

Run from the folder that contains `config\` and `logs\`: in 3.x the config
path and (in console mode) the log folder are relative to the working
directory. For a service install, always pass an absolute `--config`.

## Configuration

`config/edgevitals.json` is the current configuration: 19 roles (including
`voize` and `transbridge`, whose executable names must be confirmed on a
terminal) and the `health` section. 353 CSV columns.

The health pipe is `\\.\pipe\edgevitals-health`, separate from the metrics pipe
`\\.\pipe\edgevitals`. Access: SYSTEM and `NT SERVICE\EdgeBastion` (fails closed to
SYSTEM if that account does not exist). To query it from a console session in the
lab, add your account to `health.allowed_accounts` temporarily.

EdgeTerminal heartbeat (required for hang detection as a service):
`{"hb":1,"role":"ui"}` every 5 s on the metrics pipe.

## Log lifecycle (3.2.1)

All three streams -- telemetry CSV, agent log, discovery CSV -- are daily files,
each with a SHA-256 chain sidecar (`<file>.chain`), sealed at midnight cutover and
on shutdown. Files older than `archive_after_days` (7) are compressed to ZIP; the
`.chain` stays beside the `.zip`. Files older than `retention_days` (180) are
deleted together with their sidecar. Housekeeping runs at start-up and at every
cutover. To verify an archived day: extract the file next to its `.chain` and run
`evverify <file>` (exit 0 = verified, 1 = altered).

## Tools

`tools/evpatch.cpp` — anchored patcher used to deliver drops. Not part of the
agent build.

## Integrity

`MANIFEST.sha256` lists the SHA-256 of every file in this package.
