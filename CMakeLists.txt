cmake_minimum_required(VERSION 3.16)
project(EdgeVitals VERSION 3.2.1 LANGUAGES CXX)

# Standalone by design. No Qt, no vcpkg, no third-party anything -- this
# installs as a service on a locked-down ATM, and every DLL it does not need
# is one fewer thing to justify to a bank.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Platform-independent core. Split out so the logic that actually carries the
# bugs -- date arithmetic in retention, CSV quoting, config parsing -- can be
# tested on any host instead of only on a terminal.
add_library(edgevitals_core STATIC
    src/Json.cpp
    src/Row.cpp
    src/CsvSink.cpp
    src/Config.cpp
    src/Archive.cpp
    src/Digest.cpp
    src/FileLogger.cpp
    src/SelfCheck.cpp
    src/HandleProbe.cpp
    src/Health.cpp
    src/ChainedFile.cpp
)
target_include_directories(edgevitals_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
    target_compile_options(edgevitals_core PRIVATE /W4)
else()
    target_compile_options(edgevitals_core PRIVATE -Wall -Wextra)
endif()

if(WIN32)
    add_executable(edgevitals
        src/main.cpp
        src/Agent.cpp
        src/ProcessSampler.cpp
        src/SystemSampler.cpp
        src/IpcServer.cpp
        src/HandleProbeWin.cpp
        src/HealthServerWin.cpp
    )
    # wintrust + crypt32 for the Authenticode self-check.
    target_link_libraries(edgevitals PRIVATE edgevitals_core psapi advapi32 wintrust crypt32)

    if(MINGW)
        # Static runtime so the service has no MinGW DLL dependency. An ATM
        # image should not need libstdc++-6.dll placed next to a service exe.
        target_link_options(edgevitals PRIVATE
            -static -static-libgcc -static-libstdc++)
    endif()

    if(MSVC)
        target_compile_options(edgevitals PRIVATE /W4)
    else()
        target_compile_options(edgevitals PRIVATE -Wall -Wextra)
    endif()

    # Windows 7 SP1 floor, matching EdgeTerminal.
    target_compile_definitions(edgevitals PRIVATE
        _WIN32_WINNT=0x0601 WINVER=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)

    add_custom_command(TARGET edgevitals POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/config
                $<TARGET_FILE_DIR:edgevitals>/config
        COMMENT "Copying EdgeVitals config next to the exe")
else()
    message(STATUS "EdgeVitals: non-Windows host -- building core + tests only.")
endif()

enable_testing()
# test_core.cpp was not present in the 20 Sep source archive; guard the
# target so a fresh checkout configures cleanly either way.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_core.cpp)
    add_executable(edgevitals_tests tests/test_core.cpp)
    target_link_libraries(edgevitals_tests PRIVATE edgevitals_core)
    add_test(NAME core COMMAND edgevitals_tests)
endif()

# Security harness. Separate binary from the core tests on purpose: it is
# meant to be copied to the ATM and run there as acceptance, not only in CI.
add_executable(evsecuritytest tests/test_security.cpp)
target_link_libraries(evsecuritytest PRIVATE edgevitals_core)
add_test(NAME security COMMAND evsecuritytest)

# Chain verifier. Ships alongside the agent and also runs on the analyst's
# workstation and at the EdgeSentinel ingest boundary -- evidence a third
# party cannot check independently is not evidence.
add_executable(evverify tests/evverify.cpp)
target_link_libraries(evverify PRIVATE edgevitals_core)

# Handle-probe tests: ranking, trigger, and the NT buffer layouts on synthetic
# and adversarial buffers. Separate from evsecuritytest so that one stays at
# its declared case count.
add_executable(evhandletest tests/test_handles.cpp)
target_link_libraries(evhandletest PRIVATE edgevitals_core)
add_test(NAME handles COMMAND evhandletest)

# Health model: hysteresis, thresholds, trends, the EdgeBastion contract.
add_executable(evhealthtest tests/test_health.cpp)
target_link_libraries(evhealthtest PRIVATE edgevitals_core)
add_test(NAME health COMMAND evhealthtest)

# Log lifecycle: daily rotation, seal at cutover, archive, retention, all streams.
add_executable(evlifecycletest tests/test_lifecycle.cpp)
target_link_libraries(evlifecycletest PRIVATE edgevitals_core)
add_test(NAME lifecycle COMMAND evlifecycletest)

# Acceptance tool: speaks the health contract on a terminal without
# EdgeBastion. Windows only (named pipes).
if(WIN32)
    add_executable(evhealthclient tests/evhealthclient.cpp)
endif()

# Static runtime for the helpers too. Until 3.1 only the agent was linked
# statically, so evsecuritytest and evverify imported libstdc++-6.dll and
# libgcc_s_seh-1.dll -- they ran on the build machine (MinGW on PATH) and
# would not start on the terminal they are meant to be copied to.
if(MINGW)
    foreach(tool evsecuritytest evverify evhandletest evhealthtest evhealthclient evlifecycletest)
        target_link_options(${tool} PRIVATE -static -static-libgcc -static-libstdc++)
    endforeach()
endif()
