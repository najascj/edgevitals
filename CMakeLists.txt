cmake_minimum_required(VERSION 3.16)
project(EdgeVitals VERSION 0.1.0 LANGUAGES CXX)

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
    )
    target_link_libraries(edgevitals PRIVATE edgevitals_core psapi advapi32)

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
add_executable(edgevitals_tests tests/test_core.cpp)
target_link_libraries(edgevitals_tests PRIVATE edgevitals_core)
add_test(NAME core COMMAND edgevitals_tests)
