@echo off
rem EdgeVitals release build.
rem
rem   Clean configure -> build -> static-runtime check on every exe ->
rem   evsecuritytest (must be 46/0) -> evhandletest -> print agent_version.
rem   Any failure stops the build with a non-zero exit code.
rem
rem Toolchain paths default to the lab machine and can be overridden by
rem setting EV_MINGW and EV_NINJA before calling this script.
setlocal
if not defined EV_MINGW set "EV_MINGW=D:\Qt\Tools\mingw1310_64\bin"
if not defined EV_NINJA set "EV_NINJA=D:\Qt\Tools\Ninja"
set "PATH=%EV_MINGW%;%EV_NINJA%;%PATH%"
cd /d "%~dp0"

rem A stale cache silently misses new sources and link libraries. Always clean.
if exist build rmdir /s /q build
if exist build (
    echo [build] could not remove build\ -- is one of its binaries still running?
    goto :fail
)

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release || goto :fail
cmake --build build || goto :fail

rem Static runtime. A MinGW runtime DLL in any import table means that exe will
rem not start on a terminal -- and it would still pass here, because this
rem script put the MinGW bin directory on PATH. So check the table, not the run.
for %%E in (edgevitals evsecuritytest evverify evhandletest evhealthtest evhealthclient evlifecycletest) do (
    if not exist "build\%%E.exe" (
        echo [build] missing build\%%E.exe
        goto :fail
    )
    objdump -p "build\%%E.exe" | findstr /L /I /C:"libstdc++" /C:"libgcc_s" /C:"libwinpthread" >nul && (
        echo [build] %%E.exe imports a MinGW runtime DLL -- static linking did not take
        goto :fail
    )
)
echo [build] import table of edgevitals.exe:
objdump -p build\edgevitals.exe | findstr /C:"DLL Name"

pushd build
echo.
evsecuritytest.exe
if errorlevel 1 (
    popd
    echo [build] evsecuritytest FAILED -- must be 46 passed, 0 failed
    goto :fail
)
echo.
evhandletest.exe
if errorlevel 1 (
    popd
    echo [build] evhandletest FAILED
    goto :fail
)
echo.
evhealthtest.exe
if errorlevel 1 (
    popd
    echo [build] evhealthtest FAILED
    goto :fail
)
echo.
evlifecycletest.exe
if errorlevel 1 (
    popd
    echo [build] evlifecycletest FAILED
    goto :fail
)
popd

set "EV_VERSION="
for /f "delims=" %%V in ('build\edgevitals.exe --version') do set "EV_VERSION=%%V"
if not defined EV_VERSION (
    echo [build] edgevitals.exe --version printed nothing
    goto :fail
)
echo.
echo [build] OK   agent_version=%EV_VERSION%
exit /b 0

:fail
echo [build] FAILED
exit /b 1
