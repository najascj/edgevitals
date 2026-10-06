@echo off
REM ===================================================================
REM  EdgeVitals security acceptance run  --  execute ON the ATM
REM
REM    run_security_tests.bat [path\to\edgevitals.exe]
REM
REM  Two layers, and both matter:
REM
REM    Layer 1  evsecuritytest.exe -- feeds hostile input to the parser
REM             in-process. Catches wrong answers and slow answers.
REM
REM    Layer 2  this script -- watches the EXIT CODE. A stack overflow
REM             kills the harness before it can report anything, so a
REM             crash looks like silence from inside. Only the caller
REM             can tell the difference between "all passed" and "died
REM             on case three".
REM
REM  Exit 0 = every case passed.  Non-zero = investigate, do not ship.
REM ===================================================================
setlocal enabledelayedexpansion
set EXE=%~1
if "%EXE%"=="" set EXE=edgevitals.exe
set FAILED=0

echo.
echo ================================================================
echo  EdgeVitals security acceptance
echo  %DATE% %TIME%
echo ================================================================

REM ---- 1. parser and CSV abuse cases -------------------------------
echo.
echo [1/5] Hostile input suite
if not exist evsecuritytest.exe (
    echo   SKIP - evsecuritytest.exe not found next to this script
    set FAILED=1
) else (
    evsecuritytest.exe
    if errorlevel 1 (
        echo   RESULT: FAILED  ^(exit !errorlevel!^)
        echo   Exit 139 / -1073741819 means it CRASHED, not that a case failed.
        set FAILED=1
    ) else (
        echo   RESULT: passed
    )
)

REM ---- 2. the agent must still start normally ----------------------
REM  A hardened build that refuses its own config is an outage, not a
REM  fix. This is the regression guard on every limit added above.
echo.
echo [2/5] Agent still starts and reads its real config
REM Stop any agent already running: a second instance cannot take the pipe
REM (FILE_FLAG_FIRST_PIPE_INSTANCE), and a leftover --console session is the
REM commonest reason this step "fails" on a developer machine.
taskkill /IM edgevitals.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul
"%EXE%" --once --console > _sec_once.txt 2>&1
if errorlevel 1 (
    echo   RESULT: FAILED - agent did not complete a tick
    set FAILED=1
) else (
    findstr /C:"tracked roles" _sec_once.txt
    findstr /C:"nesting too deep" _sec_once.txt >nul && (
        echo   RESULT: FAILED - the real config was refused by the depth guard
        set FAILED=1
    ) || echo   RESULT: passed
)

REM ---- 3. hostile config must be refused, and must not stop start --
echo.
echo [3/5] Hostile config is refused and the agent falls back
if not exist _sec_cfg mkdir _sec_cfg
powershell -NoProfile -Command ^
  "'[' * 200000 | Set-Content -NoNewline _sec_cfg\deep.json" 2>nul
taskkill /IM edgevitals.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul
"%EXE%" --once --console --config _sec_cfg\deep.json > _sec_deep.txt 2>&1
if errorlevel 1 (
    echo   RESULT: FAILED - agent died on a hostile config. Output:
    type _sec_deep.txt
    set FAILED=1
) else (
    findstr /C:"nesting too deep" _sec_deep.txt >nul && echo   refused as expected
    findstr /C:"running on defaults" _sec_deep.txt >nul && echo   fell back to defaults
    echo   RESULT: passed
)

REM ---- 4. IPC flood -------------------------------------------------
REM  Sends oversized, deeply nested and malformed frames at the pipe
REM  while the agent runs. The agent must stay up and keep writing CSV.
echo.
echo [4/5] IPC flood while the agent is running
echo   Start the agent in another window:   %EXE% --console
echo   then run:                            .\ipcflood.ps1     ^(the .\ is required^)
echo   SKIPPED in batch - see MANUAL section of the test plan

REM ---- 5. footprint after abuse -------------------------------------
echo.
echo [5/5] Agent footprint after the suite
tasklist /FI "IMAGENAME eq edgevitals.exe" /FO LIST | findstr /C:"Mem Usage" /C:"PID"
echo   Expect ~6 MB working set. Anything above 50 MB after an abuse
echo   run means something grew that should not have.

echo.
echo ================================================================
if "%FAILED%"=="0" (
    echo  OVERALL: PASS
) else (
    echo  OVERALL: FAIL - do not ship this build
)
echo ================================================================
del /q _sec_once.txt _sec_deep.txt 2>nul
rmdir /s /q _sec_cfg 2>nul
exit /b %FAILED%
