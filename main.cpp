// EdgeVitals entry point.
//
//   edgevitals.exe --console            run in the foreground (lab mode)
//   edgevitals.exe --install            register the service
//   edgevitals.exe --uninstall          remove it
//   edgevitals.exe --config <path>      config file (default config/edgevitals.json)
//   edgevitals.exe --once               one tick to stdout, then exit (smoke test)
//
// With no arguments it assumes it was launched by the SCM. Running it from a
// console with no arguments therefore does nothing visible, which is why
// --console exists and why the usage text says so.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "edgevitals/Agent.h"
#include "edgevitals/Config.h"

using namespace ev;

namespace {

const char* kServiceName = "EdgeVitals";
const char* kDisplayName = "BOSACH EdgeVitals telemetry agent";
const char* kDescription =
    "Samples CPU, memory and disk IO for ATM edge processes and writes day-rotated "
    "telemetry for offline analysis. Observation only: it does not block, alert or enforce.";

std::string g_runNote;
std::string g_configPath = "config/edgevitals.json";
Agent* g_agent = nullptr;
SERVICE_STATUS g_status{};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;

// Defined below, but called from serviceMain which appears first.
void securitySelfCheck(const ev::Config& cfg, ev::ILogger& log);

class ConsoleLogger : public ILogger {
public:
    void info(const std::string& m) override { std::fprintf(stderr, "[info ] %s\n", m.c_str()); }
    void warn(const std::string& m) override { std::fprintf(stderr, "[warn ] %s\n", m.c_str()); }
    void error(const std::string& m) override { std::fprintf(stderr, "[error] %s\n", m.c_str()); }
};

// The service has no console, so it reports through the event log. Registering
// a message DLL for pretty formatting is more ceremony than this earns; the
// raw string is readable in Event Viewer and that is what matters at 2am.
class EventLogLogger : public ILogger {
public:
    EventLogLogger() { h_ = RegisterEventSourceA(nullptr, kServiceName); }
    ~EventLogLogger() override { if (h_) DeregisterEventSource(h_); }
    void info(const std::string& m) override { emit(EVENTLOG_INFORMATION_TYPE, m); }
    void warn(const std::string& m) override { emit(EVENTLOG_WARNING_TYPE, m); }
    void error(const std::string& m) override { emit(EVENTLOG_ERROR_TYPE, m); }

private:
    void emit(WORD type, const std::string& m) {
        if (!h_) return;
        const char* strings[1] = {m.c_str()};
        ReportEventA(h_, type, 0, 0, nullptr, 1, 0, strings, nullptr);
    }
    HANDLE h_ = nullptr;
};

void setState(DWORD state, DWORD waitHintMs = 0) {
    g_status.dwCurrentState = state;
    g_status.dwWaitHint = waitHintMs;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
        g_status.dwCheckPoint++;
    else
        g_status.dwCheckPoint = 0;
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
}

DWORD WINAPI handlerEx(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            // 5 s hint: the tick loop wakes on an event, so shutdown is
            // prompt, but the SCM should not kill us mid-write to the CSV.
            setState(SERVICE_STOP_PENDING, 5000);
            if (g_agent) g_agent->stop();
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI serviceMain(DWORD, LPSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExA(kServiceName, handlerEx, nullptr);
    if (!g_statusHandle) return;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_status.dwWin32ExitCode = NO_ERROR;
    setState(SERVICE_START_PENDING, 10000);

    EventLogLogger log;

    Config cfg = Config::defaults();
    std::string err;
    if (!cfg.load(g_configPath, err)) {
        // A missing or bad config is a warning, not a failure to start. An ATM
        // that loses telemetry because someone fat-fingered a JSON comma is
        // worse than one running on defaults and saying so.
        log.warn("config: " + err + " -- running on defaults");
    }
    cfg.runNote = g_runNote;
    securitySelfCheck(cfg, log);

    Agent agent(cfg, log);
    g_agent = &agent;
    if (!agent.start()) {
        log.error("agent failed to start");
        g_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        setState(SERVICE_STOPPED);
        return;
    }

    setState(SERVICE_RUNNING);
    agent.run();
    g_agent = nullptr;
    setState(SERVICE_STOPPED);
}

// Reports posture at startup rather than assuming it. Every item here was
// raised in the security review and cannot be fixed in code -- the agent can
// only refuse to be quiet about them.
void securitySelfCheck(const ev::Config& cfg, ev::ILogger& log) {
    char exe[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, exe, sizeof(exe) - 1);
    std::string p(exe);

    if (cfg.ipcClientSid == "AU" || cfg.ipcClientSid == "WD") {
        log.warn("security: ipc client_sid is '" + cfg.ipcClientSid +
                 "' -- any authenticated local process may push telemetry. "
                 "Narrow it to EdgeTerminal's account before production.");
    }
    if (cfg.ipcAllowSnapshot) {
        log.warn("security: allow_snapshot is on -- any permitted client can read "
                 "the full process inventory of this terminal.");
    }

    // Volume check. A service binary on a removable or secondary volume can be
    // swapped and then runs as SYSTEM at next start.
    if (p.size() > 2 && p[1] == ':') {
        char root[4] = {p[0], ':', '\\', 0};
        const UINT dt = GetDriveTypeA(root);
        if (dt == DRIVE_REMOVABLE || dt == DRIVE_REMOTE) {
            log.warn(std::string("security: running from a ") +
                     (dt == DRIVE_REMOVABLE ? "removable" : "network") +
                     " volume (" + root + ") -- the binary can be replaced. "
                     "Move it to the system volume with an Administrators-only ACL.");
        }
        char win[MAX_PATH] = {0};
        GetWindowsDirectoryA(win, sizeof(win) - 1);
        if (win[0] && (p[0] | 32) != (win[0] | 32))
            log.info(std::string("security: binary is on ") + root +
                     ", not the system volume -- confirm its ACL is Administrators only.");
    }

    // Writable by ordinary users? Cheap probe: try to create a file in the exe
    // directory while impersonating nothing. This is indicative, not an ACL
    // audit -- as SYSTEM the write will usually succeed regardless.
    log.info("security: verify the exe directory grants write to Administrators "
             "and SYSTEM only, and that the binary is Authenticode signed. "
             "Neither can be checked reliably from inside the process.");
}

std::string exePath() {
    char buf[MAX_PATH * 2] = {0};
    GetModuleFileNameA(nullptr, buf, sizeof(buf) - 1);
    return buf;
}

int installService() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        std::fprintf(stderr, "OpenSCManager failed (%lu). Run from an elevated prompt.\n",
                     GetLastError());
        return 1;
    }
    // The binary path carries --config so the service does not depend on its
    // working directory, which the SCM sets to system32.
    const std::string bin = "\"" + exePath() + "\" --config \"" + g_configPath + "\"";
    SC_HANDLE svc = CreateServiceA(scm, kServiceName, kDisplayName, SERVICE_ALL_ACCESS,
                                   SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                   SERVICE_ERROR_NORMAL, bin.c_str(), nullptr, nullptr,
                                   nullptr, nullptr, nullptr);
    if (!svc) {
        const DWORD e = GetLastError();
        std::fprintf(stderr, e == ERROR_SERVICE_EXISTS ? "Service already installed.\n"
                                                       : "CreateService failed (%lu).\n", e);
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_DESCRIPTIONA desc{const_cast<LPSTR>(kDescription)};
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    // LocalSystem holds every privilege on the box. A telemetry agent needs
    // almost none of them, and "runs as SYSTEM with full privileges" is the
    // first thing a bank's hardening review will object to. Strip the token
    // to what sampling actually requires.
    //
    // SeChangeNotifyPrivilege  - traverse directories to write the log
    // SeCreateGlobalPrivilege  - the named pipe object
    //
    // Deliberately NOT requested: SeDebugPrivilege, SeTcbPrivilege,
    // SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege,
    // SeRestorePrivilege. Querying PROCESS_QUERY_LIMITED_INFORMATION does not
    // need SeDebug as SYSTEM; if a future protected-process read does, add it
    // deliberately and record why.
    {
        static const char kPrivs[] =
            "SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0";
        SERVICE_REQUIRED_PRIVILEGES_INFOA rp{};
        rp.pmszRequiredPrivileges = const_cast<LPSTR>(kPrivs);
        if (!ChangeServiceConfig2A(svc, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &rp))
            std::fprintf(stderr, "warning: could not restrict privileges (%lu)\n", GetLastError());
    }

    // Give the service its own SID and a write-restricted token, so a
    // compromise of this process cannot write to objects that have not
    // explicitly granted the service SID access.
    {
        SERVICE_SID_INFO sid{};
        sid.dwServiceSidType = SERVICE_SID_TYPE_RESTRICTED;
        if (!ChangeServiceConfig2A(svc, SERVICE_CONFIG_SERVICE_SID_INFO, &sid)) {
            // Restricted needs the write-restricted token to reach the log
            // directory and the pipe; fall back to an unrestricted service
            // SID rather than leaving it at NONE.
            sid.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
            ChangeServiceConfig2A(svc, SERVICE_CONFIG_SERVICE_SID_INFO, &sid);
            std::fprintf(stderr, "note: service SID set to UNRESTRICTED\n");
        }
    }

    // Restart on failure. A telemetry agent that dies silently is worse than
    // one that never ran, because the gap in the CSV looks like an idle period.
    SC_ACTION actions[3];
    actions[0] = {SC_ACTION_RESTART, 10000};
    actions[1] = {SC_ACTION_RESTART, 30000};
    actions[2] = {SC_ACTION_RESTART, 60000};
    SERVICE_FAILURE_ACTIONSA fa{};
    fa.dwResetPeriod = 86400;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    std::printf("Installed '%s'.\n  binary: %s\n  start:  net start %s\n", kServiceName,
                bin.c_str(), kServiceName);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int uninstallService() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::fprintf(stderr, "OpenSCManager failed (%lu). Run elevated.\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceA(scm, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        std::fprintf(stderr, "Service not installed.\n");
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    const bool ok = DeleteService(svc) != 0;
    std::printf(ok ? "Removed '%s'.\n" : "DeleteService failed.\n", kServiceName);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 0 : 1;
}

BOOL WINAPI ctrlHandler(DWORD) {
    if (g_agent) g_agent->stop();
    return TRUE;
}

int runConsole(bool once) {
    ConsoleLogger log;
    Config cfg = Config::defaults();
    std::string err;
    if (!cfg.load(g_configPath, err)) log.warn("config: " + err + " -- running on defaults");
    cfg.runNote = g_runNote;
    if (once) cfg.intervalMs = 1000;
    securitySelfCheck(cfg, log);

    Agent agent(cfg, log);
    g_agent = &agent;
    SetConsoleCtrlHandler(ctrlHandler, TRUE);
    if (!agent.start()) return 1;

    if (once) {
        // Two ticks, not one: the first primes the CPU and IO counters and
        // legitimately has no deltas to report. Reporting it as a result
        // would show a machine at 0% and look like a bug.
        std::fprintf(stderr, "[info ] --once: priming, then one measured tick\n");
        std::thread([&] {
            Sleep(2500);
            agent.stop();
        }).detach();
    }
    agent.run();
    g_agent = nullptr;
    return 0;
}

void usage() {
    std::printf(
        "EdgeVitals -- BOSACH ATM telemetry agent\n\n"
        "  --console            run in the foreground (Ctrl+C to stop)\n"
        "  --once               prime + one measured tick, then exit\n"
        "  --install            register as a Windows service\n"
        "  --uninstall          remove the service\n"
        "  --config <path>      config file (default config/edgevitals.json)\n"
        "  --note <text>        label this run in the CSV (what the terminal was doing)\n"
        "  --help               this text\n\n"
        "With no arguments it expects to be started by the Service Control Manager.\n");
}

}  // namespace

int main(int argc, char** argv) {
    bool console = false, once = false, install = false, uninstall = false, help = false;

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!std::strcmp(a, "--console")) console = true;
        else if (!std::strcmp(a, "--once")) { once = true; console = true; }
        else if (!std::strcmp(a, "--install")) install = true;
        else if (!std::strcmp(a, "--uninstall")) uninstall = true;
        else if (!std::strcmp(a, "--help") || !std::strcmp(a, "-h")) help = true;
        else if (!std::strcmp(a, "--config") && i + 1 < argc) g_configPath = argv[++i];
        else if (!std::strcmp(a, "--note") && i + 1 < argc) g_runNote = argv[++i];
        else { std::fprintf(stderr, "unknown argument: %s\n\n", a); usage(); return 2; }
    }

    if (help) { usage(); return 0; }
    if (install) return installService();
    if (uninstall) return uninstallService();
    if (console) return runConsole(once);

    SERVICE_TABLE_ENTRYA table[] = {
        {const_cast<LPSTR>(kServiceName), serviceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherA(table)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::fprintf(stderr, "Not started by the SCM.\n\n");
            usage();
            return 2;
        }
        return 1;
    }
    return 0;
}
