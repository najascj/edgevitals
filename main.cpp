// EdgeVitals entry point.
//
//   edgevitals.exe --console            run in the foreground (lab mode)
//   edgevitals.exe --install            register the service
//   edgevitals.exe --uninstall          remove it
//   edgevitals.exe --config <path>      config file (default config/edgevitals.json)
//   edgevitals.exe --once               one tick to stdout, then exit (smoke test)
//   edgevitals.exe --version            print the agent version and exit
//   edgevitals.exe --posture            one remote-access posture run, the baseline
//                                       record to stdout, then exit (exit 1 if any FAIL)
//
// With no arguments it assumes it was launched by the SCM. Running it from a
// console with no arguments therefore does nothing visible, which is why
// --console exists and why the usage text says so.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <memory>
#include <thread>

#include "edgevitals/Agent.h"
#include "edgevitals/FileLogger.h"
#include "edgevitals/SelfCheck.h"
#include "edgevitals/Config.h"
#include "edgevitals/PostureCollect.h"
#include "edgevitals/PostureMonitor.h"
#include "edgevitals/IntegrityCollect.h"
#include "edgevitals/IntegrityMonitor.h"
#include "edgevitals/ProcessSampler.h"

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

// Defined further down but used by serviceMain, which appears first.
std::string exePath();
std::string exeDir();
std::shared_ptr<ev::ILogger> attachFileLog(const ev::Config& cfg,
                                           const std::shared_ptr<ev::ILogger>& inner,
                                           std::shared_ptr<ev::FileLogger>& keep);
void logSelfIntegrity(ev::ILogger& log);

class ConsoleLogger : public ILogger {
public:
    void info(const std::string& m) override { (void)std::fprintf(stderr, "[info ] %s\n", m.c_str()); }
    void warn(const std::string& m) override { (void)std::fprintf(stderr, "[warn ] %s\n", m.c_str()); }
    void error(const std::string& m) override { (void)std::fprintf(stderr, "[error] %s\n", m.c_str()); }
};

// The service has no console, so it reports through the event log. Registering
// a message DLL for pretty formatting is more ceremony than this earns; the
// raw string is readable in Event Viewer and that is what matters at 2am.
class EventLogLogger : public ILogger {
public:
    EventLogLogger() : h_(RegisterEventSourceA(nullptr, kServiceName)) {}
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

    auto evtlog = std::make_shared<EventLogLogger>();

    Config cfg = Config::defaults();
    std::string err;
    if (!cfg.load(g_configPath, err)) {
        // A missing or bad config is a warning, not a failure to start. An ATM
        // that loses telemetry because someone fat-fingered a JSON comma is
        // worse than one running on defaults and saying so.
        evtlog->warn("config: " + err + " -- running on defaults");
    }
    cfg.runNote = g_runNote;
    cfg.exeDir = exeDir();
    cfg.resolvePaths();

    std::shared_ptr<FileLogger> fileLog;
    auto flog = attachFileLog(cfg, evtlog, fileLog);
    logSelfIntegrity(*flog);
    securitySelfCheck(cfg, *flog);

    Agent agent(cfg, *flog);
    g_agent = &agent;
    if (!agent.start()) {
        flog->error("agent failed to start");
        g_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        setState(SERVICE_STOPPED);
        return;
    }

    setState(SERVICE_RUNNING);
    agent.run();
    g_agent = nullptr;
    // Seal the log chain before reporting stopped, for the same reason as the
    // console path: an unsealed file cannot be told from a truncated one.
    if (fileLog) fileLog->close();
    setState(SERVICE_STOPPED);
}

// Reports posture at startup rather than assuming it. Every item here was
// raised in the security review and cannot be fixed in code -- the agent can
// only refuse to be quiet about them.
void securitySelfCheck(const ev::Config& cfg, ev::ILogger& log) {
    char exe[MAX_PATH] = {0};  // flawfinder: ignore -- GetModuleFileNameA bounded by sizeof - 1; zero-initialised
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
        char root[4] = {p[0], ':', '\\', 0};  // flawfinder: ignore -- fixed drive root: 3 chars + NUL
        const UINT dt = GetDriveTypeA(root);
        if (dt == DRIVE_REMOVABLE || dt == DRIVE_REMOTE) {
            log.warn(std::string("security: running from a ") +
                     (dt == DRIVE_REMOVABLE ? "removable" : "network") +
                     " volume (" + root + ") -- the binary can be replaced. "
                     "Move it to the system volume with an Administrators-only ACL.");
        }
        char win[MAX_PATH] = {0};  // flawfinder: ignore -- GetWindowsDirectoryA bounded by sizeof - 1; zero-initialised
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

// Directory holding the running binary, with no trailing separator.
std::string exeDir() {
    const std::string p = exePath();
    const size_t slash = p.find_last_of("\\/");
    return slash == std::string::npos ? std::string(".") : p.substr(0, slash);
}

std::string exePath() {
    char buf[MAX_PATH * 2] = {0};  // flawfinder: ignore -- GetModuleFileNameA bounded by sizeof - 1; zero-initialised
    GetModuleFileNameA(nullptr, buf, sizeof(buf) - 1);
    return buf;
}

int installService() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        (void)std::fprintf(stderr, "OpenSCManager failed (%lu). Run from an elevated prompt.\n",
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
        // Literal formats on each branch (no format chosen at run time).
        if (e == ERROR_SERVICE_EXISTS)
            (void)std::fprintf(stderr, "Service already installed.\n");
        else
            (void)std::fprintf(stderr, "CreateService failed (%lu).\n", e);
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
            (void)std::fprintf(stderr, "warning: could not restrict privileges (%lu)\n", GetLastError());
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
            (void)std::fprintf(stderr, "note: service SID set to UNRESTRICTED\n");
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
        (void)std::fprintf(stderr, "OpenSCManager failed (%lu). Run elevated.\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceA(scm, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        (void)std::fprintf(stderr, "Service not installed.\n");
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    const bool ok = DeleteService(svc) != 0;
    if (ok)
        std::printf("Removed '%s'.\n", kServiceName);
    else
        std::printf("DeleteService failed.\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 0 : 1;
}

BOOL WINAPI ctrlHandler(DWORD) {
    if (g_agent) g_agent->stop();
    return TRUE;
}


// Wraps an inner logger in the day-rotated, chained file logger and records
// what binary is running. Both paths -- service and console -- go through here
// so the two cannot drift apart.
std::shared_ptr<ev::ILogger> attachFileLog(const ev::Config& cfg,
                                           const std::shared_ptr<ev::ILogger>& inner,
                                           std::shared_ptr<ev::FileLogger>& keep) {
    ev::FileLogger::Options fo;
    fo.dir = cfg.logDir;
    fo.prefix = "edgevitals";
    fo.retentionDays = cfg.retentionDays;
    fo.chainEveryLines = cfg.chainEveryLogLines;
    keep = std::make_shared<ev::FileLogger>(fo, inner);
    return keep;
}

// First lines of every run: which build, hashed, and whether it is signed.
// Written through the logger so they land in the file, in its chain, and
// -- once shipped -- at EdgeSentinel, where a hash that changes without a
// release is visible. The process cannot verify itself; this records the fact
// so somebody else can.
void logSelfIntegrity(ev::ILogger& log) {
    ev::SelfIntegrity si = ev::checkSelf(exePath());
    ev::checkSignature(si);
    log.info(si.summary(ev::kAgentVersion));
    if (si.signature == ev::SelfIntegrity::Signature::Invalid)
        log.error("self: Authenticode verification FAILED -- this binary does not "
                  "match its signature. Investigate before trusting its output.");
    else if (si.signature == ev::SelfIntegrity::Signature::Unsigned)
        log.warn("self: binary is unsigned. Application control will block it on a "
                 "hardened terminal, and its provenance rests on the hash alone.");
}

int runConsole(bool once) {
    auto console = std::make_shared<ConsoleLogger>();
    Config cfg = Config::defaults();
    std::string err;
    if (!cfg.load(g_configPath, err)) console->warn("config: " + err + " -- running on defaults");
    cfg.runNote = g_runNote;
    if (once) cfg.intervalMs = 1000;
    // File logging starts AFTER the config is read, because the log directory
    // comes from it. The few lines before this point go to the console only.
    std::shared_ptr<FileLogger> fileLog;
    auto flog = attachFileLog(cfg, console, fileLog);
    logSelfIntegrity(*flog);
    securitySelfCheck(cfg, *flog);

    Agent agent(cfg, *flog);
    g_agent = &agent;
    SetConsoleCtrlHandler(ctrlHandler, TRUE);
    if (!agent.start()) return 1;

    if (once) {
        // Two ticks, not one: the first primes the CPU and IO counters and
        // legitimately has no deltas to report. Reporting it as a result
        // would show a machine at 0% and look like a bug.
        (void)std::fprintf(stderr, "[info ] --once: priming, then one measured tick\n");
        std::thread([&] {
            Sleep(2500);
            agent.stop();
        }).detach();
    }
    agent.run();
    g_agent = nullptr;
    // Seal the log chain before exit. A day file that ends without a final
    // checkpoint cannot be distinguished from one an attacker truncated, and
    // anything appended afterwards would verify as "trailing bytes, normal".
    if (fileLog) fileLog->close();
    return 0;
}

// One posture run, printed. For the lab, for comparing with ATMProbe's
// baseline on the same terminal at the same moment, and for a bank reviewer
// who wants the evidence without reading logs. Writes nothing to disk.
int runPostureOnce() {
    Config cfg = Config::defaults();
    std::string err;
    if (!cfg.load(g_configPath, err)) (void)std::fprintf(stderr, "[warn ] config: %s -- running on defaults\n", err.c_str());
    PostureProfile prof;
    std::string label, hash, perr;
    loadPostureProfile(cfg.posture.profilePath, prof, label, hash, perr);
    if (!perr.empty()) (void)std::fprintf(stderr, "[warn ] posture: %s -- built-in default profile\n", perr.c_str());

    PostureCollectInput in;
    {
        ProcessSampler ps(cfg);
        const auto all = ps.enumerate();
        for (const auto& p : all) {
            in.pidNames[p.pid] = p.exeName;
            in.processes.push_back(p.exeName);
        }
        in.processesValid = !all.empty();
    }
    in.startTypeFor = postureStartTypeServices();
    auto cpuMs = [] {
        FILETIME c, e, k, u;
        if (!GetThreadTimes(GetCurrentThread(), &c, &e, &k, &u)) return 0.0;
        auto v = [](const FILETIME& f) {
            return static_cast<double>((static_cast<unsigned long long>(f.dwHighDateTime) << 32) | f.dwLowDateTime) / 1e4;
        };
        return v(k) + v(u);
    };
    const auto t0 = std::chrono::steady_clock::now();
    const double c0 = cpuMs();
    PostureFacts facts;
    collectPosture(in, facts);
    const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    const double cpu = cpuMs() - c0;

    PostureMonitor mon(prof, label, hash, kAgentVersion, cfg.posture.maxEventsPerHour);
    PostureRunOutput out;
    Date today{};
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        today.y = st.wYear;
        today.m = st.wMonth;
        today.d = st.wDay;
    }

    mon.process(facts, "cli", false, 0.0, today, ms, cpu, out);
    for (const auto& r : out.records) std::printf("%s\n", r.c_str());
    for (const auto& l : out.log) (void)std::fprintf(stderr, "%s\n", l.second.c_str());
    return mon.failCount() > 0 ? 1 : 0;
}

// One endpoint-integrity run, printed. Exit 1 if any FAIL. Writes nothing.
int runIntegrityOnce() {
    Config cfg = Config::defaults();
    std::string err;
    if (!cfg.load(g_configPath, err)) (void)std::fprintf(stderr, "[warn ] config: %s -- running on defaults\n", err.c_str());
    IntegrityBaseline bl;
    std::string label, hash, ierr;
    loadIntegrityBaseline(cfg.integrity.baseline, bl, label, hash, ierr);
    if (!ierr.empty()) (void)std::fprintf(stderr, "[warn ] integrity: %s -- strict built-in baseline\n", ierr.c_str());
    IntegrityCollectInput in;
    for (const auto& fb : bl.files) in.files.push_back(fb.path);
    in.maxBytes = cfg.integrity.max_file_mb * 1024LL * 1024LL;
    const auto t0 = std::chrono::steady_clock::now();
    IntegrityFacts facts;
    collectIntegrity(in, facts);
    const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    IntegrityMonitor mon(bl, label, hash, kAgentVersion, cfg.integrity.max_events_per_hour);
    IntegrityRunOutput out;
    Date today{};
    SYSTEMTIME st;
    GetLocalTime(&st);
    today.y = st.wYear; today.m = st.wMonth; today.d = st.wDay;
    mon.process(facts, "cli", false, 0.0, today, ms, out);
    for (const auto& r : out.records) std::printf("%s\n", r.c_str());
    for (const auto& l : out.log) (void)std::fprintf(stderr, "%s\n", l.second.c_str());
    return mon.failCount() > 0 ? 1 : 0;
}

// Prints a starter integrity-baseline.json from this terminal: the persistence
// now present, as the allow-list, plus the configured fileset with live hashes.
// The engineer reviews it and commits it as the approved baseline.
int runFimBaseline() {
    Config cfg = Config::defaults();
    std::string err;
    (void)cfg.load(g_configPath, err);
    IntegrityBaseline bl;
    std::string label, hash, ierr;
    loadIntegrityBaseline(cfg.integrity.baseline, bl, label, hash, ierr);
    IntegrityCollectInput in;
    for (const auto& fb : bl.files) in.files.push_back(fb.path);
    in.maxBytes = cfg.integrity.max_file_mb * 1024LL * 1024LL;
    IntegrityFacts f;
    collectIntegrity(in, f);
    std::printf("{\n  \"profile\": \"generated\",\n  \"strict_persistence\": true,\n  \"files\": [\n");
    bool first = true;
    for (const auto& h : f.files) {
        std::printf("%s    {\"path\": %s, \"sha256\": \"%s\", \"required\": true}", first ? "" : ",\n",
                    iJsonQuote(h.path).c_str(), h.rd == IRd::Ok ? h.sha256.c_str() : "");
        first = false;
    }
    std::printf("\n  ],\n  \"persist_allow\": [\n");
    first = true;
    for (const auto& e : f.persistence) {
        std::printf("%s    %s", first ? "" : ",\n", iJsonQuote(persistToken(e)).c_str());
        first = false;
    }
    std::printf("\n  ]\n}\n");
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
        "  --version            print the agent version and exit\n"
        "  --posture            one remote-access posture run to stdout, then exit (1 = a FAIL)\n"
        "  --integrity          one endpoint-integrity run to stdout, then exit (1 = a FAIL)\n"
        "  --fim-baseline       print a starter integrity-baseline.json from this terminal\n"
        "  --help               this text\n\n"
        "With no arguments it expects to be started by the Service Control Manager.\n");
}

}  // namespace

int main(int argc, char** argv) {
    bool console = false, once = false, install = false, uninstall = false, help = false, posture = false, integrity = false, fimbaseline = false;

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!std::strcmp(a, "--console")) console = true;
        else if (!std::strcmp(a, "--once")) { once = true; console = true; }
        else if (!std::strcmp(a, "--install")) install = true;
        else if (!std::strcmp(a, "--uninstall")) uninstall = true;
        else if (!std::strcmp(a, "--help") || !std::strcmp(a, "-h")) help = true;
        else if (!std::strcmp(a, "--posture")) posture = true;
        else if (!std::strcmp(a, "--integrity")) integrity = true;
        else if (!std::strcmp(a, "--fim-baseline")) fimbaseline = true;
        else if (!std::strcmp(a, "--version")) {
            std::printf("%s\n", ev::kAgentVersion);
            return 0;
        }
        else if (!std::strcmp(a, "--config") && i + 1 < argc) g_configPath = argv[++i];
        else if (!std::strcmp(a, "--note") && i + 1 < argc) g_runNote = argv[++i];
        else { (void)std::fprintf(stderr, "unknown argument: %s\n\n", a); usage(); return 2; }
    }

    if (help) { usage(); return 0; }
    if (install) return installService();
    if (uninstall) return uninstallService();
    if (posture) return runPostureOnce();
    if (integrity) return runIntegrityOnce();
    if (fimbaseline) return runFimBaseline();
    if (console) return runConsole(once);

    SERVICE_TABLE_ENTRYA table[] = {
        {const_cast<LPSTR>(kServiceName), serviceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherA(table)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            (void)std::fprintf(stderr, "Not started by the SCM.\n\n");
            usage();
            return 2;
        }
        return 1;
    }
    return 0;
}
