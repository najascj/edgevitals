// Remote-access posture: Win32 collection. See PostureCollect.h for the rules.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <lm.h>

#include "edgevitals/PostureCollect.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <set>
#include <vector>

namespace ev {
namespace {

std::string narrow(const wchar_t* w) {
    if (!w || !*w) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    s.resize(static_cast<size_t>(n - 1));
    return s;
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

Rd rdFromError(LONG e) {
    if (e == ERROR_SUCCESS) return Rd::Ok;
    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return Rd::Absent;
    if (e == ERROR_ACCESS_DENIED) return Rd::Denied;
    return Rd::Error;
}

// HKLM DWORD. Key absent and value absent are both Absent: either way nothing
// is configured there.
RegDword regDword(const wchar_t* path, const wchar_t* value) {
    RegDword r;
    HKEY k = nullptr;
    const LONG e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k);
    if (e != ERROR_SUCCESS) {
        r.rd = rdFromError(e);
        return r;
    }
    DWORD type = 0, v = 0, sz = sizeof(v);
    const LONG q = RegQueryValueExW(k, value, nullptr, &type, reinterpret_cast<LPBYTE>(&v), &sz);
    RegCloseKey(k);
    if (q != ERROR_SUCCESS) {
        r.rd = rdFromError(q);
        return r;
    }
    if (type != REG_DWORD || sz != sizeof(DWORD)) {
        r.rd = Rd::Error;
        return r;
    }
    r.rd = Rd::Ok;
    r.v = v;
    return r;
}

RegText regText(const wchar_t* path, const wchar_t* value) {
    RegText r;
    HKEY k = nullptr;
    const LONG e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k);
    if (e != ERROR_SUCCESS) {
        r.rd = rdFromError(e);
        return r;
    }
    wchar_t buf[128] = {0};  // flawfinder: ignore -- RegQueryValueExW bounded by sz; terminated below
    DWORD type = 0, sz = sizeof(buf) - sizeof(wchar_t);
    const LONG q = RegQueryValueExW(k, value, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(k);
    if (q != ERROR_SUCCESS) {
        r.rd = rdFromError(q);
        return r;
    }
    if (type != REG_SZ) {
        r.rd = Rd::Error;
        return r;
    }
    buf[sizeof(buf) / sizeof(buf[0]) - 1] = L'\0';
    r.rd = Rd::Ok;
    r.v = narrow(buf);
    return r;
}

FileFact systemFile(const wchar_t* relative) {
    FileFact f;
    wchar_t dir[MAX_PATH] = {0};  // flawfinder: ignore -- GetSystemDirectoryW bounded by MAX_PATH
    const UINT n = GetSystemDirectoryW(dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return f;
    std::wstring p(dir);
    p += L"\\";
    p += relative;
    const DWORD a = GetFileAttributesW(p.c_str());
    if (a != INVALID_FILE_ATTRIBUTES) {
        f.rd = (a & FILE_ATTRIBUTE_DIRECTORY) ? Rd::Absent : Rd::Ok;
        return f;
    }
    f.rd = rdFromError(static_cast<LONG>(GetLastError()));
    return f;
}

const char* stateName(DWORD s) {
    switch (s) {
        case SERVICE_STOPPED: return "stopped";
        case SERVICE_START_PENDING: return "start_pending";
        case SERVICE_STOP_PENDING: return "stop_pending";
        case SERVICE_RUNNING: return "running";
        case SERVICE_CONTINUE_PENDING: return "continue_pending";
        case SERVICE_PAUSE_PENDING: return "pause_pending";
        case SERVICE_PAUSED: return "paused";
        default: return "unknown";
    }
}

const char* startName(DWORD s) {
    switch (s) {
        case SERVICE_BOOT_START: return "boot";
        case SERVICE_SYSTEM_START: return "system";
        case SERVICE_AUTO_START: return "auto";
        case SERVICE_DEMAND_START: return "demand";
        case SERVICE_DISABLED: return "disabled";
        default: return "";
    }
}

// Start type of one service; "" when it cannot be read.
std::string startTypeOf(SC_HANDLE scm, const std::wstring& name) {
    SC_HANDLE h = OpenServiceW(scm, name.c_str(), SERVICE_QUERY_CONFIG);
    if (!h) return std::string();
    DWORD need = 0;
    std::string out;
    QueryServiceConfigW(h, nullptr, 0, &need);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && need > 0 && need < 64 * 1024) {
        std::vector<BYTE> buf(need);
        auto* qc = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (QueryServiceConfigW(h, qc, need, &need)) out = startName(qc->dwStartType);
    }
    CloseServiceHandle(h);
    return out;
}

DriverFact driverFact(SC_HANDLE scm, const wchar_t* name) {
    DriverFact d;
    SC_HANDLE h = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!h) {
        const DWORD e = GetLastError();
        d.rd = e == ERROR_SERVICE_DOES_NOT_EXIST ? Rd::Absent : e == ERROR_ACCESS_DENIED ? Rd::Denied : Rd::Error;
        return d;
    }
    DWORD need = 0;
    QueryServiceConfigW(h, nullptr, 0, &need);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && need > 0 && need < 64 * 1024) {
        std::vector<BYTE> buf(need);
        auto* qc = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (QueryServiceConfigW(h, qc, need, &need)) {
            d.start = startName(qc->dwStartType);
            d.rd = d.start.empty() ? Rd::Error : Rd::Ok;
        }
    }
    SERVICE_STATUS st;
    if (QueryServiceStatus(h, &st)) d.state = stateName(st.dwCurrentState);
    CloseServiceHandle(h);
    return d;
}

void collectServices(const PostureCollectInput& in, PostureFacts& f) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        f.servicesRd = GetLastError() == ERROR_ACCESS_DENIED ? Rd::Denied : Rd::Error;
        f.srv1.rd = f.mrxsmb10.rd = f.servicesRd;
        return;
    }
    // One enumeration for every service: state and pid for all of them,
    // including installed-but-stopped remote tools.
    DWORD need = 0, count = 0, resume = 0;
    std::vector<BYTE> buf(64 * 1024);
    bool ok = true;
    for (;;) {
        const BOOL r = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf.data(),
                                             static_cast<DWORD>(buf.size()), &need, &count, &resume, nullptr);
        const DWORD e = r ? ERROR_SUCCESS : GetLastError();
        if (!r && e != ERROR_MORE_DATA) {
            ok = false;
            f.servicesRd = e == ERROR_ACCESS_DENIED ? Rd::Denied : Rd::Error;
            break;
        }
        const auto* arr = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count && f.services.size() < 4096; ++i) {
            SvcEntry s;
            s.name = lower(narrow(arr[i].lpServiceName));
            s.state = stateName(arr[i].ServiceStatusProcess.dwCurrentState);
            s.pid = arr[i].ServiceStatusProcess.dwProcessId;
            if (!s.name.empty()) f.services.push_back(std::move(s));
        }
        if (r) break;
        // ERROR_MORE_DATA: resume continues; grow towards what was asked, capped.
        if (need > buf.size()) {
            if (need > 1024 * 1024) {
                ok = false;
                f.servicesRd = Rd::Error;
                break;
            }
            buf.resize(need);
        }
    }
    if (ok) {
        f.servicesRd = Rd::Ok;
        for (auto& s : f.services) {
            bool want = false;
            for (const auto& pat : in.startTypeFor) want = want || nameMatches(pat, s.name);
            if (!want) continue;
            std::wstring wn;
            const int n = MultiByteToWideChar(CP_UTF8, 0, s.name.c_str(), -1, nullptr, 0);  // flawfinder: ignore -- length from the sizing call; buffer allocated to that size
            if (n > 1) {
                wn.assign(static_cast<size_t>(n), L'\0');
                MultiByteToWideChar(CP_UTF8, 0, s.name.c_str(), -1, &wn[0], n);  // flawfinder: ignore -- length from the sizing call; buffer allocated to that size
                wn.resize(static_cast<size_t>(n - 1));
                s.start = startTypeOf(scm, wn);
            }
        }
    }
    f.srv1 = driverFact(scm, L"srv");
    f.mrxsmb10 = driverFact(scm, L"mrxsmb10");
    CloseServiceHandle(scm);
}

void collectShares(PostureFacts& f) {
    LPBYTE buf = nullptr;
    DWORD entries = 0, total = 0, resume = 0;
    const NET_API_STATUS st = NetShareEnum(nullptr, 1, &buf, MAX_PREFERRED_LENGTH, &entries, &total, &resume);
    if (st == 2114 /* NERR_ServerNotStarted */) {
        f.shares.rd = Rd::Ok;   // nothing is shared while the Server service is stopped
        if (buf) NetApiBufferFree(buf);
        return;
    }
    if (st != NERR_Success && st != ERROR_MORE_DATA) {
        f.shares.rd = st == ERROR_ACCESS_DENIED ? Rd::Denied : Rd::Error;
        if (buf) NetApiBufferFree(buf);
        return;
    }
    const auto* si = reinterpret_cast<const SHARE_INFO_1*>(buf);
    for (DWORD i = 0; i < entries; ++i) {
        std::string name = narrow(si[i].shi1_netname);
        for (char& c : name) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        const DWORD type = si[i].shi1_type & 0xFF;
        const bool special = (si[i].shi1_type & STYPE_SPECIAL) != 0;
        if (type == STYPE_IPC) f.shares.ipc = true;
        else if (name == "PRINT$") f.shares.print = true;
        else if (type == STYPE_DISKTREE && special) f.shares.adminShares.push_back(name);   // C$, ADMIN$
        else if (type == STYPE_DISKTREE) ++f.shares.otherDisk;                               // counted, never named
    }
    std::sort(f.shares.adminShares.begin(), f.shares.adminShares.end());
    f.shares.rd = st == ERROR_MORE_DATA ? Rd::Error : Rd::Ok;
    if (buf) NetApiBufferFree(buf);
}

// Counts enabled inbound allow rules for echo in one rule store.
Rd countEchoRules(const wchar_t* path, int& count) {
    HKEY k = nullptr;
    const LONG e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k);
    if (e != ERROR_SUCCESS) return rdFromError(e);
    std::vector<wchar_t> name(512), data(4096);
    for (DWORD i = 0; i < 5000; ++i) {
        DWORD nl = static_cast<DWORD>(name.size()), dl = static_cast<DWORD>(data.size() * sizeof(wchar_t) - sizeof(wchar_t)), type = 0;
        const LONG q = RegEnumValueW(k, i, name.data(), &nl, nullptr, &type, reinterpret_cast<LPBYTE>(data.data()), &dl);
        if (q == ERROR_NO_MORE_ITEMS) break;
        if (q != ERROR_SUCCESS || type != REG_SZ) continue;   // an over-long rule is skipped, not an error
        data[std::min<size_t>(dl / sizeof(wchar_t), data.size() - 1)] = L'\0';
        if (firewallRuleAllowsEcho(narrow(data.data()))) ++count;
    }
    RegCloseKey(k);
    return Rd::Ok;
}

void collectNetbt(PostureFacts& f) {
    HKEY k = nullptr;
    const LONG e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces", 0,
                                 KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k);
    if (e != ERROR_SUCCESS) {
        // NetBT not installed at all: nothing to disable.
        f.netbt.rd = e == ERROR_FILE_NOT_FOUND ? Rd::Ok : rdFromError(e);
        return;
    }
    wchar_t sub[256];  // flawfinder: ignore -- RegEnumKeyExW bounded by the length passed
    for (DWORD i = 0; i < 256; ++i) {
        DWORD sl = sizeof(sub) / sizeof(sub[0]);
        const LONG q = RegEnumKeyExW(k, i, sub, &sl, nullptr, nullptr, nullptr, nullptr);
        if (q == ERROR_NO_MORE_ITEMS) break;
        if (q != ERROR_SUCCESS) continue;
        const std::wstring path = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\") + sub;
        const RegDword o = regDword(path.c_str(), L"NetbiosOptions");
        ++f.netbt.interfaces;
        // 2 = disabled. 0 (DHCP decides) and 1 (enabled) both leave it on.
        if (!(o.rd == Rd::Ok && o.v == 2)) ++f.netbt.notDisabled;
    }
    RegCloseKey(k);
    f.netbt.rd = Rd::Ok;
}

int portOf(DWORD p) { return static_cast<int>(((p & 0xFF) << 8) | ((p >> 8) & 0xFF)); }

// dwLocalAddr holds the address in network byte order; on x64 (little-endian,
// the only target) its lowest byte is the first octet.
std::string ipv4(DWORD a) {
    char s[20];  // flawfinder: ignore -- written only by snprintf(s, sizeof(s), ...)
    (void)std::snprintf(s, sizeof(s), "%lu.%lu.%lu.%lu", a & 0xFFul, (a >> 8) & 0xFFul, (a >> 16) & 0xFFul, (a >> 24) & 0xFFul);
    return s;
}

// RFC 5952 text: lower-case hex, longest run of zero groups (2+) as "::".
std::string ipv6(const UCHAR* a) {
    unsigned g[8];
    for (int i = 0; i < 8; ++i) g[i] = (static_cast<unsigned>(a[2 * i]) << 8) | a[2 * i + 1];
    int bestS = -1, bestL = 0;
    for (int i = 0; i < 8;) {
        if (g[i] != 0) { ++i; continue; }
        int j = i;
        while (j < 8 && g[j] == 0) ++j;
        if (j - i > bestL && j - i >= 2) { bestS = i; bestL = j - i; }
        i = j;
    }
    std::string s;
    for (int i = 0; i < 8; ++i) {
        if (i == bestS) {
            s += "::";
            i += bestL - 1;
            continue;
        }
        if (!s.empty() && s.back() != ':') s += ":";
        char h[8];  // flawfinder: ignore -- written only by snprintf(h, sizeof(h), ...)
        (void)std::snprintf(h, sizeof(h), "%x", g[i]);
        s += h;
    }
    return s.empty() ? "::" : s;
}

bool readTable(ULONG family, bool tcp, std::vector<BYTE>& buf) {
    DWORD size = 0;
    for (int attempt = 0; attempt < 4; ++attempt) {
        const DWORD r = tcp ? GetExtendedTcpTable(buf.empty() ? nullptr : buf.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0)
                            : GetExtendedUdpTable(buf.empty() ? nullptr : buf.data(), &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
        if (r == NO_ERROR) return true;
        if (r != ERROR_INSUFFICIENT_BUFFER || size > 4 * 1024 * 1024) return false;
        buf.resize(size + 1024);   // the table can grow between the two calls
    }
    return false;
}

std::string processName(unsigned long pid, const std::map<unsigned long, std::string>& known) {
    if (pid == 0) return "idle";
    if (pid == 4) return "system";
    auto it = known.find(pid);
    if (it != known.end()) return it->second;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return std::string();
    wchar_t path[MAX_PATH] = {0};  // flawfinder: ignore -- QueryFullProcessImageNameW bounded by n
    DWORD n = MAX_PATH;
    std::string name;
    if (QueryFullProcessImageNameW(h, 0, path, &n)) {
        // File name only: a path can carry a user profile folder.
        const std::string full = narrow(path);
        const size_t slash = full.find_last_of("\\/");
        name = lower(slash == std::string::npos ? full : full.substr(slash + 1));
    }
    CloseHandle(h);
    return name;
}

void collectListeners(const PostureCollectInput& in, PostureFacts& f) {
    std::map<unsigned long, std::string> svcByPid;
    for (const auto& s : f.services)
        if (s.pid) svcByPid[s.pid] += (svcByPid[s.pid].empty() ? "" : "+") + s.name;
    std::map<unsigned long, std::string> names = in.pidNames;
    auto add = [&](const char* proto, bool v6, const std::string& addr, int port, unsigned long pid) {
        if (f.listeners.size() >= 2048) return;
        Listener l;
        l.proto = proto;
        l.v6 = v6;
        l.addr = addr;
        l.port = port;
        l.pid = pid;
        auto it = names.find(pid);
        if (it == names.end()) it = names.emplace(pid, processName(pid, in.pidNames)).first;
        l.process = it->second;
        auto sv = svcByPid.find(pid);
        if (sv != svcByPid.end()) l.service = sv->second;
        f.listeners.push_back(std::move(l));
    };

    std::vector<BYTE> b4, b6;
    const bool t4 = readTable(AF_INET, true, b4);
    const bool t6 = readTable(AF_INET6, true, b6);
    if (t4) {
        const auto* t = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(b4.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i)
            add("tcp", false, ipv4(t->table[i].dwLocalAddr), portOf(t->table[i].dwLocalPort), t->table[i].dwOwningPid);
    }
    if (t6) {
        const auto* t = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(b6.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i)
            add("tcp", true, ipv6(t->table[i].ucLocalAddr), portOf(t->table[i].dwLocalPort), t->table[i].dwOwningPid);
    }
    f.tcpRd = t4 && t6 ? Rd::Ok : Rd::Error;

    std::vector<BYTE> u4, u6;
    const bool ok4 = readTable(AF_INET, false, u4);
    const bool ok6 = readTable(AF_INET6, false, u6);
    // Dynamic-range UDP sockets are client sockets (DNS lookups and the like)
    // in all but name. Listing them would make RA-020 change every minute.
    auto udp = [&](bool v6, const std::string& addr, int port, unsigned long pid) {
        if (port >= 49152) { ++f.udpEphemeral; return; }
        add("udp", v6, addr, port, pid);
    };
    if (ok4) {
        const auto* t = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(u4.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) udp(false, ipv4(t->table[i].dwLocalAddr), portOf(t->table[i].dwLocalPort), t->table[i].dwOwningPid);
    }
    if (ok6) {
        const auto* t = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(u6.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) udp(true, ipv6(t->table[i].ucLocalAddr), portOf(t->table[i].dwLocalPort), t->table[i].dwOwningPid);
    }
    f.udpRd = ok4 && ok6 ? Rd::Ok : Rd::Error;
}

bool elevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION te{};
    DWORD sz = 0;
    const bool ok = GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &sz) && te.TokenIsElevated;
    CloseHandle(tok);
    return ok;
}

std::string utcNow() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char b[32];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), ...)
    (void)std::snprintf(b, sizeof(b), "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

}  // namespace

std::vector<std::string> postureStartTypeServices() {
    return {"termservice", "tlntsvr", "sshd", "winrm", "lanmanserver", "remoteregistry",
            "snmp", "ftpsvc", "msftpsvc", "tftpd", "mpssvc"};
}

void collectPosture(const PostureCollectInput& in, PostureFacts& f) {
    f = PostureFacts();
    f.takenAtUtc = utcNow();
    f.elevated = elevated();

    const wchar_t* tsPol = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services";
    const wchar_t* tsLoc = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
    const wchar_t* rdpTcp = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";
    f.rdpDenyPolicy = regDword(tsPol, L"fDenyTSConnections");
    f.rdpDenyLocal = regDword(tsLoc, L"fDenyTSConnections");
    f.rdpPort = regDword(rdpTcp, L"PortNumber");
    f.nlaPolicy = regDword(tsPol, L"UserAuthentication");
    f.nlaLocal = regDword(rdpTcp, L"UserAuthentication");
    f.secLayerPolicy = regDword(tsPol, L"SecurityLayer");
    f.secLayerLocal = regDword(rdpTcp, L"SecurityLayer");
    f.encLevelPolicy = regDword(tsPol, L"MinEncryptionLevel");
    f.encLevelLocal = regDword(rdpTcp, L"MinEncryptionLevel");
    f.raPolicy = regDword(tsPol, L"fAllowToGetHelp");
    f.raLocal = regDword(L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", L"fAllowToGetHelp");

    collectServices(in, f);

    f.telnetExe = systemFile(L"telnet.exe");
    f.powershellExe = systemFile(L"WindowsPowerShell\\v1.0\\powershell.exe");
    f.psPolicyGpo = regText(L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", L"ExecutionPolicy");
    f.psEnableScriptsGpo = regDword(L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", L"EnableScripts");
    f.psPolicyLocal = regText(L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"ExecutionPolicy");

    collectShares(f);
    const wchar_t* lms = L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters";
    f.autoShareWks = regDword(lms, L"AutoShareWks");
    f.autoShareServer = regDword(lms, L"AutoShareServer");
    f.smb1Server = regDword(lms, L"SMB1");

    const wchar_t* fwp = L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\";
    const wchar_t* fwl = L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\";
    auto fw = [&](const wchar_t* prof) {
        FirewallProfileFact p;
        p.policy = regDword((std::wstring(fwp) + prof).c_str(), L"EnableFirewall");
        p.local = regDword((std::wstring(fwl) + prof).c_str(), L"EnableFirewall");
        return p;
    };
    f.fwDomain = fw(L"DomainProfile");
    f.fwPrivate = fw(L"StandardProfile");
    f.fwPublic = fw(L"PublicProfile");

    int echo = 0;
    const Rd local = countEchoRules(L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", echo);
    const Rd pol = countEchoRules(L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules", echo);
    f.icmpRd = (local == Rd::Ok || local == Rd::Absent) && (pol == Rd::Ok || pol == Rd::Absent) ? Rd::Ok
             : (local == Rd::Denied || pol == Rd::Denied) ? Rd::Denied : Rd::Error;
    f.icmpEchoAllowRules = echo;

    f.llmnrPolicy = regDword(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"EnableMulticast");
    collectNetbt(f);

    collectListeners(in, f);

    f.processesRd = in.processesValid ? Rd::Ok : Rd::Error;
    f.processes = in.processes;
}

bool tcpListenerSignature(std::string& sig) {
    std::vector<BYTE> b4, b6;
    if (!readTable(AF_INET, true, b4) || !readTable(AF_INET6, true, b6)) return false;
    std::set<std::string> s;
    const auto* t4 = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(b4.data());
    for (DWORD i = 0; i < t4->dwNumEntries; ++i) {
        const std::string a = ipv4(t4->table[i].dwLocalAddr);
        if (!isLoopbackAddr(a))
            s.insert(a + ":" + std::to_string(portOf(t4->table[i].dwLocalPort)) + "/" + std::to_string(t4->table[i].dwOwningPid));
    }
    const auto* t6 = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(b6.data());
    for (DWORD i = 0; i < t6->dwNumEntries; ++i) {
        const std::string a = ipv6(t6->table[i].ucLocalAddr);
        if (!isLoopbackAddr(a))
            s.insert("[" + a + "]:" + std::to_string(portOf(t6->table[i].dwLocalPort)) + "/" + std::to_string(t6->table[i].dwOwningPid));
    }
    sig.clear();
    for (const auto& x : s) sig += x + ",";
    return true;
}

}  // namespace ev
