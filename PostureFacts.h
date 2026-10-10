// Remote-access posture (3.4): facts, profile, results.
//
// SHARED WITH ATMProbe. The catalogue (RA-001 ... RA-020), the facts below and
// the evaluation in PostureEvaluate.cpp are the same code in both products, so
// the same facts give the same statuses. ATMProbe takes the one-time baseline;
// EdgeVitals keeps watching and reports what changes. Output shape:
// edgestack.posture.remote/1 (PostureJson.cpp).
//
// The set of files shared with ATMProbe, and the only files they depend on:
//   PostureFacts.h, PostureEvaluate.cpp, PostureJson.cpp      (pure C++17)
//   PostureCollect.h, PostureCollectWin.cpp                   (Win32 only)
//   Json.h/.cpp (profile reader), Digest.h/.cpp (SHA-256)     (pure C++17)
//
// RULES (same as the rest of EdgeVitals):
//   - observe only: nothing here changes a setting, stops a service or closes
//     a port. Enforcement belongs to EdgeBastion or the bank's own tools;
//   - no child processes, no network traffic, no personal data -- process
//     names are file names only, share names other than the Windows
//     administrative ones are counted, never recorded;
//   - a value that cannot be read is UNKNOWN with its reason. UNKNOWN is never
//     PASS, and nothing below defaults an unread value to a safe one.
#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ev {

// Outcome of one read. Absent is a real answer (the value or key does not
// exist); Denied and Error mean the question could not be asked.
enum class Rd : std::uint8_t { Ok, Absent, Denied, Error };
const char* rdName(Rd r);

struct RegDword {
    Rd rd = Rd::Error;
    std::uint32_t v = 0;
};
struct RegText {
    Rd rd = Rd::Error;
    std::string v;
};
struct FileFact {
    Rd rd = Rd::Error;     // Ok = exists, Absent = does not exist
};

// One installed service, from a single EnumServicesStatusExW pass. The name
// is the service key name, lower-cased ("termservice"), never the display
// name (localised and free text).
struct SvcEntry {
    std::string name;
    std::string state;       // stopped | start_pending | stop_pending | running | continue_pending | pause_pending | paused
    std::string start;       // boot | system | auto | demand | disabled | "" (not queried or unreadable)
    unsigned long pid = 0;   // 0 unless running
};

// A driver service (srv, mrxsmb10): queried by name, not enumerated.
struct DriverFact {
    Rd rd = Rd::Error;       // Absent = not installed
    std::string start;
    std::string state;
};

struct Listener {
    std::string proto;       // tcp | udp
    bool v6 = false;
    std::string addr;        // 0.0.0.0, 127.0.0.1, ::, ::1, 10.1.2.3 ...
    int port = 0;
    unsigned long pid = 0;
    std::string process;     // lower-cased file name, "" when unreadable
    std::string service;     // owning service(s) in that pid, '+'-joined, "" when none
};

struct ShareFact {
    Rd rd = Rd::Error;
    std::vector<std::string> adminShares;   // C$, D$, ADMIN$ (upper-cased, sorted)
    bool ipc = false;                       // IPC$
    bool print = false;                     // print$
    int otherDisk = 0;                      // non-administrative disk shares: COUNT ONLY (a share name can be a person's name)
};

struct NetbtFact {
    Rd rd = Rd::Error;
    int interfaces = 0;
    int notDisabled = 0;     // NetbiosOptions != 2
};

struct FirewallProfileFact {
    RegDword policy;         // HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<P>\EnableFirewall
    RegDword local;          // ...\SharedAccess\Parameters\FirewallPolicy\<P>\EnableFirewall
};

struct PostureFacts {
    std::string takenAtUtc;           // 2026-10-07T13:10:12Z
    bool elevated = false;            // collected with an administrator / SYSTEM token

    // RA-001 / RA-004
    RegDword rdpDenyPolicy, rdpDenyLocal;
    RegDword rdpPort;                 // RDP-Tcp\PortNumber
    RegDword nlaPolicy, nlaLocal;     // UserAuthentication
    RegDword secLayerPolicy, secLayerLocal;
    RegDword encLevelPolicy, encLevelLocal;   // MinEncryptionLevel
    // RA-005
    RegDword raPolicy, raLocal;       // fAllowToGetHelp
    // Services (RA-002, 006, 008, 009, 010, 012, 013, 014, 015, 017)
    Rd servicesRd = Rd::Error;
    std::vector<SvcEntry> services;
    // RA-007, RA-016
    FileFact telnetExe, powershellExe;
    RegText psPolicyGpo, psPolicyLocal;
    RegDword psEnableScriptsGpo;
    // RA-010 / RA-011
    ShareFact shares;
    RegDword autoShareWks, autoShareServer;
    RegDword smb1Server;              // LanmanServer\Parameters\SMB1
    DriverFact srv1, mrxsmb10;
    // RA-017 / RA-018
    FirewallProfileFact fwDomain, fwPrivate, fwPublic;
    Rd icmpRd = Rd::Error;
    int icmpEchoAllowRules = 0;       // enabled inbound allow rules for ICMPv4/v6 echo
    // RA-019
    RegDword llmnrPolicy;             // DNSClient\EnableMulticast
    NetbtFact netbt;
    // RA-020
    Rd tcpRd = Rd::Error, udpRd = Rd::Error;
    std::vector<Listener> listeners;
    int udpEphemeral = 0;             // UDP sockets in the dynamic range: counted, not listed
    // RA-013 (the agent's own enumeration, reused)
    Rd processesRd = Rd::Error;
    std::vector<std::string> processes;   // lower-cased exe file names

    const SvcEntry* service(const std::string& lowerName) const;
};

// ── profile: config/posture-profile.json, the same file ATMProbe reads ─────

struct ListenerAllow {
    std::string proto;       // tcp | udp | "" = either
    std::string addr;        // exact, "*" = any, "loopback", "any" (0.0.0.0 / ::)
    int portLo = 0, portHi = 0;
    std::string process;     // lower-cased, "" = any
    std::string service;     // lower-cased, "" = any
    std::string note;
};

struct RemoteTool {
    std::string name;                       // "teamviewer"
    std::vector<std::string> services;      // lower-cased; trailing '*' = prefix
    std::vector<std::string> processes;     // lower-cased; trailing '*' = prefix
};

struct PostureProfile {
    std::string name = "default";
    std::string rdp = "deny";               // deny | allow_hardened
    bool allowIpcShare = false;
    bool thirdPartyFirewall = false;        // a vendor firewall replaces Windows Firewall
    std::string powershell = "info";        // info | restrict | deny
    std::string snmp = "deny";              // deny | allow
    std::vector<std::string> remoteToolsAllow;   // tool names, lower-cased
    std::vector<ListenerAllow> listenerAllow;
    std::vector<RemoteTool> remoteTools;    // catalogue: built-in list + profile additions
};
PostureProfile defaultPostureProfile();
std::vector<RemoteTool> defaultRemoteTools();

// ── results ─────────────────────────────────────────────────────────────────

enum class PStatus : std::uint8_t { Pass, Info, Warn, Fail, Unknown };
const char* statusName(PStatus s);

struct PostureResult {
    std::string id;          // RA-001
    std::string title;
    PStatus status = PStatus::Unknown;
    std::string severity;    // high | medium | low | info
    std::string summary;     // one line, for the agent log
    std::string flag;        // short code for the CSV (RDP, SMBADM, ...)
    // What the status rests on, canonical. A change is a change of status OR
    // of key: a second unexpected listener while RA-020 is already FAIL is
    // news, and status alone would hide it.
    std::string key;
    std::string observed;    // JSON object text
};

// The 20 checks, in catalogue order. Pure: same facts and profile, same results.
std::vector<PostureResult> evaluatePosture(const PostureFacts& f, const PostureProfile& p);

struct PostureSummary {
    int fail = 0, warn = 0, pass = 0, info = 0, unknown = 0;
};
PostureSummary summarize(const std::vector<PostureResult>& r);
// "RDP|SMBADM": flags of FAIL results, catalogue order. Empty when none fail.
std::string failFlags(const std::vector<PostureResult>& r);

// ── helpers, exposed for tests ──────────────────────────────────────────────

bool isLoopbackAddr(const std::string& addr);
bool isAnyAddr(const std::string& addr);
bool listenerAllowed(const Listener& l, const std::vector<ListenerAllow>& allow);
// Wildcard match: pattern may end in '*'. Both sides already lower-case.
bool nameMatches(const std::string& pattern, const std::string& name);
// Windows Firewall rule value text ("v2.30|Action=Allow|Active=TRUE|Dir=In|
// Protocol=1|ICMP4=8:*|...") -> true for an active inbound allow of echo.
bool firewallRuleAllowsEcho(const std::string& rule);
// SCM 7036 carries the service key name in its <Binary> as UTF-16LE hex,
// "TermService/4". Returns the lower-cased name before '/', or "".
std::string serviceNameFromScmBinary(const std::string& hex);

// ── JSON (PostureJson.cpp) ──────────────────────────────────────────────────

class Json;
// h is the parsed profile document. Unknown keys are ignored; a wrong type
// leaves the default. Errors only for values that would weaken the check
// silently (an unknown rdp mode).
bool parsePostureProfile(const Json& h, PostureProfile& out, std::string& err);

std::string jsonQuote(const std::string& s);
std::string summaryJson(const PostureSummary& s);
std::string checksJson(const std::vector<PostureResult>& r);
// sha256:<hex> over id/status/key of every result: equal digests mean equal
// posture. Carried in heartbeats as proof of "checked, unchanged".
std::string postureDigest(const std::vector<PostureResult>& r);

constexpr const char* kPostureSchema = "edgestack.posture.remote/1";

}  // namespace ev
