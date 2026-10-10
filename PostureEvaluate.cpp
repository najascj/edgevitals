// Remote-access posture: evaluation. Pure C++17, tested on any host
// (evposturetest). Shared with ATMProbe -- see PostureFacts.h.
//
// Every check follows the same discipline:
//   - a fact that could not be read makes the check UNKNOWN, with the reason
//     in "observed"; nothing is assumed to be the safe value;
//   - a policy value (HKLM\SOFTWARE\Policies) wins over the local one, and an
//     unreadable policy key is UNKNOWN, because it might have been the winner;
//   - the summary says what was seen in words an operator can act on.
#include "edgevitals/PostureFacts.h"

#include <algorithm>
#include <cctype>

namespace ev {
namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Builds a JSON object one member at a time. Values are already JSON.
class Obj {
public:
    Obj& raw(const std::string& k, const std::string& jsonValue) {
        body_ += (body_.empty() ? "" : ",") + jsonQuote(k) + ":" + jsonValue;
        return *this;
    }
    Obj& str(const std::string& k, const std::string& v) { return raw(k, jsonQuote(v)); }
    Obj& num(const std::string& k, long long v) { return raw(k, std::to_string(v)); }
    Obj& flag(const std::string& k, bool v) { return raw(k, v ? "true" : "false"); }
    Obj& reg(const std::string& k, const RegDword& r) {
        return r.rd == Rd::Ok ? num(k, static_cast<long long>(r.v)) : str(k, rdName(r.rd));
    }
    std::string done() const { return "{" + body_ + "}"; }

private:
    std::string body_;
};

std::string arr(const std::vector<std::string>& jsonValues) {
    std::string o;
    for (const auto& v : jsonValues) o += (o.empty() ? "" : ",") + v;
    return "[" + o + "]";
}

std::string strArr(const std::vector<std::string>& v) {
    std::vector<std::string> q;
    q.reserve(v.size());
    for (const auto& s : v) q.push_back(jsonQuote(s));
    return arr(q);
}

std::string join(const std::vector<std::string>& v, const char* sep) {
    std::string o;
    for (const auto& s : v) o += (o.empty() ? "" : sep) + s;
    return o;
}

// Policy wins when present. An unreadable policy key leaves the answer
// unknown: it might have been the value that applied.
struct Eff {
    Rd rd = Rd::Error;
    std::uint32_t v = 0;
    const char* src = "";
};
Eff effective(const RegDword& policy, const RegDword& local) {
    if (policy.rd == Rd::Ok) return {Rd::Ok, policy.v, "policy"};
    if (policy.rd == Rd::Denied || policy.rd == Rd::Error) return {policy.rd, 0, "policy"};
    if (local.rd == Rd::Ok) return {Rd::Ok, local.v, "local"};
    return {local.rd, 0, "local"};
}

std::string unknownWhy(const char* what, Rd rd) {
    return std::string(what) + " " + (rd == Rd::Absent ? "absent" : rd == Rd::Denied ? "access denied" : "unreadable");
}

PostureResult mk(const char* id, const char* title, const char* severity, const char* flag) {
    PostureResult r;
    r.id = id;
    r.title = title;
    r.severity = severity;
    r.flag = flag;
    return r;
}

void set(PostureResult& r, PStatus s, const std::string& summary, const std::string& key, const std::string& observed) {
    r.status = s;
    r.summary = summary;
    r.key = key;
    r.observed = observed;
}

bool running(const SvcEntry* s) {
    return s && (s->state == "running" || s->state == "start_pending" || s->state == "continue_pending");
}

std::string svcWords(const std::string& label, const SvcEntry* s) {
    if (!s) return label + " not installed";
    return label + " " + s->state + (s->start.empty() ? "" : " (start " + s->start + ")");
}

std::string svcObs(const SvcEntry* s) {
    if (!s) return "\"not_installed\"";
    return Obj().str("state", s->state).str("start", s->start.empty() ? "unread" : s->start).done();
}

std::string listenerText(const Listener& l) {
    std::string a = l.v6 ? "[" + l.addr + "]" : l.addr;
    std::string who = l.process.empty() ? "pid " + std::to_string(l.pid) : l.process;
    if (!l.service.empty()) who += " / " + l.service;
    return l.proto + " " + a + ":" + std::to_string(l.port) + " (" + who + ")";
}

std::string listenerKey(const Listener& l) {
    return l.proto + " " + (l.v6 ? "[" + l.addr + "]" : l.addr) + ":" + std::to_string(l.port) + " " + l.process;
}

std::string listenerObs(const Listener& l) {
    return Obj().str("proto", l.proto).str("addr", l.addr).num("port", l.port).str("process", l.process)
        .str("service", l.service).done();
}

// Listeners on any of the ports (proto-specific). Fills exposed (non-loopback)
// and local (loopback) lists.
void onPorts(const PostureFacts& f, const std::vector<int>& tcp, const std::vector<int>& udp,
             std::vector<const Listener*>& exposed, std::vector<const Listener*>& local) {
    for (const auto& l : f.listeners) {
        const auto& ports = l.proto == "tcp" ? tcp : udp;
        if (std::find(ports.begin(), ports.end(), l.port) == ports.end()) continue;
        (isLoopbackAddr(l.addr) ? local : exposed).push_back(&l);
    }
}

// A remote-capable server: installed service(s) plus the ports it listens on.
//   running, or anything exposed on its ports         -> FAIL (severity)
//   loopback-only listener                             -> INFO
//   installed, not disabled                            -> WARN low if optional add-on, else PASS
//   installed, disabled / not installed                -> PASS
struct ServerSpec {
    const char* id;
    const char* title;
    const char* severity;
    const char* flag;
    const char* label;
    std::vector<std::string> services;
    std::vector<int> tcp, udp;
    bool addOn;          // optional component: present at all is worth a WARN
    bool allowed;        // profile permits it: FAIL becomes INFO
    bool runningIsFail = true;   // false: only an exposed listener fails (WinRM)
};

PostureResult serverCheck(const PostureFacts& f, const ServerSpec& s) {
    PostureResult r = mk(s.id, s.title, s.severity, s.flag);
    const bool needTcp = !s.tcp.empty(), needUdp = !s.udp.empty();
    if (f.servicesRd != Rd::Ok) {
        set(r, PStatus::Unknown, std::string(s.label) + ": " + unknownWhy("service list", f.servicesRd), "unknown",
            Obj().str("reason", unknownWhy("service list", f.servicesRd)).done());
        return r;
    }
    if ((needTcp && f.tcpRd != Rd::Ok) || (needUdp && f.udpRd != Rd::Ok)) {
        const Rd bad = needTcp && f.tcpRd != Rd::Ok ? f.tcpRd : f.udpRd;
        set(r, PStatus::Unknown, std::string(s.label) + ": " + unknownWhy("socket table", bad), "unknown",
            Obj().str("reason", unknownWhy("socket table", bad)).done());
        return r;
    }
    const SvcEntry* svc = nullptr;
    std::vector<std::string> svcObsList;
    for (const auto& n : s.services) {
        const SvcEntry* e = f.service(n);
        svcObsList.push_back(jsonQuote(n) + ":" + svcObs(e));
        if (e && (!svc || running(e))) svc = e;
    }
    std::vector<const Listener*> exposed, local;
    onPorts(f, s.tcp, s.udp, exposed, local);

    std::vector<std::string> lst, lkeys;
    for (const Listener* l : exposed) {
        lst.push_back(listenerObs(*l));
        lkeys.push_back(listenerKey(*l));
    }
    std::sort(lkeys.begin(), lkeys.end());
    const std::string obs = "{\"services\":{" + join(svcObsList, ",") + "},\"exposed\":" + arr(lst) +
                            ",\"loopback\":" + std::to_string(local.size()) + "}";

    if ((s.runningIsFail && running(svc)) || !exposed.empty()) {
        std::string why = running(svc) ? svcWords(s.label, svc) : std::string(s.label);
        if (!exposed.empty()) why += ", listening on " + listenerText(*exposed.front());
        if (exposed.size() > 1) why += " +" + std::to_string(exposed.size() - 1);
        set(r, s.allowed ? PStatus::Info : PStatus::Fail, why + (s.allowed ? " (allowed by profile)" : ""),
            "on|" + (svc ? svc->state : std::string("-")) + "|" + join(lkeys, ","), obs);
        return r;
    }
    if (!local.empty()) {
        set(r, PStatus::Info, std::string(s.label) + " listening on loopback only", "loopback", obs);
        return r;
    }
    if (svc && svc->start != "disabled") {
        if (svc->start.empty()) {
            set(r, PStatus::Unknown, svcWords(s.label, svc) + "; start type unreadable", "unknown", obs);
            return r;
        }
        set(r, s.addOn ? PStatus::Warn : PStatus::Pass, svcWords(s.label, svc) + (s.addOn ? ": installed -- remove or disable" : ""),
            "installed|" + svc->start, obs);
        if (s.addOn) r.severity = "low";
        return r;
    }
    set(r, PStatus::Pass, svc ? svcWords(s.label, svc) : std::string(s.label) + " not installed",
        svc ? "disabled" : "absent", obs);
    return r;
}

}  // namespace

// ── small public helpers ────────────────────────────────────────────────────

const char* rdName(Rd r) {
    switch (r) {
        case Rd::Ok: return "ok";
        case Rd::Absent: return "absent";
        case Rd::Denied: return "denied";
        default: return "error";
    }
}

const char* statusName(PStatus s) {
    switch (s) {
        case PStatus::Pass: return "PASS";
        case PStatus::Info: return "INFO";
        case PStatus::Warn: return "WARN";
        case PStatus::Fail: return "FAIL";
        default: return "UNKNOWN";
    }
}

const SvcEntry* PostureFacts::service(const std::string& lowerName) const {
    for (const auto& s : services)
        if (s.name == lowerName) return &s;
    return nullptr;
}

bool isLoopbackAddr(const std::string& a) {
    return a == "::1" || a.rfind("127.", 0) == 0 || a.rfind("::ffff:127.", 0) == 0;
}

bool isAnyAddr(const std::string& a) { return a == "0.0.0.0" || a == "::"; }

bool nameMatches(const std::string& pattern, const std::string& name) {
    if (pattern.empty()) return false;
    if (pattern.back() == '*') return name.compare(0, pattern.size() - 1, pattern, 0, pattern.size() - 1) == 0;
    return pattern == name;
}

bool listenerAllowed(const Listener& l, const std::vector<ListenerAllow>& allow) {
    for (const auto& a : allow) {
        if (!a.proto.empty() && a.proto != l.proto) continue;
        if (l.port < a.portLo || l.port > a.portHi) continue;
        if (!a.addr.empty() && a.addr != "*") {
            if (a.addr == "loopback") { if (!isLoopbackAddr(l.addr)) continue; }
            else if (a.addr == "any") { if (!isAnyAddr(l.addr)) continue; }
            else if (a.addr != l.addr) continue;
        }
        if (!a.process.empty() && !nameMatches(a.process, l.process)) continue;
        if (!a.service.empty()) {
            // Owning services are '+'-joined: allowed if any of them matches.
            bool any = false;
            size_t p = 0;
            while (p <= l.service.size() && !any) {
                const size_t e = l.service.find('+', p);
                const std::string one = l.service.substr(p, e == std::string::npos ? std::string::npos : e - p);
                any = nameMatches(a.service, one);
                if (e == std::string::npos) break;
                p = e + 1;
            }
            if (!any) continue;
        }
        return true;
    }
    return false;
}

bool firewallRuleAllowsEcho(const std::string& rule) {
    bool allow = false, active = false, in = false, echo = false;
    size_t p = 0;
    while (p < rule.size()) {
        size_t e = rule.find('|', p);
        if (e == std::string::npos) e = rule.size();
        const std::string kv = rule.substr(p, e - p);
        const size_t eq = kv.find('=');
        if (eq != std::string::npos) {
            const std::string k = lower(kv.substr(0, eq)), v = lower(kv.substr(eq + 1));
            if (k == "action") allow = v == "allow";
            else if (k == "active") active = v == "true";
            else if (k == "dir") in = v == "in";
            else if ((k == "icmp4" && (v.rfind("8:", 0) == 0 || v == "8")) ||
                     (k == "icmp6" && (v.rfind("128:", 0) == 0 || v == "128")))
                echo = true;
        }
        p = e + 1;
    }
    return allow && active && in && echo;
}

std::string serviceNameFromScmBinary(const std::string& hex) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    for (size_t i = 0; i + 3 < hex.size() && out.size() < 256; i += 4) {
        const int a = nib(hex[i]), b = nib(hex[i + 1]), c = nib(hex[i + 2]), d = nib(hex[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return std::string();
        const int lo = a * 16 + b, hi = c * 16 + d;
        if (hi != 0) return std::string();          // not ASCII: a key name never is
        if (lo == 0 || lo == '/') return lower(out);
        if (lo < 0x20 || lo > 0x7e) return std::string();
        out.push_back(static_cast<char>(lo));
    }
    return std::string();                            // no terminator: not the shape we know
}

// ── defaults ────────────────────────────────────────────────────────────────

std::vector<RemoteTool> defaultRemoteTools() {
    // Service key names and process file names, lower-cased; '*' = prefix.
    // Additions go in the profile ("remote_tools"); built-ins cannot be removed
    // there, only allowed ("remote_tools_allow"), so detection never shrinks.
    return {
        {"vnc", {"tvnserver", "uvnc_service", "winvnc*", "vncserver"}, {"winvnc.exe", "tvnserver.exe", "vncserver.exe", "vncserverui.exe", "winvnc4.exe"}},
        {"teamviewer", {"teamviewer*"}, {"teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe"}},
        {"anydesk", {"anydesk*"}, {"anydesk.exe"}},
        {"screenconnect", {"screenconnect client*", "connectwise control*"}, {"screenconnect.clientservice.exe", "screenconnect.windowsclient.exe"}},
        {"radmin", {"rserver3", "radmin*"}, {"rserver3.exe", "radmin.exe"}},
        {"dameware", {"dwmrcs"}, {"dwrcs.exe", "dwrcst.exe", "dwmrcs.exe"}},
        {"splashtop", {"splashtopremoteservice", "sshelper"}, {"srservice.exe", "srmanager.exe", "srserver.exe", "srfeature.exe"}},
        {"rustdesk", {"rustdesk"}, {"rustdesk.exe"}},
        {"logmein", {"logmein", "lmiguardiansvc", "logmeinrescue*"}, {"logmein.exe", "lmiguardiansvc.exe", "lmi_rescue*"}},
        {"chrome-remote-desktop", {"chromoting"}, {"remoting_host.exe"}},
        {"ammyy", {}, {"aa_v3.exe", "ammyy_admin.exe"}},
        {"netsupport", {"client32"}, {"client32.exe"}},
        {"ultraviewer", {"ultraviewservice"}, {"ultraviewer_service.exe", "ultraviewer_desktop.exe"}},
        {"remote-utilities", {"rmanservice"}, {"rutserv.exe", "rfusclient.exe"}},
        {"zoho-assist", {"zohoassist*", "zaservice"}, {"zaservice.exe", "zohotray.exe"}},
        {"quick-assist", {}, {"quickassist.exe"}},
        {"atera", {"ateraagent"}, {"ateraagent.exe"}},
        {"kaseya", {"kaseyaagent*"}, {"agentmon.exe"}},
    };
}

PostureProfile defaultPostureProfile() {
    PostureProfile p;
    p.remoteTools = defaultRemoteTools();
    // Seed. The Windows RPC core (endpoint mapper and the dynamic endpoints of
    // a handful of system processes) listens on every terminal and cannot be
    // turned off without breaking Windows; everything else that listens is a
    // finding until the bank allows it. Check the first baseline on a lab
    // terminal before rollout and adjust the profile file, not this code.
    p.listenerAllow = {
        {"tcp", "127.0.0.1", 8787, 8787, "", "", "EdgeSignal-Vision (ESV), loopback only"},
        {"tcp", "*", 135, 135, "svchost.exe", "rpcss", "RPC endpoint mapper (Windows)"},
        {"tcp", "*", 49152, 65535, "wininit.exe", "", "RPC dynamic endpoint (Windows)"},
        {"tcp", "*", 49152, 65535, "lsass.exe", "", "RPC dynamic endpoint (Windows)"},
        {"tcp", "*", 49152, 65535, "services.exe", "", "RPC dynamic endpoint (Windows)"},
        {"tcp", "*", 49152, 65535, "spoolsv.exe", "", "RPC dynamic endpoint (Windows)"},
        {"tcp", "*", 49152, 65535, "svchost.exe", "eventlog", "RPC dynamic endpoint (Windows)"},
        {"tcp", "*", 49152, 65535, "svchost.exe", "schedule", "RPC dynamic endpoint (Windows)"},
        {"udp", "*", 123, 123, "svchost.exe", "w32time", "Windows Time (NTP)"},
    };
    return p;
}

// ── the catalogue ───────────────────────────────────────────────────────────

std::vector<PostureResult> evaluatePosture(const PostureFacts& f, const PostureProfile& p) {
    std::vector<PostureResult> out;
    out.reserve(20);
    const bool rdpProfileAllows = p.rdp == "allow_hardened";

    // RA-001 RDP connections allowed. Effective value: policy over local.
    const Eff rdp = effective(f.rdpDenyPolicy, f.rdpDenyLocal);
    const bool rdpKnown = rdp.rd == Rd::Ok;
    const bool rdpAllowed = rdpKnown && rdp.v == 0;
    {
        PostureResult r = mk("RA-001", "RDP connections allowed", "high", "RDP");
        const std::string obs = Obj().str("connections", !rdpKnown ? "unknown" : rdpAllowed ? "allowed" : "denied")
                                    .str("source", rdp.src).reg("policy_fDenyTSConnections", f.rdpDenyPolicy)
                                    .reg("local_fDenyTSConnections", f.rdpDenyLocal).done();
        if (!rdpKnown)
            set(r, PStatus::Unknown, unknownWhy(rdp.src == std::string("policy") ? "RDP policy value" : "fDenyTSConnections", rdp.rd),
                "unknown", obs);
        else if (!rdpAllowed)
            set(r, PStatus::Pass, std::string("RDP connections denied (") + rdp.src + ")", std::string("denied|") + rdp.src, obs);
        else if (rdpProfileAllows)
            set(r, PStatus::Info, std::string("RDP connections allowed (") + rdp.src + ") -- profile allow_hardened",
                std::string("allowed|") + rdp.src, obs);
        else
            set(r, PStatus::Fail, std::string("RDP connections ALLOWED (") + rdp.src + ")", std::string("allowed|") + rdp.src, obs);
        out.push_back(r);
    }

    // RA-002 TermService. Running with connections denied is WARN: one
    // registry write away from open, and that write is what a support visit does.
    {
        PostureResult r = mk("RA-002", "Remote Desktop Services (TermService)", "medium", "TERMSVC");
        if (f.servicesRd != Rd::Ok) {
            set(r, PStatus::Unknown, unknownWhy("service list", f.servicesRd), "unknown",
                Obj().str("reason", unknownWhy("service list", f.servicesRd)).done());
        } else {
            const SvcEntry* s = f.service("termservice");
            const std::string obs = Obj().raw("termservice", svcObs(s)).done();
            const std::string key = s ? s->state + "|" + s->start : "absent";
            if (!running(s)) {
                set(r, PStatus::Pass, svcWords("TermService", s), key, obs);
            } else if (!rdpKnown) {
                set(r, PStatus::Unknown, svcWords("TermService", s) + "; RDP connection setting unreadable", key, obs);
            } else if (!rdpAllowed) {
                set(r, PStatus::Warn, svcWords("TermService", s) + "; connections denied", key, obs);
            } else if (rdpProfileAllows) {
                set(r, PStatus::Info, svcWords("TermService", s) + "; allowed by profile", key, obs);
            } else {
                r.severity = "high";
                set(r, PStatus::Fail, svcWords("TermService", s) + "; connections ALLOWED", key, obs);
            }
        }
        out.push_back(r);
    }

    // RA-003 RDP port listening.
    {
        PostureResult r = mk("RA-003", "RDP port listening", "high", "RDPLSN");
        const int port = f.rdpPort.rd == Rd::Ok && f.rdpPort.v > 0 && f.rdpPort.v < 65536 ? static_cast<int>(f.rdpPort.v) : 3389;
        const std::string portSrc = f.rdpPort.rd == Rd::Ok ? "RDP-Tcp\\PortNumber" : std::string("default (") + rdName(f.rdpPort.rd) + ")";
        if (f.tcpRd != Rd::Ok) {
            set(r, PStatus::Unknown, unknownWhy("TCP listener table", f.tcpRd), "unknown",
                Obj().num("port", port).str("port_source", portSrc).str("reason", unknownWhy("TCP listener table", f.tcpRd)).done());
        } else {
            std::vector<const Listener*> exposed, local;
            onPorts(f, {port}, {}, exposed, local);
            std::vector<std::string> lj, keys;
            for (const Listener* l : exposed) { lj.push_back(listenerObs(*l)); keys.push_back(listenerKey(*l)); }
            std::sort(keys.begin(), keys.end());
            const std::string obs = Obj().num("port", port).str("port_source", portSrc).raw("exposed", arr(lj))
                                        .num("loopback", static_cast<long long>(local.size())).done();
            if (!exposed.empty())
                set(r, rdpProfileAllows ? PStatus::Info : PStatus::Fail,
                    "RDP listening on " + listenerText(*exposed.front()), "on|" + join(keys, ","), obs);
            else if (!local.empty())
                set(r, PStatus::Info, "RDP port " + std::to_string(port) + " listening on loopback only", "loopback", obs);
            else
                set(r, PStatus::Pass, "nothing listening on RDP port " + std::to_string(port), "off|" + std::to_string(port), obs);
        }
        out.push_back(r);
    }

    // RA-004 RDP hardening -- only meaningful when RDP is allowed.
    {
        PostureResult r = mk("RA-004", "RDP hardening (NLA, TLS, encryption)", "high", "RDPWEAK");
        const Eff nla = effective(f.nlaPolicy, f.nlaLocal);
        const Eff sl = effective(f.secLayerPolicy, f.secLayerLocal);
        const Eff enc = effective(f.encLevelPolicy, f.encLevelLocal);
        const std::string obs = Obj().reg("policy_UserAuthentication", f.nlaPolicy).reg("local_UserAuthentication", f.nlaLocal)
                                    .reg("policy_SecurityLayer", f.secLayerPolicy).reg("local_SecurityLayer", f.secLayerLocal)
                                    .reg("policy_MinEncryptionLevel", f.encLevelPolicy).reg("local_MinEncryptionLevel", f.encLevelLocal)
                                    .flag("applicable", rdpAllowed).done();
        if (!rdpKnown) {
            set(r, PStatus::Unknown, "RDP connection setting unreadable", "unknown", obs);
        } else if (!rdpAllowed) {
            set(r, PStatus::Pass, "not applicable: RDP connections denied", "n/a", obs);
        } else if (nla.rd != Rd::Ok || sl.rd != Rd::Ok || enc.rd != Rd::Ok) {
            set(r, PStatus::Unknown, "RDP allowed; hardening values unreadable", "unknown", obs);
        } else {
            std::vector<std::string> weak;
            if (nla.v != 1) weak.push_back("NLA off");
            if (sl.v < 2) weak.push_back(sl.v == 0 ? "RDP security layer (no TLS)" : "TLS negotiable");
            if (enc.v < 3) weak.push_back("encryption level " + std::to_string(enc.v) + " (below High)");
            const std::string key = std::to_string(nla.v) + "|" + std::to_string(sl.v) + "|" + std::to_string(enc.v);
            if (weak.empty())
                set(r, PStatus::Pass, "RDP allowed and hardened: NLA, TLS, encryption level " + std::to_string(enc.v), key, obs);
            else if (nla.v == 1 && sl.v >= 2) {
                r.severity = "medium";
                set(r, PStatus::Warn, "RDP allowed: " + join(weak, ", "), key, obs);
            } else
                set(r, PStatus::Fail, "RDP allowed and WEAK: " + join(weak, ", "), key, obs);
        }
        out.push_back(r);
    }

    // RA-005 Remote Assistance.
    {
        PostureResult r = mk("RA-005", "Remote Assistance", "medium", "RA");
        const Eff ra = effective(f.raPolicy, f.raLocal);
        const std::string obs = Obj().reg("policy_fAllowToGetHelp", f.raPolicy).reg("local_fAllowToGetHelp", f.raLocal).str("source", ra.src).done();
        if (ra.rd != Rd::Ok) set(r, PStatus::Unknown, unknownWhy("fAllowToGetHelp", ra.rd), "unknown", obs);
        else if (ra.v != 0) set(r, PStatus::Fail, std::string("Remote Assistance ALLOWED (") + ra.src + ")", std::string("on|") + ra.src, obs);
        else set(r, PStatus::Pass, std::string("Remote Assistance off (") + ra.src + ")", std::string("off|") + ra.src, obs);
        out.push_back(r);
    }

    // RA-006 Telnet server.
    out.push_back(serverCheck(f, {"RA-006", "Telnet server", "high", "TELNET", "Telnet server (TlntSvr)", {"tlntsvr"}, {23}, {}, true, false}));

    // RA-007 telnet.exe present (client: INFO only).
    {
        PostureResult r = mk("RA-007", "Telnet client present", "info", "");
        const std::string obs = Obj().str("telnet_exe", rdName(f.telnetExe.rd)).done();
        if (f.telnetExe.rd == Rd::Ok) set(r, PStatus::Info, "telnet.exe present (client)", "present", obs);
        else if (f.telnetExe.rd == Rd::Absent) set(r, PStatus::Pass, "telnet.exe not present", "absent", obs);
        else set(r, PStatus::Unknown, unknownWhy("System32 folder", f.telnetExe.rd), "unknown", obs);
        out.push_back(r);
    }

    // RA-008 OpenSSH server.
    out.push_back(serverCheck(f, {"RA-008", "OpenSSH server", "high", "SSH", "OpenSSH server (sshd)", {"sshd"}, {22}, {}, true, false}));

    // RA-009 WinRM. Its listener belongs to http.sys (PID 4), so exposure is
    // judged by port, not by owning process.
    out.push_back(serverCheck(f, {"RA-009", "WinRM", "high", "WINRM", "WinRM", {"winrm"}, {5985, 5986}, {}, false, false, false}));
    {
        // Running without an exposed listener: a WARN, not a PASS -- one
        // "winrm quickconfig" away from open.
        PostureResult& r = out.back();
        const SvcEntry* w = f.service("winrm");
        if (r.status == PStatus::Pass && running(w)) {
            r.status = PStatus::Warn;
            r.severity = "medium";
            r.summary = svcWords("WinRM", w) + "; no listener on 5985/5986";
            r.key = "running|nolistener";
        }
    }

    // RA-010 SMB server and shares.
    {
        PostureResult r = mk("RA-010", "SMB server and administrative shares", "high", "SMBADM");
        const SvcEntry* s = f.servicesRd == Rd::Ok ? f.service("lanmanserver") : nullptr;
        std::vector<const Listener*> exposed;
        if (f.tcpRd == Rd::Ok) {
            std::vector<const Listener*> local;
            onPorts(f, {445, 139}, {}, exposed, local);
        }
        Obj o;
        o.raw("lanmanserver", f.servicesRd == Rd::Ok ? svcObs(s) : jsonQuote(rdName(f.servicesRd)))
            .str("shares_read", rdName(f.shares.rd)).raw("admin_shares", strArr(f.shares.adminShares))
            .flag("ipc", f.shares.ipc).num("other_disk_shares", f.shares.otherDisk)
            .reg("AutoShareWks", f.autoShareWks).reg("AutoShareServer", f.autoShareServer)
            .num("smb_exposed_listeners", static_cast<long long>(exposed.size()));
        const std::string obs = o.done();
        if (f.servicesRd != Rd::Ok) {
            set(r, PStatus::Unknown, unknownWhy("service list", f.servicesRd), "unknown", obs);
        } else if (!running(s)) {
            set(r, PStatus::Pass, svcWords("Server service (LanmanServer)", s) + ": no shares reachable", "server_off", obs);
        } else if (f.shares.rd != Rd::Ok) {
            set(r, PStatus::Unknown, "Server service running; " + unknownWhy("share list", f.shares.rd), "unknown", obs);
        } else if (!f.shares.adminShares.empty() || f.shares.otherDisk > 0) {
            std::vector<std::string> what;
            if (!f.shares.adminShares.empty()) what.push_back("administrative shares " + join(f.shares.adminShares, ", "));
            if (f.shares.otherDisk > 0) what.push_back(std::to_string(f.shares.otherDisk) + " other disk share(s)");
            if (f.shares.adminShares.empty()) r.flag = "SHARE";
            set(r, PStatus::Fail, "Server service running with " + join(what, " and "),
                "shares|" + join(f.shares.adminShares, ",") + "|" + std::to_string(f.shares.otherDisk), obs);
        } else if (f.shares.ipc && !p.allowIpcShare) {
            r.severity = "medium";
            r.flag = "IPC";
            set(r, PStatus::Warn, "Server service running; IPC$ only (no disk shares)", "ipc", obs);
        } else {
            set(r, PStatus::Pass, "Server service running; no disk shares" + std::string(f.shares.ipc ? ", IPC$ allowed by profile" : ""),
                "noshares", obs);
        }
        out.push_back(r);
    }

    // RA-011 SMBv1, server and client side.
    {
        PostureResult r = mk("RA-011", "SMBv1", "medium", "SMB1");
        const std::string obs = Obj().str("srv_driver", f.srv1.rd == Rd::Ok ? f.srv1.start : rdName(f.srv1.rd))
                                    .reg("LanmanServer_SMB1", f.smb1Server)
                                    .str("mrxsmb10_driver", f.mrxsmb10.rd == Rd::Ok ? f.mrxsmb10.start : rdName(f.mrxsmb10.rd)).done();
        const bool srvKnown = f.srv1.rd == Rd::Ok || f.srv1.rd == Rd::Absent;
        const bool cliKnown = f.mrxsmb10.rd == Rd::Ok || f.mrxsmb10.rd == Rd::Absent;
        // Server: driver installed and not disabled, and SMB1 not set to 0 (absent = Windows' default, on).
        bool srvOn = false, srvUnknown = !srvKnown;
        if (f.srv1.rd == Rd::Ok && f.srv1.start != "disabled") {
            if (f.smb1Server.rd == Rd::Ok) srvOn = f.smb1Server.v != 0;
            else if (f.smb1Server.rd == Rd::Absent) srvOn = true;
            else srvUnknown = true;
        }
        const bool cliOn = f.mrxsmb10.rd == Rd::Ok && f.mrxsmb10.start != "disabled";
        if (srvOn || cliOn) {
            std::vector<std::string> on;
            if (srvOn) on.push_back("server");
            if (cliOn) on.push_back("client");
            set(r, PStatus::Fail, "SMBv1 ENABLED (" + join(on, " and ") + ")", "on|" + join(on, "+"), obs);
        } else if (srvUnknown || !cliKnown) {
            set(r, PStatus::Unknown, "SMBv1 state unreadable", "unknown", obs);
        } else {
            set(r, PStatus::Pass, "SMBv1 off (server and client)", "off", obs);
        }
        out.push_back(r);
    }

    // RA-012 Remote Registry. Built into Windows: PASS while stopped.
    out.push_back(serverCheck(f, {"RA-012", "Remote Registry", "medium", "REMREG", "Remote Registry", {"remoteregistry"}, {}, {}, false, false}));

    // RA-013 Third-party remote-control tools: services (installed at all) and
    // processes (running), against the catalogue.
    {
        PostureResult r = mk("RA-013", "Third-party remote-control tools", "high", "RTOOL");
        std::vector<std::string> failWords, failKeys, infoWords, toolObs;
        for (const auto& t : p.remoteTools) {
            std::vector<std::string> hits, hitsJ;
            bool runningHit = false;
            if (f.servicesRd == Rd::Ok)
                for (const auto& s : f.services)
                    for (const auto& pat : t.services)
                        if (nameMatches(pat, s.name)) {
                            hits.push_back("service " + s.name + " " + s.state);
                            hitsJ.push_back(jsonQuote("service:" + s.name + ":" + s.state));
                            runningHit = runningHit || running(&s);
                            break;
                        }
            if (f.processesRd == Rd::Ok)
                for (const auto& pr : f.processes)
                    for (const auto& pat : t.processes)
                        if (nameMatches(pat, pr)) {
                            hits.push_back("process " + pr);
                            hitsJ.push_back(jsonQuote("process:" + pr));
                            runningHit = true;
                            break;
                        }
            if (hits.empty()) continue;
            std::sort(hits.begin(), hits.end());
            hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
            const bool allowed = std::find(p.remoteToolsAllow.begin(), p.remoteToolsAllow.end(), t.name) != p.remoteToolsAllow.end();
            toolObs.push_back(Obj().str("tool", t.name).flag("allowed", allowed).flag("running", runningHit).raw("seen", arr(hitsJ)).done());
            const std::string words = t.name + " (" + join(hits, ", ") + ")";
            if (allowed) infoWords.push_back(words);
            else {
                failWords.push_back(words);
                failKeys.push_back(t.name + (runningHit ? ":running" : ":installed"));
            }
        }
        const std::string obs = Obj().str("services_read", rdName(f.servicesRd)).str("processes_read", rdName(f.processesRd))
                                    .raw("found", arr(toolObs)).done();
        if (!failWords.empty())
            set(r, PStatus::Fail, "remote tool(s) present: " + join(failWords, "; "), join(failKeys, ","), obs);
        else if (f.servicesRd != Rd::Ok || f.processesRd != Rd::Ok)
            set(r, PStatus::Unknown, std::string("not fully checked: services ") + rdName(f.servicesRd) + ", processes " + rdName(f.processesRd),
                "unknown", obs);
        else if (!infoWords.empty())
            set(r, PStatus::Info, "allowed remote tool(s) present: " + join(infoWords, "; "), "allowed", obs);
        else
            set(r, PStatus::Pass, "no known remote-control tool installed or running", "none", obs);
        out.push_back(r);
    }

    // RA-014 FTP / TFTP server.
    out.push_back(serverCheck(f, {"RA-014", "FTP / TFTP server", "high", "FTP", "FTP/TFTP server", {"ftpsvc", "msftpsvc", "tftpd"}, {21}, {69}, true, false}));

    // RA-015 SNMP.
    out.push_back(serverCheck(f, {"RA-015", "SNMP", "medium", "SNMP", "SNMP service", {"snmp"}, {}, {161}, true, p.snmp == "allow"}));

    // RA-016 PowerShell: present, and the execution policy that applies.
    {
        PostureResult r = mk("RA-016", "PowerShell present / execution policy", "info", "PS");
        std::string pol = "Restricted", src = "default";
        bool polKnown = true;
        // An unreadable policy value might be the one that applies, so it
        // makes the answer unknown before the local value is consulted.
        const bool gpoBad = f.psPolicyGpo.rd == Rd::Denied || f.psPolicyGpo.rd == Rd::Error;
        const bool localBad = f.psPolicyLocal.rd == Rd::Denied || f.psPolicyLocal.rd == Rd::Error;
        if (f.psEnableScriptsGpo.rd == Rd::Ok && f.psEnableScriptsGpo.v == 0) { pol = "Restricted"; src = "policy"; }
        else if (f.psPolicyGpo.rd == Rd::Ok && !f.psPolicyGpo.v.empty()) { pol = f.psPolicyGpo.v; src = "policy"; }
        else if (!gpoBad && f.psPolicyLocal.rd == Rd::Ok && !f.psPolicyLocal.v.empty()) { pol = f.psPolicyLocal.v; src = "local"; }
        else if (gpoBad || localBad) polKnown = false;
        const std::string lp = lower(pol);
        const std::string obs = Obj().str("powershell_exe", rdName(f.powershellExe.rd))
                                    .str("execution_policy", polKnown ? pol : "unknown").str("source", polKnown ? src : "unread")
                                    .str("profile", p.powershell).done();
        if (f.powershellExe.rd == Rd::Absent) {
            set(r, PStatus::Pass, "powershell.exe not present", "absent", obs);
        } else if (f.powershellExe.rd != Rd::Ok) {
            set(r, PStatus::Unknown, unknownWhy("powershell.exe", f.powershellExe.rd), "unknown", obs);
        } else if (p.powershell == "deny") {
            r.severity = "low";
            set(r, PStatus::Fail, "powershell.exe present (profile: deny)", "present|" + lp, obs);
        } else if (!polKnown) {
            set(r, PStatus::Unknown, "powershell.exe present; execution policy unreadable", "unknown", obs);
        } else if (p.powershell == "restrict" && (lp == "unrestricted" || lp == "bypass")) {
            r.severity = "low";
            set(r, PStatus::Warn, "powershell.exe present; execution policy " + pol + " (" + src + ")", "present|" + lp, obs);
        } else {
            set(r, PStatus::Info, "powershell.exe present; execution policy " + pol + " (" + src + ")", "present|" + lp, obs);
        }
        out.push_back(r);
    }

    // RA-017 Windows Firewall on for every profile, and its service running.
    {
        PostureResult r = mk("RA-017", "Windows Firewall profiles on", "high", "FWOFF");
        const Eff d = effective(f.fwDomain.policy, f.fwDomain.local);
        const Eff pr = effective(f.fwPrivate.policy, f.fwPrivate.local);
        const Eff pu = effective(f.fwPublic.policy, f.fwPublic.local);
        const SvcEntry* mps = f.servicesRd == Rd::Ok ? f.service("mpssvc") : nullptr;
        auto word = [](const Eff& e) { return e.rd != Rd::Ok ? std::string(rdName(e.rd)) : e.v ? std::string("on") : std::string("off"); };
        const std::string obs = Obj().str("domain", word(d)).str("domain_source", d.src).str("private", word(pr)).str("private_source", pr.src)
                                    .str("public", word(pu)).str("public_source", pu.src)
                                    .raw("mpssvc", f.servicesRd == Rd::Ok ? svcObs(mps) : jsonQuote(rdName(f.servicesRd)))
                                    .flag("third_party_firewall", p.thirdPartyFirewall).done();
        std::vector<std::string> off;
        if (d.rd == Rd::Ok && d.v == 0) off.push_back("domain");
        if (pr.rd == Rd::Ok && pr.v == 0) off.push_back("private");
        if (pu.rd == Rd::Ok && pu.v == 0) off.push_back("public");
        const bool svcDown = f.servicesRd == Rd::Ok && !running(mps);
        if (!off.empty() || svcDown) {
            std::string why = off.empty() ? std::string() : "firewall OFF for " + join(off, ", ");
            if (svcDown) why += std::string(why.empty() ? "" : "; ") + "firewall service (MpsSvc) not running";
            set(r, p.thirdPartyFirewall ? PStatus::Info : PStatus::Fail, why + (p.thirdPartyFirewall ? " (third-party firewall per profile)" : ""),
                "off|" + join(off, ",") + (svcDown ? "|svc" : ""), obs);
        } else if (d.rd != Rd::Ok || pr.rd != Rd::Ok || pu.rd != Rd::Ok || f.servicesRd != Rd::Ok) {
            set(r, PStatus::Unknown, "firewall state not fully readable", "unknown", obs);
        } else {
            set(r, PStatus::Pass, "firewall on for domain, private and public; MpsSvc running", "on", obs);
        }
        out.push_back(r);
    }

    // RA-018 Inbound ICMP echo -- INFO only, from the firewall rule store.
    {
        PostureResult r = mk("RA-018", "Inbound ICMP echo allowed", "info", "");
        const std::string obs = Obj().str("rules_read", rdName(f.icmpRd)).num("echo_allow_rules", f.icmpEchoAllowRules)
                                    .str("note", "rule store only; with the firewall off every echo is answered").done();
        if (f.icmpRd != Rd::Ok) set(r, PStatus::Unknown, unknownWhy("firewall rule store", f.icmpRd), "unknown", obs);
        else if (f.icmpEchoAllowRules > 0)
            set(r, PStatus::Info, "inbound echo allowed by " + std::to_string(f.icmpEchoAllowRules) + " enabled rule(s)", "allowed", obs);
        else set(r, PStatus::Info, "no enabled rule allows inbound echo", "blocked", obs);
        out.push_back(r);
    }

    // RA-019 NetBIOS over TCP/IP and LLMNR.
    {
        PostureResult r = mk("RA-019", "NetBIOS / LLMNR", "low", "NBT");
        bool llmnrKnown = true, llmnrOn = true;
        if (f.llmnrPolicy.rd == Rd::Ok) llmnrOn = f.llmnrPolicy.v != 0;
        else if (f.llmnrPolicy.rd == Rd::Absent) llmnrOn = true;      // Windows default: on
        else llmnrKnown = false;
        const std::string obs = Obj().reg("policy_EnableMulticast", f.llmnrPolicy).str("llmnr", !llmnrKnown ? "unknown" : llmnrOn ? "on" : "off")
                                    .str("netbt_read", rdName(f.netbt.rd)).num("interfaces", f.netbt.interfaces)
                                    .num("netbios_not_disabled", f.netbt.notDisabled).done();
        std::vector<std::string> on;
        if (llmnrKnown && llmnrOn) on.push_back("LLMNR on");
        if (f.netbt.rd == Rd::Ok && f.netbt.notDisabled > 0)
            on.push_back("NetBIOS not disabled on " + std::to_string(f.netbt.notDisabled) + " of " + std::to_string(f.netbt.interfaces) + " interface(s)");
        if (!on.empty()) set(r, PStatus::Warn, join(on, "; "), "on|" + std::string(llmnrOn ? "llmnr" : "") + "|" + std::to_string(f.netbt.notDisabled), obs);
        else if (!llmnrKnown || f.netbt.rd != Rd::Ok) set(r, PStatus::Unknown, "NetBIOS/LLMNR state unreadable", "unknown", obs);
        else set(r, PStatus::Pass, "LLMNR off; NetBIOS disabled on every interface", "off", obs);
        out.push_back(r);
    }

    // RA-020 Listening sockets. Every non-loopback listener must be in the
    // profile's allow-list.
    {
        PostureResult r = mk("RA-020", "Listening sockets", "high", "LSN");
        std::vector<const Listener*> unexpected, local;
        int allowed = 0;
        for (const auto& l : f.listeners) {
            if (listenerAllowed(l, p.listenerAllow)) { ++allowed; continue; }
            (isLoopbackAddr(l.addr) ? local : unexpected).push_back(&l);
        }
        std::vector<std::string> keys, uj, lj;
        for (const Listener* l : unexpected) keys.push_back(listenerKey(*l));
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        for (size_t i = 0; i < unexpected.size() && i < 32; ++i) uj.push_back(listenerObs(*unexpected[i]));
        for (size_t i = 0; i < local.size() && i < 32; ++i) lj.push_back(listenerObs(*local[i]));
        const std::string obs = Obj().str("tcp_read", rdName(f.tcpRd)).str("udp_read", rdName(f.udpRd))
                                    .num("allowed", allowed).num("udp_ephemeral_not_listed", f.udpEphemeral)
                                    .num("unexpected_count", static_cast<long long>(unexpected.size())).raw("unexpected", arr(uj))
                                    .num("loopback_count", static_cast<long long>(local.size())).raw("loopback", arr(lj)).done();
        if (!unexpected.empty()) {
            std::string s = "unexpected listener " + listenerText(*unexpected.front());
            if (unexpected.size() > 1) s += " and " + std::to_string(unexpected.size() - 1) + " more";
            set(r, PStatus::Fail, s, join(keys, ","), obs);
        } else if (f.tcpRd != Rd::Ok || f.udpRd != Rd::Ok) {
            set(r, PStatus::Unknown, std::string("socket tables not fully readable: tcp ") + rdName(f.tcpRd) + ", udp " + rdName(f.udpRd),
                "unknown", obs);
        } else if (!local.empty()) {
            set(r, PStatus::Info, std::to_string(local.size()) + " loopback listener(s), nothing unexpected exposed", "loopback", obs);
        } else {
            set(r, PStatus::Pass, "every listener is in the allow-list", "clean", obs);
        }
        out.push_back(r);
    }
    return out;
}

PostureSummary summarize(const std::vector<PostureResult>& r) {
    PostureSummary s;
    for (const auto& x : r) {
        switch (x.status) {
            case PStatus::Fail: ++s.fail; break;
            case PStatus::Warn: ++s.warn; break;
            case PStatus::Pass: ++s.pass; break;
            case PStatus::Info: ++s.info; break;
            default: ++s.unknown;
        }
    }
    return s;
}

std::string failFlags(const std::vector<PostureResult>& r) {
    std::vector<std::string> f;
    for (const auto& x : r)
        if (x.status == PStatus::Fail && !x.flag.empty() && std::find(f.begin(), f.end(), x.flag) == f.end()) f.push_back(x.flag);
    return join(f, "|");
}

}  // namespace ev
