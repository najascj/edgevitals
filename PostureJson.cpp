// Remote-access posture: profile reader and edgestack.posture.remote/1 output.
// Shared with ATMProbe -- see PostureFacts.h.
#include "edgevitals/PostureFacts.h"

#include "edgevitals/Digest.h"
#include "edgevitals/Json.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace ev {
namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::vector<std::string> lowerList(const Json& a) {
    std::vector<std::string> v;
    for (size_t i = 0; i < a.size(); ++i) {
        const std::string s = lower(a[i].asString());
        if (!s.empty()) v.push_back(s);
    }
    return v;
}

}  // namespace

std::string jsonQuote(const std::string& s) {
    std::string o = "\"";
    for (unsigned char c : s) {
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c < 0x20) {
            char b[8];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), "\\u%04x", ...)
            (void)std::snprintf(b, sizeof(b), "\\u%04x", c);
            o += b;
        } else {
            o.push_back(static_cast<char>(c));
        }
    }
    return o + "\"";
}

std::string summaryJson(const PostureSummary& s) {
    return "{\"fail\":" + std::to_string(s.fail) + ",\"warn\":" + std::to_string(s.warn) + ",\"pass\":" + std::to_string(s.pass) +
           ",\"info\":" + std::to_string(s.info) + ",\"unknown\":" + std::to_string(s.unknown) + "}";
}

std::string checksJson(const std::vector<PostureResult>& r) {
    std::string o = "[";
    for (size_t i = 0; i < r.size(); ++i) {
        const auto& x = r[i];
        if (i) o += ",";
        o += "{\"id\":" + jsonQuote(x.id) + ",\"title\":" + jsonQuote(x.title) + ",\"status\":" + jsonQuote(statusName(x.status)) +
             ",\"severity\":" + jsonQuote(x.severity) + ",\"summary\":" + jsonQuote(x.summary) +
             ",\"observed\":" + (x.observed.empty() ? std::string("{}") : x.observed) + "}";
    }
    return o + "]";
}

std::string postureDigest(const std::vector<PostureResult>& r) {
    Sha256 h;
    for (const auto& x : r) {
        h.update(x.id);
        h.update("\x1f", 1);
        h.update(statusName(x.status));
        h.update("\x1f", 1);
        h.update(x.key);
        h.update("\x1e", 1);
    }
    return "sha256:" + h.hex();
}

bool parsePostureProfile(const Json& h, PostureProfile& out, std::string& err) {
    PostureProfile p = defaultPostureProfile();
    if (!h.isObject()) {
        err = "profile must be a JSON object";
        return false;
    }
    p.name = h["profile"].asString(h["name"].asString(p.name));
    if (h.has("rdp")) {
        const std::string m = lower(h["rdp"].asString());
        if (m != "deny" && m != "allow_hardened") {
            // Refused rather than defaulted: a typo here must not quietly
            // decide whether RDP is a finding.
            err = "rdp must be \"deny\" or \"allow_hardened\", got \"" + h["rdp"].asString() + "\"";
            return false;
        }
        p.rdp = m;
    }
    p.allowIpcShare = h["allow_ipc_share"].asBool(p.allowIpcShare);
    p.thirdPartyFirewall = h["third_party_firewall"].asBool(p.thirdPartyFirewall);
    if (h.has("powershell")) {
        // ATMProbe's profile may say true/false: true = allowed (info), false = deny.
        const Json& v = h["powershell"];
        std::string m = v.type() == Json::Type::Bool ? (v.asBool(true) ? "info" : "deny") : lower(v.asString());
        if (m == "allow") m = "info";
        if (m != "info" && m != "restrict" && m != "deny") {
            err = "powershell must be info, restrict or deny";
            return false;
        }
        p.powershell = m;
    }
    if (h.has("snmp")) {
        const Json& v = h["snmp"];
        std::string m = v.type() == Json::Type::Bool ? (v.asBool(false) ? "allow" : "deny") : lower(v.asString());
        if (m != "allow" && m != "deny") {
            err = "snmp must be allow or deny";
            return false;
        }
        p.snmp = m;
    }
    if (h.has("remote_tools_allow")) p.remoteToolsAllow = lowerList(h["remote_tools_allow"]);
    if (h.has("remote_tools")) {
        // Additive: a profile can teach the catalogue a vendor tool, never
        // remove a built-in one. Allowing a tool is what remote_tools_allow is for.
        const Json& a = h["remote_tools"];
        for (size_t i = 0; i < a.size(); ++i) {
            RemoteTool t;
            t.name = lower(a[i]["name"].asString());
            t.services = lowerList(a[i]["services"]);
            t.processes = lowerList(a[i]["processes"]);
            if (t.name.empty() || (t.services.empty() && t.processes.empty())) {
                err = "remote_tools[" + std::to_string(i) + "] needs a name and services or processes";
                return false;
            }
            bool merged = false;
            for (auto& existing : p.remoteTools)
                if (existing.name == t.name) {
                    existing.services.insert(existing.services.end(), t.services.begin(), t.services.end());
                    existing.processes.insert(existing.processes.end(), t.processes.begin(), t.processes.end());
                    merged = true;
                }
            if (!merged) p.remoteTools.push_back(t);
        }
    }
    if (h.has("listener_allow")) {
        // Replaces the seed: the profile file is the bank's statement of what
        // may listen, and a seed entry it leaves out is meant to be gone.
        p.listenerAllow.clear();
        const Json& a = h["listener_allow"];
        for (size_t i = 0; i < a.size(); ++i) {
            const Json& e = a[i];
            ListenerAllow la;
            la.proto = lower(e["proto"].asString());
            la.addr = lower(e["addr"].asString("*"));
            la.process = lower(e["process"].asString());
            la.service = lower(e["service"].asString());
            la.note = e["note"].asString();
            if (e.has("port")) {
                la.portLo = la.portHi = static_cast<int>(e["port"].asInt(-1));
            } else if (e["port_range"].size() == 2) {
                la.portLo = static_cast<int>(e["port_range"][0].asInt(-1));
                la.portHi = static_cast<int>(e["port_range"][1].asInt(-1));
            } else {
                la.portLo = -1;
            }
            if (la.portLo < 1 || la.portHi > 65535 || la.portLo > la.portHi) {
                err = "listener_allow[" + std::to_string(i) + "] needs port (1-65535) or port_range [lo, hi]";
                return false;
            }
            if (!la.proto.empty() && la.proto != "tcp" && la.proto != "udp") {
                err = "listener_allow[" + std::to_string(i) + "].proto must be tcp or udp";
                return false;
            }
            // "*" on any address with no process and no service would allow
            // anything on that port from anyone: refused, it hides the very
            // thing RA-020 exists to show.
            if ((la.addr == "*" || la.addr == "any") && la.process.empty() && la.service.empty() && la.portHi - la.portLo > 0) {
                err = "listener_allow[" + std::to_string(i) + "]: a port range on every address needs a process or service";
                return false;
            }
            p.listenerAllow.push_back(la);
        }
    }
    out = std::move(p);
    return true;
}

}  // namespace ev
