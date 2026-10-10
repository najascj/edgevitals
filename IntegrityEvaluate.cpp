// Endpoint integrity: evaluation. Pure C++17, tested on any host.
#include "edgevitals/IntegrityFacts.h"

#include <algorithm>
#include <cctype>

namespace ev {
namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string join(const std::vector<std::string>& v, const char* sep) {
    std::string o;
    for (const auto& s : v) o += (o.empty() ? "" : sep) + s;
    return o;
}

IntegrityResult mk(const char* id, const char* title, const char* sev, const char* flag) {
    IntegrityResult r;
    r.id = id;
    r.title = title;
    r.severity = sev;
    r.flag = flag;
    return r;
}
void set(IntegrityResult& r, IStatus s, const std::string& sum, const std::string& key, const std::string& obs) {
    r.status = s;
    r.summary = sum;
    r.key = key;
    r.observed = obs;
}

}  // namespace

const char* irdName(IRd r) {
    switch (r) {
        case IRd::Ok: return "ok";
        case IRd::Absent: return "absent";
        case IRd::Denied: return "denied";
        default: return "error";
    }
}
const char* iStatusName(IStatus s) {
    switch (s) {
        case IStatus::Pass: return "PASS";
        case IStatus::Info: return "INFO";
        case IStatus::Warn: return "WARN";
        case IStatus::Fail: return "FAIL";
        default: return "UNKNOWN";
    }
}

const FileHash* IntegrityFacts::file(const std::string& path) const {
    for (const auto& f : files)
        if (f.path == path) return &f;
    return nullptr;
}

std::string persistToken(const PersistEntry& e) {
    return lower(e.kind) + ":" + lower(e.name) + ":" + lower(e.target);
}

bool persistAllowed(const PersistEntry& e, const std::vector<std::string>& allow) {
    const std::string full = persistToken(e);                                   // kind:name:target
    const std::string kn = lower(e.kind) + ":" + lower(e.name);                 // kind:name (any target)
    for (const auto& a : allow) {
        const std::string la = lower(a);
        if (la == full || la == kn) return true;
        // trailing '*' prefix on the whole token
        if (!la.empty() && la.back() == '*' && full.compare(0, la.size() - 1, la, 0, la.size() - 1) == 0) return true;
    }
    return false;
}

IntegrityBaseline defaultIntegrityBaseline() {
    // Empty by design: with no baseline the bank has approved nothing, so FIM
    // reports every watched file as "no pinned hash" (INFO) and persistence
    // reports every entry as unapproved. A real deployment ships a baseline
    // generated on a known-good terminal. Strict so a missing baseline can
    // only make findings louder.
    IntegrityBaseline b;
    b.strictPersistence = true;
    return b;
}

std::vector<IntegrityResult> evaluateIntegrity(const IntegrityFacts& f, const IntegrityBaseline& b) {
    std::vector<IntegrityResult> out;

    // ── FI-001: file integrity ────────────────────────────────────────────
    {
        IntegrityResult r = mk("FI-001", "File integrity (watched set)", "high", "FIM");
        if (f.filesRd != IRd::Ok && f.files.empty()) {
            set(r, IStatus::Unknown, std::string("fileset could not be read: ") + irdName(f.filesRd), "unknown",
                "{\"reason\":\"" + std::string(irdName(f.filesRd)) + "\"}");
            out.push_back(r);
        } else {
            std::vector<std::string> changed, missing, unreadable, unpinned, keyParts, obsParts;
            for (const auto& fb : b.files) {
                const FileHash* h = f.file(fb.path);
                if (!h || h->rd == IRd::Absent) {
                    if (fb.required) missing.push_back(fb.path);
                    obsParts.push_back(iJsonQuote(fb.path) + ":\"absent\"");
                    if (fb.required) keyParts.push_back("missing:" + fb.path);
                    continue;
                }
                if (h->rd != IRd::Ok) {
                    unreadable.push_back(fb.path);
                    obsParts.push_back(iJsonQuote(fb.path) + ":\"" + irdName(h->rd) + "\"");
                    continue;
                }
                if (fb.sha256.empty()) {
                    unpinned.push_back(fb.path);
                    obsParts.push_back(iJsonQuote(fb.path) + ":{\"sha256\":\"" + h->sha256.substr(0, 12) + "...\",\"pinned\":false}");
                } else if (lower(h->sha256) != lower(fb.sha256)) {
                    changed.push_back(fb.path);
                    keyParts.push_back("changed:" + fb.path + ":" + h->sha256.substr(0, 12));
                    obsParts.push_back(iJsonQuote(fb.path) + ":{\"expected\":\"" + fb.sha256.substr(0, 12) + "...\",\"actual\":\"" + h->sha256.substr(0, 12) + "...\"}");
                } else {
                    obsParts.push_back(iJsonQuote(fb.path) + ":\"match\"");
                }
            }
            const std::string obs = "{\"files\":{" + join(obsParts, ",") + "}}";
            std::sort(keyParts.begin(), keyParts.end());
            if (!changed.empty()) {
                set(r, IStatus::Fail, "watched file(s) changed: " + join(changed, ", "), join(keyParts, ","), obs);
            } else if (!missing.empty()) {
                r.flag = "FIMMISS";
                set(r, IStatus::Fail, "required watched file(s) missing: " + join(missing, ", "), join(keyParts, ","), obs);
            } else if (!unreadable.empty()) {
                set(r, IStatus::Unknown, "watched file(s) unreadable: " + join(unreadable, ", "), "unreadable", obs);
            } else if (b.files.empty()) {
                set(r, IStatus::Unknown, "no baseline fileset configured", "no_baseline", obs);
            } else if (!unpinned.empty()) {
                r.severity = "medium";
                set(r, IStatus::Info, std::to_string(unpinned.size()) + " file(s) watched without a pinned hash; " +
                    std::to_string(b.files.size() - unpinned.size()) + " verified", "unpinned", obs);
            } else {
                set(r, IStatus::Pass, "all " + std::to_string(b.files.size()) + " watched file(s) match the baseline", "match", obs);
            }
            out.push_back(r);
        }
    }

    // ── FI-002: persistence (autostart / service / task) ──────────────────
    {
        IntegrityResult r = mk("FI-002", "Persistence (autostart, services, tasks)", "high", "PERSIST");
        if (f.persistRd != IRd::Ok) {
            set(r, IStatus::Unknown, std::string("persistence list could not be read: ") + irdName(f.persistRd), "unknown",
                "{\"reason\":\"" + std::string(irdName(f.persistRd)) + "\"}");
            out.push_back(r);
        } else {
            std::vector<std::string> unapproved, keyParts, obsParts;
            for (const auto& e : f.persistence) {
                if (persistAllowed(e, b.persistAllow)) continue;
                unapproved.push_back(e.kind + " " + e.name + " -> " + e.target);
                keyParts.push_back(persistToken(e));
                obsParts.push_back("{\"kind\":" + iJsonQuote(e.kind) + ",\"name\":" + iJsonQuote(e.name) + ",\"target\":" + iJsonQuote(e.target) + "}");
            }
            std::sort(keyParts.begin(), keyParts.end());
            keyParts.erase(std::unique(keyParts.begin(), keyParts.end()), keyParts.end());
            const std::string obs = "{\"total\":" + std::to_string(f.persistence.size()) +
                                    ",\"unapproved\":" + std::to_string(unapproved.size()) +
                                    ",\"entries\":[" + join(obsParts, ",") + "]}";
            if (unapproved.empty()) {
                set(r, IStatus::Pass, "no persistence entry outside the baseline (" + std::to_string(f.persistence.size()) + " total)", "clean", obs);
            } else if (b.strictPersistence) {
                std::string s = "unapproved persistence: " + unapproved.front();
                if (unapproved.size() > 1) s += " and " + std::to_string(unapproved.size() - 1) + " more";
                set(r, IStatus::Fail, s, join(keyParts, ","), obs);
            } else {
                r.severity = "medium";
                set(r, IStatus::Warn, std::to_string(unapproved.size()) + " persistence entry(ies) outside the baseline", join(keyParts, ","), obs);
            }
            out.push_back(r);
        }
    }
    return out;
}

IntegritySummary summarizeIntegrity(const std::vector<IntegrityResult>& r) {
    IntegritySummary s;
    for (const auto& x : r) {
        switch (x.status) {
            case IStatus::Fail: ++s.fail; break;
            case IStatus::Warn: ++s.warn; break;
            case IStatus::Pass: ++s.pass; break;
            case IStatus::Info: ++s.info; break;
            default: ++s.unknown;
        }
    }
    return s;
}

std::string integrityFlags(const std::vector<IntegrityResult>& r) {
    std::vector<std::string> f;
    for (const auto& x : r)
        if (x.status == IStatus::Fail && !x.flag.empty() && std::find(f.begin(), f.end(), x.flag) == f.end()) f.push_back(x.flag);
    return join(f, "|");
}

}  // namespace ev
