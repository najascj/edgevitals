// Endpoint integrity: baseline reader and edgestack.integrity.endpoint/1 output.
#include "edgevitals/IntegrityFacts.h"

#include "edgevitals/Digest.h"
#include "edgevitals/Json.h"

#include <cctype>
#include <cstdio>

namespace ev {

std::string iJsonQuote(const std::string& s) {
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

std::string integritySummaryJson(const IntegritySummary& s) {
    return "{\"fail\":" + std::to_string(s.fail) + ",\"warn\":" + std::to_string(s.warn) + ",\"pass\":" + std::to_string(s.pass) +
           ",\"info\":" + std::to_string(s.info) + ",\"unknown\":" + std::to_string(s.unknown) + "}";
}

std::string integrityChecksJson(const std::vector<IntegrityResult>& r) {
    std::string o = "[";
    for (size_t i = 0; i < r.size(); ++i) {
        const auto& x = r[i];
        if (i) o += ",";
        o += "{\"id\":" + iJsonQuote(x.id) + ",\"title\":" + iJsonQuote(x.title) + ",\"status\":" + iJsonQuote(iStatusName(x.status)) +
             ",\"severity\":" + iJsonQuote(x.severity) + ",\"summary\":" + iJsonQuote(x.summary) +
             ",\"observed\":" + (x.observed.empty() ? std::string("{}") : x.observed) + "}";
    }
    return o + "]";
}

std::string integrityDigest(const std::vector<IntegrityResult>& r) {
    Sha256 h;
    for (const auto& x : r) {
        h.update(x.id);
        h.update("\x1f", 1);
        h.update(iStatusName(x.status));
        h.update("\x1f", 1);
        h.update(x.key);
        h.update("\x1e", 1);
    }
    return "sha256:" + h.hex();
}

bool parseIntegrityBaseline(const Json& h, IntegrityBaseline& out, std::string& err) {
    IntegrityBaseline b = defaultIntegrityBaseline();
    if (!h.isObject()) {
        err = "integrity baseline must be a JSON object";
        return false;
    }
    b.name = h["profile"].asString(h["name"].asString(b.name));
    b.strictPersistence = h["strict_persistence"].asBool(b.strictPersistence);
    if (h.has("files")) {
        const Json& a = h["files"];
        for (size_t i = 0; i < a.size(); ++i) {
            FileBaseline fb;
            // Either a bare string "path" (watch, no pinned hash) or an object.
            if (a[i].type() == Json::Type::String) {
                fb.path = a[i].asString();
            } else {
                fb.path = a[i]["path"].asString();
                fb.sha256 = a[i]["sha256"].asString();
                fb.required = a[i]["required"].asBool(true);
            }
            if (fb.path.empty()) {
                err = "integrity.files[" + std::to_string(i) + "] has no path";
                return false;
            }
            b.files.push_back(std::move(fb));
        }
    }
    if (h.has("persist_allow")) {
        const Json& a = h["persist_allow"];
        for (size_t i = 0; i < a.size(); ++i)
            if (!a[i].asString().empty()) b.persistAllow.push_back(a[i].asString());
    }
    out = std::move(b);
    return true;
}

}  // namespace ev
