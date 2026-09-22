#include "edgevitals/Json.h"

#include <cstdlib>

namespace ev {

const Json Json::kNull{};

bool Json::asBool(bool f) const {
    if (type_ == Type::Bool) return bool_;
    if (type_ == Type::Number) return num_ != 0.0;
    return f;
}

double Json::asNumber(double f) const { return type_ == Type::Number ? num_ : f; }

long long Json::asInt(long long f) const {
    return type_ == Type::Number ? static_cast<long long>(num_) : f;
}

std::string Json::asString(const std::string& f) const {
    return type_ == Type::String ? str_ : f;
}

const Json& Json::operator[](const std::string& k) const {
    if (type_ != Type::Object) return kNull;
    auto it = obj_.find(k);
    return it == obj_.end() ? kNull : it->second;
}

const Json& Json::operator[](size_t i) const {
    if (type_ != Type::Array || i >= arr_.size()) return kNull;
    return arr_[i];
}

size_t Json::size() const {
    if (type_ == Type::Array) return arr_.size();
    if (type_ == Type::Object) return obj_.size();
    return 0;
}

bool Json::has(const std::string& k) const {
    return type_ == Type::Object && obj_.count(k) != 0;
}

std::vector<std::string> Json::keys() const {
    std::vector<std::string> out;
    if (type_ == Type::Object)
        for (const auto& kv : obj_) out.push_back(kv.first);
    return out;
}

// ── parser ───────────────────────────────────────────────────────────────
class JsonParser {
public:
    explicit JsonParser(const std::string& s) : s_(s) {}

    bool parse(Json& out, std::string& err) {
        skip();
        if (!value(out)) { err = error(); return false; }
        skip();
        if (i_ != s_.size()) { fail("trailing content after value"); err = error(); return false; }
        return true;
    }

private:
    const std::string& s_;
    size_t i_ = 0;
    size_t line_ = 1;
    std::string msg_;

    std::string error() const { return "line " + std::to_string(line_) + ": " + msg_; }
    bool fail(const char* m) { if (msg_.empty()) msg_ = m; return false; }

    void skip() {
        for (;;) {
            while (i_ < s_.size() &&
                   (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\r' || s_[i_] == '\n')) {
                if (s_[i_] == '\n') ++line_;
                ++i_;
            }
            // Comments are not JSON. Every config file in this product carries
            // explanatory comments, and a config nobody can annotate is a
            // config nobody maintains correctly.
            if (i_ + 1 < s_.size() && s_[i_] == '/' && s_[i_ + 1] == '/') {
                while (i_ < s_.size() && s_[i_] != '\n') ++i_;
                continue;
            }
            if (i_ + 1 < s_.size() && s_[i_] == '/' && s_[i_ + 1] == '*') {
                i_ += 2;
                while (i_ + 1 < s_.size() && !(s_[i_] == '*' && s_[i_ + 1] == '/')) {
                    if (s_[i_] == '\n') ++line_;
                    ++i_;
                }
                i_ = (i_ + 1 < s_.size()) ? i_ + 2 : s_.size();
                continue;
            }
            return;
        }
    }

    bool lit(const char* w) {
        size_t n = 0;
        while (w[n]) ++n;
        if (s_.compare(i_, n, w) != 0) return false;
        i_ += n;
        return true;
    }

    bool value(Json& v) {
        if (i_ >= s_.size()) return fail("unexpected end of input");
        char c = s_[i_];
        if (c == '{') return object(v);
        if (c == '[') return array(v);
        if (c == '"') { v.type_ = Json::Type::String; return str(v.str_); }
        if (lit("true")) { v.type_ = Json::Type::Bool; v.bool_ = true; return true; }
        if (lit("false")) { v.type_ = Json::Type::Bool; v.bool_ = false; return true; }
        if (lit("null")) { v.type_ = Json::Type::Null; return true; }
        return number(v);
    }

    bool object(Json& v) {
        v.type_ = Json::Type::Object;
        ++i_;
        skip();
        if (i_ < s_.size() && s_[i_] == '}') { ++i_; return true; }
        for (;;) {
            skip();
            if (i_ >= s_.size() || s_[i_] != '"') return fail("expected object key");
            std::string k;
            if (!str(k)) return false;
            skip();
            if (i_ >= s_.size() || s_[i_] != ':') return fail("expected ':' after key");
            ++i_;
            skip();
            Json child;
            if (!value(child)) return false;
            v.obj_[k] = std::move(child);
            skip();
            if (i_ < s_.size() && s_[i_] == ',') { ++i_; continue; }
            if (i_ < s_.size() && s_[i_] == '}') { ++i_; return true; }
            return fail("expected ',' or '}'");
        }
    }

    bool array(Json& v) {
        v.type_ = Json::Type::Array;
        ++i_;
        skip();
        if (i_ < s_.size() && s_[i_] == ']') { ++i_; return true; }
        for (;;) {
            skip();
            Json child;
            if (!value(child)) return false;
            v.arr_.push_back(std::move(child));
            skip();
            if (i_ < s_.size() && s_[i_] == ',') { ++i_; continue; }
            if (i_ < s_.size() && s_[i_] == ']') { ++i_; return true; }
            return fail("expected ',' or ']'");
        }
    }

    bool str(std::string& out) {
        out.clear();
        ++i_;  // opening quote
        while (i_ < s_.size()) {
            char c = s_[i_++];
            if (c == '"') return true;
            if (c == '\n') { ++line_; return fail("unterminated string"); }
            if (c != '\\') { out.push_back(c); continue; }
            if (i_ >= s_.size()) return fail("unterminated escape");
            char e = s_[i_++];
            switch (e) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    if (i_ + 4 > s_.size()) return fail("truncated \\u escape");
                    unsigned cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        char h = s_[i_++];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= unsigned(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= unsigned(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= unsigned(h - 'A' + 10);
                        else return fail("bad hex in \\u escape");
                    }
                    // UTF-8 encode. Surrogate pairs are NOT reassembled --
                    // config paths are ASCII in practice, and pretending
                    // otherwise would be a correctness claim this does not earn.
                    if (cp < 0x80) {
                        out.push_back(char(cp));
                    } else if (cp < 0x800) {
                        out.push_back(char(0xC0 | (cp >> 6)));
                        out.push_back(char(0x80 | (cp & 0x3F)));
                    } else {
                        out.push_back(char(0xE0 | (cp >> 12)));
                        out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
                        out.push_back(char(0x80 | (cp & 0x3F)));
                    }
                    break;
                }
                default: return fail("unknown escape");
            }
        }
        return fail("unterminated string");
    }

    bool number(Json& v) {
        size_t start = i_;
        if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
        bool any = false;
        while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') { ++i_; any = true; }
        if (i_ < s_.size() && s_[i_] == '.') {
            ++i_;
            while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') { ++i_; any = true; }
        }
        if (any && i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) {
            ++i_;
            if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
            while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') ++i_;
        }
        if (!any) return fail("expected a value");
        v.type_ = Json::Type::Number;
        v.num_ = std::strtod(s_.substr(start, i_ - start).c_str(), nullptr);
        return true;
    }
};

bool Json::parse(const std::string& text, Json& out, std::string& err) {
    out = Json{};
    JsonParser p(text);
    return p.parse(out, err);
}

}  // namespace ev
