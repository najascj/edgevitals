#include "edgevitals/Row.h"

#include <cmath>
#include <cstdio>

namespace ev {

std::string csvEscape(const std::string& v) {
    bool needs = false;
    for (char c : v) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') { needs = true; break; }
    }
    if (!needs) return v;
    std::string out;
    out.reserve(v.size() + 8);
    out.push_back('"');
    for (char c : v) {
        if (c == '"') out.push_back('"');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

std::string Cell::toCsv(int precision) const {
    switch (kind_) {
        case Kind::Empty:
            return std::string();
        case Kind::Text:
            return csvEscape(txt_);
        case Kind::Number: {
            // NaN and inf are written as empty rather than "nan"/"inf". A
            // spreadsheet reading "nan" produces a text column and silently
            // breaks every formula below it.
            if (!std::isfinite(num_)) return std::string();
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.*f", precision, num_);
            std::string s(buf);
            // Trim a pointless fractional tail: 12.00 -> 12, 12.50 -> 12.5
            if (s.find('.') != std::string::npos) {
                size_t end = s.size();
                while (end > 0 && s[end - 1] == '0') --end;
                if (end > 0 && s[end - 1] == '.') --end;
                s.resize(end);
            }
            if (s == "-0") s = "0";
            return s;
        }
    }
    return std::string();
}

size_t Schema::add(const std::string& name, int precision) {
    if (frozen_) return npos;
    auto it = index_.find(name);
    if (it != index_.end()) return it->second;
    size_t i = names_.size();
    names_.push_back(name);
    precision_.push_back(precision);
    index_[name] = i;
    return i;
}

size_t Schema::indexOf(const std::string& name) const {
    auto it = index_.find(name);
    return it == index_.end() ? npos : it->second;
}

std::string Schema::headerCsv() const {
    std::string out;
    for (size_t i = 0; i < names_.size(); ++i) {
        if (i) out.push_back(',');
        out += csvEscape(names_[i]);
    }
    return out;
}

bool Row::setNumber(const std::string& name, double v) {
    size_t i = schema_->indexOf(name);
    if (i == Schema::npos) return false;
    setNumber(i, v);
    return true;
}

bool Row::setText(const std::string& name, std::string v) {
    size_t i = schema_->indexOf(name);
    if (i == Schema::npos) return false;
    setText(i, std::move(v));
    return true;
}

std::string Row::toCsv() const {
    std::string out;
    out.reserve(cells_.size() * 8);
    for (size_t i = 0; i < cells_.size(); ++i) {
        if (i) out.push_back(',');
        out += cells_[i].toCsv(schema_->precision(i));
    }
    return out;
}

}  // namespace ev
