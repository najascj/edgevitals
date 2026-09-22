// Minimal JSON reader.
//
// Deliberately not a general-purpose library: it parses the subset EdgeVitals
// config needs (objects, arrays, strings, numbers, bools, null) plus // and
// /* */ comments, and nothing else.
//
// Hand-rolled rather than vendored so the agent has ZERO external
// dependencies. It installs as a Windows service on a locked-down ATM, and
// every DLL it does not need is one fewer thing to justify to a bank.
#pragma once
#include <map>
#include <string>
#include <vector>

namespace ev {

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Json() = default;

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isObject() const { return type_ == Type::Object; }
    bool isArray() const { return type_ == Type::Array; }

    // Accessors return the fallback when the node is absent or the wrong
    // type. A malformed config degrades to defaults rather than throwing on a
    // service that has no console to throw at.
    bool asBool(bool fallback = false) const;
    double asNumber(double fallback = 0.0) const;
    long long asInt(long long fallback = 0) const;
    std::string asString(const std::string& fallback = "") const;

    const Json& operator[](const std::string& key) const;  // null if missing
    const Json& operator[](size_t i) const;                // null if OOR

    size_t size() const;
    bool has(const std::string& key) const;
    std::vector<std::string> keys() const;

    // On failure returns false and fills err with "line N: message".
    static bool parse(const std::string& text, Json& out, std::string& err);

private:
    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0.0;
    std::string str_;
    std::vector<Json> arr_;
    std::map<std::string, Json> obj_;

    friend class JsonParser;
    static const Json kNull;
};

}  // namespace ev
