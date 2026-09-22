// Schema and Row.
//
// Design note: the schema is BUILT AT RUNTIME from config rather than being a
// fixed struct of 70 named fields. Two reasons, both of which came out of the
// sizing work:
//
//   1. The tracked-process list is config-driven, so the column set is too.
//      Adding a process to watch must not require a recompile.
//
//   2. Clients push their own columns over the pipe. EdgeVitals does not know
//      what a "frame_p99_ms" is and should not have to -- EdgeTerminal knows.
//      Open/closed: new metrics ship without touching the agent.
//
// Cell carries an explicit Empty state. This is not pedantry: a component that
// is not licensed and a component that is idle must never both render as 0.0,
// or the CSV is unreadable six weeks later.
#pragma once
#include <string>
#include <unordered_map>
#include <vector>

namespace ev {

class Cell {
public:
    enum class Kind { Empty, Number, Text };

    Cell() = default;
    static Cell number(double v) { Cell c; c.kind_ = Kind::Number; c.num_ = v; return c; }
    static Cell text(std::string v) { Cell c; c.kind_ = Kind::Text; c.txt_ = std::move(v); return c; }

    Kind kind() const { return kind_; }
    bool empty() const { return kind_ == Kind::Empty; }
    double num() const { return num_; }
    const std::string& txt() const { return txt_; }

    // CSV rendering. Empty -> "" (not "0"). Numbers use the given precision
    // and drop a trailing ".0" so integers stay integers in the file.
    std::string toCsv(int precision) const;

private:
    Kind kind_ = Kind::Empty;
    double num_ = 0.0;
    std::string txt_;
};

// Ordered column list. Order is fixed once frozen, because the CSV header is
// written once per file and every row must match it positionally.
class Schema {
public:
    // Returns the column index. Adding a column after freeze() is a no-op
    // returning npos -- a late column would desynchronise every row already
    // written to today's file.
    size_t add(const std::string& name, int precision = 2);
    void freeze() { frozen_ = true; }
    bool frozen() const { return frozen_; }

    size_t size() const { return names_.size(); }
    size_t indexOf(const std::string& name) const;  // npos if absent
    const std::string& name(size_t i) const { return names_[i]; }
    int precision(size_t i) const { return precision_[i]; }

    std::string headerCsv() const;

    static constexpr size_t npos = static_cast<size_t>(-1);

private:
    std::vector<std::string> names_;
    std::vector<int> precision_;
    std::unordered_map<std::string, size_t> index_;
    bool frozen_ = false;
};

class Row {
public:
    explicit Row(const Schema& s) : schema_(&s), cells_(s.size()) {}

    void set(size_t col, Cell c) { if (col < cells_.size()) cells_[col] = std::move(c); }
    void setNumber(size_t col, double v) { set(col, Cell::number(v)); }
    void setText(size_t col, std::string v) { set(col, Cell::text(std::move(v))); }

    // Named setters. Silently ignore unknown names so a client pushing a
    // column we do not carry cannot take the service down.
    bool setNumber(const std::string& name, double v);
    bool setText(const std::string& name, std::string v);

    const Cell& at(size_t col) const { return cells_[col]; }
    void clear() { for (auto& c : cells_) c = Cell{}; }

    std::string toCsv() const;

private:
    const Schema* schema_;
    std::vector<Cell> cells_;
};

// RFC4180 quoting: wrap in quotes and double any embedded quote, but only
// when the value actually needs it. Unconditional quoting would bloat a file
// that is 95% numbers.
std::string csvEscape(const std::string& v);

}  // namespace ev
