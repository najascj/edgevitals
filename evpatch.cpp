// evpatch -- anchored source patcher for EdgeVitals drops.
//
//     evpatch --check <patchfile> <source-root>    verify every edit, write nothing
//     evpatch         <patchfile> <source-root>    verify every edit, then apply all
//
// Exists because whole-file replacement has silently deleted work twice. Every
// edit names an exact anchor, and the anchor must occur EXACTLY ONCE in the
// file as it stands at that point in the patch. Zero matches (already applied,
// or the file has drifted) and two matches (ambiguous) both fail loudly with
// the file, the edit number and the first line of the anchor.
//
// ALL OR NOTHING. Every edit to every file is computed in memory first. If any
// one fails, nothing is written. Running a patch twice therefore fails cleanly
// on its first anchor rather than half-applying.
//
// Zero dependencies, like the agent: C++17 standard library only.
//
// Patch format. Directive lines start with "@@@ "; everything else is content.
// Content is taken line by line with "\n" endings; the patcher converts to the
// target file's line ending (CRLF or LF) before matching, so a checkout that
// git converted to CRLF patches the same as one that did not.
//
//     @@@ # comment
//     @@@ FILE src/Agent.cpp            following edits apply to this file
//     @@@ FIND
//     <exact lines>
//     @@@ REPLACE
//     <replacement lines, may be none>
//     @@@ END
//     @@@ NEWFILE src/Foo.cpp [crlf]    refused if the file already exists
//     <content>
//     @@@ END
//     @@@ DELETEFILE path               refused if the file does not exist
//
// Paths are relative to the source root. Absolute paths and ".." are refused.
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct Edit {
    std::string find, replace;
    int line = 0;  // line in the patch file, for messages
};

struct Op {
    enum Kind { Modify, Create, Delete } kind = Modify;
    std::string path;
    std::vector<Edit> edits;  // Modify
    std::string content;      // Create
    bool crlf = false;        // Create
    int line = 0;
};

bool fail(const std::string& m) {
    std::fprintf(stderr, "evpatch: %s\n", m.c_str());
    return false;
}

bool safePath(const std::string& p) {
    if (p.empty() || p[0] == '/' || p[0] == '\\') return false;
    if (p.size() > 1 && p[1] == ':') return false;
    std::string part;
    for (size_t i = 0; i <= p.size(); ++i) {
        if (i == p.size() || p[i] == '/' || p[i] == '\\') {
            if (part == "..") return false;
            part.clear();
        } else {
            part.push_back(p[i]);
        }
    }
    return true;
}

bool readAll(const fs::path& p, std::string& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool parsePatch(const std::string& text, std::vector<Op>& ops) {
    std::vector<std::string> lines;
    {
        std::string cur;
        for (char c : text) {
            if (c == '\n') {
                if (!cur.empty() && cur.back() == '\r') cur.pop_back();
                lines.push_back(cur);
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) lines.push_back(cur);
    }

    auto isDir = [](const std::string& l) { return l.rfind("@@@ ", 0) == 0 || l == "@@@"; };
    auto collect = [&](size_t& i, std::string& out) {
        // Reads content lines until the next directive; returns that index.
        out.clear();
        while (i < lines.size() && !isDir(lines[i])) {
            out += lines[i];
            out += '\n';
            ++i;
        }
    };

    std::string currentFile;
    Op* modify = nullptr;
    for (size_t i = 0; i < lines.size();) {
        const std::string& l = lines[i];
        const int ln = static_cast<int>(i) + 1;
        if (!isDir(l)) {
            if (l.empty()) { ++i; continue; }
            return fail("line " + std::to_string(ln) + ": content outside a block");
        }
        const std::string d = l.size() > 4 ? l.substr(4) : std::string();
        if (d.rfind("#", 0) == 0) { ++i; continue; }

        if (d.rfind("FILE ", 0) == 0) {
            currentFile = d.substr(5);
            if (!safePath(currentFile)) return fail("line " + std::to_string(ln) + ": unsafe path");
            ops.push_back(Op{});
            modify = &ops.back();
            modify->kind = Op::Modify;
            modify->path = currentFile;
            modify->line = ln;
            ++i;
        } else if (d == "FIND") {
            if (!modify) return fail("line " + std::to_string(ln) + ": FIND before FILE");
            Edit e;
            e.line = ln;
            ++i;
            collect(i, e.find);
            if (i >= lines.size() || lines[i] != "@@@ REPLACE")
                return fail("line " + std::to_string(ln) + ": FIND without REPLACE");
            ++i;
            collect(i, e.replace);
            if (i >= lines.size() || lines[i] != "@@@ END")
                return fail("line " + std::to_string(ln) + ": REPLACE without END");
            ++i;
            if (e.find.empty()) return fail("line " + std::to_string(ln) + ": empty anchor");
            modify->edits.push_back(std::move(e));
        } else if (d.rfind("NEWFILE ", 0) == 0) {
            Op op;
            op.kind = Op::Create;
            op.line = ln;
            std::string rest = d.substr(8);
            const std::string tag = " crlf";
            if (rest.size() > tag.size() && rest.compare(rest.size() - tag.size(), tag.size(), tag) == 0) {
                op.crlf = true;
                rest.resize(rest.size() - tag.size());
            }
            op.path = rest;
            if (!safePath(op.path)) return fail("line " + std::to_string(ln) + ": unsafe path");
            ++i;
            collect(i, op.content);
            if (i >= lines.size() || lines[i] != "@@@ END")
                return fail("line " + std::to_string(ln) + ": NEWFILE without END");
            ++i;
            ops.push_back(std::move(op));
            modify = nullptr;
        } else if (d.rfind("DELETEFILE ", 0) == 0) {
            Op op;
            op.kind = Op::Delete;
            op.line = ln;
            op.path = d.substr(11);
            if (!safePath(op.path)) return fail("line " + std::to_string(ln) + ": unsafe path");
            ops.push_back(std::move(op));
            modify = nullptr;
            ++i;
        } else {
            return fail("line " + std::to_string(ln) + ": unknown directive '" + l + "'");
        }
    }
    return true;
}

std::string toCrlf(const std::string& s) {
    std::string o;
    o.reserve(s.size() + s.size() / 32);
    for (char c : s) {
        if (c == '\n') o.push_back('\r');
        o.push_back(c);
    }
    return o;
}

size_t countOf(const std::string& hay, const std::string& needle, size_t& first) {
    size_t n = 0;
    first = std::string::npos;
    for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1)) {
        if (n == 0) first = p;
        ++n;
    }
    return n;
}

int lineAt(const std::string& s, size_t pos) {
    int l = 1;
    for (size_t i = 0; i < pos && i < s.size(); ++i)
        if (s[i] == '\n') ++l;
    return l;
}

std::string firstLine(const std::string& s) {
    const size_t n = s.find('\n');
    return n == std::string::npos ? s : s.substr(0, n);
}

}  // namespace

int main(int argc, char** argv) {
    bool check = false;
    int a = 1;
    if (a < argc && std::string(argv[a]) == "--check") { check = true; ++a; }
    if (argc - a != 2) {
        std::fprintf(stderr, "usage: evpatch [--check] <patchfile> <source-root>\n");
        return 2;
    }
    const fs::path patchPath = argv[a], root = argv[a + 1];

    std::string text;
    if (!readAll(patchPath, text)) { fail("cannot read " + patchPath.string()); return 2; }
    std::vector<Op> ops;
    if (!parsePatch(text, ops)) return 2;

    // Stage everything in memory. path -> new content ("" + deleted flag for removals).
    std::map<std::string, std::string> staged;
    std::map<std::string, bool> deleted, created;
    int edits = 0;

    for (const Op& op : ops) {
        const fs::path p = root / fs::u8path(op.path);
        if (op.kind == Op::Create) {
            if (fs::exists(p) || staged.count(op.path)) {
                fail(op.path + ": NEWFILE refused, file already exists (patch already applied?)");
                return 1;
            }
            staged[op.path] = op.crlf ? toCrlf(op.content) : op.content;
            created[op.path] = true;
            std::printf("  new     %s\n", op.path.c_str());
            continue;
        }
        if (op.kind == Op::Delete) {
            if (!fs::exists(p) || deleted.count(op.path)) {
                fail(op.path + ": DELETEFILE refused, file does not exist");
                return 1;
            }
            deleted[op.path] = true;
            std::printf("  delete  %s\n", op.path.c_str());
            continue;
        }

        std::string body;
        auto it = staged.find(op.path);
        if (it != staged.end()) {
            body = it->second;
        } else if (!readAll(p, body)) {
            fail(op.path + ": cannot read");
            return 1;
        }
        const bool hasCrlf = body.find("\r\n") != std::string::npos;
        if (hasCrlf) {
            for (size_t i = 0; i < body.size(); ++i)
                if (body[i] == '\n' && (i == 0 || body[i - 1] != '\r')) {
                    fail(op.path + ": mixed line endings, refusing to guess");
                    return 1;
                }
        }
        int k = 0;
        for (const Edit& e : op.edits) {
            ++k;
            const std::string f = hasCrlf ? toCrlf(e.find) : e.find;
            const std::string r = hasCrlf ? toCrlf(e.replace) : e.replace;
            size_t pos = 0;
            const size_t n = countOf(body, f, pos);
            if (n != 1) {
                fail(op.path + " edit " + std::to_string(k) + " (patch line " + std::to_string(e.line) +
                     "): anchor matched " + std::to_string(n) + " times, need exactly 1\n" +
                     "         anchor starts: " + firstLine(e.find) +
                     (n == 0 ? "\n         (already applied, or the file has drifted from 3.0.7)" : ""));
                return 1;
            }
            std::printf("  edit    %-44s #%-2d at line %d\n", op.path.c_str(), k, lineAt(body, pos));
            body.replace(pos, f.size(), r);
            ++edits;
        }
        staged[op.path] = body;
    }

    if (check) {
        std::printf("check OK: %d edits, %zu new, %zu deleted -- nothing written\n", edits,
                    created.size(), deleted.size());
        return 0;
    }

    // Write via temp + rename so a crash mid-write leaves a whole file, old or new.
    for (const auto& kv : staged) {
        const fs::path p = root / fs::u8path(kv.first);
        if (p.has_parent_path()) fs::create_directories(p.parent_path());
        const fs::path tmp = p.string() + ".evpatch.tmp";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out.write(kv.second.data(), static_cast<std::streamsize>(kv.second.size()));
            if (!out) { fail("write failed: " + tmp.string()); return 1; }
        }
        std::error_code ec;
        fs::rename(tmp, p, ec);
        if (ec) {
            fs::remove(p, ec);
            fs::rename(tmp, p, ec);
            if (ec) { fail("rename failed: " + p.string() + ": " + ec.message()); return 1; }
        }
    }
    for (const auto& kv : deleted) fs::remove(root / fs::u8path(kv.first));
    std::printf("applied: %d edits, %zu new, %zu deleted\n", edits, created.size(), deleted.size());
    return 0;
}
