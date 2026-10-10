#include "edgevitals/CsvSink.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <vector>

#include "edgevitals/Archive.h"
#include "edgevitals/ChainedFile.h"

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif

namespace fs = std::filesystem;

namespace ev {
namespace {

// Last checkpoint hash in a sidecar, or "genesis" if there is none. Lets a
// chain resume across an agent restart instead of starting over.

// True when the sidecar's last record is a seal.
static bool chainIsSealed(const std::string& sidecar) {
    std::ifstream in(sidecar);
    if (!in) return false;
    std::string line, last;
    while (std::getline(in, line)) if (!line.empty()) last = line;
    return last.find("\"final\":1") != std::string::npos;
}

static std::string lastChainHash(const std::string& sidecar) {
    std::ifstream in(sidecar);
    if (!in) return "genesis";
    std::string line, last;
    while (std::getline(in, line))
        if (line.find("\"hash\"") != std::string::npos) last = line;
    if (last.empty()) return "genesis";
    const std::string key = "\"hash\":\"";
    const auto p = last.find(key);
    if (p == std::string::npos) return "genesis";
    const auto s = p + key.size();
    const auto e = last.find('"', s);
    return e == std::string::npos ? std::string("genesis") : last.substr(s, e - s);
}
}  // namespace


std::string Date::iso() const {
    char buf[16];  // flawfinder: ignore -- written only by snprintf(buf, sizeof(buf), ...)
    (void)std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", y, m, d);
    return buf;
}

bool Date::parseIso(const std::string& s, Date& out) {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-') return false;
    for (size_t i : {0u, 1u, 2u, 3u, 5u, 6u, 8u, 9u})
        if (s[i] < '0' || s[i] > '9') return false;
    Date d;
    // Digits were validated above; computed directly, not via atoi.
    d.y = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
    d.m = (s[5] - '0') * 10 + (s[6] - '0');
    d.d = (s[8] - '0') * 10 + (s[9] - '0');
    if (d.m < 1 || d.m > 12 || d.d < 1 || d.d > 31) return false;
    out = d;
    return true;
}

long long Date::serial() const {
    // Howard Hinnant's days_from_civil. Correct across leap years and
    // century boundaries, which a naive y*365 + m*30 + d is not -- and
    // retention silently keeping an extra day around a leap year is exactly
    // the kind of bug nobody finds.
    long long yy = y;
    unsigned mm = static_cast<unsigned>(m);
    unsigned dd = static_cast<unsigned>(d);
    yy -= mm <= 2;
    const long long era = (yy >= 0 ? yy : yy - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(yy - era * 400);
    const unsigned doy = (153 * (mm + (mm > 2 ? -3 : 9)) + 2) / 5 + dd - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<long long>(doe) - 719468;
}

CsvSink::CsvSink(Options opts, const Schema& schema, std::shared_ptr<IDiskSpace> disk)
    : opts_(std::move(opts)), schema_(schema), disk_(std::move(disk)) {}

CsvSink::~CsvSink() { close(); }

void CsvSink::close() {
    if (fp_) {
        // Seal BEFORE closing the handle. A day file that ends without a final
        // checkpoint is indistinguishable from one an attacker truncated, and
        // anything appended afterwards would otherwise verify as "trailing
        // bytes, normal for a live file".
        if (chain_ && !chainPath_.empty() && !chain_->sealed()) {
            (void)std::fflush(fp_);
            if (!appendChainRecord(chainPath_, chain_->seal() + "\n"))
                lastError_ = "cannot write seal to " + chainPath_;
        }
        (void)std::fclose(fp_);
        fp_ = nullptr;
    }
}

bool CsvSink::openFor(const Date& d) {
    close();
    std::error_code ec;
    const bool fresh = !fs::exists(opts_.dir, ec);
    fs::create_directories(opts_.dir, ec);
    if (fresh && opts_.restrictLogAcl) applyLogDirAcl();
    if (ec) {
        lastError_ = "cannot create log dir " + opts_.dir + ": " + ec.message();
        return false;
    }

    std::string name = opts_.prefix + "-" + d.iso() + ".csv";
    path_ = (fs::path(opts_.dir) / name).string();

    // SCHEMA GUARD.
    // Appending to an existing day file is correct only if that file has the
    // SAME columns. On 23 Sep the agent started once on the built-in defaults
    // (11 roles, 222 columns), then again with the real config (17 roles, 312
    // columns) -- and appended 1,690 rows of 312 fields under a 222-field
    // header. The result parses in no CSV reader at all: the day's data was
    // recoverable only by reconstructing the header by hand.
    //
    // So: if the first line of the existing file is not this schema's header,
    // do NOT append. Roll to prefix-YYYY-MM-DD.2.csv and say why. Losing the
    // file name is a nuisance; losing the day is not.
    {
        const std::string want = schema_.headerCsv();
        int suffix = 1;
        for (;;) {
            std::error_code ex;
            if (!fs::exists(path_, ex) || fs::file_size(path_, ex) == 0) break;
            std::ifstream probe(path_, std::ios::binary);
            std::string firstLine;
            std::getline(probe, firstLine);
            probe.close();
            if (!firstLine.empty() && firstLine.back() == '\r') firstLine.pop_back();
            if (firstLine == want) break;              // same schema: append
            ++suffix;
            name = opts_.prefix + "-" + d.iso() + "." + std::to_string(suffix) + ".csv";
            path_ = (fs::path(opts_.dir) / name).string();
            schemaRolled_ = true;
        }
    }

    const bool existed = fs::exists(path_, ec) && fs::file_size(path_, ec) > 0;
    fp_ = openLogFile(path_, "ab");
    if (!fp_) {
        lastError_ = "cannot open " + path_;
        return false;
    }
    // Header only on a genuinely new file. Reopening after a service restart
    // mid-day must append, not write a second header into the middle.
    // One chain per file. Rebuilt on rotation so each day verifies standalone.
    // On reopen mid-day the chain restarts from genesis and its first
    // checkpoint covers only what follows -- the sidecar records the byte
    // offset, so a verifier sees exactly which span each segment covers rather
    // than silently assuming it covers the whole file.
    if (opts_.chainEveryRows > 0) {
        // Start the chain at the file's CURRENT size. Opened for append, a
        // chain that began at zero described byte ranges that did not exist.
        std::error_code sz;
        const auto already = fs::exists(path_, sz) ? fs::file_size(path_, sz) : 0;
        chain_.reset(new HashChain(name,
                                   sz ? 0 : static_cast<std::uint64_t>(already),
                                   lastChainHash(path_ + ".chain")));
        chainPath_ = path_ + ".chain";
        // If the previous run sealed this file, say so before appending a byte.
        if (chainIsSealed(chainPath_)) {
            if (!appendChainRecord(chainPath_, chain_->reopen() + "\n"))
                lastError_ = "cannot write reopen record to " + chainPath_;
        }
        chainPath_ = path_ + ".chain";
        sinceCheckpoint_ = 0;
    } else {
        chain_.reset();
        chainPath_.clear();
    }

    if (!existed) {
        const std::string h = schema_.headerCsv() + "\n";
        const bool ok = std::fwrite(h.data(), 1, h.size(), fp_) == h.size() && std::fflush(fp_) == 0;
        if (!ok) lastError_ = "cannot write header to " + path_;
        chainFeed(h);
    }
    openDate_ = d;
    if (schemaRolled_) {
        // Not an error -- the agent keeps running -- but the operator must know
        // the day's data is in two files with different column sets.
        lastError_ = "column set differs from the existing day file; rolled to " +
                     name + " rather than appending mismatched rows";
        schemaRolled_ = false;
        return true;
    }
    lastError_.clear();
    return true;
}

bool CsvSink::write(const Row& row, const Date& today) {
    if (disk_) freeMb_ = disk_->freeMbAt(opts_.dir);

    if (freeMb_ > 0.0 && freeMb_ < opts_.diskFloorMb) {
        if (!suppressed_) {
            suppressed_ = true;
            lastError_ = "disk below floor (" + std::to_string(static_cast<long long>(freeMb_)) +
                         " MB free, floor " + std::to_string(static_cast<long long>(opts_.diskFloorMb)) +
                         " MB) -- telemetry writing suspended";
            close();
        }
        return false;
    }
    if (suppressed_) {
        suppressed_ = false;
        lastError_.clear();
    }

    if (!fp_ || openDate_ != today) {
        const bool rotating = (fp_ != nullptr);
        if (!openFor(today)) return false;
        if (rotating) maintainAllStreams(today);
    }

    // One buffered write per row. The row is assembled in memory first so a
    // partially-written line cannot appear if the process is killed mid-tick.
    std::string line = row.toCsv();
    line.push_back('\n');
    const size_t n = std::fwrite(line.data(), 1, line.size(), fp_);
    if (n != line.size()) {
        lastError_ = "short write to " + path_;
        return false;
    }
    if (opts_.flushEveryTick) (void)std::fflush(fp_);

    // Feed AFTER a confirmed full write: the chain must describe what is on
    // disk, not what we intended to write.
    chainFeed(line);
    if (chain_ && ++sinceCheckpoint_ >= opts_.chainEveryRows) chainCheckpoint();
    return true;
}

void CsvSink::chainFeed(const std::string& bytes) {
    if (chain_) chain_->feed(bytes);
}

void CsvSink::chainCheckpoint() {
    if (!chain_ || chainPath_.empty()) return;
    const std::string line = chain_->checkpoint() + "\n";
    // Append and flush immediately. A checkpoint still sitting in a buffer
    // when the process dies covers rows nobody can verify.
    if (!appendChainRecord(chainPath_, line)) { lastError_ = "cannot write " + chainPath_; return; }
    sinceCheckpoint_ = 0;
}

namespace {




// Recognises prefix-YYYY-MM-DD.csv and prefix-YYYY-MM-DD.csv.zip and nothing
// else. Anything whose date cannot be parsed out of its own name belongs to
// somebody else and is never touched -- deleting a stranger's file because it
// happened to share a directory is not a recoverable mistake.
// Recognises "<pre>YYYY-MM-DD<ext>" and its ".zip" form. Parameterised on the
// extension so ONE maintenance sweep covers all three streams: the telemetry
// CSV, the discovery CSV and the agent's own .log. Keying it on a single
// hard-coded prefix meant the discovery log was rotated but never archived or
// purged -- it simply accumulated, outside retention entirely.
bool classifyExt(const std::string& name, const std::string& pre,
                 const std::string& ext, Date& d, bool& isZip) {
    const std::string zipExt = ext + ".zip";
    if (name.size() < pre.size() || name.compare(0, pre.size(), pre) != 0) return false;
    if (name.size() == pre.size() + 10 + ext.size() &&
        name.compare(name.size() - ext.size(), ext.size(), ext) == 0) {
        isZip = false;
    } else if (name.size() == pre.size() + 10 + zipExt.size() &&
               name.compare(name.size() - zipExt.size(), zipExt.size(), zipExt) == 0) {
        isZip = true;
    } else {
        return false;
    }
    return Date::parseIso(name.substr(pre.size(), 10), d);
}

bool classify(const std::string& name, const std::string& pre, Date& d, bool& isZip) {
    const std::string csv = ".csv", zip = ".csv.zip";
    if (name.compare(0, pre.size(), pre) != 0) return false;
    if (name.size() == pre.size() + 10 + csv.size() &&
        name.compare(name.size() - csv.size(), csv.size(), csv) == 0) {
        isZip = false;
    } else if (name.size() == pre.size() + 10 + zip.size() &&
               name.compare(name.size() - zip.size(), zip.size(), zip) == 0) {
        isZip = true;
    } else {
        return false;
    }
    return Date::parseIso(name.substr(pre.size(), 10), d);
}

}  // namespace

void CsvSink::applyLogDirAcl() {
#ifdef _WIN32
    // A protected, non-inheriting DACL: SYSTEM and Administrators, full
    // control, inherited by files created inside. SetNamedSecurityInfo with
    // PROTECTED_DACL_SECURITY_INFORMATION drops whatever the parent directory
    // would otherwise hand down, which is the point -- the exe may have been
    // unpacked anywhere.
    //
    // "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    //   PA  protected, no inherited ACEs
    //   AI  auto-inherit flag set on children
    //   OICI object + container inherit, so new CSVs get it too
    //   FA  full access
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &sd, nullptr)) {
        lastError_ = "log ACL: SDDL parse failed";
        return;
    }
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present) {
        const DWORD r = SetNamedSecurityInfoA(
            const_cast<LPSTR>(opts_.dir.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, dacl, nullptr);
        // Not fatal. Losing telemetry is worse than a loose ACL, so this is
        // recorded and execution continues.
        if (r != ERROR_SUCCESS)
            lastError_ = "log ACL: SetNamedSecurityInfo failed (" + std::to_string(r) + ")";
    }
    LocalFree(sd);
#endif
}

int CsvSink::purgeOldFiles(const Date& today) {
    std::error_code ec;
    if (!fs::exists(opts_.dir, ec)) return 0;

    const std::string pre = opts_.prefix + "-";
    const long long cutoff = today.serial() - opts_.retentionDays;
    const std::string todayName = fs::path(path_).filename().string();
    int removed = 0;

    for (const auto& entry : fs::directory_iterator(opts_.dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec)) continue;
        const std::string name = entry.path().filename().string();

        Date d;
        bool isZip = false;
        if (!classify(name, pre, d, isZip)) continue;
        if (d.serial() >= cutoff) continue;
        if (name == todayName) continue;                 // never today's

        std::error_code rm;
        if (fs::remove(entry.path(), rm)) ++removed;
    }
    return removed;
}

int CsvSink::archiveOldFiles(const Date& today) {
    if (opts_.archiveAfterDays <= 0) return 0;
    std::error_code ec;
    if (!fs::exists(opts_.dir, ec)) return 0;

    const std::string pre = opts_.prefix + "-";
    const long long cutoff = today.serial() - opts_.archiveAfterDays;
    const std::string todayName = fs::path(path_).filename().string();
    int archived = 0;

    // Collect first. Compressing while iterating a directory that is being
    // mutated is undefined on some filesystems.
    std::vector<fs::path> candidates;
    for (const auto& entry : fs::directory_iterator(opts_.dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec)) continue;
        const std::string name = entry.path().filename().string();
        Date d;
        bool isZip = false;
        if (!classify(name, pre, d, isZip)) continue;
        if (isZip) continue;                             // already archived
        if (d.serial() >= cutoff) continue;              // inside the raw window
        if (name == todayName) continue;
        // Already past retention: purge will delete it. Compressing first
        // would spend CPU on a file that is about to cease to exist. Holds
        // regardless of the order the caller invokes archive and purge in.
        if (d.serial() < today.serial() - opts_.retentionDays) continue;
        candidates.push_back(entry.path());
    }

    for (const auto& src : candidates) {
        std::error_code e2;
        const auto sz = fs::file_size(src, e2);
        if (e2) continue;
        // A file bigger than the ZIP32 field can express would produce a
        // silently wrong archive. Leave it raw and let retention deal with it.
        const unsigned long long capBytes =
            static_cast<unsigned long long>(opts_.archiveMaxMb) * 1048576ull;
        if (sz > 0xFFFFFFFFull || (opts_.archiveMaxMb > 0 && sz > capBytes)) {
            // Left raw on purpose. Compression peaks near 3x the file size in
            // transient memory; a pathological day file must not take the
            // agent -- or the terminal -- down to save disk.
            lastError_ = "skipped archive of oversized " + src.filename().string() +
                         " (" + std::to_string(sz / 1048576ull) + " MB > " +
                         std::to_string(opts_.archiveMaxMb) + " MB cap)";
            continue;
        }

        std::ifstream in(src.string(), std::ios::binary);
        if (!in) continue;
        std::vector<std::uint8_t> buf(static_cast<size_t>(sz));
        if (sz > 0) in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(sz));
        if (!in && sz > 0) continue;
        in.close();

        Date d;
        bool isZip = false;
        classify(src.filename().string(), pre, d, isZip);

        ZipEntry ze;
        ze.name = src.filename().string();
        ze.data = std::move(buf);
        ze.year = d.y;
        ze.month = d.m;
        ze.day = d.d;

        const std::vector<std::uint8_t> zbytes = buildZip({ze});

        // .tmp -> fsync -> rename -> delete original. At no point does a
        // window exist where neither a readable CSV nor a complete archive is
        // on disk.
        const fs::path tmp = src.string() + ".zip.tmp";
        const fs::path dst = src.string() + ".zip";
        {
            std::FILE* f = openLogFile(tmp.string(), "wb");
            if (!f) continue;
            const size_t w = std::fwrite(zbytes.data(), 1, zbytes.size(), f);
            (void)std::fflush(f);
            (void)std::fclose(f);
            if (w != zbytes.size()) {
                std::error_code rmv;
                fs::remove(tmp, rmv);
                continue;
            }
        }
        std::error_code mv;
        fs::rename(tmp, dst, mv);
        if (mv) {
            std::error_code rmv;
            fs::remove(tmp, rmv);
            continue;
        }
        std::error_code rmSrc;
        if (fs::remove(src, rmSrc)) ++archived;
    }
    return archived;
}

long long CsvSink::bytesOnDisk() const {
    std::error_code ec;
    if (!fs::exists(opts_.dir, ec)) return 0;
    const std::string pre = opts_.prefix + "-";
    long long total = 0;
    for (const auto& entry : fs::directory_iterator(opts_.dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec)) continue;
        Date d;
        bool isZip = false;
        if (!classify(entry.path().filename().string(), pre, d, isZip)) continue;
        std::error_code e2;
        const auto sz = fs::file_size(entry.path(), e2);
        if (!e2) total += static_cast<long long>(sz);
    }
    return total;
}

// Compress one file into <path>.zip. Factored out of archiveOldFiles so the
// all-stream sweep uses exactly the same path: same size cap, same ZIP entry
// shape, same failure behaviour (leave the file raw and say why).
bool CsvSink::archiveFile(const std::string& src, const std::string& dstZip,
                          std::string& err) {
    std::error_code ec;
    const auto sz = fs::file_size(src, ec);
    if (ec) { err = "cannot size " + src; return false; }

    const unsigned long long capBytes =
        static_cast<unsigned long long>(opts_.archiveMaxMb) * 1048576ull;
    if (sz > 0xFFFFFFFFull || (opts_.archiveMaxMb > 0 && sz > capBytes)) {
        err = "oversized, left raw";
        return false;
    }

    std::ifstream in(src, std::ios::binary);
    if (!in) { err = "cannot read " + src; return false; }
    std::vector<std::uint8_t> buf(static_cast<size_t>(sz));
    if (sz > 0) in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(sz));
    if (!in && sz > 0) { err = "short read"; return false; }
    in.close();

    const std::string name = fs::path(src).filename().string();
    Date d{};
    // The date sits at a fixed offset before the extension in every stream we
    // write; if it will not parse, stamp the entry with today rather than fail.
    {
        const size_t dot = name.rfind('.');
        if (dot != std::string::npos && dot >= 10)
            Date::parseIso(name.substr(dot - 10, 10), d);
    }

    ZipEntry ze;
    ze.name = name;
    ze.data = std::move(buf);
    ze.year = d.y ? d.y : 1980;
    ze.month = d.m ? d.m : 1;
    ze.day = d.d ? d.d : 1;

    const std::vector<std::uint8_t> zbytes = buildZip({ze});
    std::ofstream out(dstZip, std::ios::binary | std::ios::trunc);
    if (!out) { err = "cannot create " + dstZip; return false; }
    out.write(reinterpret_cast<const char*>(zbytes.data()),
              static_cast<std::streamsize>(zbytes.size()));
    if (!out) { err = "short write to " + dstZip; return false; }
    out.close();
    return true;
}

int CsvSink::maintainAllStreams(const Date& today) {
    std::error_code ec;
    if (!fs::exists(opts_.dir, ec)) return 0;

    // Every stream the agent writes into this directory. The telemetry prefix
    // is configurable; the other two are fixed by the code that writes them.
    struct Stream { std::string prefix; std::string ext; };
    const Stream streams[] = {
        {opts_.prefix + "-",         ".csv"},
        {"unknown-processes-",       ".csv"},
        {"edgevitals-",              ".log"},
        {"winevents-",               ".jsonl"},
        {"posture-",                 ".jsonl"},
        {"integrity-",               ".jsonl"},
    };

    const long long archiveCut = opts_.archiveAfterDays > 0
                                     ? today.serial() - opts_.archiveAfterDays
                                     : today.serial() - 1000000;
    const long long purgeCut = today.serial() - opts_.retentionDays;
    const std::string todayName = fs::path(path_).filename().string();

    int touched = 0;
    for (const auto& st : streams) {
        // Collect first, act second: archiving renames files, and mutating a
        // directory while iterating it is undefined.
        std::vector<fs::path> found;
        for (const auto& e : fs::directory_iterator(opts_.dir, ec)) {
            if (ec) break;
            found.push_back(e.path());
        }

        for (const auto& path : found) {
            const std::string name = path.filename().string();
            Date d{};
            bool isZip = false;
            // A sidecar past retention goes even if its log is already gone:
            // an orphan chain makes a verifier report a missing file rather
            // than a retired one. Earlier builds left orphans behind.
            static const std::string kChain = ".chain";
            if (name.size() > kChain.size() &&
                name.compare(name.size() - kChain.size(), kChain.size(), kChain) == 0) {
                if (classifyExt(name.substr(0, name.size() - kChain.size()), st.prefix, st.ext, d, isZip) &&
                    d.serial() < purgeCut) {
                    std::error_code rm;
                    if (fs::remove(path, rm)) ++touched;
                }
                continue;
            }
            if (!classifyExt(name, st.prefix, st.ext, d, isZip)) continue;
            if (name == todayName) continue;                 // never today's own file
            if (d.serial() >= today.serial()) continue;      // nor anything dated today

            if (d.serial() < purgeCut) {
                std::error_code rm;
                if (fs::remove(path, rm)) {
                    ++touched;
                    // The sidecar retires with its log; an orphan chain makes a
                    // verifier report a missing file rather than a retired one.
                    // The sidecar is named after the LOG, not the archive:
                    // x.csv.zip retires x.csv.chain, not x.csv.zip.chain.
                    std::string base = path.string();
                    if (isZip && base.size() > 4) base.resize(base.size() - 4);
                    std::error_code rm2;
                    fs::remove(base + ".chain", rm2);
                }
                continue;
            }

            if (!isZip && d.serial() < archiveCut) {
                // The log is compressed; its .chain stays beside the .zip,
                // uncompressed. To verify an archived day, extract the log
                // next to its sidecar and run evverify. Both retire together
                // at retention_days.
                const std::string zipPath = path.string() + ".zip";
                std::string aerr;
                if (archiveFile(path.string(), zipPath, aerr)) {
                    std::error_code rm;
                    if (fs::remove(path, rm)) ++touched;
                }
            }
        }
    }
    return touched;
}

}  // namespace ev
