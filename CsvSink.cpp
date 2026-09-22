#include "edgevitals/CsvSink.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <vector>

#include "edgevitals/Archive.h"

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif

namespace fs = std::filesystem;

namespace ev {

std::string Date::iso() const {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", y, m, d);
    return buf;
}

bool Date::parseIso(const std::string& s, Date& out) {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-') return false;
    for (size_t i : {0u, 1u, 2u, 3u, 5u, 6u, 8u, 9u})
        if (s[i] < '0' || s[i] > '9') return false;
    Date d;
    d.y = std::atoi(s.substr(0, 4).c_str());
    d.m = std::atoi(s.substr(5, 2).c_str());
    d.d = std::atoi(s.substr(8, 2).c_str());
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
        std::fclose(fp_);
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

    const std::string name = opts_.prefix + "-" + d.iso() + ".csv";
    path_ = (fs::path(opts_.dir) / name).string();

    const bool existed = fs::exists(path_, ec) && fs::file_size(path_, ec) > 0;
    fp_ = std::fopen(path_.c_str(), "ab");
    if (!fp_) {
        lastError_ = "cannot open " + path_;
        return false;
    }
    // Header only on a genuinely new file. Reopening after a service restart
    // mid-day must append, not write a second header into the middle.
    if (!existed) {
        const std::string h = schema_.headerCsv();
        std::fwrite(h.data(), 1, h.size(), fp_);
        std::fputc('\n', fp_);
        std::fflush(fp_);
    }
    openDate_ = d;
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
        if (rotating) purgeOldFiles(today);
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
    if (opts_.flushEveryTick) std::fflush(fp_);
    return true;
}

namespace {

// Recognises prefix-YYYY-MM-DD.csv and prefix-YYYY-MM-DD.csv.zip and nothing
// else. Anything whose date cannot be parsed out of its own name belongs to
// somebody else and is never touched -- deleting a stranger's file because it
// happened to share a directory is not a recoverable mistake.
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
            std::FILE* f = std::fopen(tmp.string().c_str(), "wb");
            if (!f) continue;
            const size_t w = std::fwrite(zbytes.data(), 1, zbytes.size(), f);
            std::fflush(f);
            std::fclose(f);
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

}  // namespace ev
