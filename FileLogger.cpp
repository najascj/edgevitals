#include "edgevitals/FileLogger.h"

#include "edgevitals/ChainedFile.h"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <system_error>

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



Date todayLocal() {
    const auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tmv{};
#if defined(_WIN32)
    // On failure fall back to UTC rather than stamp year 1900.
    if (localtime_s(&tmv, &t) != 0) (void)gmtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    return Date{tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday};
}

std::string stampLocal() {
    const auto now = std::chrono::system_clock::now();
    const auto t = std::chrono::system_clock::to_time_t(now);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()).count() % 1000;
    std::tm tmv{};
#if defined(_WIN32)
    // On failure fall back to UTC rather than stamp year 1900.
    if (localtime_s(&tmv, &t) != 0) (void)gmtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char b[64];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), ...)
    (void)std::snprintf(b, sizeof(b), "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec, static_cast<int>(ms));
    return b;
}

// edgevitals-YYYY-MM-DD.log and its .zip, and nothing else. Same shape as the
// CSV classifier so retention treats every stream identically.
bool classifyLog(const std::string& name, const std::string& pre, Date& d) {
    const std::string ext = ".log";
    if (name.size() != pre.size() + 10 + ext.size()) return false;
    if (name.compare(0, pre.size(), pre) != 0) return false;
    if (name.compare(name.size() - ext.size(), ext.size(), ext) != 0) return false;
    return Date::parseIso(name.substr(pre.size(), 10), d);
}

}  // namespace

FileLogger::FileLogger(Options opts, std::shared_ptr<ILogger> inner)
    : opts_(std::move(opts)), inner_(std::move(inner)) {}

FileLogger::~FileLogger() { close(); }

bool FileLogger::openFor(const Date& d) {
    // Seal the outgoing day before opening the next one.
    if (fp_) {
        checkpoint(true);
        (void)std::fclose(fp_);
        fp_ = nullptr;
    }

    std::error_code ec;
    fs::create_directories(opts_.dir, ec);
    if (ec) { lastError_ = "cannot create log dir: " + ec.message(); return false; }

    const std::string name = opts_.prefix + "-" + d.iso() + ".log";
    path_ = (fs::path(opts_.dir) / name).string();
    chainPath_ = path_ + ".chain";

    fp_ = openLogFile(path_, "ab");
    if (!fp_) { lastError_ = "cannot open " + path_; return false; }

    openDate_ = d;
    if (opts_.chainEveryLines > 0) {
        std::error_code sz;
        const auto already = fs::exists(path_, sz) ? fs::file_size(path_, sz) : 0;
        chain_.reset(new HashChain(name,
                                   sz ? 0 : static_cast<std::uint64_t>(already),
                                   lastChainHash(chainPath_)));
        if (chainIsSealed(chainPath_)) {
            // A failed record leaves a gap that evverify reports.
            (void)appendChainRecord(chainPath_, chain_->reopen() + "\n");
        }
        sinceCheckpoint_ = 0;
    } else {
        chain_.reset();
    }
    return true;
}

void FileLogger::write(const char* level, const std::string& msg) {
    std::lock_guard<std::mutex> lk(mu_);
    if (inner_ && opts_.alsoTo) {
        // Mirror first: if the file write fails we still want the operator to
        // see the line on the console.
        if (level[0] == 'e')      inner_->error(msg);
        else if (level[0] == 'w') inner_->warn(msg);
        else                      inner_->info(msg);
    }

    const Date d = todayLocal();
    if (!fp_ || openDate_ != d) {
        const bool rotating = (fp_ != nullptr);
        if (!openFor(d)) return;
        if (rotating) purgeOld(d);
    }

    std::string line = stampLocal();
    line += " [";
    line += level;
    line += "] ";
    line += msg;
    line.push_back('\n');

    const size_t n = std::fwrite(line.data(), 1, line.size(), fp_);
    if (n != line.size()) { lastError_ = "short write to " + path_; return; }
    // Flushed every line on purpose. This is the file someone reads after a
    // crash, and buffered lines lost at the moment of the crash are exactly
    // the ones they need.
    (void)std::fflush(fp_);

    chainWrite(line);
}

void FileLogger::chainWrite(const std::string& line) {
    if (!chain_) return;
    chain_->feed(line);
    if (++sinceCheckpoint_ >= opts_.chainEveryLines) checkpoint(false);
}

void FileLogger::checkpoint(bool final) {
    if (!chain_ || chainPath_.empty()) return;
    // A failed record leaves a gap that evverify reports.
    (void)appendChainRecord(chainPath_, (final ? chain_->seal() : chain_->checkpoint()) + "\n");
    sinceCheckpoint_ = 0;
}

void FileLogger::close() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!fp_) return;
    checkpoint(true);
    (void)std::fclose(fp_);
    fp_ = nullptr;
}

int FileLogger::purgeOld(const Date& today) {
    std::error_code ec;
    if (!fs::exists(opts_.dir, ec)) return 0;

    const std::string pre = opts_.prefix + "-";
    const long long cutoff = today.serial() - opts_.retentionDays;
    const std::string todayName = fs::path(path_).filename().string();

    int removed = 0;
    for (const auto& entry : fs::directory_iterator(opts_.dir, ec)) {
        if (ec) break;
        const std::string name = entry.path().filename().string();
        Date d{};
        if (!classifyLog(name, pre, d)) continue;
        if (d.serial() >= cutoff) continue;
        if (name == todayName) continue;

        std::error_code rm;
        if (fs::remove(entry.path(), rm)) {
            ++removed;
            // The chain sidecar goes with its log. Leaving an orphan sidecar
            // behind makes a verifier report a missing file rather than a
            // retired one.
            std::error_code rm2;
            fs::remove(entry.path().string() + ".chain", rm2);
        }
    }
    return removed;
}

}  // namespace ev
