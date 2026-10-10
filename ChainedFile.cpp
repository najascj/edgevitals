#include "edgevitals/ChainedFile.h"

#include <filesystem>
#include <fstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace ev {
namespace {

// True for a symlink, or on Windows any reparse point (junction, mount point,
// symlink) -- std::filesystem does not report junctions as symlinks.
bool isLinkLike(const fs::path& p) {
    std::error_code ec;
    const auto st = fs::symlink_status(p, ec);
    if (ec || !fs::exists(st)) return false;
    if (fs::is_symlink(st)) return true;
#ifdef _WIN32
    const DWORD a = GetFileAttributesW(p.wstring().c_str());
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT)) return true;
#endif
    return false;
}

}  // namespace

bool appendChainRecord(const std::string& sidecarPath, const std::string& recordLine) {
    std::FILE* cf = openLogFile(sidecarPath, "ab");
    if (!cf) return false;
    const bool wrote = std::fwrite(recordLine.data(), 1, recordLine.size(), cf) == recordLine.size();
    const bool flushed = std::fflush(cf) == 0;
    const bool closed = std::fclose(cf) == 0;
    return wrote && flushed && closed;
}

std::FILE* openLogFile(const std::string& path, const char* mode) {
    const fs::path p(path);
    if (p.has_parent_path() && isLinkLike(p.parent_path())) return nullptr;
    std::error_code ec;
    const auto st = fs::symlink_status(p, ec);
    if (!ec && fs::exists(st) && (isLinkLike(p) || !fs::is_regular_file(st))) return nullptr;
    return std::fopen(path.c_str(), mode);  // flawfinder: ignore -- target checked above: plain file, no link, junction or device
}

bool chainSidecarIsSealed(const std::string& sidecar) {
    std::ifstream in(sidecar);
    if (!in) return false;
    std::string line, last;
    while (std::getline(in, line))
        if (!line.empty()) last = line;
    return last.find("\"final\":1") != std::string::npos;
}

std::string chainSidecarLastHash(const std::string& sidecar) {
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

bool ChainedFile::open(const std::string& path, std::string& err) {  // flawfinder: ignore -- member function named open, not POSIX open()
    close();
    std::error_code ec;
    const fs::path parent = fs::path(path).parent_path();
    if (!parent.empty()) fs::create_directories(parent, ec);

    std::error_code sz;
    const auto already = fs::exists(path, sz) ? fs::file_size(path, sz) : 0;
    fp_ = openLogFile(path, "ab");
    if (!fp_) {
        err = "cannot open " + path + " (or not a plain file)";
        return false;
    }
    path_ = path;
    chainPath_ = path + ".chain";
    since_ = 0;
    if (every_ > 0) {
        chain_.reset(new HashChain(fs::path(path).filename().string(),
                                   sz ? 0 : static_cast<std::uint64_t>(already),
                                   chainSidecarLastHash(chainPath_)));
        // Same-day restart: the earlier run sealed this file. Record the
        // reopen BEFORE any new byte, or the file fails verification until
        // the next checkpoint.
        if (chainSidecarIsSealed(chainPath_)) writeRecord(chain_->reopen());
    } else {
        chain_.reset();
    }
    return true;
}

bool ChainedFile::append(const std::string& bytes) {
    if (!fp_) return false;
    const size_t w = std::fwrite(bytes.data(), 1, bytes.size(), fp_);
    (void)std::fflush(fp_);
    if (w != bytes.size()) return false;
    if (chain_) {
        chain_->feed(bytes);
        if (++since_ >= every_) {
            writeRecord(chain_->checkpoint());
            since_ = 0;
        }
    }
    return true;
}

void ChainedFile::close() {
    if (!fp_) return;
    if (chain_) writeRecord(chain_->seal());
    (void)std::fclose(fp_);
    fp_ = nullptr;
    chain_.reset();
}

void ChainedFile::writeRecord(const std::string& rec) {
    if (chainPath_.empty()) return;
    // A failed record leaves a gap that evverify reports; nothing else to do here.
    (void)appendChainRecord(chainPath_, rec + "\n");
}

}  // namespace ev
