#include "edgevitals/ChainedFile.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace ev {

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

bool ChainedFile::open(const std::string& path, std::string& err) {
    close();
    std::error_code ec;
    const fs::path parent = fs::path(path).parent_path();
    if (!parent.empty()) fs::create_directories(parent, ec);

    std::error_code sz;
    const auto already = fs::exists(path, sz) ? fs::file_size(path, sz) : 0;
    fp_ = std::fopen(path.c_str(), "ab");
    if (!fp_) {
        err = "cannot open " + path;
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
    std::fflush(fp_);
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
    std::fclose(fp_);
    fp_ = nullptr;
    chain_.reset();
}

void ChainedFile::writeRecord(const std::string& rec) {
    if (chainPath_.empty()) return;
    if (std::FILE* cf = std::fopen(chainPath_.c_str(), "ab")) {
        const std::string line = rec + "\n";
        std::fwrite(line.data(), 1, line.size(), cf);
        std::fflush(cf);
        std::fclose(cf);
    }
}

}  // namespace ev
