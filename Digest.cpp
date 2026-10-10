#include "edgevitals/Digest.h"

#include "edgevitals/Config.h"   // kAgentVersion

#include <cstdio>
#include <cstring>

namespace ev {
namespace {

inline std::uint32_t ror(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

const std::uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

}  // namespace

void Sha256::reset() {
    h_[0]=0x6a09e667u; h_[1]=0xbb67ae85u; h_[2]=0x3c6ef372u; h_[3]=0xa54ff53au;
    h_[4]=0x510e527fu; h_[5]=0x9b05688cu; h_[6]=0x1f83d9abu; h_[7]=0x5be0cd19u;
    buflen_ = 0;
    total_ = 0;
}

void Sha256::block(const std::uint8_t* p) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (std::uint32_t(p[i*4]) << 24) | (std::uint32_t(p[i*4+1]) << 16) |
               (std::uint32_t(p[i*4+2]) << 8) | std::uint32_t(p[i*4+3]);
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
        const std::uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    std::uint32_t a=h_[0],b=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],hh=h_[7];
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        const std::uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d; h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=hh;
}

void Sha256::update(const void* data, std::size_t len) {
    const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
    total_ += len;
    while (len) {
        const std::size_t take = (64 - buflen_) < len ? (64 - buflen_) : len;
        std::memcpy(buf_ + buflen_, p, take);  // flawfinder: ignore -- take <= 64 - buflen_: bounded to the 64-byte block
        buflen_ += take; p += take; len -= take;
        if (buflen_ == 64) { block(buf_); buflen_ = 0; }
    }
}

std::string Sha256::hex() const {
    // Finalise on a COPY. Callers checkpoint mid-stream and keep feeding, so
    // finalising in place would corrupt every subsequent byte.
    Sha256 t = *this;
    const std::uint64_t bits = t.total_ * 8;
    const std::uint8_t pad = 0x80;
    t.update(&pad, 1);
    const std::uint8_t zero = 0;
    while (t.buflen_ != 56) t.update(&zero, 1);
    std::uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = std::uint8_t((bits >> (56 - i*8)) & 0xFF);
    t.update(len, 8);

    char out[65];  // flawfinder: ignore -- 8 x snprintf(out + i*8, 9, ...) = 64 hex chars + NUL
    for (int i = 0; i < 8; ++i) (void)std::snprintf(out + i*8, 9, "%08x", t.h_[i]);
    return std::string(out, 64);
}

std::string sha256Hex(const std::string& s) {
    Sha256 h;
    h.update(s);
    return h.hex();
}

// ── chain ────────────────────────────────────────────────────────────────
void HashChain::feed(const std::string& bytes) {
    seg_.update(bytes);
    bytes_ += bytes.size();
    for (char c : bytes) if (c == '\n') ++rows_;
}

std::string HashChain::reopen() {
    char line[512];  // flawfinder: ignore -- snprintf(line, sizeof(line)); fields are the agent version and our own short file names
    (void)std::snprintf(line, sizeof(line),
        "{\"v\":2,\"agent\":\"%s\",\"file\":\"%s\",\"event\":\"reopen\","
        "\"prev\":\"%s\",\"start\":%llu,\"bytes\":%llu}",
        kAgentVersion, label_.c_str(), prev_.c_str(),
        static_cast<unsigned long long>(segStart_),
        static_cast<unsigned long long>(bytes_));
    sealed_ = false;
    return std::string(line);
}

std::string HashChain::seal() {
    sealed_ = true;
    return checkpoint();
}

std::string HashChain::checkpoint() {
    // The digest covers the previous checkpoint AND this segment, which is
    // what links them: altering anything behind this point changes every
    // checkpoint after it.
    Sha256 link;
    link.update(prev_);
    link.update(seg_.hex());
    const std::string digest = link.hex();

    char line[512];  // flawfinder: ignore -- snprintf(line, sizeof(line)); fields are the agent version and our own short file names
    (void)std::snprintf(line, sizeof(line),
        "{\"v\":2,\"agent\":\"%s\",\"file\":\"%s\",\"seq\":%llu,"
        "\"prev\":\"%s\",\"hash\":\"%s\","
        "\"start\":%llu,\"bytes\":%llu,\"rows\":%llu,\"alg\":\"sha256\","
        "\"sig\":null%s}",
        kAgentVersion,
        label_.c_str(),
        static_cast<unsigned long long>(seq_),
        prev_.c_str(), digest.c_str(),
        static_cast<unsigned long long>(segStart_),
        static_cast<unsigned long long>(bytes_),
        static_cast<unsigned long long>(rows_),
        sealed_ ? ",\"final\":1" : "");

    prev_ = digest;
    ++seq_;
    segStart_ = bytes_;    // the next segment begins where this one ended
    seg_.reset();          // next checkpoint covers only what follows
    return std::string(line);
}

}  // namespace ev
