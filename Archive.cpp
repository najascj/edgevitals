#include "edgevitals/Archive.h"

#include <cstring>

namespace ev {
namespace {

// ── CRC32 (IEEE 802.3, the polynomial ZIP uses) ──────────────────────────
struct Crc32Table {
    std::uint32_t t[256];
    Crc32Table() {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
    }
};
const Crc32Table kCrc;

// ── bit writer ───────────────────────────────────────────────────────────
// DEFLATE packs bits into bytes starting at the least-significant bit. Huffman
// codes are the one exception: they are written most-significant bit first,
// which is why putCode reverses them.
class BitWriter {
public:
    explicit BitWriter(std::vector<std::uint8_t>& out) : out_(out) {}

    void putBits(std::uint32_t value, int count) {
        bits_ |= static_cast<std::uint64_t>(value) << nbits_;
        nbits_ += count;
        while (nbits_ >= 8) {
            out_.push_back(static_cast<std::uint8_t>(bits_ & 0xFFu));
            bits_ >>= 8;
            nbits_ -= 8;
        }
    }

    // Huffman code, MSB first.
    void putCode(std::uint32_t code, int count) {
        for (int i = count - 1; i >= 0; --i)
            putBits((code >> i) & 1u, 1);
    }

    void flushByte() {
        if (nbits_ > 0) {
            out_.push_back(static_cast<std::uint8_t>(bits_ & 0xFFu));
            bits_ = 0;
            nbits_ = 0;
        }
    }

private:
    std::vector<std::uint8_t>& out_;
    std::uint64_t bits_ = 0;
    int nbits_ = 0;
};

// ── fixed Huffman code tables (RFC 1951 section 3.2.6) ───────────────────
void literalCode(int sym, std::uint32_t& code, int& len) {
    if (sym <= 143)      { code = 0x30u + sym;              len = 8; }
    else if (sym <= 255) { code = 0x190u + (sym - 144);     len = 9; }
    else if (sym <= 279) { code = static_cast<std::uint32_t>(sym - 256); len = 7; }
    else                 { code = 0xC0u + (sym - 280);      len = 8; }
}

// Length codes 257-285.
const std::uint16_t kLenBase[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258};
const std::uint8_t kLenExtra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 0};

// Distance codes 0-29.
const std::uint16_t kDistBase[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
    769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
const std::uint8_t kDistExtra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

int lengthCodeIndex(int len) {
    for (int i = 28; i >= 0; --i)
        if (len >= kLenBase[i]) return i;
    return 0;
}

int distCodeIndex(int dist) {
    for (int i = 29; i >= 0; --i)
        if (dist >= kDistBase[i]) return i;
    return 0;
}

// ── LZ77 with a hash chain ───────────────────────────────────────────────
constexpr int kWindow = 32768;
constexpr int kMinMatch = 3;
constexpr int kMaxMatch = 258;
constexpr int kHashBits = 15;
constexpr int kHashSize = 1 << kHashBits;
// Bounded chain walk. Telemetry CSV is highly repetitive, so long chains are
// common and an unbounded search turns compression from milliseconds into
// seconds. 32 is the point past which the ratio stops moving on this data.
constexpr int kMaxChain = 32;

inline std::uint32_t hash3(const std::uint8_t* p) {
    return ((static_cast<std::uint32_t>(p[0]) << 10) ^
            (static_cast<std::uint32_t>(p[1]) << 5) ^
            static_cast<std::uint32_t>(p[2])) & (kHashSize - 1);
}

}  // namespace

std::uint32_t crc32Of(const std::uint8_t* data, std::size_t n, std::uint32_t seed) {
    std::uint32_t c = seed ^ 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i)
        c = kCrc.t[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

std::vector<std::uint8_t> deflateRaw(const std::uint8_t* data, std::size_t n) {
    std::vector<std::uint8_t> out;
    out.reserve(n / 3 + 64);
    BitWriter bw(out);

    // Single fixed-Huffman block covering the whole input.
    bw.putBits(1, 1);   // BFINAL
    bw.putBits(1, 2);   // BTYPE = 01, fixed Huffman

    if (n == 0) {
        std::uint32_t c; int l;
        literalCode(256, c, l);
        bw.putCode(c, l);
        bw.flushByte();
        return out;
    }

    // prev[] is indexed circularly over the 32 KB LZ77 window, not over the
    // whole input. A match can never be further back than kWindow, so entries
    // beyond that are unreachable -- and a flat prev[n] costs 4 bytes per
    // input byte, which on a 7.4 MB day file is ~30 MB of transient against a
    // 15 MB self-budget. Circular makes it a fixed 128 KB.
    std::vector<int> head(kHashSize, -1);
    std::vector<int> prev(kWindow, -1);
    const std::size_t kWinMask = static_cast<std::size_t>(kWindow) - 1;

    std::size_t pos = 0;
    while (pos < n) {
        int bestLen = 0, bestDist = 0;

        if (pos + kMinMatch <= n) {
            const std::uint32_t h = hash3(data + pos);
            int cand = head[h];
            int chain = kMaxChain;
            const std::size_t maxLen = (n - pos) < static_cast<std::size_t>(kMaxMatch)
                                           ? (n - pos)
                                           : static_cast<std::size_t>(kMaxMatch);
            while (cand >= 0 && chain-- > 0) {
                const std::size_t dist = pos - static_cast<std::size_t>(cand);
                if (dist > static_cast<std::size_t>(kWindow)) break;
                // Cheap reject before the memcmp-style walk.
                if (bestLen >= kMinMatch &&
                    data[cand + static_cast<std::size_t>(bestLen)] !=
                        data[pos + static_cast<std::size_t>(bestLen)]) {
                    cand = prev[static_cast<std::size_t>(cand) & kWinMask];
                    continue;
                }
                std::size_t l = 0;
                while (l < maxLen && data[cand + l] == data[pos + l]) ++l;
                if (static_cast<int>(l) > bestLen) {
                    bestLen = static_cast<int>(l);
                    bestDist = static_cast<int>(dist);
                    if (bestLen >= kMaxMatch) break;
                }
                cand = prev[static_cast<std::size_t>(cand) & kWinMask];
            }
        }

        if (bestLen >= kMinMatch) {
            const int li = lengthCodeIndex(bestLen);
            std::uint32_t c; int l;
            literalCode(257 + li, c, l);
            bw.putCode(c, l);
            if (kLenExtra[li])
                bw.putBits(static_cast<std::uint32_t>(bestLen - kLenBase[li]), kLenExtra[li]);

            const int di = distCodeIndex(bestDist);
            bw.putCode(static_cast<std::uint32_t>(di), 5);   // fixed 5-bit distance code
            if (kDistExtra[di])
                bw.putBits(static_cast<std::uint32_t>(bestDist - kDistBase[di]), kDistExtra[di]);

            // Insert every position the match covers, or later matches lose
            // the chain entries and the ratio collapses on repetitive input.
            for (int k = 0; k < bestLen; ++k) {
                const std::size_t p = pos + static_cast<std::size_t>(k);
                if (p + kMinMatch <= n) {
                    const std::uint32_t hh = hash3(data + p);
                    prev[p & kWinMask] = head[hh];
                    head[hh] = static_cast<int>(p);
                }
            }
            pos += static_cast<std::size_t>(bestLen);
        } else {
            std::uint32_t c; int l;
            literalCode(data[pos], c, l);
            bw.putCode(c, l);
            if (pos + kMinMatch <= n) {
                const std::uint32_t hh = hash3(data + pos);
                prev[pos & kWinMask] = head[hh];
                head[hh] = static_cast<int>(pos);
            }
            ++pos;
        }
    }

    std::uint32_t c; int l;
    literalCode(256, c, l);   // end of block
    bw.putCode(c, l);
    bw.flushByte();
    return out;
}

namespace {

void put16(std::vector<std::uint8_t>& v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>(x & 0xFFu));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFFu));
}

void put32(std::vector<std::uint8_t>& v, std::uint32_t x) {
    put16(v, x & 0xFFFFu);
    put16(v, (x >> 16) & 0xFFFFu);
}

std::uint16_t dosTime(const ZipEntry& e) {
    return static_cast<std::uint16_t>((e.hour << 11) | (e.minute << 5) | (e.second / 2));
}

std::uint16_t dosDate(const ZipEntry& e) {
    int y = e.year - 1980;
    if (y < 0) y = 0;
    return static_cast<std::uint16_t>((y << 9) | (e.month << 5) | e.day);
}

}  // namespace

std::vector<std::uint8_t> buildZip(const std::vector<ZipEntry>& entries) {
    std::vector<std::uint8_t> out;
    struct Central {
        std::uint32_t crc, csize, usize, offset;
        std::uint16_t method, time, date;
        std::string name;
    };
    std::vector<Central> central;
    central.reserve(entries.size());

    for (const auto& e : entries) {
        const std::uint32_t usize = static_cast<std::uint32_t>(e.data.size());
        const std::uint32_t crc = crc32Of(e.data.data(), e.data.size());

        std::vector<std::uint8_t> comp = deflateRaw(e.data.data(), e.data.size());
        std::uint16_t method = 8;
        // A deflate stream larger than the input happens on incompressible or
        // tiny content. Storing is still a valid entry; refusing to archive
        // would be the worse outcome.
        if (comp.size() >= e.data.size()) {
            comp = e.data;
            method = 0;
        }

        Central c;
        c.crc = crc;
        c.csize = static_cast<std::uint32_t>(comp.size());
        c.usize = usize;
        c.offset = static_cast<std::uint32_t>(out.size());
        c.method = method;
        c.time = dosTime(e);
        c.date = dosDate(e);
        c.name = e.name;

        put32(out, 0x04034B50u);          // local file header
        put16(out, 20);                   // version needed
        put16(out, 0);                    // flags
        put16(out, method);
        put16(out, c.time);
        put16(out, c.date);
        put32(out, crc);
        put32(out, c.csize);
        put32(out, c.usize);
        put16(out, static_cast<std::uint32_t>(e.name.size()));
        put16(out, 0);                    // extra length
        out.insert(out.end(), e.name.begin(), e.name.end());
        out.insert(out.end(), comp.begin(), comp.end());

        central.push_back(std::move(c));
    }

    const std::uint32_t cdOffset = static_cast<std::uint32_t>(out.size());
    for (const auto& c : central) {
        put32(out, 0x02014B50u);          // central directory header
        put16(out, 20);                   // version made by
        put16(out, 20);                   // version needed
        put16(out, 0);                    // flags
        put16(out, c.method);
        put16(out, c.time);
        put16(out, c.date);
        put32(out, c.crc);
        put32(out, c.csize);
        put32(out, c.usize);
        put16(out, static_cast<std::uint32_t>(c.name.size()));
        put16(out, 0);                    // extra
        put16(out, 0);                    // comment
        put16(out, 0);                    // disk number
        put16(out, 0);                    // internal attrs
        put32(out, 0);                    // external attrs
        put32(out, c.offset);
        out.insert(out.end(), c.name.begin(), c.name.end());
    }
    const std::uint32_t cdSize = static_cast<std::uint32_t>(out.size()) - cdOffset;

    put32(out, 0x06054B50u);              // end of central directory
    put16(out, 0);
    put16(out, 0);
    put16(out, static_cast<std::uint32_t>(central.size()));
    put16(out, static_cast<std::uint32_t>(central.size()));
    put32(out, cdSize);
    put32(out, cdOffset);
    put16(out, 0);                        // comment length
    return out;
}

}  // namespace ev
