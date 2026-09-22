// Minimal ZIP writer: CRC32 + raw DEFLATE + the ZIP container.
//
// WHY THIS EXISTS RATHER THAN A LIBRARY
// The Win7 SP1 floor (_WIN32_WINNT=0x0601) rules out the Windows Compression
// API, which is Windows 8 and later. Zero third-party dependency rules out
// zlib. Shelling out to makecab or PowerShell would put a process spawn on a
// locked-down terminal for the sake of saving disk. So the compressor is here,
// in the platform-independent core, where it is testable on any host and
// verifiable against a reference implementation.
//
// SCOPE: compression only. There is no inflate path -- nothing in EdgeVitals
// ever reads an archive back. Anything that opens one (Explorer, 7-Zip,
// Python's zipfile) already has a decompressor.
//
// The DEFLATE encoder emits fixed-Huffman blocks with LZ77 matching. Dynamic
// Huffman would gain roughly another 25-30% on this data and costs several
// hundred more lines of table construction; fixed already turns a 7 MB
// telemetry CSV into well under 1 MB, and the marginal megabyte is not worth
// the additional surface for a bug that produces a corrupt archive.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ev {

std::uint32_t crc32Of(const std::uint8_t* data, std::size_t n,
                      std::uint32_t seed = 0);

// Raw DEFLATE stream (RFC 1951). No zlib or gzip wrapper -- ZIP method 8
// wants the bare stream.
std::vector<std::uint8_t> deflateRaw(const std::uint8_t* data, std::size_t n);

// One entry in a ZIP file.
struct ZipEntry {
    std::string name;                 // stored path, forward slashes
    std::vector<std::uint8_t> data;   // uncompressed content
    // DOS timestamp fields. Zero is legal and renders as 1980-01-01, which is
    // worse than useless when an analyst is looking for a date -- so the
    // caller passes the file's own date.
    int year = 1980, month = 1, day = 1, hour = 0, minute = 0, second = 0;
};

// Builds a complete ZIP archive in memory. Single-threaded, no temp files.
// Entries are stored with method 8 unless deflate fails to shrink them, in
// which case that entry falls back to method 0 -- a stored entry is still a
// valid archive, and refusing to archive at all would be worse.
std::vector<std::uint8_t> buildZip(const std::vector<ZipEntry>& entries);

}  // namespace ev
