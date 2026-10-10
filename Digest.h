// SHA-256 and a rolling hash chain for tamper-evident telemetry.
//
// WHY THIS EXISTS
// The CSV is written locally and shipped to EdgeSentinel. Anyone who can write
// the log directory can edit a row, and nothing in the file would show it. A
// 32-bit FNV-1a config hash detects a fat-finger; it does not detect an
// attacker, because FNV is not collision-resistant.
//
// WHAT THIS GIVES AND WHAT IT DOES NOT
// A hash chain makes modification, reordering, insertion and truncation
// DETECTABLE by anyone holding the chain file. It does not make them
// impossible, and on its own it does not prove WHO wrote the data -- an
// attacker who owns the box can rewrite both the CSV and the chain.
//
// It becomes strong in two ways, both outside this file:
//   - the chain is shipped to EdgeSentinel promptly, so the attacker's window
//     is one checkpoint interval rather than a day, and the server copy is the
//     reference;
//   - a checkpoint is signed, which needs a key and a decision about where it
//     lives. The envelope carries an "alg" field so signing layers on without
//     changing the format.
//
// Implemented here rather than taken from a library for the same reason
// DEFLATE was: the Win7 SP1 floor and zero third-party dependencies. SHA-256
// is 150 lines and is verified against the FIPS 180-4 test vectors in the test
// suite.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace ev {

// Streaming SHA-256. Feed bytes with update(), read the digest with hex().
// Copyable so a running chain state can be snapshotted for a checkpoint
// without disturbing the stream.
class Sha256 {
public:
    Sha256() { reset(); }
    void reset();
    void update(const void* data, std::size_t len);
    void update(const std::string& s) { update(s.data(), s.size()); }
    // Returns the digest as 64 lowercase hex characters. Does not disturb the
    // running state, so it can be called at a checkpoint and then fed more.
    std::string hex() const;

private:
    void block(const std::uint8_t* p);
    std::uint32_t h_[8];
    std::uint8_t buf_[64] = {};
    std::size_t buflen_;
    std::uint64_t total_;
};

std::string sha256Hex(const std::string& s);

// A rolling chain over everything written to one file.
//
// Each checkpoint covers the bytes since the previous one AND the previous
// checkpoint's digest, so a verifier walking the chain detects a change
// anywhere behind it. Recording the byte offset and row count is what makes
// TRUNCATION detectable: a file shorter than the last checkpoint claims is
// missing data, which a plain per-row hash would never reveal.
class HashChain {
public:
    // label appears in the sidecar so a reader knows what was covered.
    // startOffset is the size the file ALREADY has. A chain that always began
    // counting at zero while the file was opened for append produced
    // checkpoints whose byte ranges were wrong from the second agent start
    // onward -- every restart within a day silently invalidated that day's
    // whole chain. Observed on 23 Sep: a freshly written telemetry file failed
    // its own verification because the agent had been run more than once.
    // resumePrev is the `hash` of the last checkpoint already in the sidecar.
    // Passing it keeps ONE unbroken chain per file across agent restarts; left
    // at "genesis" every restart began a fresh chain and the verifier reported
    // a broken link on a file nobody had touched.
    explicit HashChain(std::string label, std::uint64_t startOffset = 0,
                       std::string resumePrev = "genesis")
        : label_(std::move(label)), prev_(std::move(resumePrev)),
          bytes_(startOffset), segStart_(startOffset) {}

    // Every byte written to the file must also go through here, in order.
    void feed(const std::string& bytes);

    // Produces one checkpoint line (NDJSON, no trailing newline) and starts
    // the next segment. Safe to call at any cadence; callers pick the
    // interval.
    std::string checkpoint();

    // Seals the file. Identical to checkpoint() except the record carries
    // "final":1, which tells a verifier that NOTHING may legitimately follow.
    //
    // Without this a verifier cannot distinguish a file still being written
    // from one an attacker appended to after the agent stopped -- and appending
    // forged rows to yesterday's closed file, then letting the server ingest
    // them, is the upward-poisoning case this whole mechanism exists to stop.
    // Measured before the fix: an appended row verified OK, exit 0.
    std::string seal();

    // Marks a sealed file as legitimately continued. A same-day agent restart
    // appends to a file whose chain already ends in a seal; until its first
    // checkpoint those bytes look exactly like an append-after-close attack,
    // and the verifier said so. Observed 23 Sep: the same file FAILED, then
    // passed moments later once a checkpoint landed.
    //
    // Written at open time, BEFORE any byte is appended, so the window where
    // the file would fail verification does not exist.
    std::string reopen();

    std::uint64_t bytes() const { return bytes_; }
    std::uint64_t rows() const { return rows_; }
    // Digest of the chain as it stands, without emitting a checkpoint.
    std::string head() const { return prev_; }

private:
    std::string label_;
    Sha256 seg_;                 // hash of the current segment
    std::string prev_ = "genesis";   // initialised from resumePrev
    std::uint64_t bytes_ = 0;
    std::uint64_t segStart_ = 0;     // file offset this segment begins at
    std::uint64_t rows_ = 0;
    std::uint64_t seq_ = 0;
    bool sealed_ = false;

public:
    bool sealed() const { return sealed_; }
};

}  // namespace ev
