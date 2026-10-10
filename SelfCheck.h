// Self-integrity: what binary is actually running, and is it the one we shipped.
//
// WHY
// Every telemetry file now carries agent_version, but a version string is just
// a string the binary prints about itself -- a tampered exe reports whatever it
// likes. The SHA-256 of the file on disk is a fact about the artifact, and it
// goes into the log and into the chain at startup so the question "which build
// produced this data" has an answer that survives an argument.
//
// This is NOT self-protection. A process cannot meaningfully verify itself: an
// attacker who has replaced the exe has also replaced this code. What it gives
// you is PROVENANCE -- the value is recorded, chained, and shipped to
// EdgeSentinel, where a hash that changes without a release changes visibly.
// The check that matters happens off the box, comparing against a release
// manifest. Say that plainly rather than implying the agent guards itself.
//
// Authenticode is the complementary half: it says the binary is signed by us
// and the signature covers its bytes. WinVerifyTrust answers that on Windows
// and nothing answers it elsewhere, so the result is reported, never enforced
// -- an unsigned build must still run in the lab, and refusing to start on a
// failed check hands an attacker a denial of service via the certificate store.
#pragma once
#include <string>

namespace ev {

struct SelfIntegrity {
    std::string exePath;
    std::string sha256;        // of the file on disk, empty if unreadable
    long long sizeBytes = 0;

    // Authenticode. Tri-state on purpose: "not checked" and "not signed" are
    // different facts and must not both read as false.
    enum class Signature { NotChecked, Unsigned, Valid, Invalid, Expired };
    Signature signature = Signature::NotChecked;
    std::string signer;        // subject name when available
    std::string signatureNote; // error text or reason

    // One line for the log, e.g.
    //   self: edgevitals.exe 3.0.1-sealed sha256=a3f1... 3204592 bytes, signature=unsigned
    std::string summary(const std::string& version) const;
};

const char* signatureName(SelfIntegrity::Signature s);

// Hashes the running executable. Portable: uses only the path and the file.
SelfIntegrity checkSelf(const std::string& exePath);

// Authenticode check. Win32 only; elsewhere it leaves the field NotChecked.
// Separate from checkSelf so the hash still works if signature checking is
// unavailable or slow.
void checkSignature(SelfIntegrity& out);

}  // namespace ev
