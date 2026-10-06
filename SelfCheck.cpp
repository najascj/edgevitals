#include "edgevitals/SelfCheck.h"

#include <cstdio>
#include <vector>

#include "edgevitals/Digest.h"

#if defined(_WIN32)
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>
#endif

namespace ev {

const char* signatureName(SelfIntegrity::Signature s) {
    switch (s) {
        case SelfIntegrity::Signature::Unsigned: return "unsigned";
        case SelfIntegrity::Signature::Valid:    return "valid";
        case SelfIntegrity::Signature::Invalid:  return "INVALID";
        case SelfIntegrity::Signature::Expired:  return "expired";
        default:                                 return "not-checked";
    }
}

SelfIntegrity checkSelf(const std::string& exePath) {
    SelfIntegrity si;
    si.exePath = exePath;

    std::FILE* f = std::fopen(exePath.c_str(), "rb");
    if (!f) return si;

    // Streamed in 64 KB blocks. The binary is a few megabytes and this runs
    // once at startup, but reading it whole would put a 3 MB allocation in the
    // path of a process whose entire budget is 15 MB.
    Sha256 h;
    std::vector<unsigned char> buf(64 * 1024);
    for (;;) {
        const size_t n = std::fread(buf.data(), 1, buf.size(), f);
        if (n == 0) break;
        h.update(buf.data(), n);
        si.sizeBytes += static_cast<long long>(n);
    }
    std::fclose(f);
    si.sha256 = h.hex();
    return si;
}

#if defined(_WIN32)

void checkSignature(SelfIntegrity& out) {
    if (out.exePath.empty()) return;

    std::wstring wpath(out.exePath.begin(), out.exePath.end());

    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = wpath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    // Revocation checking reaches the network. On an air-gapped ATM that means
    // a multi-second stall at every startup for a check that cannot succeed.
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;

    const LONG r = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

    switch (r) {
        case ERROR_SUCCESS:
            out.signature = SelfIntegrity::Signature::Valid;
            break;
        // One label each. TRUST_E_NOSIGNATURE *is* 0x800B0100 and
        // CERT_E_EXPIRED *is* 0x800B0101, so listing both forms was a
        // duplicate-case compile error.
        case TRUST_E_NOSIGNATURE:
            out.signature = SelfIntegrity::Signature::Unsigned;
            out.signatureNote = "no embedded Authenticode signature";
            break;
        case TRUST_E_BAD_DIGEST:
            // The file was modified after signing -- the strongest signal here.
            out.signature = SelfIntegrity::Signature::Invalid;
            out.signatureNote = "digest mismatch: the binary was altered after signing";
            break;
        case CERT_E_EXPIRED:
            out.signature = SelfIntegrity::Signature::Expired;
            out.signatureNote = "certificate expired";
            break;
        case CERT_E_UNTRUSTEDROOT:
            out.signature = SelfIntegrity::Signature::Invalid;
            out.signatureNote = "certificate chains to an untrusted root";
            break;
        default: {
            out.signature = SelfIntegrity::Signature::Invalid;
            char b[64];
            std::snprintf(b, sizeof(b), "WinVerifyTrust 0x%08lX", static_cast<unsigned long>(r));
            out.signatureNote = b;
            break;
        }
    }

    // Release the state WinVerifyTrust allocated; skipping this leaks per call.
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
}

#else

void checkSignature(SelfIntegrity& out) {
    // Nothing off Windows. Left NotChecked rather than Unsigned: we do not know,
    // and reporting "unsigned" would be a claim we cannot support.
    (void)out;
}

#endif

std::string SelfIntegrity::summary(const std::string& version) const {
    std::string s = "self: version=" + version;
    s += " sha256=" + (sha256.empty() ? std::string("unreadable") : sha256);
    s += " size=" + std::to_string(sizeBytes);
    s += " signature=" + std::string(signatureName(signature));
    if (!signer.empty()) s += " signer=\"" + signer + "\"";
    if (!signatureNote.empty()) s += " (" + signatureNote + ")";
    return s;
}

}  // namespace ev
