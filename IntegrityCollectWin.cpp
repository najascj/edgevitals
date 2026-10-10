// Endpoint integrity: Win32 persistence read + collection entry point.
// Read-only: registry (KEY_QUERY_VALUE / ENUMERATE), service config. No child
// processes. File hashing is the portable hashFiles() in IntegrityHash.cpp.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "edgevitals/IntegrityCollect.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <vector>

namespace ev {
namespace {

std::string narrow(const wchar_t* w) {
    if (!w || !*w) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    s.resize(static_cast<size_t>(n - 1));
    return s;
}
std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
IRd rdFromError(LONG e) {
    if (e == ERROR_SUCCESS) return IRd::Ok;
    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return IRd::Absent;
    if (e == ERROR_ACCESS_DENIED) return IRd::Denied;
    return IRd::Error;
}

// From a command line, extract the lower-cased executable FILE NAME only: strip
// a leading quote, take up to the next quote or space, then the basename, drop
// any extension-less noise. Deliberately discards the directory (which can name
// a user profile) and all arguments.
std::string exeFileName(const std::string& cmd) {
    std::string s = cmd;
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    std::string token;
    if (i < s.size() && s[i] == '"') {
        const size_t end = s.find('"', i + 1);
        token = s.substr(i + 1, end == std::string::npos ? std::string::npos : end - i - 1);
    } else {
        const size_t end = s.find_first_of(" \t", i);
        token = s.substr(i, end == std::string::npos ? std::string::npos : end - i);
    }
    const size_t slash = token.find_last_of("\\/");
    if (slash != std::string::npos) token = token.substr(slash + 1);
    return lower(token);
}

// Enumerate value names + data under an HKLM subkey (Run / RunOnce).
void readRunKey(const wchar_t* path, const char* kind, std::vector<PersistEntry>& out, bool& anyOk) {
    HKEY k = nullptr;
    const LONG e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k);
    if (e != ERROR_SUCCESS) {
        // Absent is fine (no autostarts there); denied/error is noted by the caller via anyOk.
        if (e == ERROR_FILE_NOT_FOUND) anyOk = true;
        return;
    }
    anyOk = true;
    wchar_t name[512];  // flawfinder: ignore -- RegEnumValueW bounded by nl = sizeof(name)/sizeof; data length checked separately
    std::vector<wchar_t> data(8192);
    for (DWORD i = 0; i < 1024; ++i) {
        DWORD nl = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
        DWORD dl = static_cast<DWORD>(data.size() * sizeof(wchar_t) - sizeof(wchar_t)), type = 0;
        const LONG q = RegEnumValueW(k, i, name, &nl, nullptr, &type, reinterpret_cast<LPBYTE>(data.data()), &dl);
        if (q == ERROR_NO_MORE_ITEMS) break;
        if (q != ERROR_SUCCESS) continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        data[std::min<size_t>(dl / sizeof(wchar_t), data.size() - 1)] = L'\0';
        PersistEntry pe;
        pe.kind = kind;
        pe.name = lower(narrow(name));
        pe.target = exeFileName(narrow(data.data()));
        if (!pe.name.empty() && out.size() < 2048) out.push_back(std::move(pe));
    }
    RegCloseKey(k);
}

// Auto-start services: enumerate, keep SERVICE_AUTO_START, target = exe file
// name from the service's ImagePath via QueryServiceConfig.
void readAutoServices(std::vector<PersistEntry>& out, bool& anyOk) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;
    anyOk = true;
    DWORD need = 0, count = 0, resume = 0;
    std::vector<BYTE> buf(64 * 1024);
    for (;;) {
        const BOOL r = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf.data(),
                                             static_cast<DWORD>(buf.size()), &need, &count, &resume, nullptr);
        const DWORD e = r ? ERROR_SUCCESS : GetLastError();
        if (!r && e != ERROR_MORE_DATA) break;
        const auto* arr = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count && out.size() < 4096; ++i) {
            const std::wstring key = arr[i].lpServiceName ? arr[i].lpServiceName : L"";
            SC_HANDLE h = OpenServiceW(scm, key.c_str(), SERVICE_QUERY_CONFIG);
            if (!h) continue;
            DWORD cneed = 0;
            QueryServiceConfigW(h, nullptr, 0, &cneed);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cneed > 0 && cneed < 64 * 1024) {
                std::vector<BYTE> cb(cneed);
                auto* qc = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cb.data());
                if (QueryServiceConfigW(h, qc, cneed, &cneed) && qc->dwStartType == SERVICE_AUTO_START) {
                    PersistEntry pe;
                    pe.kind = "service";
                    pe.name = lower(narrow(key.c_str()));
                    pe.target = exeFileName(narrow(qc->lpBinaryPathName ? qc->lpBinaryPathName : L""));
                    if (!pe.name.empty()) out.push_back(std::move(pe));
                }
            }
            CloseServiceHandle(h);
        }
        if (r) break;
        if (need > buf.size()) {
            if (need > 2 * 1024 * 1024) break;
            buf.resize(need);
        }
    }
    CloseServiceHandle(scm);
}

// Scheduled tasks: names only, from the TaskCache\Tree. Target is left empty
// (reading a task's action needs the task XML; a new task NAME is the signal).
void readTasks(std::vector<PersistEntry>& out, bool& anyOk) {
    const wchar_t* base = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree";
    // Walk one level of folders plus their immediate task subkeys (bounded).
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &root) != ERROR_SUCCESS) return;
    anyOk = true;
    std::vector<std::wstring> stack{L""};
    int visited = 0;
    while (!stack.empty() && visited < 4096) {
        const std::wstring rel = stack.back();
        stack.pop_back();
        HKEY k = root;
        bool opened = false;
        if (!rel.empty()) {
            if (RegOpenKeyExW(root, rel.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) continue;
            opened = true;
        }
        // A leaf task key has an "Id" value; record its name.
        if (RegQueryValueExW(k, L"Id", nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS && !rel.empty()) {
            const size_t slash = rel.find_last_of(L'\\');
            PersistEntry pe;
            pe.kind = "task";
            pe.name = lower(narrow((slash == std::wstring::npos ? rel : rel.substr(slash + 1)).c_str()));
            if (!pe.name.empty() && out.size() < 4096) out.push_back(std::move(pe));
        }
        wchar_t sub[256];  // flawfinder: ignore -- RegEnumKeyExW bounded by sl = sizeof(sub)/sizeof
        for (DWORD i = 0; i < 2048; ++i) {
            DWORD sl = sizeof(sub) / sizeof(sub[0]);
            if (RegEnumKeyExW(k, i, sub, &sl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            stack.push_back(rel.empty() ? std::wstring(sub) : rel + L"\\" + sub);
            ++visited;
        }
        if (opened) RegCloseKey(k);
    }
    RegCloseKey(root);
}

bool elevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION te{};
    DWORD sz = 0;
    const bool ok = GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &sz) && te.TokenIsElevated;
    CloseHandle(tok);
    return ok;
}

std::string utcNow() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char b[32];  // flawfinder: ignore -- written only by snprintf(b, sizeof(b), ...)
    (void)std::snprintf(b, sizeof(b), "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

// Refine the portable hash outcome on Windows: Absent vs Denied.
void refineFileOutcomes(std::vector<FileHash>& files) {
    for (auto& f : files) {
        if (f.rd != IRd::Absent) continue;   // only unopenable ones need refining
        std::wstring w;
        const int n = MultiByteToWideChar(CP_UTF8, 0, f.path.c_str(), -1, nullptr, 0);  // flawfinder: ignore -- length from the sizing call; buffer allocated to that size
        if (n > 1) {
            w.assign(static_cast<size_t>(n), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, f.path.c_str(), -1, &w[0], n);  // flawfinder: ignore -- length from the sizing call; buffer allocated to that size
            w.resize(static_cast<size_t>(n - 1));
        }
        const DWORD a = GetFileAttributesW(w.c_str());
        if (a == INVALID_FILE_ATTRIBUTES) f.rd = rdFromError(static_cast<LONG>(GetLastError()));
    }
}

}  // namespace

void collectIntegrity(const IntegrityCollectInput& in, IntegrityFacts& out) {
    out = IntegrityFacts();
    out.takenAtUtc = utcNow();
    out.elevated = elevated();

    hashFiles(in.files, in.maxBytes, out.files, out.filesRd);
    refineFileOutcomes(out.files);

    bool anyOk = false;
    readRunKey(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "run", out.persistence, anyOk);
    readRunKey(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "run_once", out.persistence, anyOk);
    readRunKey(L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "run", out.persistence, anyOk);
    readAutoServices(out.persistence, anyOk);
    readTasks(out.persistence, anyOk);
    out.persistRd = anyOk ? IRd::Ok : IRd::Denied;

    // Stable order so the change-detection key is deterministic.
    std::sort(out.persistence.begin(), out.persistence.end(), [](const PersistEntry& a, const PersistEntry& b) {
        if (a.kind != b.kind) return a.kind < b.kind;
        if (a.name != b.name) return a.name < b.name;
        return a.target < b.target;
    });
}

}  // namespace ev
