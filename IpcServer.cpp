#include "edgevitals/IpcServer.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>

#include <algorithm>

#include "edgevitals/Json.h"

namespace ev {

IpcServer::IpcServer(std::string pipeName, std::vector<std::string> acceptedKeys)
    : pipeName_(std::move(pipeName)), accepted_(std::move(acceptedKeys)) {
    std::sort(accepted_.begin(), accepted_.end());
}

IpcServer::~IpcServer() { stop(); }

bool IpcServer::start() {
    if (running_.load()) return true;
    stopEvent_ = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) {
        lastError_ = "CreateEvent failed";
        return false;
    }
    running_.store(true);
    listener_ = std::thread([this] { listenLoop(); });
    return true;
}

void IpcServer::stop() {
    // NO early return on !running_. The listener sets running_ = false itself
    // when the pipe cannot be created -- a squatted name, or an SDDL the
    // system rejects. Returning here left a JOINABLE std::thread for the
    // destructor to destroy, which is exactly "terminate called without an
    // active exception" on shutdown. Observed 23 Sep after client_sid was
    // changed to IU and pipe creation began failing.
    const bool wasRunning = running_.load();
    running_.store(false);
    if (!wasRunning) {
        if (listener_.joinable()) listener_.join();
        return;
    }
    if (stopEvent_) SetEvent(static_cast<HANDLE>(stopEvent_));
    // Unblock a ConnectNamedPipe that is waiting with no client by connecting
    // to our own pipe once. Without this the listener thread would sit until
    // a client happened to arrive, and service shutdown would hang.
    HANDLE poke = CreateFileA(pipeName_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (poke != INVALID_HANDLE_VALUE) CloseHandle(poke);
    if (listener_.joinable()) listener_.join();
    if (stopEvent_) {
        CloseHandle(static_cast<HANDLE>(stopEvent_));
        stopEvent_ = nullptr;
    }
}

void IpcServer::listenLoop() {
    // SDDL rather than a NULL DACL. A NULL DACL grants everyone full control,
    // which on an ATM is an audit finding waiting to happen. This grants
    // SYSTEM and Administrators full access and authenticated users
    // read/write -- enough for a session-1 UI to reach a session-0 service,
    // which is what this needs once the agent is installed as a service.
    // A named pipe is reachable remotely as \\<host>\pipe\<name> through IPC$,
    // so the DACL is the only thing standing between this pipe and every
    // account on the bank's network. Two changes from the first cut:
    //
    //   NU denied first. Network Logon Users covers anyone arriving over SMB.
    //   A deny ACE placed ahead of the allows makes remote access impossible
    //   regardless of what the client SID resolves to.
    //
    //   The client SID is configurable and should be narrowed to the account
    //   EdgeTerminal runs as. Authenticated Users is the default only because
    //   it is the loosest thing that works out of the box; on a domain-joined
    //   ATM it means every domain account.
    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    const std::string sddlStr =
        "D:(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;" + clientSid_ + ")";
    const char* sddl = sddlStr.c_str();
    const bool haveSd =
        ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, nullptr) != 0;
    if (!haveSd) {
        // Refuse to fall back to an inherited descriptor. A pipe with a
        // default DACL is not obviously wrong from the outside, which is
        // exactly what makes it dangerous.
        lastError_ = "SDDL parse failed for client_sid '" + clientSid_ + "'; IPC disabled";
        running_.store(false);
        return;
    }
    if (haveSd) {
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = sd;
        sa.bInheritHandle = FALSE;
    }

    bool first = true;
    while (running_.load()) {
        // FILE_FLAG_FIRST_PIPE_INSTANCE on the first creation only. Without
        // it, anything that wins the race to create this name at boot owns
        // the pipe and our clients connect to it instead -- and we would
        // never notice, because CreateNamedPipe happily adds an instance to
        // somebody else's pipe. If the name is already taken, that is a
        // squat: stop rather than coexist with it.
        DWORD mode = PIPE_ACCESS_DUPLEX;
        if (first) mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

        HANDLE pipe = CreateNamedPipeA(
            pipeName_.c_str(), mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            static_cast<DWORD>(maxClients_ > 0 ? maxClients_ : 4),
            8192, 8192, 0, &sa);
        if (pipe == INVALID_HANDLE_VALUE) {
            const DWORD e = GetLastError();
            if (first && (e == ERROR_ACCESS_DENIED || e == ERROR_PIPE_BUSY ||
                          e == ERROR_ALREADY_EXISTS)) {
                lastError_ = "pipe name already owned by another process -- refusing to start IPC";
                running_.store(false);
                break;
            }
            lastError_ = "CreateNamedPipe failed";
            Sleep(1000);
            continue;
        }
        first = false;
        listening_.store(true);   // the pipe now genuinely exists

        const BOOL ok = ConnectNamedPipe(pipe, nullptr);
        if (!running_.load()) {
            CloseHandle(pipe);
            break;
        }
        if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }

        // Bounded. One process opening connections in a loop would otherwise
        // spawn a thread each and take the agent down; the real client count
        // is one.
        if (maxClients_ > 0 && clients_.load() >= maxClients_) {
            lastError_ = "client limit reached, connection refused";
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            continue;
        }

        // Detached: a wedged client must not stall the listener, and the
        // handler owns the handle from here.
        clients_.fetch_add(1);
        std::thread([this, pipe] {
            serveClient(pipe);
            clients_.fetch_sub(1);
        }).detach();
    }

    if (sd) LocalFree(sd);
}

void IpcServer::serveClient(void* h) {
    HANDLE pipe = static_cast<HANDLE>(h);
    std::string buf;
    char chunk[1024];

    while (running_.load()) {
        DWORD got = 0;
        if (!ReadFile(pipe, chunk, sizeof(chunk), &got, nullptr) || got == 0) break;
        buf.append(chunk, got);

        // Guard against a client that never sends a newline. Without this a
        // malformed sender could grow this buffer until the service dies.
        if (buf.size() > 256 * 1024) {
            buf.clear();
            continue;
        }

        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            std::string reply;
            handleLine(line, reply);
            reply.push_back('\n');
            DWORD wrote = 0;
            WriteFile(pipe, reply.data(), static_cast<DWORD>(reply.size()), &wrote, nullptr);
        }
    }

    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}

void IpcServer::handleLine(const std::string& line, std::string& reply) {
    Json j;
    std::string err;
    if (!Json::parse(line, j, err) || !j.isObject()) {
        reply = "{\"ok\":0,\"err\":\"bad json\"}";
        return;
    }

    if (j["cmd"].asString() == "snapshot") {
        // The snapshot is the entire current row: every tracked process, its
        // memory, and by implication the terminal's whole security stack.
        // That is reconnaissance, so it is opt-in rather than on by default.
        if (!allowSnapshot_) {
            reply = "{\"ok\":0,\"err\":\"snapshot disabled\"}";
            return;
        }
        std::lock_guard<std::mutex> lk(mu_);
        reply = snapshot_.empty() ? "{\"ok\":1,\"snapshot\":null}" : snapshot_;
        return;
    }

    // Heartbeat: {"hb":1,"role":"ui"}. Recorded by role on the monotonic
    // clock. Bounded: at most 64 roles, names up to 32 characters.
    if (j.has("hb")) {
        const std::string role = j["role"].asString();
        if (!role.empty() && role.size() <= 32) {
            std::lock_guard<std::mutex> lk(mu_);
            if (hb_.size() < 64 || hb_.count(role)) hb_[role] = std::chrono::steady_clock::now();
        }
    }

    int taken = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& key : j.keys()) {
            // Only configured columns are accepted. An unknown key is dropped
            // silently: a client cannot invent a column mid-file, because a
            // new column would desynchronise every row already written today.
            if (!std::binary_search(accepted_.begin(), accepted_.end(), key)) continue;
            const Json& v = j[key];
            Value val;
            if (v.type() == Json::Type::String) {
                val.isText = true;
                val.txt = v.asString();
            } else if (v.type() == Json::Type::Number) {
                val.num = v.asNumber();
            } else if (v.type() == Json::Type::Bool) {
                val.num = v.asBool() ? 1.0 : 0.0;
            } else {
                continue;
            }
            pending_[key] = std::move(val);
            ++taken;
        }
    }
    reply = "{\"ok\":1,\"taken\":" + std::to_string(taken) + "}";
}

std::map<std::string, IpcServer::Value> IpcServer::drain() {
    std::lock_guard<std::mutex> lk(mu_);
    std::map<std::string, Value> out;
    out.swap(pending_);
    return out;
}

void IpcServer::publishSnapshot(std::string json) {
    std::lock_guard<std::mutex> lk(mu_);
    snapshot_ = std::move(json);
}

}  // namespace ev
