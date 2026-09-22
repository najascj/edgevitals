// Named-pipe server for metrics only the owning process can measure.
//
// EdgeVitals does not know what a "frame_p99_ms" is and should not have to --
// EdgeTerminal knows. Clients push a one-line JSON object per tick; the agent
// merges any key matching a configured extra column into the next row and
// ignores the rest. New metrics therefore ship without touching this agent.
//
// Protocol, deliberately trivial so a client is ~40 lines:
//   client -> {"role":"ui","state":"pin","frame_p99_ms":18.2}\n
//   server -> {"ok":1}\n                     (ack, so a client can detect loss)
//   client -> {"cmd":"snapshot"}\n
//   server -> {"ts":"...","ui_cpu_pct":12.3,...}\n   (last row, for the panel)
//
// A client that never connects costs nothing. EdgeTerminal must start and run
// normally with this agent absent, and vice versa -- they are separately
// licensed and neither may become a dependency of the other.
#pragma once
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ev {

class IpcServer {
public:
    struct Value {
        bool isText = false;
        double num = 0.0;
        std::string txt;
    };

    IpcServer(std::string pipeName, std::vector<std::string> acceptedKeys);
    ~IpcServer();

    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    bool start();
    void stop();
    bool running() const { return running_.load(); }
    const std::string& lastError() const { return lastError_; }

    // Takes everything pushed since the last call and clears the buffer.
    // Drain-on-read: a client that stops pushing leaves its columns EMPTY
    // rather than repeating a stale value forever.
    std::map<std::string, Value> drain();

    // Published for the snapshot command so a side panel and the CSV can
    // never disagree -- the panel is a view of the row, not its own sample.
    void publishSnapshot(std::string json);

    int clientCount() const { return clients_.load(); }

    // Must be called before start(). Defaults are the permissive ones, so a
    // caller that forgets this gets a working but wide-open pipe -- which is
    // why Agent sets it unconditionally rather than only when configured.
    void setSecurity(std::string clientSid, int maxClients, bool allowSnapshot) {
        if (!clientSid.empty()) clientSid_ = std::move(clientSid);
        if (maxClients > 0) maxClients_ = maxClients;
        allowSnapshot_ = allowSnapshot;
    }

private:
    void listenLoop();
    void serveClient(void* pipe);
    void handleLine(const std::string& line, std::string& reply);

    std::string pipeName_;
    std::vector<std::string> accepted_;
    std::string lastError_;

    std::thread listener_;
    std::atomic<bool> running_{false};
    std::atomic<int> clients_{0};
    std::string clientSid_ = "AU";   // SDDL form, from config
    int maxClients_ = 4;
    bool allowSnapshot_ = false;
    void* stopEvent_ = nullptr;

    std::mutex mu_;
    std::map<std::string, Value> pending_;
    std::string snapshot_;
};

}  // namespace ev
