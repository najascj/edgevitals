// Win32 transport for the health link: the pipe EdgeBastion connects to, the
// GUI-window probe, and the set of PIDs EdgeBastion asked us to watch.
// No decisions are made here; HealthModel makes them.
#pragma once
#include "edgevitals/Health.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ev {

class ILogger;

class HealthServer {
public:
    // clock: the agent's monotonic seconds, so request times and tick times
    // share one base (heartbeat and sample ages depend on it).
    HealthServer(HealthModel& model, ILogger& log, std::function<double()> clock);
    ~HealthServer();
    HealthServer(const HealthServer&) = delete;
    HealthServer& operator=(const HealthServer&) = delete;

    // Resolves allowed accounts, builds the DACL, starts the listener.
    // Returns false (with err) only for configuration errors; a pipe that
    // fails to appear is reported through listening() and the log.
    bool start(std::string& err);
    void stop();
    bool listening() const { return listening_.load(); }
    int clientCount() const { return clients_.load(); }
    // Unsolicited message (an advisory) to every connected client.
    void push(const std::string& line);
    // The SDDL actually applied, for the start-up log line.
    const std::string& sddl() const { return sddl_; }

private:
    struct Client;
    void listenLoop();
    void serve(const std::shared_ptr<Client>& c);

    HealthModel& model_;
    ILogger& log_;
    std::function<double()> clock_;
    std::string sddl_;
    void* sd_ = nullptr;
    void* stopEvent_ = nullptr;
    std::thread listener_;
    std::atomic<bool> running_{false};
    std::atomic<bool> listening_{false};
    std::atomic<int> clients_{0};
    std::mutex mu_;
    std::vector<std::shared_ptr<Client>> live_;
    std::vector<std::thread> threads_;
};

// 1 = a top-level visible window of one of these PIDs responds, 0 = one is
// hung, -1 = no such window visible from here. Always -1 in service mode:
// Session 0 cannot see the interactive desktop.
int windowResponding(const std::vector<unsigned long>& pids);

// PIDs EdgeBastion registered. Each is held by a SYNCHRONIZE handle and its
// creation time, so PID reuse can never be mistaken for the same process.
class WatchedSet {
public:
    ~WatchedSet();
    // Returns false with a reason when the PID cannot be opened.
    bool add(unsigned long pid, std::string& exe, std::string& why);
    void remove(unsigned long pid);
    struct Sample {
        unsigned long pid;
        ProcObs obs;
    };
    void sample(std::vector<Sample>& out);

private:
    struct Entry {
        unsigned long pid = 0;
        void* h = nullptr;
        std::uint64_t created = 0;
        bool dead = false;
    };
    std::vector<Entry> e_;
};

}  // namespace ev
