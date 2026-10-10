// Win32 transport for the Windows Event Log watcher: subscriptions, batched
// reads, bookmarks. Decisions (what to keep, how to strip it, how much) are
// in WinEvents.h. Observe only: subscriptions are read-only.
#pragma once
#include "edgevitals/WinEvents.h"

#include <string>
#include <vector>

namespace ev {

class WinEventWatcher {
public:
    // stateDir holds one bookmark per channel (winevents-bookmark-<channel>.xml)
    // so a restart resumes where it stopped: no repeats, no gap -- including
    // events Windows wrote while the terminal rebooted after a crash.
    WinEventWatcher(const WinEventsConfig& cfg, std::string stateDir);
    ~WinEventWatcher();
    WinEventWatcher(const WinEventWatcher&) = delete;
    WinEventWatcher& operator=(const WinEventWatcher&) = delete;

    // One status line per channel ("System: subscribed", "Security: access
    // denied -- not recorded"). A failed channel never stops the agent.
    std::vector<std::string> start();
    // Reads up to max events across channels; bookmarks advance after each batch.
    void poll(int max, std::vector<WinEvent>& out);
    int activeChannels() const;
    // Wait handles (HANDLE, manual-reset) signalled when a subscribed channel
    // has new events. The agent waits on them between ticks so a routed event
    // (SCM 7036 for the posture monitor) is seen in seconds, not at the next tick.
    std::vector<void*> signals() const;

private:
    struct Sub;
    WinEventsConfig cfg_;
    std::string dir_;
    std::vector<Sub*> subs_;
};

}  // namespace ev
