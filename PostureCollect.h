// Remote-access posture: Win32 collection (PostureCollectWin.cpp). Shared
// with ATMProbe -- see PostureFacts.h.
//
// Read-only Win32 calls only: registry (KEY_QUERY_VALUE), the service manager
// (enumerate / query config), NetShareEnum level 1, GetExtendedTcpTable /
// GetExtendedUdpTable, GetFileAttributesW, the process token. No child
// processes (no netstat, sc, reg, wmic, powershell, net), no network traffic,
// no COM.
#pragma once
#include "edgevitals/PostureFacts.h"

#include <map>
#include <string>
#include <vector>

namespace ev {

struct PostureCollectInput {
    // From the agent's own process enumeration (reused, not repeated). When
    // processesValid is false RA-013 checks services only and says so.
    bool processesValid = false;
    std::vector<std::string> processes;          // lower-cased exe file names
    std::map<unsigned long, std::string> pidNames;   // pid -> lower-cased exe file name
    // Service key names (lower-cased, '*' = prefix) whose start type is read.
    // Start type costs one OpenService + QueryServiceConfig each, so only the
    // services the catalogue judges.
    std::vector<std::string> startTypeFor;
};

// Fills every fact; never throws. Each fact carries its own read outcome, so
// a partial failure (one key denied) costs that check, not the run.
void collectPosture(const PostureCollectInput& in, PostureFacts& out);

// The cheap pass for listener_poll_seconds: non-loopback TCP listeners
// (v4 and v6) as one sorted signature. False when the table is unreadable.
bool tcpListenerSignature(std::string& signature);

// Service key names for the catalogue's start-type reads.
std::vector<std::string> postureStartTypeServices();

}  // namespace ev
