// The agent's own operational log, on disk, day-rotated and chained.
//
// WHY THIS EXISTS
// Until now EdgeVitals wrote its telemetry to a rotated, retained, chained CSV
// -- and kept no record of ITSELF anywhere durable. Console output vanished
// with the window; service mode went to the Windows Event Log, where nobody
// looks and from which nothing reaches EdgeSentinel.
//
// That is backwards. The lines that matter most in an incident are the agent's
// own: "config refused", "client limit reached", "pipe name already owned",
// "security: ipc client_sid is AU". Those are the security controls announcing
// themselves, and they were announcing into a void.
//
// It follows the same rules as the telemetry, deliberately -- one mechanism for
// every artifact, so an auditor learns it once:
//   - one file per day, edgevitals-YYYY-MM-DD.log
//   - the same retention as the CSVs
//   - the same SHA-256 chain, sealed on close, verifiable with the same
//     evverify tool
//
// It decorates rather than replaces an inner logger, so console and Event Log
// output continue unchanged. A lab engineer watching stdout sees what they
// always saw; the file is additional, not instead.
#pragma once
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>

#include "edgevitals/Agent.h"
#include "edgevitals/CsvSink.h"   // Date
#include "edgevitals/Digest.h"

namespace ev {

class FileLogger : public ILogger {
public:
    struct Options {
        std::string dir;                    // same directory as the telemetry
        std::string prefix = "edgevitals";  // edgevitals-YYYY-MM-DD.log
        int retentionDays = 180;
        int chainEveryLines = 50;           // checkpoint cadence
        bool alsoTo = true;                 // keep writing to the inner logger
    };

    // inner may be null; the file is then the only destination.
    FileLogger(Options opts, std::shared_ptr<ILogger> inner);
    ~FileLogger() override;

    FileLogger(const FileLogger&) = delete;
    FileLogger& operator=(const FileLogger&) = delete;

    void info(const std::string& msg) override  { write("info ", msg); }
    void warn(const std::string& msg) override  { write("warn ", msg); }
    void error(const std::string& msg) override { write("error", msg); }

    // Seals the chain and closes the file. Called from main on shutdown so a
    // day's log ends with a final checkpoint; without one a verifier cannot
    // tell a clean stop from a truncation.
    void close();

    const std::string& currentPath() const { return path_; }
    const std::string& lastError() const { return lastError_; }

private:
    void write(const char* level, const std::string& msg);
    bool openFor(const Date& d);
    void chainWrite(const std::string& line);
    void checkpoint(bool final);
    int purgeOld(const Date& today);

    Options opts_;
    std::shared_ptr<ILogger> inner_;
    std::FILE* fp_ = nullptr;
    std::string path_;
    std::string chainPath_;
    Date openDate_{};
    std::unique_ptr<HashChain> chain_;
    int sinceCheckpoint_ = 0;
    std::string lastError_;
    // The agent logs from the sampling thread, the IPC listener and each
    // client handler. Without this, two writes interleave: the bytes reach
    // the file in one order and the chain in another, and the log fails its
    // own verification. Observed 23 Sep: CONTENT ALTERED between 2276 and 3622.
    std::mutex mu_;
};

}  // namespace ev
