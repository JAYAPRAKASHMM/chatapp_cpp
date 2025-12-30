#pragma once
#include <windows.h>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <string>
#include <fstream>
#include "../../common/config/config.h"

/* Log levels */
enum class LogLevel {
    DEBUG,
    INFO,
    ERR   // ✅ renamed from ERROR
};

/* Logger API */
void logger_init(const Config& cfg);
void logger_shutdown();
void log_debug(const char* fmt, ...);
void log_info(const char* fmt, ...);
void log_error(const char* fmt, ...);

/* Internal structures */
struct LogEntry {
    LogLevel level;
    std::string message;
};

extern std::queue<LogEntry> logQueue;
extern std::mutex logMutex;
extern std::condition_variable logCV;
extern std::atomic<bool> loggerRunning;
extern std::thread logWorker;
extern std::ofstream logFile;
