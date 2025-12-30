#include "server_logger.h"
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <chrono>
#include <ctime>

std::queue<LogEntry> logQueue;
std::mutex logMutex;
std::condition_variable logCV;
std::atomic<bool> loggerRunning{false};
std::thread logWorker;
std::ofstream logFile;

static HANDLE g_console;

/* ---------------- internal helpers ---------------- */

static void set_color(LogLevel lvl) {
    switch (lvl) {
    case LogLevel::DEBUG:
        SetConsoleTextAttribute(g_console, 8);   // Gray
        break;
    case LogLevel::INFO:
        SetConsoleTextAttribute(g_console, 10);  // Green
        break;
    case LogLevel::ERR:
        SetConsoleTextAttribute(g_console, 12);  // Red
        break;
    }
}

static const char* level_str(LogLevel lvl) {
    switch (lvl) {
    case LogLevel::DEBUG: return "DEBUG";
    case LogLevel::INFO:  return "INFO ";
    case LogLevel::ERR:   return "ERROR";
    }
    return "UNKWN";
}

static void log_to_console_and_file(LogLevel lvl, const std::string& msg) {
    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::tm tm;
    localtime_s(&tm, &time_t);

    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &tm);
    std::string fullMsg = std::string("[") + timeStr + "." + std::to_string(ms.count()) + "] [" + level_str(lvl) + "] " + msg + "\n";

    // Console
    set_color(lvl);
    std::cout << fullMsg;
    SetConsoleTextAttribute(g_console, 15); // Reset white

    // File
    if (logFile.is_open()) {
        logFile << fullMsg;
        logFile.flush(); // Ensure written immediately
    }
}

static void log_worker() {
    while (loggerRunning) {
        std::unique_lock<std::mutex> lk(logMutex);
        logCV.wait(lk, [] { return !logQueue.empty() || !loggerRunning; });

        if (!loggerRunning && logQueue.empty()) break;

        while (!logQueue.empty()) {
            LogEntry entry = logQueue.front();
            logQueue.pop();
            lk.unlock();
            log_to_console_and_file(entry.level, entry.message);
            lk.lock();
        }
    }
}

/* ---------------- public API ---------------- */

void logger_init(const Config& cfg) {
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    std::string logFilePath = cfg.getString("Logging", "file", "server.log");
    // Create directory if needed
    size_t pos = logFilePath.find_last_of("/\\");
    if (pos != std::string::npos) {
        std::string dir = logFilePath.substr(0, pos);
        CreateDirectoryA(dir.c_str(), NULL);
    }
    logFile.open(logFilePath.c_str(), std::ios::app);
    if (!logFile.is_open()) {
        // Fallback, but since it's server, maybe log to console only
        std::cerr << "Failed to open log file: " << logFilePath << std::endl;
    }
    loggerRunning = true;
    logWorker = std::thread(log_worker);
}

void logger_shutdown() {
    loggerRunning = false;
    logCV.notify_one();
    if (logWorker.joinable()) {
        logWorker.join();
    }
    if (logFile.is_open()) {
        logFile.close();
    }
}

void log_debug(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    std::lock_guard<std::mutex> lk(logMutex);
    logQueue.push({LogLevel::DEBUG, std::string(buf)});
    logCV.notify_one();
}

void log_info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    std::lock_guard<std::mutex> lk(logMutex);
    logQueue.push({LogLevel::INFO, std::string(buf)});
    logCV.notify_one();
}

void log_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    std::lock_guard<std::mutex> lk(logMutex);
    logQueue.push({LogLevel::ERR, std::string(buf)});
    logCV.notify_one();
}
