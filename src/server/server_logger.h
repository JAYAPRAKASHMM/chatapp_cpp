#pragma once
#include <windows.h>

/* Log levels */
enum class LogLevel {
    DEBUG,
    INFO,
    ERR   // ✅ renamed from ERROR
};

/* Logger API */
void logger_init();
void log_debug(const char* fmt, ...);
void log_info(const char* fmt, ...);
void log_error(const char* fmt, ...);
