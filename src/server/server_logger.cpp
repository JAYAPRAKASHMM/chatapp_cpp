#include "server_logger.h"
#include <cstdio>
#include <cstdarg>

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

static void log_internal(LogLevel lvl, const char* fmt, va_list args) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    set_color(lvl);

    printf(
        "[%02d:%02d:%02d.%03d] [%s] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        level_str(lvl)
    );

    vprintf(fmt, args);
    printf("\n");

    SetConsoleTextAttribute(g_console, 15); // Reset white
}

/* ---------------- public API ---------------- */

void logger_init() {
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
}

void log_debug(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_internal(LogLevel::DEBUG, fmt, args);
    va_end(args);
}

void log_info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_internal(LogLevel::INFO, fmt, args);
    va_end(args);
}

void log_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_internal(LogLevel::ERR, fmt, args);
    va_end(args);
}
