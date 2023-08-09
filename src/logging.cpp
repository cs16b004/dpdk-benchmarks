#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>

#include "logging.hpp"

#define TIME_NOW_STR_SIZE 24
void time_now_str(char* now);

int Log::level_s = Log::DEBUG;
FILE* Log::fp_s = stdout;
pthread_mutex_t Log::m_s = PTHREAD_MUTEX_INITIALIZER;

void Log::set_level(int level) {
    pthread_mutex_lock(&m_s);
    level_s = level;
    pthread_mutex_unlock(&m_s);
}

void Log::set_file(FILE* fp) {
    assert(fp != nullptr);
    pthread_mutex_lock(&m_s);
    fp_s = fp;
    pthread_mutex_unlock(&m_s);
}

void Log::log_v(int level, int line, const char* file, const char* fmt, va_list args) {
    static char indicator[] = { 'F', 'E', 'W', 'I', 'D' };
    assert(level <= Log::DEBUG);
    if (level <= level_s) {
        char now_time[TIME_NOW_STR_SIZE];
        time_now_str(now_time);
        const char* filebase = file;
        assert(filebase != nullptr);
        char buf[4096];
        int offset = 0;
        offset += sprintf(buf+offset, "%c ", indicator[level]);
        offset += sprintf(buf+offset, "[%s:%d] ", filebase, line);
        offset += sprintf(buf+offset, "%s | ", now_time);
        offset += vsprintf(buf+offset, fmt, args);
        offset += sprintf(buf+offset, "\n");
        fprintf(fp_s, "%s", buf);
    }
}

void Log::fatal(int line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_v(Log::FATAL, line, file, fmt, args);
    va_end(args);
    abort();
}

void Log::error(int line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_v(Log::ERROR, line, file, fmt, args);
    va_end(args);
}

void Log::warn(int line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_v(Log::WARN, line, file, fmt, args);
    va_end(args);
}

void Log::info(int line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_v(Log::INFO, line, file, fmt, args);
    va_end(args);
}

void Log::debug(int line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_v(Log::DEBUG, line, file, fmt, args);
    va_end(args);
}

void make_int(char* str, int val, int digits) {
    char* p = str + digits;
    for (int i = 0; i < digits; i++) {
        int d = val % 10;
        val /= 10;
        p--;
        *p = '0' + d;
    }
}

void time_now_str(char* now) {
    time_t seconds_since_epoch = time(nullptr);
    struct tm local_calendar;
    localtime_r(&seconds_since_epoch, &local_calendar);
    make_int(now, local_calendar.tm_year + 1900, 4);
    now[4] = '-';
    make_int(now + 5, local_calendar.tm_mon + 1, 2);
    now[7] = '-';
    make_int(now + 8, local_calendar.tm_mday, 2);
    now[10] = ' ';
    make_int(now + 11, local_calendar.tm_hour, 2);
    now[13] = ':';
    make_int(now + 14, local_calendar.tm_min, 2);
    now[16] = ':';
    make_int(now + 17, local_calendar.tm_sec, 2);
    now[19] = '.';
    timeval tv;
    gettimeofday(&tv, nullptr);
    make_int(now + 20, tv.tv_usec / 1000, 3);
    now[23] = '\0';
}
