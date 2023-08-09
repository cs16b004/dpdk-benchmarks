#ifndef _LOGGING_H_
#define _LOGGING_H_

#define __FILENAME__ __FILE__

#define log_debug(msg, ...) Log::debug(__LINE__, __FILENAME__, msg, ## __VA_ARGS__)
#define log_info(msg, ...) Log::info(__LINE__, __FILENAME__, msg, ## __VA_ARGS__)
#define log_warn(msg, ...) Log::warn(__LINE__, __FILENAME__, msg, ## __VA_ARGS__)
#define log_error(msg, ...) Log::error(__LINE__, __FILENAME__, msg, ## __VA_ARGS__)
#define log_fatal(msg, ...) Log::fatal(__LINE__, __FILENAME__, msg, ## __VA_ARGS__)

class Log {
private:
    static int level_s;
    static FILE* fp_s;
    static pthread_mutex_t m_s;

private:
    static void log_v(int level, int line, const char* file, const char* fmt, va_list args);

public:
    enum {
        FATAL = 0, ERROR = 1, WARN = 2, INFO = 3, DEBUG = 4
    };

    static void set_file(FILE* fp);
    static void set_level(int level);

    static void fatal(int line, const char* file, const char* fmt, ...);
    static void error(int line, const char* file, const char* fmt, ...);
    static void warn(int line, const char* file, const char* fmt, ...);
    static void info(int line, const char* file, const char* fmt, ...);
    static void debug(int line, const char* file, const char* fmt, ...);
};

#endif
