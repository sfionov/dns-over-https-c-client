#include <unistd.h>
#include <stdint.h>
#include <syscall.h>
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/time.h>
#include <time.h>

#include "logger.h"

intmax_t gettid() {
    return syscall(SYS_gettid);
}

void loginfo(const char *format, ...) {
    va_list args;

    va_start(args, format);
    int size = vsnprintf(NULL, 0, format, args);
    va_end(args);

    va_start(args, format);
    char msg[size + 1u];
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);

    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    char time_str[25];
    strftime(time_str, sizeof(time_str), "%d.%m.%Y %H:%M:%S", localtime(&tv.tv_sec));

    fprintf(stderr, "%s.%03d [tid=%" PRIdMAX "] %s\n", time_str, (int) tv.tv_usec / 1000, gettid(), msg);
}
