#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/time.h>
#include <time.h>

#include "logger.h"

#if defined(__linux__)
#include <syscall.h>
intmax_t gettid(void) {
    return syscall(SYS_gettid);
}
#elif defined(__FreeBSD__)
#include <pthread_np.h>
intmax_t gettid(void) {
    return pthread_getthreadid_np();
}
#elif defined(__MACH__)
#include <pthread.h>
intmax_t gettid(void) {
    uint64_t ktid = 0;
    pthread_threadid_np(NULL, &ktid);
    return ktid;
}
#else
intmax_t gettid(void) {
    return -1;
}
#endif

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
