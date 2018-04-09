#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "util.h"

int make_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int set_reuse_addr(int fd) {
    int value = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
}

int set_reuse_port(int fd) {
    int value = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value));
}

int set_tcp_nodelay(int fd) {
    int value = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
}

void fatal(const char *msg) {
    perror(msg);
    exit(1);
}

const char *hex_string(char *hex, size_t hex_len, void *src, size_t src_len) {
    int pos = 0;
    for (size_t j = 0; j < src_len && pos < hex_len - 4; j++) {
        char *hex_digits = "0123456789abcdef";
        uint8_t number = ((const uint8_t *)src)[j];
        char hex_number[2] = {
                hex_digits[(number >> 4) & 15],
                hex_digits[number & 15]
        };
        if (j != 0) {
            hex[pos] = ':';
            pos++;
        }
        memcpy(hex + pos, hex_number, 2);
        pos += 2;
    }
    hex[pos] = 0;
    return hex;
}
