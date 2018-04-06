//
// Created by s.fionov on 05.04.18.
//

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
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
    setsockopt(fd, SOL_TCP, TCP_NODELAY, &value, sizeof(value));
}

void fatal(const char *msg) {
    perror(msg);
    exit(1);
}
