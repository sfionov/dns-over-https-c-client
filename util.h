//
// Created by s.fionov on 05.04.18.
//

#ifndef DNS_OVER_HTTPS_CLIENT_UTIL_H
#define DNS_OVER_HTTPS_CLIENT_UTIL_H

int make_non_blocking(int fd);

int set_reuse_addr(int fd);

int set_reuse_port(int fd);

int set_tcp_nodelay(int fd);

void fatal(const char *msg);


#endif //DNS_OVER_HTTPS_CLIENT_UTIL_H
