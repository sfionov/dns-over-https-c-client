#ifndef DNS_OVER_HTTPS_CLIENT_UTIL_H
#define DNS_OVER_HTTPS_CLIENT_UTIL_H

#define DEFAULT_HTTPS_PORT "443"

int make_non_blocking(int fd);

int set_reuse_addr(int fd);

int set_reuse_port(int fd);

int set_tcp_nodelay(int fd);

void fatal(const char *msg);

const char *hex_string(char *hex, size_t hex_len, void *src, size_t src_len);

#endif //DNS_OVER_HTTPS_CLIENT_UTIL_H
