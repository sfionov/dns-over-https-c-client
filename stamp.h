//
// Created by s.fionov on 05.04.18.
//

#ifndef DNS_OVER_HTTPS_CLIENT_STAMP_H
#define DNS_OVER_HTTPS_CLIENT_STAMP_H

#define DNS_STAMP_FLAGS_SUPPORTS_DNSSEC 1
#define DNS_STAMP_FLAGS_NO_LOGGING      2
#define DNS_STAMP_FLAGS_NO_FILTERING    4

typedef struct {
    uint64_t flags;
    char *addr;
    char *hash0;
    char *hostname;
    char *path;
} dns_stamp_t;

int dns_stamp_parse(const char *stamp, dns_stamp_t **p_stamp);
void dns_stamp_free(dns_stamp_t *stamp);

#endif //DNS_OVER_HTTPS_CLIENT_STAMP_H
