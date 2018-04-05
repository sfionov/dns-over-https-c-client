//
// Created by s.fionov on 05.04.18.
//

#include <string.h>
#include <mbedtls/base64.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "stamp.h"
#include "logger.h"

static const char *const SDNS_SCHEME = "sdns://";

static void print_flags(uint64_t flags) {
    if (flags & DNS_STAMP_FLAGS_SUPPORTS_DNSSEC) {
        loginfo("DNS stamp: This server supports DNSSEC");
    } else {
        loginfo("DNS stamp: This server doesn't support DNSSEC");
    }

    if (flags & DNS_STAMP_FLAGS_NO_LOGGING) {
        loginfo("DNS stamp: This server doesn't log requests");
    } else {
        loginfo("DNS stamp: This server may log requests");
    }

    if (flags & DNS_STAMP_FLAGS_NO_FILTERING) {
        loginfo("DNS stamp: This server doesn't block requests");
    } else {
        loginfo("DNS stamp: This server may block requests");
    }
}

int dns_stamp_parse(const char *stamp, dns_stamp_t **p_stamp) {
    if (strncasecmp(stamp, SDNS_SCHEME, strlen(SDNS_SCHEME)) != 0) {
        loginfo("Can't parse DNS stamp: unknown scheme");
        return -1;
    }

    stamp += strlen(SDNS_SCHEME);
    size_t stamp_len = strlen(stamp);
    char stamp_base64[stamp_len + 4];
    for (size_t i = 0; i < stamp_len; i++) {
        if (stamp[i] == '-') {
            stamp_base64[i] = '+';
        } else if (stamp[i] == '_') {
            stamp_base64[i] = '/';
        } else {
            stamp_base64[i] = stamp[i];
        }
    }
    size_t i;
    for (i = stamp_len; i <= (stamp_len + 3) / 4 * 4; i++) {
        stamp_base64[i] = '=';
    }
    stamp_len = i - 1;
    uint8_t stamp_bytes[stamp_len / 4 * 3 + 1];
    size_t stamp_bytes_len;
    if (mbedtls_base64_decode(stamp_bytes, sizeof(stamp_bytes), &stamp_bytes_len, stamp_base64, stamp_len) < 0) {
        loginfo("Can't parse DNS stamp: invalid base64");
        return -1;
    }

    uint8_t *stamp_bytes_pos = stamp_bytes;
    uint8_t *stamp_bytes_end = stamp_bytes + stamp_bytes_len;

    if (*stamp_bytes_pos != 0x02) {
        loginfo("Can't parse DNS stamp: not a DNS-over-HTTPS stamp");
        return -1;
    }
    stamp_bytes_pos++;

    if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint64_t)) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    dns_stamp_t *dns_stamp = malloc(sizeof(dns_stamp_t));
    dns_stamp->flags = *(uint64_t*)(stamp_bytes_pos);
    print_flags(dns_stamp->flags);
    stamp_bytes_pos += sizeof(uint64_t);

    if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint8_t)) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    size_t addr_len = *stamp_bytes_pos++;
    if (stamp_bytes_end - stamp_bytes_pos < addr_len) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    dns_stamp->addr = strndup((const char *) stamp_bytes_pos, addr_len);
    loginfo("DNS stamp: address: %s", dns_stamp->addr);
    stamp_bytes_pos += addr_len;

    if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint8_t)) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    size_t hash0_len = *stamp_bytes_pos++;
    if (stamp_bytes_end - stamp_bytes_pos < hash0_len) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    dns_stamp->hash0 = strndup((const char *) stamp_bytes_pos, hash0_len);
    loginfo("DNS stamp: hash0: %s", dns_stamp->hash0);
    stamp_bytes_pos += hash0_len;

    if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint8_t)) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    size_t hostname_len = *stamp_bytes_pos++;
    if (stamp_bytes_end - stamp_bytes_pos < hostname_len) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    dns_stamp->hostname = strndup((const char *) stamp_bytes_pos, hostname_len);
    loginfo("DNS stamp: hostname: %s", dns_stamp->hostname);
    stamp_bytes_pos += hostname_len;

    if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint8_t)) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    size_t path_len = *stamp_bytes_pos++;
    if (stamp_bytes_end - stamp_bytes_pos < path_len) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        return -1;
    }
    dns_stamp->path = strndup((const char *) stamp_bytes_pos, path_len);
    loginfo("DNS stamp: path: %s", dns_stamp->path);
    stamp_bytes_pos += path_len;

    *p_stamp = dns_stamp;
    return 0;
}

void dns_stamp_free(dns_stamp_t *stamp) {
    if (stamp) {
        free(stamp->addr);
        free(stamp->hash0);
        free(stamp->hostname);
        free(stamp->path);
    }
}
