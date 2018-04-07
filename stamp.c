//
// Created by s.fionov on 05.04.18.
//

#include <string.h>
#include <mbedtls/base64.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "stamp.h"
#include "logger.h"

static const char *const SDNS_SCHEME = "sdns://";

static void print_flags(uint64_t flags) {
    if (flags & DNS_STAMP_FLAGS_SUPPORTS_DNSSEC) {
        loginfo("Server supports DNSSEC");
    } else {
        loginfo("Server doesn't support DNSSEC");
    }

    if (flags & DNS_STAMP_FLAGS_NO_LOGGING) {
        loginfo("Server doesn't log requests");
    } else {
        loginfo("Server may log requests");
    }

    if (flags & DNS_STAMP_FLAGS_NO_BLOCKING) {
        loginfo("Server doesn't block requests");
    } else {
        loginfo("Server may block requests");
    }
}

void print_cert_pins(struct iovec *pins, size_t count) {
    for (size_t i = 0; i < count; i++) {
        char pin[256 * 3 + 1];
        int pos = 0;
        for (size_t j = 0; j < pins[i].iov_len && pos < sizeof(pin) - 4; j++) {
            char hex[3];
            snprintf(hex, 3, "%02x", ((const uint8_t *)pins[i].iov_base)[j]);
            if (j != 0) {
                pin[pos] = ':';
                pos++;
            }
            memcpy(pin + pos, hex, 2);
            pos += 2;
        }
        pin[pos] = 0;
        loginfo("Cert pin: %s", pin);
    }
}


size_t base64uri_to_base64(char *dst, size_t dst_len, const char *src) {
    const char *s = src;
    char *d = dst, *dend = dst + dst_len;
    for (; *s && d < dend - 1; s++, d++) {
        if (*s == '-') {
            *d = '+';
        } else if (*s == '_') {
            *d = '/';
        } else {
            *d = *s;
        }
    }
    ptrdiff_t padding = (-(d - dst)) & 3;
    for (ptrdiff_t i = 0; i < padding && d < dend - 1; d++) {
        *d = '=';
    }
    if (d < dend) {
        *d = '\0';
    }
    return d - dst;
}

int dns_stamp_parse(const char *stamp, dns_stamp_t **p_stamp) {
    if (strncasecmp(stamp, SDNS_SCHEME, strlen(SDNS_SCHEME)) != 0) {
        loginfo("Can't parse DNS stamp: unknown scheme");
        return -1;
    }

    stamp += strlen(SDNS_SCHEME);
    size_t stamp_len = strlen(stamp);
    char stamp_base64[stamp_len + 2 + 1]; // Two padding bytes + null-terminator
    size_t stamp_base64_len = base64uri_to_base64(stamp_base64, sizeof(stamp_base64), stamp);
    uint8_t stamp_bytes[stamp_base64_len / 4 * 3 + 1];
    size_t stamp_bytes_len;
    if (mbedtls_base64_decode(stamp_bytes, sizeof(stamp_bytes), &stamp_bytes_len, stamp_base64, stamp_base64_len) < 0) {
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

    dns_stamp_t *dns_stamp = calloc(1, sizeof(dns_stamp_t));

    dns_stamp->flags = *(uint64_t*)(stamp_bytes_pos);
    stamp_bytes_pos += sizeof(uint64_t);

    if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint8_t)) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        goto error;
    }
    size_t addr_len = *stamp_bytes_pos++;
    if (stamp_bytes_end - stamp_bytes_pos < addr_len) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        goto error;
    }
    dns_stamp->addr = strndup((const char *) stamp_bytes_pos, addr_len);
    stamp_bytes_pos += addr_len;

    int has_next = 0;
    do {
        if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint8_t)) {
            loginfo("Can't parse DNS stamp: truncated stamp");
            goto error;
        }
        uint8_t cert_pin_len = *stamp_bytes_pos++;
        has_next = (cert_pin_len & 0x80) != 0;
        cert_pin_len &= 0x7f;
        if (stamp_bytes_end - stamp_bytes_pos < cert_pin_len) {
            loginfo("Can't parse DNS stamp: truncated stamp");
            goto error;
        }
        void *cert_pin = malloc(cert_pin_len);
        memcpy(cert_pin, stamp_bytes_pos, cert_pin_len);
        dns_stamp->cert_pins[dns_stamp->cert_pin_count++] = (struct iovec){
                .iov_base = cert_pin,
                .iov_len = cert_pin_len
        };;
        stamp_bytes_pos += cert_pin_len;
    } while (has_next == 1);

    if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint8_t)) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        goto error;
    }
    size_t hostname_len = *stamp_bytes_pos++;
    if (stamp_bytes_end - stamp_bytes_pos < hostname_len) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        goto error;
    }
    dns_stamp->hostname = strndup((const char *) stamp_bytes_pos, hostname_len);
    stamp_bytes_pos += hostname_len;

    if (stamp_bytes_end - stamp_bytes_pos < sizeof(uint8_t)) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        goto error;
    }
    size_t path_len = *stamp_bytes_pos++;
    if (stamp_bytes_end - stamp_bytes_pos < path_len) {
        loginfo("Can't parse DNS stamp: truncated stamp");
        goto error;
    }
    dns_stamp->path = strndup((const char *) stamp_bytes_pos, path_len);
    stamp_bytes_pos += path_len;
    (void)stamp_bytes_pos;

    loginfo("Server info taken from DNS stamp:");
    print_flags(dns_stamp->flags);
    loginfo("Server address: %s", dns_stamp->addr);
    print_cert_pins(dns_stamp->cert_pins, dns_stamp->cert_pin_count);
    loginfo("Path: %s", dns_stamp->path);
    loginfo("Host: %s", dns_stamp->hostname);

    *p_stamp = dns_stamp;
    return 0;

error:
    dns_stamp_free(dns_stamp);
    return -1;
}

void dns_stamp_free(dns_stamp_t *stamp) {
    if (stamp) {
        free(stamp->addr);
        for (size_t i = 0; i < stamp->cert_pin_count; i++) {
            free(stamp->cert_pins[i].iov_base);
        }
        free(stamp->hostname);
        free(stamp->path);
    }
}
