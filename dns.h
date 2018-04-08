#ifndef DNS_OVER_HTTPS_CLIENT_DNS_H
#define DNS_OVER_HTTPS_CLIENT_DNS_H

#include <stdint.h>

struct dnshdr {
    uint16_t tsid;
    union {
        struct {
            uint8_t qd:1;
            uint8_t opcode:3;
            uint8_t aa:1;
            uint8_t tc:1;
            uint8_t rd:1;
            uint8_t ra:1;
            uint8_t z:3;
            uint8_t rcode:4;
        };
        uint16_t raw;
    } flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* Reply codes */
#define RCODE_NOERROR    0
#define RCODE_FORMERR    1
#define RCODE_SERVFAIL   2
#define RCODE_NXDOMAIN   3
#define RCODE_NOTIMPL    4
#define RCODE_REFUSED    5
#define RCODE_YXDOMAIN   6
#define RCODE_YXRRSET    7
#define RCODE_NXRRSET    8
#define RCODE_NOTAUTH    9
#define RCODE_NOTZONE   10

#define RCODE_BAD       16
#define RCODE_BADKEY    17
#define RCODE_BADTIME   18
#define RCODE_BADMODE   19
#define RCODE_BADNAME   20
#define RCODE_BADALG    21
#define RCODE_BADTRUNC  22

#endif //DNS_OVER_HTTPS_CLIENT_DNS_H
