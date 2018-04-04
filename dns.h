//
// Created by s.fionov on 01.04.18.
//

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

/* type values  */
#define T_A              1              /* host address */
#define T_NS             2              /* authoritative name server */
#define T_MD             3              /* mail destination (obsolete) */
#define T_MF             4              /* mail forwarder (obsolete) */
#define T_CNAME          5              /* canonical name */
#define T_SOA            6              /* start of authority zone */
#define T_MB             7              /* mailbox domain name (experimental) */
#define T_MG             8              /* mail group member (experimental) */
#define T_MR             9              /* mail rename domain name (experimental) */
#define T_NULL          10              /* null RR (experimental) */
#define T_WKS           11              /* well known service */
#define T_PTR           12              /* domain name pointer */
#define T_HINFO         13              /* host information */
#define T_MINFO         14              /* mailbox or mail list information */
#define T_MX            15              /* mail routing information */
#define T_TXT           16              /* text strings */
#define T_RP            17              /* responsible person (RFC 1183) */
#define T_AFSDB         18              /* AFS data base location (RFC 1183) */
#define T_X25           19              /* X.25 address (RFC 1183) */
#define T_ISDN          20              /* ISDN address (RFC 1183) */
#define T_RT            21              /* route-through (RFC 1183) */
#define T_NSAP          22              /* OSI NSAP (RFC 1706) */
#define T_NSAP_PTR      23              /* PTR equivalent for OSI NSAP (RFC 1348 - obsolete) */
#define T_SIG           24              /* digital signature (RFC 2535) */
#define T_KEY           25              /* public key (RFC 2535) */
#define T_PX            26              /* pointer to X.400/RFC822 mapping info (RFC 1664) */
#define T_GPOS          27              /* geographical position (RFC 1712) */
#define T_AAAA          28              /* IPv6 address (RFC 1886) */
#define T_LOC           29              /* geographical location (RFC 1876) */
#define T_NXT           30              /* "next" name (RFC 2535) */
#define T_EID           31              /* Endpoint Identifier */
#define T_NIMLOC        32              /* Nimrod Locator */
#define T_SRV           33              /* service location (RFC 2052) */
#define T_ATMA          34              /* ATM Address */
#define T_NAPTR         35              /* naming authority pointer (RFC 3403) */
#define T_KX            36              /* Key Exchange (RFC 2230) */
#define T_CERT          37              /* Certificate (RFC 4398) */
#define T_A6            38              /* IPv6 address with indirection (RFC 2874 - obsolete) */
#define T_DNAME         39              /* Non-terminal DNS name redirection (RFC 2672) */
#define T_SINK          40              /* SINK */
#define T_OPT           41              /* OPT pseudo-RR (RFC 2671) */
#define T_APL           42              /* Lists of Address Prefixes (APL RR) (RFC 3123) */
#define T_DS            43              /* Delegation Signature (RFC 4034) */
#define T_SSHFP         44              /* Using DNS to Securely Publish SSH Key Fingerprints (RFC 4255) */
#define T_IPSECKEY      45              /* RFC 4025 */
#define T_RRSIG         46              /* RFC 4034 */
#define T_NSEC          47              /* RFC 4034 */
#define T_DNSKEY        48              /* RFC 4034 */
#define T_DHCID         49              /* DHCID RR (RFC 4701) */
#define T_NSEC3         50              /* Next secure hash (RFC 5155) */
#define T_NSEC3PARAM    51              /* NSEC3 parameters (RFC 5155) */
#define T_TLSA          52              /* TLSA (RFC 6698) */
#define T_HIP           55              /* Host Identity Protocol (HIP) RR (RFC 5205) */
#define T_NINFO         56              /* NINFO */
#define T_RKEY          57              /* RKEY */
#define T_TALINK        58              /* Trust Anchor LINK */
#define T_CDS           59              /* Child DS */
#define T_SPF           99              /* SPF RR (RFC 4408) section 3 */
#define T_UINFO        100              /* [IANA-Reserved] */
#define T_UID          101              /* [IANA-Reserved] */
#define T_GID          102              /* [IANA-Reserved] */
#define T_UNSPEC       103              /* [IANA-Reserved] */
#define T_NID          104              /* ILNP [RFC6742] */
#define T_L32          105              /* ILNP [RFC6742] */
#define T_L64          106              /* ILNP [RFC6742] */
#define T_LP           107              /* ILNP [RFC6742] */
#define T_EUI48        108              /*[draft-jabley-dnsext-eui48-eui64-rrtypes] */
#define T_EUI64        109              /*[draft-jabley-dnsext-eui48-eui64-rrtypes] */
#define T_TKEY         249              /* Transaction Key (RFC 2930) */
#define T_TSIG         250              /* Transaction Signature (RFC 2845) */
#define T_IXFR         251              /* incremental transfer (RFC 1995) */
#define T_AXFR         252              /* transfer of an entire zone (RFC 5936) */
#define T_MAILB        253              /* mailbox-related RRs (MB, MG or MR) (RFC 1035) */
#define T_MAILA        254              /* mail agent RRs (OBSOLETE - see MX) (RFC 1035) */
#define T_ANY          255              /* A request for all records (RFC 1035) */
#define T_URI          256              /* URI */
#define T_CAA          257              /* Certification Authority Authorization (RFC 6844) */
#define T_TA         32768              /* DNSSEC Trust Authorities */
#define T_DLV        32769              /* DNSSEC Lookaside Validation (DLV) DNS Resource Record (RFC 4431) */
#define T_WINS       65281              /* Microsoft's WINS RR */
#define T_WINS_R     65282              /* Microsoft's WINS-R RR */

/* Class values */
#define C_IN             1              /* the Internet */
#define C_CS             2              /* CSNET (obsolete) */
#define C_CH             3              /* CHAOS */
#define C_HS             4              /* Hesiod */
#define C_NONE         254              /* none */
#define C_ANY          255              /* any */

#define C_QU            (1<<15)         /* High bit is set in queries for unicast queries */
#define C_FLUSH         (1<<15)         /* High bit is set for MDNS cache flush */

/* Bit fields in the flags */
#define F_RESPONSE      (1<<15)         /* packet is response */
#define F_OPCODE        (0xF<<11)       /* query opcode */
#define OPCODE_SHIFT    11
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_CONFLICT      (1<<10)         /* conflict detected */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_TENTATIVE     (1<<8)          /* response is tentative */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_Z             (1<<6)          /* Z */
#define F_AUTHENTIC     (1<<5)          /* authentic data (RFC2535) */
#define F_CHECKDISABLE  (1<<4)          /* checking disabled (RFC2535) */
#define F_RCODE         (0xF<<0)        /* reply code */

/* Optcode values for EDNS0 options (RFC 2671) */
#define O_LLQ            1              /* Long-lived query (on-hold, draft-sekar-dns-llq) */
#define O_UL             2              /* Update lease (on-hold, draft-sekar-dns-ul) */
#define O_NSID           3              /* Name Server Identifier (RFC 5001) */
#define O_OWNER          4              /* Owner, reserved (draft-cheshire-edns0-owner-option) */
#define O_DAU            5              /* DNSSEC Algorithm Understood (RFC6975) */
#define O_DHU            6              /* DS Hash Understood (RFC6975) */
#define O_N3U            7              /* NSEC3 Hash Understood  (RFC6975) */
#define O_CLIENT_SUBNET  8              /* Client subnet as assigned by IANA */
#define O_CLIENT_SUBNET_EXP 0x50fa      /* Client subnet (placeholder value, draft-vandergaast-edns-client-subnet) */

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
