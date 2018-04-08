# dns-over-https-c-client
DNS over HTTPS client written in C

### Goal
Make an alternative to `dnscrypt-proxy` and `cloudflared` written in C.

### Compiling

To compile, run `cmake` and `make doh_client`.

### Usage

```
DNS over HTTPS client

Only HTTP/2+POST+udp-wireformat supported
Usage: ./doh_client -p listen-port [-h listen-host] [-t threads] [-u sdns://uri]
       -p <listen port>    -- Listen port for plain DNS requests (required parameter)
       -h <listen host>    -- Listen host. Default value is `::'
       -t <threads>        -- Worker thread count. Default value is 1, and this should be enough in most cases.
       -u <sdns uri>       -- SDNS stamp URI of DNS-over-HTTPS server.
                              Default value is SDNS for 1.0.0.1: 
                              sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk
```

### Example

```
$ ./doh_client -p 15353
08.04.2018 23:37:16.512 [tid=29236] Using sdns uri: sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk
08.04.2018 23:37:16.512 [tid=29236] Configuration for remote DNS-over-HTTPS server (provided in sdns:// uri, may differ from actual server options):
08.04.2018 23:37:16.512 [tid=29236]     Server supports DNSSEC
08.04.2018 23:37:16.512 [tid=29236]     Server doesn't log requests
08.04.2018 23:37:16.512 [tid=29236]     Server doesn't block requests
08.04.2018 23:37:16.512 [tid=29236]     Address: 1.0.0.1
08.04.2018 23:37:16.512 [tid=29236]     Port: not specified (using 443)
08.04.2018 23:37:16.512 [tid=29236]     Cert pin: 10:d9:3c:98:64:a5:21:f3:06:5c:c3:a5:22:50:9c:2a:fa:bb:01:58:1c:ad:9c:6d:8e:89:fd:d7:5f:9e:a7:47
08.04.2018 23:37:16.512 [tid=29236]     Cert pin: eb:75:25:f8:8f:0d:94:58:f8:1a:99:50:19:bf:d3:4c:b8:9c:cd:c9:57:e7:b0:ef:31:5f:10:f8:97:63:81:18
08.04.2018 23:37:16.512 [tid=29236]     Path: /dns-query
08.04.2018 23:37:16.512 [tid=29236]     Host: dns.cloudflare.com
08.04.2018 23:37:16.524 [tid=29236] Listening for DNS requests on port 15353
08.04.2018 23:37:21.785 [tid=29236] Connecting to 1.0.0.1 port 443
08.04.2018 23:37:21.794 [tid=29236] Found cert pin: 10:d9:3c:98:64:a5:21:f3:06:5c:c3:a5:22:50:9c:2a:fa:bb:01:58:1c:ad:9c:6d:8e:89:fd:d7:5f:9e:a7:47
08.04.2018 23:37:21.801 [tid=29236] Connected to remote server
08.04.2018 23:37:21.801 [tid=29236] DNS request sent stream=1
08.04.2018 23:37:25.800 [tid=29236] DNS request sent stream=3
```

### Obtaining SDNS links

List on encrypted DNS server may be found in `dnscrypt-proxy` project:
https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v2/public-resolvers.md

sdns:// links starting with "Ag" is probably DNS over HTTPS (HTTP/2).
