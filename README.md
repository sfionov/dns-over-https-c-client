# dns-over-https-c-client
DNS over HTTPS client written in C

### Usage

```
DNS over HTTPS client

Only HTTP/2+POST+udp-wireformat supported
Usage: ./dns-over-https-client -p listen-port [-h listen-host] [-t threads] [-u sdns://uri]
       -p <listen port>    -- Listen port (required parameter)
       -h <listen host>    -- Listen host. Default value is `::'
       -t <threads>        -- Worker thread count. Default value is 1, and this should be enough is most cases.
       -u <sdns uri>       -- SDNS stamp URI of DNS-over-HTTPS server.
                              Default value is SDNS for 1.0.0.1: 
                              sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk
```

### Compiling

To compile, run `cmake` and `make doh_c_client`.
