#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <nghttp2/nghttp2.h>
#include <signal.h>
#include <pthread.h>
#include <getopt.h>

#include "client.h"
#include "logger.h"
#include "http2.h"
#include "request.h"
#include "util.h"
#include "tls.h"

static const int MAXD_GRAM_SIZE = 65535;

#define PH_STATUS ":status"
#define DEFAULT_LISTEN_ADDRESS "::"
#define DEFAULT_SDNS_URI "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zLmNsb3VkZmxhcmUuY29tCi9kbnMtcXVlcnk"

// Global state
int stopping = 0;
struct addrinfo *listen_addr;
dns_stamp_t *dns_stamp;

// Getopt options
char *opt_listen_address = DEFAULT_LISTEN_ADDRESS;
void *opt_listen_port;
char *opt_sdns_uri = DEFAULT_SDNS_URI;
int opt_threads = 1;

ssize_t raw_send(void *arg, const void *msg, size_t msglen, const struct sockaddr *sa, socklen_t salen) {
    return sendto(*(int *)arg, msg, msglen, 0, sa, salen);
}

void process_request(doh_request_t *req) {
    if (req->parent->fd == -1) {
        req->parent->deferred_req = req;
        if (doh_client_connect(req->parent) != 0) {
            doh_request_send_reject(req);
            doh_request_free(req);
        }
        return;
    }

    if (req->parent->session == NULL) {
        doh_request_send_reject(req);
        doh_request_free(req);
        return;
    }

    doh_request_submit(req);
}

int init_listen_socket(int *p_server_fd, struct addrinfo *listen_addr) {
    int server_fd = socket(listen_addr->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (server_fd == -1) {
        loginfo("Error creating server fd");
        return -1;
    }

    if (set_reuse_addr(server_fd) < 0) {
        loginfo("Error setting reuseaddr flag on server socket");
        return -1;
    }

    if (set_reuse_port(server_fd) < 0) {
        loginfo("Error setting reuseport flag on server socket");
        return -1;
    }

    if (bind(server_fd, listen_addr->ai_addr, listen_addr->ai_addrlen) != 0) {
        loginfo("Can't bind server socket: %s", strerror(errno));
        return -1;
    }

    if (make_non_blocking(server_fd) < 0) {
        loginfo("Error making server socket non-blocking");
        return -1;
    }

    *p_server_fd = server_fd;
    return 0;
}

doh_request_t *read_request(int server_fd, doh_client_t *client) {
    char buf[MAXD_GRAM_SIZE];
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    int r = (int) recvfrom(server_fd, buf, sizeof(buf), 0, (struct sockaddr *) &sa, &salen);
    if (r < 0) {
        loginfo("recvfrom failed :(");
    }
    doh_request_create(client, buf, r, &sa, salen);
}

void *do_work(void *arg) {
    (void)arg;
    doh_client_t client;
    int server_fd;

    if (init_listen_socket(&server_fd, listen_addr) < 0) {
        return NULL;
    }
    if (doh_client_init(&client, dns_stamp, raw_send, &server_fd) == -1) {
        loginfo("Error initializing DNS over HTTPS client");
        return NULL;
    }

    loginfo("Listening for DNS requests on port %s", opt_listen_port);
    while (!stopping) {
        struct pollfd pfd[2];
        nfds_t pfdlen = 0;
        pfd[0].fd = server_fd;
        pfd[0].events = client.deferred_req ? 0 : POLLIN;
        pfd[0].revents = 0;
        pfdlen++;
        pfd[1].fd = client.fd;
        pfd[1].events = client.fd != -1 ? client.events : 0;
        pfd[1].revents = 0;
        pfdlen++;

        int r = poll(pfd, pfdlen, -1);
        if (r < 1) {
            if (errno != EINTR) {
                fatal("Poll failed");
            }
        }
        if (pfd[0].revents & POLLIN) {
            doh_request_t *req = read_request(server_fd, &client);
            process_request(req);
        }
        if (pfd[1].revents & (POLLIN | POLLOUT)) {
            if (!client.ssl_connected) {
                doh_tls_handshake_io(&client);
            } else {
                doh_http2_io(&client);
            }
        }
    }

    doh_client_deinit(&client);
    return NULL;
}

#define usage_line(x) fprintf(stderr, x "\n");

void usage() {
    usage_line("DNS over HTTPS client");
    usage_line("");
    usage_line("Only HTTP/2+POST+udp-wireformat supported");
    usage_line("Usage: ./doh_client -p listen-port [-h listen-host] [-t threads] [-u sdns://uri]");
    usage_line("       -p <listen port>    -- Listen port for plain DNS requests (required parameter)");
    usage_line("       -h <listen host>    -- Listen host. Default value is `::'");
    usage_line("       -t <threads>        -- Worker thread count. Default value is 1, and this should be enough in most cases.");
    usage_line("       -u <sdns uri>       -- SDNS stamp URI of DNS-over-HTTPS server.");
    usage_line("                              Default value is SDNS for 1.0.0.1: ");
    usage_line("                              " DEFAULT_SDNS_URI);
}

struct addrinfo *get_listen_addr(const char *host, const char *serv) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = NI_NUMERICSERV;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *result = NULL;

    if (getaddrinfo(host, serv, &hints, &result) != 0) {
        return NULL;
    }
    return result;
}

int main(int argc, char *argv[]) {
    int c;
    while ((c = getopt (argc, argv, "h:p:u:t:")) != -1) {
        switch (c) {
            case 'h':
                opt_listen_address = optarg;
                break;
            case 'p':
                opt_listen_port = optarg;
                break;
            case 'u':
                opt_sdns_uri = optarg;
                break;
            case 't':
                opt_threads = (int) strtol(optarg, NULL, 0);
                if (opt_threads > 64) {
                    goto fail;
                }
                break;
            fail:
            default:
            case '?':
                usage();
                return 1;
        }
    }
    if (opt_listen_port == 0) {
        usage();
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    listen_addr = get_listen_addr(opt_listen_address, opt_listen_port);
    if (listen_addr == 0) {
        fatal("Can't resolve listen host");
    }

    loginfo("Using sdns uri: %s", opt_sdns_uri);
    if (dns_stamp_parse(opt_sdns_uri, &dns_stamp) < 0) {
        fatal("Can't parse DNS stamp");
    }

    if (opt_threads != 1) {
        loginfo("Spawning %d workers", opt_threads);
    }
    int thread_idx;
    for (thread_idx = 0; thread_idx < opt_threads - 1; thread_idx++) {
        pthread_t thr;
        pthread_create(&thr, NULL, do_work, NULL);
        pthread_detach(thr);
    }
    if (thread_idx < opt_threads) {
        do_work(NULL);
    } else {
        loginfo("Nothing to do, exiting");
    }

    freeaddrinfo(listen_addr);
    dns_stamp_free(dns_stamp);

    return 0;
}
