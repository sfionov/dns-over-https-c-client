//
// Created by s.fionov on 02.04.18.
//

#include "client.h"
#include "http2.h"
#include "request.h"
#include "tls.h"
#include "logger.h"
#include "util.h"
#include "stamp.h"
#include <unistd.h>
#include <sys/poll.h>
#include <errno.h>
#include <memory.h>
#include <netdb.h>

int doh_client_init(doh_client_t *client, dns_stamp_t *dns_stamp, send_reply_fn send, void *arg) {
    memset(client, 0, sizeof(*client));
    client->fd = -1;
    client->ssl_connected = 0;
    client->session = NULL;
    client->events = POLLIN;
    client->send_reply = send;
    client->send_reply_arg = arg;
    client->dns_stamp = dns_stamp;
    return doh_tls_init(client);
}

int doh_client_connect(doh_client_t *client) {
    const char *addr = client->dns_stamp->addr;
    const char *port = client->dns_stamp->port ? client->dns_stamp->port : DEFAULT_HTTPS_PORT;
    loginfo("Connecting to %s port %s", addr, port);
    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = NI_NUMERICSERV | NI_NUMERICHOST;
    struct addrinfo *result;
    int ret;
    if ((ret = getaddrinfo(addr, port , &hints, &result)) != 0) {
        loginfo("Can't connect to remote host: %s", gai_strerror(ret));
        return -1;
    }
    if (result == NULL) {
        loginfo("Can't connect to remote host: Host wasn't resolved", gai_strerror(ret));
        return -1;
    }
    client->fd = socket(result->ai_family, SOCK_STREAM, IPPROTO_TCP);
    make_non_blocking(client->fd);
    if (connect(client->fd, result->ai_addr, result->ai_addrlen) < 0) {
        if (errno == EINPROGRESS) {
            client->events = POLLOUT;
        } else {
            loginfo("Failed to connect to remote server: %s", strerror(errno));
            freeaddrinfo(result);
            return -1;
        }
    }
    set_tcp_nodelay(client->fd);
    freeaddrinfo(result);

    doh_tls_connect(client);
    return 0;
}

void doh_client_reset_session(doh_client_t *client) {
    if (client->session) {
        doh_http2_reset_session(client);
    }

    doh_tls_reset_session(client);
    client->ssl_connected = 0;

    close(client->fd);
    client->fd = -1;

    if (client->deferred_req) {
        doh_request_send_reject(client->deferred_req);
        doh_request_free(client->deferred_req);
    }
}

void doh_client_deinit(doh_client_t *client) {
    doh_client_reset_session(client);
    doh_tls_deinit(client);
}
