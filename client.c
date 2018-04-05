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

static int doh_client_send_impl(void *ctx, const unsigned char *buf, size_t len) {
    doh_client_t *cctx = ctx;
    int w = (int) write(cctx->fd, buf, len);
    if (w >= 0) {
        return w;
    }
    if (w < 0) {
        if (errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
}

static int doh_client_recv_impl(void *ctx, unsigned char *buf, size_t len) {
    doh_client_t *cctx = ctx;
    int w = (int) read(cctx->fd, buf, len);
    if (w >= 0) {
        return w;
    }
    if (w < 0) {
        if (errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
    }

}

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

void doh_client_connect(doh_client_t *client) {
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x01010101);
    sa.sin_port = htons(443);
    client->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    make_non_blocking(client->fd);
    if (connect(client->fd, (const struct sockaddr *) &sa, sizeof(sa)) < 0) {
        if (errno == EINPROGRESS) {
            client->events = POLLOUT;
        } else {
            loginfo("connect failed: %s", strerror(errno));
        }
    }

    mbedtls_ssl_setup(&client->ssl, &client->conf);
    mbedtls_ssl_set_hostname(&client->ssl, "1.1.1.1");
    mbedtls_ssl_set_bio(&client->ssl, client, doh_client_send_impl, doh_client_recv_impl, NULL);
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
