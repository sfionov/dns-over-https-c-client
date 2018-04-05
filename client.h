//
// Created by s.fionov on 02.04.18.
//

#ifndef DNS_OVER_HTTPS_CLIENT_DOH_CLIENT_H
#define DNS_OVER_HTTPS_CLIENT_DOH_CLIENT_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <nghttp2/nghttp2.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

typedef ssize_t (*send_reply_fn)(void *arg, const void *msg, size_t msglen, const struct sockaddr *sa, socklen_t salen);

typedef struct doh_request doh_request_t;

typedef struct {
    int fd;
    int ssl_connected;
    mbedtls_ssl_context ssl;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    short events;
    nghttp2_session *session;
    doh_request_t *deferred_req;

    send_reply_fn send_reply;
    void *send_reply_arg;
} doh_client_t;

int doh_client_init(doh_client_t *client, send_reply_fn send, void *arg);
void doh_client_connect(doh_client_t *client);
void doh_client_reset_session(doh_client_t *client);
void doh_client_deinit(doh_client_t *cctx);

//
//void doh_client_init(doh_client_ctx_t *cctx);
//
//void doh_client_ctx_deinit(doh_client_ctx_t *cctx);
//
//void doh_client_connect(doh_client_ctx_t *cctx, char *url, char *path);

#endif //DNS_OVER_HTTPS_CLIENT_DOH_CLIENT_H
