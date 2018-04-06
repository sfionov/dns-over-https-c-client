//
// Created by s.fionov on 05.04.18.
//

#include <unistd.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <string.h>
#include <sys/poll.h>
#include <errno.h>
#include "tls.h"
#include "logger.h"
#include "client.h"
#include "http2.h"
#include "request.h"

static mbedtls_ecp_group_id CURVE_LIST[] = {
        MBEDTLS_ECP_DP_SECP256R1,
        MBEDTLS_ECP_DP_SECP384R1,
        MBEDTLS_ECP_DP_SECP521R1,
        MBEDTLS_ECP_DP_CURVE25519,
        MBEDTLS_ECP_DP_NONE
};

static const char *ALPN[] = {
        HTTP2_ALPN,
        NULL
};

void logssl(void *ctx, int level, const char *file, int line, const char *msg) {
    (void)ctx;
    (void)level;
    (void)file;
    (void)line;
    loginfo("%s", msg);
}

int doh_tls_init(doh_client_t *client) {
    int ret;

    // Init entropy
    mbedtls_entropy_init(&client->entropy);
    // Time as seed
    struct timespec ts = {time(0), 0};
    // Nanoseconds as seed
    timespec_get(&ts, TIME_UTC);
    // Init seed
    const char *seed = "fjklsdjf";
    if ((ret = mbedtls_ctr_drbg_seed(&client->ctr_drbg, mbedtls_entropy_func, &client->entropy, seed, strlen(seed))) != 0) {
        loginfo("Can't initialize PRNG, error: %d\n", ret);
        return -1;
    }

    // Init config
    mbedtls_ssl_config_init(&client->conf);
    mbedtls_ssl_conf_ciphersuites(&client->conf, mbedtls_cipher_list());
    mbedtls_ssl_conf_curves(&client->conf, CURVE_LIST);
    mbedtls_ssl_conf_sig_hashes(&client->conf, mbedtls_md_list());
    mbedtls_ssl_conf_rng(&client->conf, mbedtls_ctr_drbg_random, &client->ctr_drbg);
    mbedtls_ssl_conf_dbg(&client->conf, logssl, NULL);
    mbedtls_ssl_conf_min_version(&client->conf, 3, 1);
    mbedtls_ssl_conf_max_version(&client->conf, 3, 3);
    mbedtls_ssl_conf_alpn_protocols(&client->conf, ALPN);

    // Init context
    mbedtls_ssl_init(&client->ssl);

    return 0;
}

void doh_tls_handshake_io(doh_client_t *client) {
    int r = mbedtls_ssl_handshake(&client->ssl);
    if (r < 0) {
        if (r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            client->events |= POLLOUT;
            return;
        }
        client->events &= ~POLLOUT;

        if (r == MBEDTLS_ERR_SSL_WANT_READ) {
            client->events |= POLLIN;
            return;
        }

        loginfo("TLS handshake error: -%x", -r);
        doh_client_reset_session(client);
        return;
    }

    const char *alpn_proto = mbedtls_ssl_get_alpn_protocol(&client->ssl);
    if (alpn_proto == NULL || strcmp(alpn_proto, HTTP2_ALPN) != 0) {
        loginfo("Remote server doesn't support HTTP/2, disconnecting");
        doh_client_reset_session(client);
        return;
    }

    loginfo("Connected to remote server");
    client->ssl_connected = 1;
    client->events &= ~POLLOUT;
    doh_http2_init_client(client);
    doh_request_submit(client->deferred_req);
    client->deferred_req = NULL;
}

void doh_tls_reset_session(doh_client_t *client) {
    mbedtls_ssl_session_reset(&client->ssl);
}

void doh_tls_deinit(doh_client_t *client) {
    mbedtls_ssl_free(&client->ssl);
    mbedtls_ssl_config_free(&client->conf);
    mbedtls_ctr_drbg_free(&client->ctr_drbg);
    mbedtls_entropy_free(&client->entropy);
}

static int doh_tls_send_impl(void *ctx, const unsigned char *buf, size_t len) {
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

static int doh_tls_recv_impl(void *ctx, unsigned char *buf, size_t len) {
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

void doh_tls_connect(doh_client_t *client) {
    mbedtls_ssl_setup(&client->ssl, &client->conf);
    mbedtls_ssl_set_hostname(&client->ssl, client->dns_stamp->hostname);
    mbedtls_ssl_set_bio(&client->ssl, client, doh_tls_send_impl, doh_tls_recv_impl, NULL);
}
