#include <unistd.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <errno.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/sha1.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>

#include "tls.h"
#include "logger.h"
#include "client.h"
#include "http2.h"
#include "request.h"
#include "cacert.h"
#include "stamp.h"
#include "util.h"

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

static int verify_pins(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    doh_client_t *client = data;
    unsigned char sha256[32];
    mbedtls_sha256(crt->tbs.p, crt->tbs.len, sha256, 0);
    for (int i = 0; i < client->dns_stamp->cert_pin_count; i++) {
        if (client->dns_stamp->cert_pins[i].iov_len == sizeof(sha256) &&
            memcmp(client->dns_stamp->cert_pins[i].iov_base, sha256, sizeof(sha256)) == 0) {
            client->ssl_pin_verified = 1;
            char hex[sizeof(sha256) * 3 + 1];
            loginfo("Found cert pin: %s", hex_string(hex, sizeof(hex), sha256, sizeof(sha256)));
        }
    }
    if (depth == 0) {
        if (!client->ssl_pin_verified) {
            loginfo("Can't find certificates matching certificate pins. Please check that sdns:// url is not out-of-date.");
            return -1;
        }
    }
    return 0;
}

int doh_tls_init(doh_client_t *client) {
    int ret;

    client->ssl_connected = 0;
    // Init entropy
    mbedtls_entropy_init(&client->entropy);
    // Time as seed
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    // Init seed
    if ((ret = mbedtls_ctr_drbg_seed(&client->ctr_drbg, mbedtls_entropy_func, &client->entropy, (void *)&tv, sizeof(tv))) != 0) {
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

    mbedtls_x509_crt_init(&client->crt);
    if ((ret = mbedtls_x509_crt_parse(&client->crt, (const unsigned char *) cacert, sizeof(cacert))) != 0) {
        loginfo("Error loading CA certificates: -%x", -ret);
        return -1;
    }
    mbedtls_ssl_conf_cert_profile(&client->conf, &mbedtls_x509_crt_profile_default);
    mbedtls_ssl_conf_ca_chain(&client->conf, &client->crt, NULL);
    mbedtls_ssl_conf_authmode(&client->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_verify(&client->conf, verify_pins, client);

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
    client->ssl_connected = 0;
    client->ssl_pin_verified = 0;
}

void doh_tls_deinit(doh_client_t *client) {
    mbedtls_ssl_free(&client->ssl);
    mbedtls_ssl_config_free(&client->conf);
    mbedtls_ctr_drbg_free(&client->ctr_drbg);
    mbedtls_entropy_free(&client->entropy);
    mbedtls_x509_crt_free(&client->crt);
}

static int doh_tls_send_impl(void *ctx, const unsigned char *buf, size_t len) {
    doh_client_t *cctx = ctx;
    int w = (int) write(cctx->fd, buf, len);
    if (w >= 0) {
        return w;
    }
    if (errno == EWOULDBLOCK) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int doh_tls_recv_impl(void *ctx, unsigned char *buf, size_t len) {
    doh_client_t *cctx = ctx;
    int w = (int) read(cctx->fd, buf, len);
    if (w >= 0) {
        return w;
    }
    if (errno == EWOULDBLOCK) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

void doh_tls_connect(doh_client_t *client) {
    mbedtls_ssl_setup(&client->ssl, &client->conf);
    mbedtls_ssl_set_hostname(&client->ssl, client->dns_stamp->hostname);
    mbedtls_ssl_set_bio(&client->ssl, client, doh_tls_send_impl, doh_tls_recv_impl, NULL);
}
