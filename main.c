#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <nghttp2/nghttp2.h>
#include <mbedtls/debug.h>
#include <signal.h>
#include <syscall.h>
#include "dns.h"
#include "doh_client.h"

static const int MAXD_GRAM_SIZE = 65535;
static const int HTTP2_MAX_FIELDS_NUM = 20;

#define CF_IP "1.1.1.1"
#define CF_PATH "/dns-query"
#define PH_STATUS ":status"

int set_reuse_addr(int fd);

void do_tls_handshake();

void do_connect();

void http2_session_start();

void reset_session();

int stopping = 0;

typedef struct {
    int fd;
    int ssl_connected;
    mbedtls_ssl_context ssl;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    short events;
    nghttp2_session *session;
} doh_client_ctx_t;

typedef struct {
    struct sockaddr *sa;
    socklen_t salen;
    void *msg;
    size_t msglen;
    nghttp2_data_provider dpr;
    int success;
} doh_client_req_t;

typedef struct {
    int fd;
} doh_listen_ctx_t;

typedef struct {
    doh_listen_ctx_t listen;
    doh_client_ctx_t client;
    doh_client_req_t *deferred_req;
} doh_proxy_ctx_t;

void doh_request_send_reject(doh_client_req_t *req);

_Thread_local doh_proxy_ctx_t ctx;

const char *HTTP2_ALPN[] = {"h2", NULL};

intmax_t gettid() {
    return syscall(SYS_gettid);
}

void loginfo(const char *format, ...) {
    va_list args;

    va_start(args, format);
    int size = vsnprintf(NULL, 0, format, args);
    va_end(args);

    va_start(args, format);
    char msg[size + 1u];
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);

    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    char time_str[25];
    strftime(time_str, sizeof(time_str), "%d.%m.%Y %H:%M:%S", localtime(&tv.tv_sec));

    fprintf(stderr, "%s.%03d [tid=%" PRIdMAX "] %s\n", time_str, (int) tv.tv_usec / 1000, gettid(), msg);
}

void logssl(void *ctx, int level, const char *file, int line, const char *msg) {
    (void)ctx;
    (void)level;
    (void)file;
    (void)line;
    loginfo("%s", msg);
}

void fatal(const char *msg) {
    perror(msg);
    exit(1);
}

int make_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int set_reuse_addr(int fd) {
    int value = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
}

int set_reuse_port(int fd) {
    int value = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value));
}

int doh_send(void *ctx, const unsigned char *buf, size_t len) {
    doh_client_ctx_t *cctx = ctx;
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

int doh_recv(void *ctx, unsigned char *buf, size_t len) {
    doh_client_ctx_t *cctx = ctx;
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

void doh_client_ctx_init(doh_client_ctx_t *cctx) {
    cctx->fd = -1;
    cctx->ssl_connected = 0;
    cctx->session = NULL;
    cctx->events = POLLIN;
}

ssize_t req_read(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                 uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    doh_client_req_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (length > req->msglen) {
        length = req->msglen;
    }
    memcpy(buf, req->msg, length);
    *data_flags = NGHTTP2_FLAG_END_STREAM;
    return length;
}

doh_client_req_t *doh_request_create(char *msg, size_t len, struct sockaddr_storage *sa, socklen_t salen) {
    doh_client_req_t *req = calloc(1, sizeof(doh_client_req_t));
    req->msg = malloc(len);
    req->msglen = len;
    memcpy(req->msg, msg, len);

    req->sa = malloc(salen);
    req->salen = salen;
    memcpy(req->sa, sa, salen);

    req->dpr.source.ptr = req;
    req->dpr.read_callback = req_read;

    return req;
}

typedef struct {
    nghttp2_nv *nv;
    size_t nvlen;
} http2_headers_t;

http2_headers_t *http2_headers_create() {
    http2_headers_t *headers = calloc(1, sizeof(http2_headers_t));
    headers->nv = calloc(HTTP2_MAX_FIELDS_NUM, sizeof(nghttp2_nv));
}

void http2_add_header(http2_headers_t *headers, char *name, char *valuefmt, ...) {
    if (headers->nvlen == HTTP2_MAX_FIELDS_NUM) {
        return;
    }

    headers->nv[headers->nvlen].name = (uint8_t *) strdup(name);
    headers->nv[headers->nvlen].namelen = strlen(name);

    va_list args;

    va_start(args, valuefmt);
    int size = vsnprintf(NULL, 0, valuefmt, args);
    va_end(args);
    char *value = malloc(size + 1u);
    va_start(args, valuefmt);
    vsnprintf(value, size + 1u, valuefmt, args);
    va_end(args);

    headers->nv[headers->nvlen].value = (uint8_t *) value;
    headers->nv[headers->nvlen].valuelen = strlen(value);

    headers->nvlen++;
}

void http2_headers_free(http2_headers_t *headers) {
    if (headers == NULL) {
        return;
    }

    for (size_t i = 0; i < headers->nvlen; i++) {
        free(headers->nv[i].name);
        free(headers->nv[i].value);
    }

    free(headers);
}

void doh_request_send(doh_client_req_t *req) {
    http2_headers_t *headers = http2_headers_create();

    http2_add_header(headers, ":method", "POST");
    http2_add_header(headers, ":scheme", "https");
    http2_add_header(headers, ":authority", "cloudflare-dns.com");
    http2_add_header(headers, ":path", "/dns-query");
    http2_add_header(headers, "accept", "application/dns-udpwireformat");
    http2_add_header(headers, "content-type", "application/dns-udpwireformat");
    http2_add_header(headers, "content-length", "%zd", req->msglen);

    int stream_id = nghttp2_submit_request(ctx.client.session, NULL, headers->nv, headers->nvlen, &req->dpr, req);
    if (stream_id < 0) {
        loginfo("nghttp2 send request error: %d", stream_id);
    }
    nghttp2_session_send(ctx.client.session);

    http2_headers_free(headers);
    loginfo("DNS request sent stream=%d", stream_id);
}

void doh_request_free(doh_client_req_t *req) {
    if (req) {
        free(req->msg);
        free(req->sa);
    }
    free(req);
}

void process_request(doh_client_req_t *req) {
    if (ctx.client.fd == -1) {
        ctx.deferred_req = req;
        loginfo("Connecting to remote server");
        do_connect();
        return;
    }

    if (ctx.client.session == NULL) {
        doh_request_send_reject(req);
        doh_request_free(req);
        return;
    }

    doh_request_send(req);
}

void do_work(void *arg) {
    struct addrinfo *result = arg;

    ctx.listen.fd = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx.listen.fd == -1) {
        fatal("Error creating server fd");
    }

    if (bind(ctx.listen.fd, result->ai_addr, result->ai_addrlen) != 0) {
        loginfo("Can't bind server socket: ", strerror(errno));
    }

    if (make_non_blocking(ctx.listen.fd) < 0) {
        fatal("Error making server socket non-blocking");
    }

    if (set_reuse_addr(ctx.listen.fd) < 0) {
        fatal("Error setting reuseaddr flag on server socket");
    }

    if (set_reuse_port(ctx.listen.fd) < 0) {
        fatal("Error setting reuseport flag on server socket");
    }

    doh_client_ctx_init(&ctx.client);

    char buf[MAXD_GRAM_SIZE];

    while (!stopping) {
        struct pollfd pfd[2];
        nfds_t pfdlen = 0;
        pfd[0].fd = ctx.listen.fd;
        pfd[0].events = (short) (ctx.deferred_req ? 0 : POLLIN);
        pfd[0].revents = 0;
        pfdlen++;
        if (ctx.client.fd != -1) {
            pfd[1].fd = ctx.client.fd;
            pfd[1].events = ctx.client.events;
            pfd[1].revents = 0;
            pfdlen++;
        }

        int r = poll(pfd, pfdlen, -1);
        if (r < 1) {
            fatal("Poll failed");
        }
        //loginfo("Events on %d descriptors", r);
        if (pfd[0].revents & POLLIN) {
            struct sockaddr_storage sa;
            socklen_t salen = sizeof(sa);
            int r = recvfrom(ctx.listen.fd, buf, sizeof(buf), 0, (struct sockaddr *) &sa, &salen);
            if (r < 0) {
                loginfo("recvfrom failed :(");
            }
            doh_client_req_t *req = doh_request_create(buf, r, &sa, salen);
            process_request(req);
        }
        if (!ctx.client.ssl_connected && pfd[1].revents & (POLLIN | POLLOUT)) {
            do_tls_handshake();
        } else if (pfd[1].revents & (POLLIN | POLLOUT)) {
            int r = nghttp2_session_recv(ctx.client.session);
            if (r < 0 && r != NGHTTP2_ERR_WOULDBLOCK) {
                if (r != NGHTTP2_ERR_CALLBACK_FAILURE) {
                    loginfo("HTTP/2 error: %d", r);
                }
                reset_session();
                continue;
            }
            nghttp2_session_send(ctx.client.session);
            if (nghttp2_session_want_write(ctx.client.session)) {
                ctx.client.events |= POLLOUT;
            } else {
                ctx.client.events &= ~POLLOUT;
            }
        }
    }
    reset_session();
}

void do_connect() {
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x01010101);
    sa.sin_port = htons(443);
    ctx.client.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    make_non_blocking(ctx.client.fd);
    if (connect(ctx.client.fd, (const struct sockaddr *) &sa, sizeof(sa)) < 0) {
        if (errno == EINPROGRESS) {
            ctx.client.events = POLLOUT;
        } else {
            loginfo("connect failed: %s", strerror(errno));
        }
    }

    mbedtls_ssl_setup(&ctx.client.ssl, &ctx.client.conf);
    mbedtls_ssl_set_hostname(&ctx.client.ssl, "1.1.1.1");
    mbedtls_ssl_set_bio(&ctx.client.ssl, &ctx.client, doh_send, doh_recv, NULL);
}

void do_tls_handshake() {
    int r = mbedtls_ssl_handshake(&ctx.client.ssl);
    if (r < 0) {
        if (r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            ctx.client.events |= POLLOUT;
            return;
        }
        ctx.client.events &= ~POLLOUT;

        if (r == MBEDTLS_ERR_SSL_WANT_READ) {
            ctx.client.events |= POLLIN;
            return;
        }

        loginfo("TLS handshake error: -%x", -r);
        reset_session();
        return;
    }

    const char *alpn_proto = mbedtls_ssl_get_alpn_protocol(&ctx.client.ssl);
    if (alpn_proto == NULL || strcmp(alpn_proto, HTTP2_ALPN[0]) != 0) {
        loginfo("Remote server doesn't support HTTP/2, disconnecting");
        reset_session();
        return;
    }

    ctx.client.ssl_connected = 1;
    ctx.client.events &= ~POLLOUT;
    http2_session_start();
}

void http2_session_reset() {
    nghttp2_session_terminate_session(ctx.client.session, NGHTTP2_ERR_INTERNAL);
    nghttp2_session_send(ctx.client.session);
    nghttp2_session_del(ctx.client.session);
    ctx.client.session = NULL;
}

void reset_session() {
    if (ctx.client.session) {
        http2_session_reset();
    }

    mbedtls_ssl_session_reset(&ctx.client.ssl);
    ctx.client.ssl_connected = 0;

    close(ctx.client.fd);
    ctx.client.fd = -1;

    if (ctx.deferred_req) {
        doh_request_send_reject(ctx.deferred_req);
        doh_request_free(ctx.deferred_req);
    }
}

ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                      size_t length, int flags,
                      void *user_data) {
    int ret = mbedtls_ssl_read(&ctx.client.ssl, buf, length);
    if (ret > 0) {
        return ret;
    }
    if (ret == 0) {
        return NGHTTP2_ERR_EOF;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    loginfo("TLS read error: -%x", -ret);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}


ssize_t send_callback(nghttp2_session *session,
                                 const uint8_t *data, size_t length,
                                 int flags, void *user_data) {
    int ret = mbedtls_ssl_write(&ctx.client.ssl, data, length);
    if (ret >= 0) {
        return ret;
    }
    loginfo("mbedtls send error: %d", ret);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

int reply_recv(nghttp2_session *session, uint8_t flags,
        int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
    doh_client_req_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (req) {
        if (req->success) {
//            loginfo("Sending server reply: %.*s", (int)len, data);
            int r = (int) sendto(ctx.listen.fd, data, len, 0, (const struct sockaddr *) req->sa, req->salen);
            if (r < 0) {
                loginfo("Error sending reply: %s", strerror(errno));
            }
        } else {
            doh_request_send_reject(req);
        }
    }
}

int frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    //loginfo("frame received stream=%d type=%d", frame->hd.stream_id, frame->hd.type);
    return 0;
}

int header(nghttp2_session *session, const nghttp2_frame *frame,
           const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
           uint8_t flags, void *user_data) {
    if (namelen == strlen(PH_STATUS) && memcmp(name, PH_STATUS, strlen(PH_STATUS)) == 0) {
        char *status_code_str = strndup((const char *) value, valuelen);
        long status_code = strtol(status_code_str, NULL, 10);
        free(status_code_str);
        if (status_code >= 200 && status_code < 300) {
            doh_client_req_t *req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            if (req) {
                req->success = 1;
            }
        } else {
            loginfo("Non-success status received for stream=%d: %.*s", frame->hd.stream_id, (int)valuelen, value);
        }
    }
    return 0;
}

int on_stream_close(nghttp2_session *session,
                    int32_t stream_id, uint32_t error_code, void *user_data) {
    doh_client_req_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
        doh_request_free(req);
    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
}

void http2_session_start() {
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, reply_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_client_new(&ctx.client.session, callbacks, &ctx.client);
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_submit_settings(ctx.client.session, 0, NULL, 0);
    nghttp2_session_send(ctx.client.session);
    doh_request_send(ctx.deferred_req);
    ctx.deferred_req = NULL;
}

void doh_request_send_reject(doh_client_req_t *req) {
    struct dnshdr *hdr = (struct dnshdr *) req->msg;
    hdr->flags.rcode = RCODE_SERVFAIL;
    int r = (int) sendto(ctx.listen.fd, req->msg, (size_t) req->msglen, 0, (const struct sockaddr *) req->sa, req->salen);
    if (r < 0) {
        loginfo("sendto failed :(");
    }
    if (ctx.deferred_req == req) {
        ctx.deferred_req = NULL;
    }
}

void usage() {
    fprintf(stderr, "DNS over HTTPS client");
    fprintf(stderr, "Only HTTP/2+POST+udp-wireformat supported");
    fprintf(stderr, "Usage: ./dns-over-https-client <listen port>");
    fprintf(stderr, "   or: ./dns-over-https-client <listen host> <listen port>");
    fprintf(stderr, "       default listen host is `::'");
}

void ssl_init() {
    mbedtls_entropy_init(&ctx.client.entropy);
    char *pers = "fkljafkl";
    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(&ctx.client.ctr_drbg, mbedtls_entropy_func, &ctx.client.entropy,
                                     (const unsigned char *) pers, strlen(pers))) != 0) {
        loginfo("Can't initialize PRNG, error: %d\n", ret);
    }
    mbedtls_ssl_config_init(&ctx.client.conf);
    mbedtls_ssl_conf_ciphersuites(&ctx.client.conf, mbedtls_cipher_list());
    mbedtls_ecp_group_id curve_list[1];
    curve_list[0] = MBEDTLS_ECP_DP_NONE;
    mbedtls_ssl_conf_curves(&ctx.client.conf, curve_list);
    mbedtls_ssl_conf_sig_hashes(&ctx.client.conf, mbedtls_md_list());
    mbedtls_ssl_conf_rng(&ctx.client.conf, mbedtls_ctr_drbg_random, &ctx.client.ctr_drbg);
    mbedtls_ssl_conf_dbg(&ctx.client.conf, logssl, NULL);
    mbedtls_ssl_conf_min_version(&ctx.client.conf, 3, 1);
    mbedtls_ssl_conf_max_version(&ctx.client.conf, 3, 3);
    mbedtls_ssl_conf_alpn_protocols(&ctx.client.conf, HTTP2_ALPN);
    mbedtls_ssl_init(&ctx.client.ssl);
}

void ssl_deinit() {
    mbedtls_ssl_config_free(&ctx.client.conf);
}

int main(int argc, char *argv[]) {
    if (argc > 3 || argc == 1) {
        usage();
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    ssl_init();

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = NI_NUMERICSERV;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *result = NULL;

    if (argc == 3) {
        if (getaddrinfo(argv[1], argv[2], &hints, &result) != 0) {
            fatal("Can't resolve listen host");
        }
    } else {
        if (getaddrinfo("::", argv[1], &hints, &result) != 0) {
            fatal("Can't resolve listen host");
        }
    }
    if (result == 0) {
        fatal("Can't resolve listen host");
    }

    do_work(result);

    freeaddrinfo(result);

    ssl_deinit();

    return 0;
}
