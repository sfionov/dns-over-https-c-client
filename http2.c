#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/poll.h>

#include "http2.h"
#include "logger.h"
#include "client.h"
#include "request.h"

#define HTTP2_MAX_FIELDS_NUM 20
#define PH_STATUS ":status"

http2_headers_t *http2_headers_create() {
    http2_headers_t *headers = calloc(1, sizeof(http2_headers_t));
    headers->nv = calloc(HTTP2_MAX_FIELDS_NUM, sizeof(nghttp2_nv));
    return headers;
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

int http2cb_on_header(nghttp2_session *session, const nghttp2_frame *frame,
                      const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
                      uint8_t flags, void *user_data) {
    if (namelen == strlen(PH_STATUS) && memcmp(name, PH_STATUS, strlen(PH_STATUS)) == 0) {
        char *status_code_str = strndup((const char *) value, valuelen);
        long status_code = strtol(status_code_str, NULL, 10);
        free(status_code_str);
        if (status_code >= 200 && status_code < 300) {
            doh_request_t *req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            if (req) {
                req->success = 1;
            }
        } else {
            loginfo("Non-success status received for stream=%d: %.*s", frame->hd.stream_id, (int)valuelen, value);
        }
    }
    return 0;
}

int http2cb_on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                               int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
    doh_request_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (req) {
        if (req->success) {
            doh_request_send_reply(req, data, len);
        } else {
            doh_request_send_reject(req);
        }
    }
    return 0;
}

void doh_http2_reset_session(doh_client_t *client) {
    nghttp2_session_terminate_session(client->session, NGHTTP2_ERR_INTERNAL);
    nghttp2_session_send(client->session);
    nghttp2_session_del(client->session);
    client->session = NULL;
}

int http2cb_on_stream_close(nghttp2_session *session,
                            int32_t stream_id, uint32_t error_code, void *user_data) {
    doh_request_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!req->replied) {
        doh_request_send_reject(req);
    }
    doh_request_free(req);
    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    return 0;
}

ssize_t doh_http2_recv_via_tls(nghttp2_session *session,
                               uint8_t *buf, size_t length, int flags,
                               void *user_data) {
    (void)session;
    (void)flags;

    doh_client_t *client = user_data;
    int ret = mbedtls_ssl_read(&client->ssl, buf, length);
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


ssize_t doh_http2_send_via_tls(nghttp2_session *session,
                               const uint8_t *data, size_t length,
                               int flags, void *user_data) {
    (void)session;
    (void)flags;
    doh_client_t *client = user_data;
    int ret = mbedtls_ssl_write(&client->ssl, data, length);
    if (ret >= 0) {
        return ret;
    }
    loginfo("mbedtls send error: %d", ret);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

void doh_http2_init_client(doh_client_t *client) {
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, http2cb_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, http2cb_on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, http2cb_on_stream_close);
    nghttp2_session_callbacks_set_recv_callback(callbacks, doh_http2_recv_via_tls);
    nghttp2_session_callbacks_set_send_callback(callbacks, doh_http2_send_via_tls);
    nghttp2_session_client_new(&client->session, callbacks, client);
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_settings_entry settings[1];
    settings[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
    settings[0].value = 0;
    nghttp2_submit_settings(client->session, 0, settings, 1);
    nghttp2_session_send(client->session);
}

void doh_http2_io(doh_client_t *client) {
    int r = nghttp2_session_recv(client->session);
    if (r < 0 && r != NGHTTP2_ERR_WOULDBLOCK) {
        goto error;
    }

    r = nghttp2_session_send(client->session);
    if (r < 0 && r != NGHTTP2_ERR_WOULDBLOCK) {
        goto error;
    }
    if (nghttp2_session_want_write(client->session)) {
        client->events |= POLLOUT;
        return;
    }
    client->events &= ~POLLOUT;

    return;

error:
    if (r != NGHTTP2_ERR_CALLBACK_FAILURE) {
        loginfo("HTTP/2 error: %d", r);
    }
    doh_client_reset_session(client);
}

static ssize_t iovec_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                                   uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    struct iovec *msg = source->ptr;
    if (length > msg->iov_len) {
        length = msg->iov_len;
    }
    memcpy(buf, msg->iov_base, length);
    *data_flags = NGHTTP2_FLAG_END_STREAM;
    return length;
}

int doh_http2_submit_request(nghttp2_session *session, http2_headers_t *headers, nghttp2_data_provider *dpr,
                             struct iovec *msg, void *ptr) {
    dpr->source.ptr = msg;
    dpr->read_callback = iovec_read_callback;

    int stream_id = nghttp2_submit_request(session, NULL, headers->nv, headers->nvlen, dpr, ptr);
    if (stream_id < 0) {
        return stream_id;
    }
    nghttp2_session_send(session);
    return stream_id;
}
