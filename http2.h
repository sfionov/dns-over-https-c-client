#ifndef DNS_OVER_HTTPS_CLIENT_HTTP2_H
#define DNS_OVER_HTTPS_CLIENT_HTTP2_H

#include <nghttp2/nghttp2.h>
#include "client.h"

#define HTTP2_ALPN "h2"

typedef struct {
    nghttp2_nv *nv;
    size_t nvlen;
} http2_headers_t;

http2_headers_t *http2_headers_create();

void http2_add_header(http2_headers_t *headers, char *name, char *valuefmt, ...);

void http2_headers_free(http2_headers_t *headers);

void doh_http2_init_client(doh_client_t *client);

void doh_http2_io(doh_client_t *client);

void doh_http2_reset_session(doh_client_t *client);

int doh_http2_submit_request(nghttp2_session *session, http2_headers_t *headers, nghttp2_data_provider *dpr,
                             struct iovec *msg, void *ptr);


#endif //DNS_OVER_HTTPS_CLIENT_HTTP2_H
