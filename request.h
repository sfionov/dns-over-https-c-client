#ifndef DNS_OVER_HTTPS_CLIENT_REQUEST_H
#define DNS_OVER_HTTPS_CLIENT_REQUEST_H

#include "client.h"

struct doh_request {
    doh_client_t *parent;
    struct sockaddr *sa;
    socklen_t salen;
    struct iovec msg;
    nghttp2_data_provider dpr;
    int success;
    int replied;
};

doh_request_t *doh_request_create(doh_client_t *client, char *msg, size_t len, struct sockaddr_storage *sa, socklen_t salen);
void doh_request_submit(doh_request_t *req);
void doh_request_send_reply(doh_request_t *req, const uint8_t *data, size_t len);
void doh_request_send_reject(doh_request_t *req);
void doh_request_free(doh_request_t *req);

#endif //DNS_OVER_HTTPS_CLIENT_REQUEST_H
