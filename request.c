#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "request.h"
#include "logger.h"
#include "http2.h"
#include "dns.h"

doh_request_t *doh_request_create(doh_client_t *client, char *msg, size_t len, struct sockaddr_storage *sa, socklen_t salen) {
    doh_request_t *req = calloc(1, sizeof(doh_request_t));
    req->parent = client;

    req->msg.iov_base = malloc(len);
    req->msg.iov_len = len;
    memcpy(req->msg.iov_base, msg, len);

    req->sa = malloc(salen);
    req->salen = salen;
    memcpy(req->sa, sa, salen);

    return req;
}


void doh_request_submit(doh_request_t *req) {
    http2_headers_t *headers = http2_headers_create();

    http2_add_header(headers, ":method", "POST");
    http2_add_header(headers, ":scheme", "https");
    http2_add_header(headers, ":authority", req->parent->dns_stamp->hostname);
    http2_add_header(headers, ":path", req->parent->dns_stamp->path);
    http2_add_header(headers, "accept", "application/dns-udpwireformat");
    http2_add_header(headers, "content-type", "application/dns-udpwireformat");
    http2_add_header(headers, "content-length", "%zd", req->msg.iov_len);

    int stream_id = doh_http2_submit_request(req->parent->session, headers, &req->dpr, &req->msg, req);
    if (stream_id < 0) {
        loginfo("Error sending request via HTTP/2: %d", stream_id);
        doh_request_send_reject(req);
        goto finish;
    }
    loginfo("DNS request sent stream=%d", stream_id);

finish:
    http2_headers_free(headers);
}

void doh_request_send_reply(doh_request_t *req, const uint8_t *data, size_t len) {
    int r = (int) req->parent->send_reply(req->parent->send_reply_arg, data, len,
                                          (const struct sockaddr *) req->sa, req->salen);
    if (r < 0) {
        loginfo("Failed to send reply: %s", strerror(errno));
    }
}

void doh_request_send_reject(doh_request_t *req) {
    struct dnshdr *hdr = (struct dnshdr *) req->msg.iov_base;
    hdr->flags.rcode = RCODE_SERVFAIL;
    int r = (int) req->parent->send_reply(req->parent->send_reply_arg, req->msg.iov_base, req->msg.iov_len,
                                          (const struct sockaddr *) req->sa, req->salen);
    if (r < 0) {
        loginfo("Failed to send reply: %s", strerror(errno));
    }
    if (req->parent->deferred_req == req) {
        req->parent->deferred_req = NULL;
    }
}

void doh_request_free(doh_request_t *req) {
    if (req) {
        free(req->msg.iov_base);
        free(req->sa);
    }
    free(req);
}
