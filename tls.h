#ifndef DNS_OVER_HTTPS_CLIENT_TLS_H
#define DNS_OVER_HTTPS_CLIENT_TLS_H

#include "client.h"

int doh_tls_init(doh_client_t *client);

void doh_tls_connect(doh_client_t *client);

void doh_tls_reset_session(doh_client_t *client);

void doh_tls_handshake_io(doh_client_t *client);

void doh_tls_deinit(doh_client_t *client);

#endif //DNS_OVER_HTTPS_CLIENT_TLS_H
