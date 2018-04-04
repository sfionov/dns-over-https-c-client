//
// Created by s.fionov on 02.04.18.
//

#include "doh_client.h"
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include <mbedtls/entropy.h>
#include <string.h>
#include <mbedtls/debug.h>

//void doh_client_ctx_deinit(doh_client_ctx_t *cctx) {
//
//}
//
//
//void doh_client_connect(doh_client_ctx_t *cctx, char *url, char *path) {
//}
//
//void doh_client_read(doh_client_ctx_t *cctx) {
//
//}
//
//void doh_client_write(doh_client_ctx_t *cctx) {
//    if (cctx->events & POLLOUT) {
//    }
//}
