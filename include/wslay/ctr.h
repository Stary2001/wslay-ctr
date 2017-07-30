#pragma once
#include <stdbool.h>

typedef struct wslay_ctr_ctx
{
	bool secure;
	sslcContext sslc;
	wslay_event_context_ptr ctx;
	int fd;
	int extra_ssl_opt;
	
	char *hostname;
	uint16_t port;
} wslay_ctr_ctx;

// Don't touch these.
ssize_t wslay_ctr_recv(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data);
ssize_t wslay_ctr_send(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data);
int wslay_ctr_genmask(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data);

// REALLY don't touch these.
ssize_t wslay_ctr_recv_internal(struct wslay_ctr_ctx *udata, uint8_t *buf, size_t len, int flags);
ssize_t wslay_ctr_send_internal(struct wslay_ctr_ctx *udata, const uint8_t *buf, size_t len, int flags);
int wslay_ctr_connect_internal(const char *hostname, uint16_t port);
void wslay_ctr_make_nonblock(int fd);

Result wslay_ctr_client_init(const char *hostname, uint16_t port, struct wslay_ctr_ctx *ctx, struct wslay_event_callbacks *cbs);
Result wslay_ctr_client_init_secure(const char *hostname, uint16_t port, struct wslay_ctr_ctx *ctx, struct wslay_event_callbacks *cbs, int extra_ssl_opt);
Result wslay_ctr_client_free(struct wslay_ctr_ctx *ctx);
Result wslay_ctr_client_run(struct wslay_ctr_ctx *ctx);
Result wslay_ctr_client_connect(struct wslay_ctr_ctx *ctx);