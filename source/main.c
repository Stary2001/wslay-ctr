#include <3ds.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <wslay/wslay.h>
#include <wslay/ctr.h>
#include <poll.h>

#include "base64.h"
#include "sha1.h"
#include "builtin_rootca_der.h"

void wslay_ctr_setup_callbacks(struct wslay_event_callbacks *cbs)
{
	cbs->recv_callback = wslay_ctr_recv;
	cbs->send_callback = wslay_ctr_send;
	cbs->genmask_callback = wslay_ctr_genmask;
}

Result wslay_ctr_client_init(const char *hostname, uint16_t port, struct wslay_ctr_ctx *ctx, struct wslay_event_callbacks *cbs)
{
	wslay_ctr_setup_callbacks(cbs);
	
	ctx->secure = false;
	ctx->hostname = strdup(hostname);
	ctx->port = port;

	wslay_event_context_client_init(&ctx->ctx, cbs, ctx);
	return 0;
}

Result wslay_ctr_client_init_secure(const char *hostname, uint16_t port, struct wslay_ctr_ctx *ctx, struct wslay_event_callbacks *cbs, int extra_ssl_opt)
{
	wslay_ctr_setup_callbacks(cbs);
	
	ctx->secure = true;
	ctx->hostname = strdup(hostname);
	ctx->port = port;
	ctx->extra_ssl_opt = extra_ssl_opt;
	
	wslay_event_context_client_init(&ctx->ctx, cbs, ctx);
	return 0;
}

Result wslay_ctr_client_free(struct wslay_ctr_ctx *ctx)
{
	wslay_event_context_free(ctx->ctx);
	if(ctx->secure)
	{
		sslcDestroyContext(&ctx->sslc);
	}
	
	closesocket(ctx->fd);
	
	free(ctx);

	return 0;
}

Result wslay_ctr_client_connect(struct wslay_ctr_ctx *ctx)
{
	Result r;

	static Handle root_cert_chain_handle = 0;
	if(root_cert_chain_handle == 0)
	{
		r = sslcCreateRootCertChain(&root_cert_chain_handle);
		if(R_FAILED(r)) return r;
		r = sslcAddTrustedRootCA(root_cert_chain_handle, (u8*)builtin_rootca_der, builtin_rootca_der_size, NULL);
		if(R_FAILED(r))
		{
			sslcDestroyRootCertChain(root_cert_chain_handle);
			return r;
		}
	}

	ctx->fd = wslay_ctr_connect_internal(ctx->hostname, ctx->port);
	if(ctx->fd < 0) return -1;

	if(ctx->secure)
	{
		r = sslcCreateContext(&ctx->sslc, ctx->fd, ctx->extra_ssl_opt, ctx->hostname);
		if(R_FAILED(r))
		{
			closesocket(ctx->fd);
			return r;
		}

		r = sslcContextSetRootCertChain(&ctx->sslc, root_cert_chain_handle);
		if(R_FAILED(r))
		{
			sslcDestroyContext(&ctx->sslc);
			closesocket(ctx->fd);
			return r;
		}

		r = sslcStartConnection(&ctx->sslc, NULL, NULL);
		if(R_FAILED(r))
		{
			sslcDestroyContext(&ctx->sslc);
			closesocket(ctx->fd);
			return r;
		}
	}

	u8 client_key[16];
	char client_key_str[64];
	sslcGenerateRandomData(client_key, 16);
	base64_encode(client_key, (u8*)client_key_str, 16, 0);

	const char *path = "/";

	char buf[512];
	size_t handshake_len = snprintf(buf, sizeof(buf),
           "GET %s HTTP/1.1\r\n"
           "Host: %s:%i\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "\r\n",
           path, ctx->hostname, ctx->port, client_key_str);

	wslay_ctr_send_internal(ctx, (u8*)buf, handshake_len, 0);

	bool accept_found = false;
	bool reading_accept_header = false;

	int accept_key_len;
	char accept_key_str[64];

	int len = -1;
	len = wslay_ctr_recv_internal(ctx, (uint8_t*)buf, sizeof(buf)-1, 0);
	printf("%i\n", len);
	buf[len] = 0;

	while(len != 0)
	{
		if(reading_accept_header)
		{
			accept_found = true;
			char *accept_end = strstr(buf, "\r\n");
			int accept_key_remaining = accept_end - buf;
			memcpy(accept_key_str + accept_key_len, buf, accept_key_remaining);
			accept_key_len += accept_key_remaining;
			reading_accept_header = false;
		}
		else
		{
			char *accept_hdr = strstr(buf, "Sec-WebSocket-Accept");
			if(accept_hdr == NULL)
			{
				accept_found = false;
			}
			else
			{
				char *accept_end = strstr(accept_hdr, "\r\n");
				if(accept_end == NULL)
				{
					reading_accept_header = true;
					accept_key_len = sizeof(buf) - (accept_hdr - buf) - 22;
					memcpy(accept_key_str, accept_hdr + 22, accept_key_len);
				}
				else
				{
					accept_found = true;
					accept_key_len = accept_end - accept_hdr - 22;
					memcpy(accept_key_str, accept_hdr + 22, accept_key_len);
				}
			}
		}

		if(strstr(buf, "\r\n\r\n"))
		{
			// end of response i guess
			break;
		}
		len = wslay_ctr_recv_internal(ctx, (uint8_t*)buf, sizeof(buf), 0);
	}

	if(accept_found)
	{
		u8 accept_key[20];
		u8 calc_accept_key[20];
		base64_decode((u8*)accept_key_str, accept_key, accept_key_len);
			
		const char *websocket_uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		SHA1_CTX ctx;
		sha1_init(&ctx);
		sha1_update(&ctx, (u8*)client_key_str, strlen(client_key_str));
		sha1_update(&ctx, (u8*)websocket_uuid, 36);
		sha1_final(&ctx, calc_accept_key);

		if(memcmp(accept_key, calc_accept_key, 20) == 0)
		{
			return 0;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	wslay_ctr_make_nonblock(ctx->fd);
	return 0;
}

Result wslay_ctr_client_run(struct wslay_ctr_ctx *ctx)
{
	Result r;
	struct pollfd pfd;
	pfd.fd = ctx->fd;
	pfd.events = pfd.revents = 0;

	if(wslay_event_want_read(ctx->ctx))
	{
		pfd.events |= POLLIN;
	}

	if(wslay_event_want_write(ctx->ctx))
	{
	    pfd.events |= POLLOUT;
	}

	while(wslay_event_want_read(ctx->ctx) || wslay_event_want_write(ctx->ctx))
	{
		pfd.revents = 0;
		r = poll(&pfd, 1, 100);
		if(R_FAILED(r))
		{
			return r;
		}

		if((pfd.revents & POLLIN))
		{
			if(wslay_event_recv(ctx->ctx)) return -1;
		}

		if((pfd.revents & POLLOUT))
		{
			if(wslay_event_send(ctx->ctx)) return -1;
		}
		

		pfd.events = 0;
		if(wslay_event_want_read(ctx->ctx))
		{
			pfd.events |= POLLIN;
		}

		if(wslay_event_want_write(ctx->ctx))
		{
		    pfd.events |= POLLOUT;
		}
	}

	return 0;
}

int wslay_ctr_genmask(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data)
{
	sslcGenerateRandomData(buf, len);
	return 0;
}
