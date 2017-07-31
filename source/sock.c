#include <3ds.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netdb.h>

#include <wslay/wslay.h>
#include <wslay/ctr.h>

int wslay_ctr_connect_internal(const char *hostname, uint16_t port)
{
	struct addrinfo hints;
	struct addrinfo *addr_list, *addr;

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd == -1)
	{
		return -1;
	}
	
	memset(&hints, 0, sizeof(struct addrinfo));
	char port_s[16];
	snprintf(port_s, 16, "%i", port);

	if(getaddrinfo(hostname, port_s, &hints, &addr_list) != 0)
	{
		closesocket(fd);
		return -1;
	}

	for(addr = addr_list; addr != NULL; addr = addr->ai_next)
	{
		if(connect(fd, addr->ai_addr, addr->ai_addrlen) == 0)
			break;
	}
	
	freeaddrinfo(addr_list);
	if(addr == NULL) // Failed to connect!
	{
		closesocket(fd);
		return -1;
	}

	return fd;
}

ssize_t wslay_ctr_recv_internal(struct wslay_ctr_ctx *udata, uint8_t *buf, size_t len, int flags)
{
	if(udata->secure)
	{
		ssize_t r = sslcRead(&udata->sslc, buf, len, (flags & MSG_PEEK) ? true : false);
		if(r == 0xD840B802) // Would block.
		{
			errno = EWOULDBLOCK;
			r = -1;
		}
		else if(r < 0)
		{
			r = -1;
		}

		return r;
	}
	else
	{
		return recv(udata->fd, buf, len, flags);
	}
}

ssize_t wslay_ctr_send_internal(struct wslay_ctr_ctx *udata, const uint8_t *buf, size_t len, int flags)
{
	if(udata->secure)
	{
		ssize_t r = sslcWrite(&udata->sslc, buf, len);
		if(r == 0xD840B803) // Would block.
		{
			errno = EWOULDBLOCK;
			r = -1;
		}
		else if(r < 0)
		{
			r = -1;
		}

		return r;
	}
	else
	{
		return send(udata->fd, buf, len, flags);
	}
}

ssize_t wslay_ctr_recv(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data)
{
	struct wslay_ctr_ctx *udata = user_data;
	
	ssize_t r = wslay_ctr_recv_internal(udata, buf, len, flags);
	if(r == -1)
	{
		if(errno == EAGAIN || errno == EWOULDBLOCK)
		{
			wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
		}
		else
		{
			wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
		}
	}
	else if(r == 0)
	{
		// unexepected eof
		wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    	r = -1;
	}
	return r;
}

ssize_t wslay_ctr_send(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data)
{
	struct wslay_ctr_ctx *udata = user_data;
	ssize_t r = wslay_ctr_send_internal(udata, data, len, flags);

	if(r == -1)
	{
		if(errno == EAGAIN || errno == EWOULDBLOCK)
		{
			wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
		}
		else
		{
			wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
		}
	}
	return r;
}

void wslay_ctr_make_nonblock(int fd)
{
	int curr = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, curr | O_NONBLOCK);
}