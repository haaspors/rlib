/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include "rev-private.h"
#include "../rnetworking-private.h"
#include <rlib/ev/revudp.h>

#include <rlib/rmem.h>
#include <rlib/rqueue.h>

typedef struct {
  REvUDPBufferAllocFunc alloc;
  REvUDPBufferFunc func;
  rpointer data;
  RDestroyNotify datanotify;
} REvUDPRecvCtx;

#define r_ev_udp_recv_ctx_clear(recv)                                         \
  R_STMT_START {                                                              \
    if ((recv)->datanotify != NULL)                                           \
      (recv)->datanotify ((recv)->data);                                      \
    r_memclear (recv, sizeof (REvUDPRecvCtx));                                \
  } R_STMT_END


typedef struct {
  RBuffer * buf;
  RSocketAddress * addr;
  REvUDPBufferFunc done;
  rpointer data;
  RDestroyNotify datanotify;
} REvUDPSendCtx;

#define r_ev_udp_send_ctx_clear(send)                                         \
  R_STMT_START {                                                              \
    r_socket_address_unref ((send)->addr);                                    \
    r_buffer_unref ((send)->buf);                                             \
    if ((send)->datanotify != NULL)                                           \
      (send)->datanotify ((send)->data);                                      \
  } R_STMT_END


struct _REvUDP {
  REvIO evio;

  RSocketFamily family;
  RSocket * socket;
  REvIOEvents events;

  REvUDPRecvCtx recv;
  RQueue qsend;
};

static void
r_ev_udp_free (REvUDP * evudp)
{
  r_queue_clear (&evudp->qsend, r_buffer_unref);
  r_socket_unref (evudp->socket);
  r_ev_io_clear (&evudp->evio);
  r_free (evudp);
}

REvUDP *
r_ev_udp_new (RSocketFamily family, REvLoop * loop)
{
  REvUDP * ret;
  RSocket * socket;

  if ((socket = r_socket_new (family, R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)) != NULL) {
    if ((ret = r_mem_new0 (REvUDP)) != NULL) {
      r_ev_io_init (&ret->evio, loop, socket->handle,
          (RDestroyNotify)r_ev_udp_free);
      ret->family = family;
      ret->socket = socket;
      r_queue_init (&ret->qsend);
    } else {
      r_socket_unref (socket);
    }
  } else {
    ret = NULL;
  }

  return ret;
}

rboolean
r_ev_udp_bind (REvUDP * evudp, const RSocketAddress * address, rboolean reuse)
{
  return evudp != NULL && evudp->family == r_socket_address_get_family (address) &&
    r_socket_bind (evudp->socket, address, reuse) == R_SOCKET_OK;
}

#define R_EV_UDP_BUFFER_SIZE        2048

static RBuffer *
r_ev_udp_buffer_alloc_default (rpointer data, REvUDP * evudp)
{
  (void) data;
  (void) evudp;

  return r_buffer_new_alloc (NULL, R_EV_UDP_BUFFER_SIZE, NULL);
}

static void
r_ev_udp_recv_iocb (REvUDP * evudp)
{
  RBuffer * buf;
  RSocketStatus res;
  RSocketAddress addr;
  rsize size;

  r_memclear (&addr, sizeof (RSocketAddress));

  do {
    if ((buf = evudp->recv.alloc (evudp->recv.data, evudp)) == NULL) {
      res = R_SOCKET_OOM;
      break;
    }

    addr.addrlen = sizeof (addr.addr);
    res = r_socket_receive_message (evudp->socket, &addr, buf, &size);
    switch (res) {
      case R_SOCKET_OK:
        evudp->recv.func (evudp->recv.data, buf, &addr, evudp);
        break;
      /* FIXME: Handle errors?? */
      default:
        break;
    }
    r_buffer_unref (buf);
  } while (res == R_SOCKET_OK);

  /* FIXME: What do we do when something fails and we are unable to drain socket? */
  if (res != R_SOCKET_WOULD_BLOCK)
    abort ();
}

static void
r_ev_udp_send_iocb (REvUDP * evudp)
{
  REvUDPSendCtx * ctx;
  RSocketStatus res;
  rsize sent;

  while ((ctx = r_queue_peek (&evudp->qsend)) != NULL) {
    res = r_socket_send_message (evudp->socket, ctx->addr, ctx->buf, &sent);
    if (res == R_SOCKET_OK) {
      r_queue_pop (&evudp->qsend);
      ctx->done (ctx->data, ctx->buf, ctx->addr, evudp);
      r_ev_udp_send_ctx_clear (ctx);
      r_free (ctx);
    } else if (res == R_SOCKET_WOULD_BLOCK) {
      break;
    } else {
      /* FIXME: What do we do when something fails and we are unable to drain send queue? */
      abort ();
    }
  }
}

static void
r_ev_udp_error_iocb (REvUDP * evudp)
{
  (void) evudp;
  /* TODO */
  abort ();
}

static void
r_ev_udp_iocb (rpointer data, REvIOEvents events, REvIO * evio)
{
  (void) data;

  if (events & R_EV_IO_READABLE) r_ev_udp_recv_iocb ((REvUDP *)evio);
  if (events & R_EV_IO_WRITABLE) r_ev_udp_send_iocb ((REvUDP *)evio);
  if (events & R_EV_IO_ERROR) r_ev_udp_error_iocb ((REvUDP *)evio);
}

static rboolean
r_ev_udp_start (REvUDP * evudp, REvIOEvent event)
{
  if (R_UNLIKELY (evudp->events & event)) return TRUE;

  evudp->events |= event;
  return r_ev_io_start (&evudp->evio, evudp->events, r_ev_udp_iocb, NULL, NULL);
}

static rboolean
r_ev_udp_stop (REvUDP * evudp, REvIOEvent event)
{
  if (R_UNLIKELY ((evudp->events & event) == 0)) return TRUE;

  if ((evudp->events &= ~event))
    return r_ev_io_start (&evudp->evio, evudp->events, r_ev_udp_iocb, NULL, NULL);
  else
    return r_ev_io_stop (&evudp->evio);
}

rboolean
r_ev_udp_recv_start (REvUDP * evudp,
    REvUDPBufferAllocFunc alloc, REvUDPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify)
{
  rboolean ret;

  if (R_UNLIKELY (recv == NULL)) return FALSE;
  if (R_UNLIKELY (evudp->recv.func != NULL)) return FALSE;

  if ((ret = r_ev_udp_start (evudp, R_EV_IO_READABLE))) {
    if (alloc == NULL)
      alloc = r_ev_udp_buffer_alloc_default;

    evudp->recv.func = recv;
    evudp->recv.alloc = alloc;
    evudp->recv.data = data;
  }

  return ret;
}

rboolean
r_ev_udp_recv_stop (REvUDP * evudp)
{
  rboolean ret;

  if ((ret = r_ev_udp_stop (evudp, R_EV_IO_READABLE)))
    r_ev_udp_recv_ctx_clear (&evudp->recv);

  return ret;
}

rboolean
r_ev_udp_send (REvUDP * evudp, RBuffer * buf,
    RSocketAddress * address, REvUDPBufferFunc done,
    rpointer data, RDestroyNotify datanotify)
{
  REvUDPSendCtx * ctx;
  rboolean ret;

  if ((ret = (ctx = r_mem_new (REvUDPSendCtx)) != NULL)) {
    ctx->buf = r_buffer_ref (buf);
    ctx->addr = r_socket_address_ref (address);
    ctx->done = done;
    ctx->data = data;
    ctx->datanotify = datanotify;
    r_queue_push (&evudp->qsend, ctx);

    if (r_queue_size (&evudp->qsend) == 1) {
      ret = r_ev_loop_add_callback (evudp->evio.loop, TRUE,
          (REvFunc)r_ev_udp_send_iocb, r_ev_udp_ref (evudp), r_ev_udp_unref);
    }
  }

  return ret;
}

rboolean
r_ev_udp_send_take (REvUDP * evudp, rpointer buffer, rsize size,
    RSocketAddress * address, REvUDPBufferFunc done,
    rpointer data, RDestroyNotify datanotify)
{
  RBuffer * buf;
  rboolean ret;

  if ((buf = r_buffer_new_take (buffer, size)) != NULL) {
    ret = r_ev_udp_send (evudp, buf, address, done, data, datanotify);
    r_buffer_unref (buf);
  } else {
    ret = FALSE;
  }

  return ret;
}

