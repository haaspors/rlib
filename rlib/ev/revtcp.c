/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "../rsocket-private.h"
#include "../net/rnet-private.h"
#include <rlib/ev/revtcp.h>

#include <rlib/rmem.h>

#define R_LOG_CAT_DEFAULT &revlogcat

typedef struct {
  RBuffer * buf;
  REvTCPBufferFunc done;
  rpointer data;
  RDestroyNotify datanotify;
} REvTCPSendCtx;

#define r_ev_tcp_send_ctx_clear(send)                                         \
  R_STMT_START {                                                              \
    r_buffer_unref ((send)->buf);                                             \
    if ((send)->datanotify != NULL)                                           \
      (send)->datanotify ((send)->data);                                      \
  } R_STMT_END


struct _REvTCP {
  REvIO evio;

  RSocket * socket;
  ruint taskgroup;

  REvTCPConnectionReadyFunc connection;
  REvTCPConnectedFunc connected;

  REvTCPBufferAllocFunc alloc;
  REvTCPBufferFunc recv;
  rpointer recv_data;
  rpointer listen_iocb_ctx;
  rpointer connect_iocb_ctx;
  rpointer recv_iocb_ctx;
  rpointer send_iocb_ctx;
  rauint recv_counter;
  RTask * recv_task;

  RQueue qsend;
};

static void
r_ev_tcp_free (REvTCP * evtcp)
{
  r_queue_clear (&evtcp->qsend, r_buffer_unref);
  r_socket_unref (evtcp->socket);
  r_ev_io_clear (&evtcp->evio);
  r_free (evtcp);
}

static REvTCP *
r_ev_tcp_new_with_socket (RSocket * socket, REvLoop * loop)
{
  REvTCP * ret;

  if ((ret = r_mem_new0 (REvTCP)) != NULL) {
    r_ev_io_init (&ret->evio, loop, socket->handle,
        (RDestroyNotify)r_ev_tcp_free);
    ret->socket = socket;
    r_queue_init (&ret->qsend);
  }

  return ret;
}

REvTCP *
r_ev_tcp_new (RSocketFamily family, REvLoop * loop)
{
  REvTCP * ret;
  RSocket * socket;

  if ((socket = r_socket_new (family, R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)) != NULL) {
    if ((ret = r_ev_tcp_new_with_socket (socket, loop)) == NULL)
      r_socket_unref (socket);
  } else {
    ret = NULL;
  }

  return ret;
}

rboolean
r_ev_tcp_close (REvTCP * evtcp, REvIOFunc close_cb, rpointer data, RDestroyNotify datanotify)
{
  rboolean ret;

  R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT,
      evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
  r_ev_tcp_recv_stop (evtcp);

  if (evtcp->send_iocb_ctx != NULL) {
    r_ev_io_stop (&evtcp->evio, evtcp->send_iocb_ctx);
    evtcp->send_iocb_ctx = NULL;
  }
  if (evtcp->connect_iocb_ctx != NULL) {
    r_ev_io_stop (&evtcp->evio, evtcp->connect_iocb_ctx);
    evtcp->connect_iocb_ctx = NULL;
  }
  if (evtcp->listen_iocb_ctx != NULL) {
    r_ev_io_stop (&evtcp->evio, evtcp->listen_iocb_ctx);
    evtcp->listen_iocb_ctx = NULL;
  }

  if ((ret = r_ev_io_close ((REvIO *)evtcp, close_cb, data, datanotify))) {
    evtcp->socket->handle = R_SOCKET_HANDLE_INVALID;
  }

  return ret;
}

RSocketAddress *
r_ev_tcp_get_local_address (const REvTCP * evtcp)
{
  return evtcp != NULL ? r_socket_get_local_address (evtcp->socket) : NULL;
}

RSocketAddress *
r_ev_tcp_get_remote_address (const REvTCP * evtcp)
{
  return evtcp != NULL ? r_socket_get_remote_address (evtcp->socket) : NULL;
}

RSocketStatus
r_ev_tcp_bind (REvTCP * evtcp, const RSocketAddress * address, rboolean reuse)
{
  if (R_UNLIKELY (evtcp == NULL)) return R_SOCKET_INVAL;
  return r_socket_bind (evtcp->socket, address, reuse);
}

REvTCP *
r_ev_tcp_accept (REvTCP * evtcp, RSocketStatus * res)
{
  REvTCP * ret;
  RSocket * socket;

  if (R_UNLIKELY (evtcp == NULL)) {
    if (res != NULL)
      *res = R_SOCKET_INVAL;
    return NULL;
  }

  if ((socket = r_socket_accept (evtcp->socket, res)) != NULL) {
    if ((ret = r_ev_tcp_new_with_socket (socket, evtcp->evio.loop)) == NULL) {
      if (res != NULL)
        *res = R_SOCKET_OOM;
      r_socket_unref (socket);
    }
  } else {
    ret = NULL;
  }

  return ret;
}

static void
r_ev_tcp_connected_cb (rpointer data, REvIOEvents events, REvIO * evio)
{
  REvTCP * evtcp = (REvTCP *)evio;

  if (events & R_EV_IO_WRITABLE) {
    /* Make sure stop is called as part of after callbacks */
    r_ev_loop_add_cb_after (evio->loop, (RFunc)r_ev_io_stop,
        evio, NULL, evtcp->connect_iocb_ctx, NULL);
    evtcp->connect_iocb_ctx = NULL;

    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT, evio->loop, R_EV_IO_ARGS (evio));
    evtcp->connected (data, evtcp, r_socket_get_error (evtcp->socket));
  }
}

RSocketStatus
r_ev_tcp_connect (REvTCP * evtcp, const RSocketAddress * address,
    REvTCPConnectedFunc connected, rpointer data, RDestroyNotify datanotify)
{
  RSocketStatus ret;

  if (R_UNLIKELY (evtcp == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (connected == NULL)) return R_SOCKET_INVAL;

  if ((ret = r_socket_connect (evtcp->socket, address)) >= R_SOCKET_OK) {
    evtcp->connected = connected;
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT, evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
    if ((evtcp->connect_iocb_ctx = r_ev_io_start (&evtcp->evio, R_EV_IO_WRITABLE,
        r_ev_tcp_connected_cb, data, datanotify)) == NULL) {
      /* FIXME: What to do about this? */
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT,
          evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
      abort ();
    }
  }

  return ret;
}

static void
r_ev_tcp_listen_cb (rpointer data, REvIOEvents events, REvIO * evio)
{
  REvTCP * newtcp, * ltcp = (REvTCP *)evio;
  RSocketStatus res;

  (void) events;

  while ((newtcp = r_ev_tcp_accept (ltcp, &res)) != NULL) {
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT" accept "R_EV_IO_FORMAT,
        evio->loop, R_EV_IO_ARGS (evio), R_EV_IO_ARGS (newtcp));
    ltcp->connection (data, newtcp, ltcp);
    r_ev_tcp_unref (newtcp);
  }
}

RSocketStatus
r_ev_tcp_listen (REvTCP * evtcp, ruint8 backlog,
    REvTCPConnectionReadyFunc connection, rpointer data, RDestroyNotify datanotify)
{
  RSocketStatus ret;

  if (R_UNLIKELY (evtcp == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (connection == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (evtcp->recv_iocb_ctx != NULL)) return R_SOCKET_INVALID_OP;
  if (R_UNLIKELY (evtcp->send_iocb_ctx != NULL)) return R_SOCKET_INVALID_OP;
  if (R_UNLIKELY (evtcp->connect_iocb_ctx != NULL)) return R_SOCKET_INVALID_OP;
  if (R_UNLIKELY (evtcp->listen_iocb_ctx != NULL)) return R_SOCKET_INVALID_OP;

  if ((ret = r_socket_listen_full (evtcp->socket, backlog)) >= R_SOCKET_OK) {
    evtcp->connection = connection;
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT,
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
    if ((evtcp->listen_iocb_ctx = r_ev_io_start (&evtcp->evio, R_EV_IO_READABLE,
        r_ev_tcp_listen_cb, data, datanotify)) == NULL) {
      /* FIXME: What to do about this? */
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT,
          evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
      abort ();
    }
  }

  return ret;
}

#define R_EV_TCP_BUFFER_SIZE        4096

static RBuffer *
r_ev_tcp_buffer_alloc_default (rpointer data, REvTCP * evtcp)
{
  (void) data;
  (void) evtcp;

  return r_buffer_new_alloc (NULL, R_EV_TCP_BUFFER_SIZE, NULL);
}

static void
r_ev_tcp_recv_iocb (REvTCP * evtcp)
{
  RBuffer * buf;
  RSocketStatus res;
  rsize size;

  r_atomic_uint_store (&evtcp->recv_counter, 0);

  do {
    if ((buf = evtcp->alloc (evtcp->recv_data, evtcp)) == NULL) {
      res = R_SOCKET_OOM;
      break;
    }

    res = r_socket_receive_message (evtcp->socket, NULL, buf, &size);
    switch (res) {
      case R_SOCKET_OK:
        if (size > 0) {
          R_LOG_TRACE ("loop %p evio "R_EV_IO_FORMAT,
              evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
          evtcp->recv (evtcp->recv_data, buf, evtcp);
        } else {
          R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT" EOF",
              evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
          evtcp->recv (evtcp->recv_data, NULL, evtcp);
          r_ev_loop_add_cb_after (evtcp->evio.loop, (RFunc)r_ev_io_stop,
              evtcp, NULL, evtcp->recv_iocb_ctx, NULL);
          evtcp->recv_iocb_ctx = NULL;
          r_ev_tcp_recv_stop (evtcp);
          if (evtcp->recv_task != NULL) {
            r_task_unref (evtcp->recv_task);
            evtcp->recv_task = NULL;
          }
          return;
        }
        break;
      /* FIXME: Handle errors?? */
      default:
        break;
    }
    r_buffer_unref (buf);
  } while (res == R_SOCKET_OK);

  /* FIXME: What do we do when something fails and we are unable to drain socket? */
  if (res != R_SOCKET_WOULD_BLOCK) {
    R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" res %d",
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp), res);
    abort ();
  }
}

static void r_ev_tcp_iocb (rpointer data, REvIOEvents events, REvIO * evio);

static void
r_ev_tcp_send_iocb (REvTCP * evtcp)
{
  REvTCPSendCtx * ctx;
  RSocketStatus res;
  rsize sent;

  while ((ctx = r_queue_peek (&evtcp->qsend)) != NULL) {
    res = r_socket_send_message (evtcp->socket, NULL, ctx->buf, &sent);
    R_LOG_TRACE ("loop %p evio "R_EV_IO_FORMAT" res %d sent %"RSIZE_FMT,
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp), res, sent);
    if (res == R_SOCKET_OK) {
      r_queue_pop (&evtcp->qsend);
      if (ctx->done != NULL)
        ctx->done (ctx->data, ctx->buf, evtcp);
      r_ev_tcp_send_ctx_clear (ctx);
      r_free (ctx);
    } else if (res == R_SOCKET_WOULD_BLOCK) {
      if (evtcp->send_iocb_ctx == NULL)
        evtcp->send_iocb_ctx = r_ev_io_start (&evtcp->evio, R_EV_IO_WRITABLE,
          r_ev_tcp_iocb, NULL, NULL);
      break;
    } else {
      /* FIXME: What do we do when something fails and we are unable to drain send queue? */
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" res %d",
          evtcp->evio.loop, R_EV_IO_ARGS (evtcp), res);
      abort ();
    }
  }
}

static void
r_ev_tcp_error_iocb (REvTCP * evtcp)
{
  R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT,
      evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
  /* TODO */
  abort ();
}

static void
r_ev_tcp_iocb (rpointer data, REvIOEvents events, REvIO * evio)
{
  (void) data;

  if (events & R_EV_IO_READABLE) r_ev_tcp_recv_iocb ((REvTCP *)evio);
  if (events & R_EV_IO_WRITABLE) r_ev_tcp_send_iocb ((REvTCP *)evio);
  if (events & R_EV_IO_ERROR) r_ev_tcp_error_iocb ((REvTCP *)evio);
}

static void
r_ev_tcp_task_recv_iocb (REvTCP * evtcp)
{
  RTask * task;

  if (r_atomic_uint_fetch_add (&evtcp->recv_counter, 1) > 0)
    return;

  if ((task = r_ev_loop_add_task_full (evtcp->evio.loop,
          evtcp->taskgroup, (RTaskFunc) r_ev_tcp_recv_iocb, NULL,
          r_ev_tcp_ref (evtcp), r_ev_tcp_unref, evtcp->recv_task, NULL)) != NULL) {
    if (evtcp->recv_task != NULL)
      r_task_unref (evtcp->recv_task);
    evtcp->recv_task = task;
  } else {
    r_ev_tcp_unref (evtcp);
  }
}

static void
r_ev_tcp_task_iocb (rpointer data, REvIOEvents events, REvIO * evio)
{
  (void) data;

  if (events & R_EV_IO_READABLE) r_ev_tcp_task_recv_iocb ((REvTCP *)evio);
  if (events & R_EV_IO_WRITABLE) r_ev_tcp_send_iocb ((REvTCP *)evio);
  if (events & R_EV_IO_ERROR) r_ev_tcp_error_iocb ((REvTCP *)evio);
}

rboolean
r_ev_tcp_recv_start (REvTCP * evtcp,
    REvTCPBufferAllocFunc alloc, REvTCPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (recv == NULL)) return FALSE;
  if (R_UNLIKELY (evtcp->recv_iocb_ctx != NULL)) return FALSE;

  if ((evtcp->recv_iocb_ctx = r_ev_io_start (&evtcp->evio, R_EV_IO_READABLE,
      r_ev_tcp_iocb, data, datanotify))) {
    if (alloc == NULL)
      alloc = r_ev_tcp_buffer_alloc_default;

    evtcp->alloc = alloc;
    evtcp->recv = recv;
    evtcp->recv_data = data;
    return TRUE;
  }

  return FALSE;
}

rboolean
r_ev_tcp_task_recv_start (REvTCP * evtcp, ruint taskgroup,
    REvTCPBufferAllocFunc alloc, REvTCPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (recv == NULL)) return FALSE;
  if (R_UNLIKELY (evtcp->recv_iocb_ctx != NULL)) return FALSE;
  if (R_UNLIKELY (!r_ev_io_validate_taskgroup (&evtcp->evio, taskgroup))) return FALSE;

  if ((evtcp->recv_iocb_ctx = r_ev_io_start (&evtcp->evio, R_EV_IO_READABLE,
      r_ev_tcp_task_iocb, data, datanotify))) {
    if (alloc == NULL)
      alloc = r_ev_tcp_buffer_alloc_default;

    evtcp->taskgroup = taskgroup;
    evtcp->alloc = alloc;
    evtcp->recv = recv;
    evtcp->recv_data = data;
    r_atomic_uint_store (&evtcp->recv_counter, 0);
    evtcp->recv_task = NULL;
    return TRUE;
  }

  return FALSE;
}

rboolean
r_ev_tcp_recv_stop (REvTCP * evtcp)
{
  rboolean ret;

  ret = r_ev_io_stop (&evtcp->evio, evtcp->recv_iocb_ctx);
  evtcp->recv_iocb_ctx = NULL;
  if (evtcp->recv_task != NULL) {
    r_task_wait (evtcp->recv_task);
    r_task_unref (evtcp->recv_task);
    evtcp->recv_task = NULL;
  }

  return ret;
}

rboolean
r_ev_tcp_send (REvTCP * evtcp, RBuffer * buf,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify)
{
  REvTCPSendCtx * ctx;
  rboolean ret;

  if ((ret = (ctx = r_mem_new (REvTCPSendCtx)) != NULL)) {
    ctx->buf = r_buffer_ref (buf);
    ctx->done = done;
    ctx->data = data;
    ctx->datanotify = datanotify;
    r_queue_push (&evtcp->qsend, ctx);

    R_LOG_TRACE ("loop %p evio "R_EV_IO_FORMAT" buf %p",
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp), buf);
    if (r_queue_size (&evtcp->qsend) == 1) {
      ret = r_ev_loop_add_callback (evtcp->evio.loop, TRUE,
          (REvFunc)r_ev_tcp_send_iocb, r_ev_tcp_ref (evtcp), r_ev_tcp_unref);
    }
  }

  return ret;
}

rboolean
r_ev_tcp_send_take (REvTCP * evtcp, rpointer buffer, rsize size,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify)
{
  RBuffer * buf;
  rboolean ret;

  if ((buf = r_buffer_new_take (buffer, size)) != NULL) {
    ret = r_ev_tcp_send (evtcp, buf, done, data, datanotify);
    r_buffer_unref (buf);
  } else {
    ret = FALSE;
  }

  return ret;
}

rboolean
r_ev_tcp_send_dup (REvTCP * evtcp, rconstpointer buffer, rsize size,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify)
{
  RBuffer * buf;
  rboolean ret;

  if ((buf = r_buffer_new_dup (buffer, size)) != NULL) {
    ret = r_ev_tcp_send (evtcp, buf, done, data, datanotify);
    r_buffer_unref (buf);
  } else {
    ret = FALSE;
  }

  return ret;
}

