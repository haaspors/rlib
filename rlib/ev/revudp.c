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
/* Before rsocket-private.h / rev-private.h: orders <winsock2.h> first. */
#include "rev-iocp-private.h"
#include "rev-private.h"
#include "../net/rsocket-private.h"
#include "../net/rnet-private.h"
#include <rlib/ev/revudp.h>

#include <rlib/rmem.h>

#define R_LOG_CAT_DEFAULT &revlogcat

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

static void
r_ev_udp_send_ctx_free (rpointer data)
{
  REvUDPSendCtx * ctx = data;
  r_ev_udp_send_ctx_clear (ctx);
  r_free (ctx);
}


struct REvUDP {
  REvIO evio;

  RSocketFamily family;
  RSocket * socket;
  ruint taskgroup;

  REvUDPBufferAllocFunc alloc;
  REvUDPBufferFunc recv;
  rpointer recv_data;
  REvUDPErrorFunc error;
  rpointer error_data;
  RDestroyNotify error_datanotify;
  rpointer recv_iocb_ctx;
  rauint recv_counter;
  RTask * recv_task;

  RQueue qsend;

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  /* Completion (proactor) backend: overlapped WSARecvFrom per datagram (the
   * socket is associated with the port lazily, on recv_start). See revtcp.c for
   * the ref/lifetime model. */
  REvIOCPOp iocp_recv;
  RBuffer * iocp_recv_buf;     /* buffer backing the in-flight WSARecvFrom */
  RMemMapInfo iocp_recv_map;
  struct sockaddr_storage iocp_recv_addr;  /* sender address WSARecvFrom fills */
  INT iocp_recv_addrlen;
  DWORD iocp_recv_flags;
  rboolean iocp_recv_active;
  rboolean iocp_recv_task;
  RDestroyNotify recv_datanotify;

  REvIOCPOp iocp_send;
  RMemMapInfo iocp_send_map;
  rboolean iocp_send_active;
  rboolean iocp_associated;    /* bound to the completion port (on recv_start) */
#endif
};

static void
r_ev_udp_free (REvUDP * evudp)
{
  r_queue_clear (&evudp->qsend, r_ev_udp_send_ctx_free);
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  /* No op can be in flight (each holds a ref); release leftovers. */
  if (evudp->iocp_recv_buf != NULL)
    r_buffer_unref (evudp->iocp_recv_buf);
  if (evudp->recv_datanotify != NULL)
    evudp->recv_datanotify (evudp->recv_data);
#endif
  if (evudp->error_datanotify != NULL)
    evudp->error_datanotify (evudp->error_data);
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
      r_ev_io_init (&ret->evio, loop, (RIOHandle)socket->handle,
          (RDestroyNotify)r_ev_udp_free);
      ret->family = family;
      ret->socket = socket;
      r_queue_init (&ret->qsend);
      /* The socket is associated with the completion port lazily, on
       * recv_start: a send-only socket stays unassociated so it can send
       * synchronously (an overlapped send from a port-associated socket does
       * not deliver a loopback datagram to a peer on the same port). */
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

#define R_EV_UDP_BUFFER_SIZE        4096

static RBuffer *
r_ev_udp_buffer_alloc_default (rpointer data, REvUDP * evudp)
{
  (void) data;
  (void) evudp;

  return r_buffer_new_alloc (NULL, R_EV_UDP_BUFFER_SIZE, NULL);
}

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_udp_recv_iocb (REvUDP * evudp)
{
  RBuffer * buf;
  RSocketStatus res;
  RSocketAddress addr, * copy;
  rsize size;

  r_memclear (&addr, sizeof (RSocketAddress));
  r_atomic_uint_store (&evudp->recv_counter, 0);

  do {
    if ((buf = evudp->alloc (evudp->recv_data, evudp)) == NULL) {
      res = R_SOCKET_OOM;
      break;
    }

    addr.addrlen = sizeof (addr.addr);
    res = r_socket_receive_message (evudp->socket, &addr, buf, &size);
    switch (res) {
      case R_SOCKET_OK:
        copy = r_socket_address_copy (&addr);
        evudp->recv (evudp->recv_data, buf, copy, evudp);
        r_socket_address_unref (copy);
        break;
      case R_SOCKET_WOULD_BLOCK:
        break;
      default:
        R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" recv res %d",
            evudp->evio.loop, R_EV_IO_ARGS (evudp), res);
        break;
    }
    r_buffer_unref (buf);
  } while (res == R_SOCKET_OK);

  /* A datagram socket stays usable on error: stop draining until the
   * next event and report. */
  if (res != R_SOCKET_WOULD_BLOCK && evudp->error != NULL)
    evudp->error (evudp->error_data, evudp, res);
}
#endif

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
      if (ctx->done != NULL)
        ctx->done (ctx->data, ctx->buf, ctx->addr, evudp);
      r_ev_udp_send_ctx_clear (ctx);
      r_free (ctx);
    } else if (res == R_SOCKET_WOULD_BLOCK) {
      break;
    } else {
      /* This datagram cannot be sent: drop it, report, and keep
       * draining the rest -- the socket stays usable. */
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" send res %d",
          evudp->evio.loop, R_EV_IO_ARGS (evudp), res);
      r_queue_pop (&evudp->qsend);
      if (evudp->error != NULL)
        evudp->error (evudp->error_data, evudp, res);
      r_ev_udp_send_ctx_clear (ctx);
      r_free (ctx);
    }
  }
}

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_udp_error_iocb (REvUDP * evudp)
{
  RSocketStatus err = r_socket_get_error (evudp->socket);
  R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" err: %d",
      evudp->evio.loop, R_EV_IO_ARGS (evudp), err);
  /* Only notify on a still-set error (the recv / send path may already
   * have consumed and reported it in this same dispatch). */
  if (err != R_SOCKET_OK && evudp->error != NULL)
    evudp->error (evudp->error_data, evudp, err);
}
#endif

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_udp_recv_iocb_task (rpointer data, RTaskQueue * queue, RTask * task)
{
  (void) queue;
  (void) task;
  r_ev_udp_recv_iocb (data);
}
#endif

static void
r_ev_udp_send_iocb_ev (rpointer data, REvLoop * loop)
{
  (void) loop;
  r_ev_udp_send_iocb (data);
}

/* Readiness backends only; the completion backend drives recv/send via
 * overlapped completions, not this readiness dispatch. */
#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_udp_iocb (rpointer data, REvIOEvents events, REvIO * evio)
{
  (void) data;

  if (events & R_EV_IO_READABLE) r_ev_udp_recv_iocb ((REvUDP *)evio);
  if (events & R_EV_IO_WRITABLE) r_ev_udp_send_iocb ((REvUDP *)evio);
  if (events & R_EV_IO_ERROR) r_ev_udp_error_iocb ((REvUDP *)evio);
}
#endif

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_udp_task_recv_iocb (REvUDP * evudp)
{
  RTask * task;

  if (r_atomic_uint_fetch_add (&evudp->recv_counter, 1) > 0)
    return;

  if ((task = r_ev_loop_add_task_full (evudp->evio.loop,
          evudp->taskgroup, r_ev_udp_recv_iocb_task, NULL,
          r_ev_udp_ref (evudp), r_ev_udp_unref, evudp->recv_task, NULL)) != NULL) {
    if (evudp->recv_task != NULL)
      r_task_unref (evudp->recv_task);
    evudp->recv_task = task;
  } else {
    r_ev_udp_unref (evudp);
  }
}
#endif

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_udp_task_iocb (rpointer data, REvIOEvents events, REvIO * evio)
{
  (void) data;

  if (events & R_EV_IO_READABLE) r_ev_udp_task_recv_iocb ((REvUDP *)evio);
  if (events & R_EV_IO_WRITABLE) r_ev_udp_send_iocb ((REvUDP *)evio);
  if (events & R_EV_IO_ERROR) r_ev_udp_error_iocb ((REvUDP *)evio);
}
#endif

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
/* ---- IOCP (completion / proactor) UDP path -------------------------------
 * Overlapped WSARecvFrom per datagram (re-armed on completion) and WSASendTo
 * for the ordered send queue; the ref / lifetime model is the same as
 * revtcp.c. */
#define R_EV_UDP_IOCP_SOCKET(evudp)  R_IO_HANDLE_TO_SOCKET_HANDLE ((evudp)->socket->handle)

static rboolean r_ev_udp_iocp_post_recv (REvUDP * evudp);
static rboolean r_ev_udp_iocp_post_send (REvUDP * evudp);

static RSocketStatus
r_ev_udp_iocp_status (DWORD err)
{
  switch (err) {
    case 0:                       return R_SOCKET_OK;
    case ERROR_OPERATION_ABORTED: return R_SOCKET_CANCELED;
    case WSAECONNRESET:           return R_SOCKET_CONN_RESET;
    case WSAECONNREFUSED:         return R_SOCKET_CONN_REFUSED;
    case WSAEMSGSIZE:             return R_SOCKET_MSG_SIZE;
    default:                      return R_SOCKET_ERROR;
  }
}

static DWORD
r_ev_udp_iocp_result (REvUDP * evudp, REvIOCPOp * op, rsize * bytes)
{
  DWORD transferred = 0, flags = 0;

  if (WSAGetOverlappedResult (R_EV_UDP_IOCP_SOCKET (evudp), &op->overlapped,
        &transferred, FALSE, &flags)) {
    if (bytes != NULL)
      *bytes = (rsize) transferred;
    return 0;
  }
  if (bytes != NULL)
    *bytes = 0;
  return (DWORD) WSAGetLastError ();
}

/* Task-group delivery: hand the datagram to the task group; the buffer, sender
 * address and the evudp ref are released when the task context is freed. */
typedef struct {
  REvUDP * evudp;
  RBuffer * buf;
  RSocketAddress * addr;
} REvUDPRecvTaskCtx;

static void
r_ev_udp_iocp_recv_task (rpointer data, RTaskQueue * queue, RTask * task)
{
  REvUDPRecvTaskCtx * ctx = data;
  (void) queue;
  (void) task;
  ctx->evudp->recv (ctx->evudp->recv_data, ctx->buf, ctx->addr, ctx->evudp);
}

static void
r_ev_udp_iocp_recv_task_free (rpointer data)
{
  REvUDPRecvTaskCtx * ctx = data;
  r_socket_address_unref (ctx->addr);
  r_buffer_unref (ctx->buf);
  r_ev_udp_unref (ctx->evudp);
  r_free (ctx);
}

static void
r_ev_udp_iocp_recv_deliver (REvUDP * evudp, RBuffer * buf, RSocketAddress * addr)
{
  REvUDPRecvTaskCtx * ctx;
  RTask * task;

  if (!evudp->iocp_recv_task) {
    evudp->recv (evudp->recv_data, buf, addr, evudp);
    r_socket_address_unref (addr);
    r_buffer_unref (buf);
    return;
  }

  if ((ctx = r_mem_new (REvUDPRecvTaskCtx)) != NULL) {
    ctx->evudp = r_ev_udp_ref (evudp);
    ctx->buf = buf;     /* ownership transferred to the task */
    ctx->addr = addr;
    if ((task = r_ev_loop_add_task_full (evudp->evio.loop, evudp->taskgroup,
            r_ev_udp_iocp_recv_task, NULL, ctx, r_ev_udp_iocp_recv_task_free,
            evudp->recv_task, NULL)) != NULL) {
      if (evudp->recv_task != NULL)
        r_task_unref (evudp->recv_task);
      evudp->recv_task = task;
      return;
    }
    /* Queuing failed: undo without releasing buf/addr (delivered inline). */
    r_ev_udp_unref (ctx->evudp);
    r_free (ctx);
  }

  evudp->recv (evudp->recv_data, buf, addr, evudp);
  r_socket_address_unref (addr);
  r_buffer_unref (buf);
}

static void
r_ev_udp_iocp_recv_complete (REvIOCPOp * op, REvLoop * loop, rsize bytes)
{
  REvUDP * evudp = op->data;
  RBuffer * buf = evudp->iocp_recv_buf;
  rsize got = 0;
  DWORD err;
  (void) loop;
  (void) bytes;

  err = r_ev_udp_iocp_result (evudp, op, &got);
  r_buffer_unmap (buf, &evudp->iocp_recv_map);
  evudp->iocp_recv_buf = NULL;

  if (err == 0) {
    /* A zero-length datagram is valid: deliver an empty buffer, not EOS. */
    RSocketAddress * addr = r_socket_address_new_from_native (
        &evudp->iocp_recv_addr, (rsize) evudp->iocp_recv_addrlen);
    r_buffer_set_size (buf, got);
    r_ev_udp_iocp_recv_deliver (evudp, buf, addr);
    if (evudp->iocp_recv_active && !r_socket_is_closed (evudp->socket))
      r_ev_udp_iocp_post_recv (evudp);
  } else {
    r_buffer_unref (buf);
    if (err != ERROR_OPERATION_ABORTED) {
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" recv err %lu",
          evudp->evio.loop, R_EV_IO_ARGS (evudp), (unsigned long) err);
      if (evudp->error != NULL)
        evudp->error (evudp->error_data, evudp, r_ev_udp_iocp_status (err));
      /* The socket stays usable on a datagram error; keep receiving. */
      if (evudp->iocp_recv_active && !r_socket_is_closed (evudp->socket))
        r_ev_udp_iocp_post_recv (evudp);
    }
  }

  r_ev_udp_unref (evudp);
}

static rboolean
r_ev_udp_iocp_post_recv (REvUDP * evudp)
{
  RBuffer * buf;
  int res;

  if (!evudp->iocp_associated) {
    if (!r_ev_loop_iocp_associate (evudp->evio.loop, (RIOHandle) evudp->socket->handle))
      return FALSE;
    evudp->iocp_associated = TRUE;
  }

  if ((buf = evudp->alloc (evudp->recv_data, evudp)) == NULL)
    return FALSE;
  if (!r_buffer_map (buf, &evudp->iocp_recv_map, R_MEM_MAP_WRITE)) {
    r_buffer_unref (buf);
    return FALSE;
  }
  evudp->iocp_recv_buf = buf;
  evudp->iocp_recv_flags = 0;
  evudp->iocp_recv_addrlen = (INT) sizeof (evudp->iocp_recv_addr);

  r_ev_iocp_op_init (&evudp->iocp_recv, r_ev_udp_iocp_recv_complete, evudp);
  evudp->iocp_recv.wbuf.buf = (CHAR *) evudp->iocp_recv_map.data;
  evudp->iocp_recv.wbuf.len = r_ev_iocp_wsabuf_len (evudp->iocp_recv_map.size);
  r_ev_udp_ref (evudp);
  r_ev_loop_iocp_submit (evudp->evio.loop);
  res = WSARecvFrom (R_EV_UDP_IOCP_SOCKET (evudp), &evudp->iocp_recv.wbuf, 1, NULL,
      &evudp->iocp_recv_flags, (struct sockaddr *) &evudp->iocp_recv_addr,
      &evudp->iocp_recv_addrlen, &evudp->iocp_recv.overlapped, NULL);
  if (res == 0 || WSAGetLastError () == WSA_IO_PENDING)
    return TRUE;

  R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" WSARecvFrom failed %d",
      evudp->evio.loop, R_EV_IO_ARGS (evudp), WSAGetLastError ());
  r_ev_loop_iocp_unsubmit (evudp->evio.loop);
  r_buffer_unmap (buf, &evudp->iocp_recv_map);
  r_buffer_unref (buf);
  evudp->iocp_recv_buf = NULL;
  r_ev_udp_unref (evudp);
  return FALSE;
}

static void
r_ev_udp_iocp_send_complete (REvIOCPOp * op, REvLoop * loop, rsize bytes)
{
  REvUDP * evudp = op->data;
  REvUDPSendCtx * ctx = r_queue_peek (&evudp->qsend);
  DWORD err;
  (void) loop;
  (void) bytes;

  evudp->iocp_send_active = FALSE;
  err = r_ev_udp_iocp_result (evudp, op, NULL);
  if (ctx != NULL) {
    r_buffer_unmap (ctx->buf, &evudp->iocp_send_map);
    r_queue_pop (&evudp->qsend);
    if (err == 0) {
      if (ctx->done != NULL)
        ctx->done (ctx->data, ctx->buf, ctx->addr, evudp);
    } else if (err != ERROR_OPERATION_ABORTED) {
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" send err %lu",
          evudp->evio.loop, R_EV_IO_ARGS (evudp), (unsigned long) err);
      if (evudp->error != NULL)
        evudp->error (evudp->error_data, evudp, r_ev_udp_iocp_status (err));
    }
    r_ev_udp_send_ctx_clear (ctx);
    r_free (ctx);
    if (!r_socket_is_closed (evudp->socket))
      r_ev_udp_iocp_post_send (evudp);
  }

  r_ev_udp_unref (evudp);
}

static rboolean
r_ev_udp_iocp_post_send (REvUDP * evudp)
{
  REvUDPSendCtx * ctx;
  int res;
  DWORD err;

  /* Drive the send queue. A datagram that cannot be sent is dropped (after
   * reporting) rather than left to stall the queue -- datagrams are
   * independent, unlike a TCP stream. */
  while ((ctx = r_queue_peek (&evudp->qsend)) != NULL) {
    if (!r_buffer_map (ctx->buf, &evudp->iocp_send_map, R_MEM_MAP_READ)) {
      if (evudp->error != NULL)
        evudp->error (evudp->error_data, evudp, R_SOCKET_OOM);
      r_queue_pop (&evudp->qsend);
      r_ev_udp_send_ctx_clear (ctx);
      r_free (ctx);
      continue;
    }
    if (evudp->iocp_send_map.size > (rsize) 0xFFFFFFFFu) {
      r_buffer_unmap (ctx->buf, &evudp->iocp_send_map);
      if (evudp->error != NULL)
        evudp->error (evudp->error_data, evudp, R_SOCKET_MSG_SIZE);
      r_queue_pop (&evudp->qsend);
      r_ev_udp_send_ctx_clear (ctx);
      r_free (ctx);
      continue;
    }

    r_ev_iocp_op_init (&evudp->iocp_send, r_ev_udp_iocp_send_complete, evudp);
    evudp->iocp_send.wbuf.buf = (CHAR *) evudp->iocp_send_map.data;
    evudp->iocp_send.wbuf.len = (ULONG) evudp->iocp_send_map.size;
    evudp->iocp_send_active = TRUE;
    r_ev_udp_ref (evudp);
    r_ev_loop_iocp_submit (evudp->evio.loop);
    res = WSASendTo (R_EV_UDP_IOCP_SOCKET (evudp), &evudp->iocp_send.wbuf, 1, NULL, 0,
        (const struct sockaddr *) &ctx->addr->addr, (int) ctx->addr->addrlen,
        &evudp->iocp_send.overlapped, NULL);
    if (res == 0 || WSAGetLastError () == WSA_IO_PENDING)
      return TRUE;

    /* Synchronous failure: capture the error before logging (a log call can
     * clobber the thread last-error), report, drop, and keep draining. */
    err = (DWORD) WSAGetLastError ();
    R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" WSASendTo failed %lu",
        evudp->evio.loop, R_EV_IO_ARGS (evudp), (unsigned long) err);
    r_ev_loop_iocp_unsubmit (evudp->evio.loop);
    r_buffer_unmap (ctx->buf, &evudp->iocp_send_map);
    evudp->iocp_send_active = FALSE;
    if (evudp->error != NULL)
      evudp->error (evudp->error_data, evudp, r_ev_udp_iocp_status (err));
    r_queue_pop (&evudp->qsend);
    r_ev_udp_send_ctx_clear (ctx);
    r_free (ctx);
    r_ev_udp_unref (evudp);
  }

  return TRUE;
}

#endif /* R_OS_WIN32 && !R_EV_USE_RPOLL */

rboolean
r_ev_udp_recv_start (REvUDP * evudp,
    REvUDPBufferAllocFunc alloc, REvUDPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (recv == NULL)) return FALSE;
  if (R_UNLIKELY (evudp->recv_iocb_ctx != NULL)) return FALSE;

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  if (R_UNLIKELY (evudp->iocp_recv_active)) return FALSE;
  if (alloc == NULL)
    alloc = r_ev_udp_buffer_alloc_default;
  if (evudp->recv_datanotify != NULL)
    evudp->recv_datanotify (evudp->recv_data);
  evudp->alloc = alloc;
  evudp->recv = recv;
  evudp->recv_data = data;
  evudp->recv_datanotify = datanotify;
  evudp->iocp_recv_active = TRUE;
  if (R_UNLIKELY (!r_ev_udp_iocp_post_recv (evudp))) {
    evudp->iocp_recv_active = FALSE;
    evudp->recv = NULL;
    evudp->recv_datanotify = NULL;
    if (datanotify != NULL)
      datanotify (data);
    return FALSE;
  }
  return TRUE;
#else
  if ((evudp->recv_iocb_ctx = r_ev_io_start (&evudp->evio, R_EV_IO_READABLE,
      r_ev_udp_iocb, data, datanotify))) {
    if (alloc == NULL)
      alloc = r_ev_udp_buffer_alloc_default;

    evudp->alloc = alloc;
    evudp->recv = recv;
    evudp->recv_data = data;
    return TRUE;
  }

  return FALSE;
#endif
}

rboolean
r_ev_udp_task_recv_start (REvUDP * evudp, ruint taskgroup,
    REvUDPBufferAllocFunc alloc, REvUDPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (recv == NULL)) return FALSE;
  if (R_UNLIKELY (evudp->recv_iocb_ctx != NULL)) return FALSE;
  if (R_UNLIKELY (!r_ev_io_validate_taskgroup (&evudp->evio, taskgroup))) return FALSE;

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  if (R_UNLIKELY (evudp->iocp_recv_active)) return FALSE;
  if (alloc == NULL)
    alloc = r_ev_udp_buffer_alloc_default;
  if (evudp->recv_datanotify != NULL)
    evudp->recv_datanotify (evudp->recv_data);
  evudp->taskgroup = taskgroup;
  evudp->alloc = alloc;
  evudp->recv = recv;
  evudp->recv_data = data;
  evudp->recv_datanotify = datanotify;
  evudp->iocp_recv_active = TRUE;
  evudp->iocp_recv_task = TRUE;
  if (R_UNLIKELY (!r_ev_udp_iocp_post_recv (evudp))) {
    evudp->iocp_recv_active = FALSE;
    evudp->iocp_recv_task = FALSE;
    evudp->recv = NULL;
    evudp->recv_datanotify = NULL;
    if (datanotify != NULL)
      datanotify (data);
    return FALSE;
  }
  return TRUE;
#else
  if ((evudp->recv_iocb_ctx = r_ev_io_start (&evudp->evio, R_EV_IO_READABLE,
      r_ev_udp_task_iocb, data, datanotify))) {
    if (alloc == NULL)
      alloc = r_ev_udp_buffer_alloc_default;

    evudp->taskgroup = taskgroup;
    evudp->alloc = alloc;
    evudp->recv = recv;
    evudp->recv_data = data;
    r_atomic_uint_store (&evudp->recv_counter, 0);
    evudp->recv_task = NULL;
    return TRUE;
  }

  return FALSE;
#endif
}

rboolean
r_ev_udp_recv_stop (REvUDP * evudp)
{
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  /* Stop re-arming and cancel any in-flight WSARecvFrom; its completion
   * arrives with ERROR_OPERATION_ABORTED and drops the op ref. */
  evudp->iocp_recv_active = FALSE;
  if (evudp->iocp_recv_buf != NULL)
    CancelIoEx ((HANDLE) evudp->socket->handle, &evudp->iocp_recv.overlapped);
  if (evudp->recv_task != NULL) {
    r_task_wait (evudp->recv_task);
    r_task_unref (evudp->recv_task);
    evudp->recv_task = NULL;
  }
  return TRUE;
#else
  rboolean ret;

  ret = r_ev_io_stop (&evudp->evio, evudp->recv_iocb_ctx);
  evudp->recv_iocb_ctx = NULL;
  if (evudp->recv_task != NULL) {
    r_task_wait (evudp->recv_task);
    r_task_unref (evudp->recv_task);
  }

  return ret;
#endif
}

void
r_ev_udp_set_error_handler (REvUDP * evudp, REvUDPErrorFunc error,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (evudp == NULL)) return;

  if (evudp->error_datanotify != NULL)
    evudp->error_datanotify (evudp->error_data);
  evudp->error = error;
  evudp->error_data = data;
  evudp->error_datanotify = datanotify;
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
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
      /* An unassociated (send-only) socket sends synchronously -- it delivers a
       * loopback datagram like a plain socket. A receiving socket is associated
       * with the port, where a synchronous send is not usable, so it sends with
       * an overlapped op. */
      if (evudp->iocp_associated)
        ret = r_ev_udp_iocp_post_send (evudp);
      else
        ret = r_ev_loop_add_callback (evudp->evio.loop, TRUE,
            r_ev_udp_send_iocb_ev, r_ev_udp_ref (evudp), r_ev_udp_unref);
#else
      ret = r_ev_loop_add_callback (evudp->evio.loop, TRUE,
          r_ev_udp_send_iocb_ev, r_ev_udp_ref (evudp), r_ev_udp_unref);
#endif
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

