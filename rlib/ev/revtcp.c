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
/* Before rsocket-private.h / rev-private.h: orders <winsock2.h> first. */
#include "rev-iocp-private.h"
#include "rev-private.h"
#include "../net/rsocket-private.h"
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

static void
r_ev_tcp_send_ctx_free (rpointer data)
{
  REvTCPSendCtx * ctx = data;
  r_ev_tcp_send_ctx_clear (ctx);
  r_free (ctx);
}

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
/* One pre-posted AcceptEx slot: its overlapped op, the socket the incoming
 * connection is accepted into, and the address output buffer AcceptEx fills
 * (room for the local + remote address, each sockaddr_storage + 16 bytes as
 * AcceptEx requires). */
typedef struct {
  REvIOCPOp op;
  RSocket * sock;
  ruint8 addr[2 * (sizeof (struct sockaddr_storage) + 16)];
} REvTCPAccept;
#endif

struct REvTCP {
  REvIO evio;

  RSocket * socket;
  ruint taskgroup;

  REvTCPConnectionReadyFunc connection;
  REvTCPConnectedFunc connected;

  REvTCPBufferAllocFunc alloc;
  REvTCPBufferFunc recv;
  rpointer recv_data;
  REvTCPErrorFunc error;
  rpointer error_data;
  RDestroyNotify error_datanotify;
  rpointer listen_iocb_ctx;
  rpointer connect_iocb_ctx;
  rpointer recv_iocb_ctx;
  rpointer send_iocb_ctx;
  rauint recv_counter;
  RTask * recv_task;

  RQueue qsend;

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  /* Completion (proactor) backend: an op is posted, its completion delivers
   * the result. Each in-flight op holds one ref on this REvTCP. */
  REvIOCPOp iocp_recv;
  RBuffer * iocp_recv_buf;     /* buffer backing the in-flight WSARecv */
  RMemMapInfo iocp_recv_map;
  rboolean iocp_recv_active;   /* receiving (recv_start, not yet stopped) */
  rboolean iocp_recv_task;     /* deliver received buffers via a task group */

  REvIOCPOp iocp_send;
  RMemMapInfo iocp_send_map;
  rboolean iocp_send_active;   /* a WSASend is in flight for the queue head */

  REvIOCPOp iocp_connect;
  rpointer connect_data;       /* user data for the connected callback */
  RDestroyNotify connect_datanotify;
  RDestroyNotify recv_datanotify;

  rpointer accept_data;        /* user data for the connection callback */
  RDestroyNotify accept_datanotify;
  REvTCPAccept * iocp_accept;  /* array of pre-posted AcceptEx slots */
  ruint iocp_naccept;
#endif
};

static void
r_ev_tcp_free (REvTCP * evtcp)
{
  r_queue_clear (&evtcp->qsend, r_ev_tcp_send_ctx_free);
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  /* No ops can be in flight here: each holds a ref, so the last unref (which
   * brought us here) cannot run while one is outstanding. Release whatever
   * the completion paths did not get to free. */
  if (evtcp->iocp_recv_buf != NULL)
    r_buffer_unref (evtcp->iocp_recv_buf);
  if (evtcp->iocp_accept != NULL) {
    ruint i;
    for (i = 0; i < evtcp->iocp_naccept; i++) {
      if (evtcp->iocp_accept[i].sock != NULL)
        r_socket_unref (evtcp->iocp_accept[i].sock);
    }
    r_free (evtcp->iocp_accept);
  }
  /* The recv / connection user data outlived every op that referenced it
   * (each held a ref); release it now that the socket is gone. */
  if (evtcp->recv_datanotify != NULL)
    evtcp->recv_datanotify (evtcp->recv_data);
  if (evtcp->accept_datanotify != NULL)
    evtcp->accept_datanotify (evtcp->accept_data);
#endif
  if (evtcp->error_datanotify != NULL)
    evtcp->error_datanotify (evtcp->error_data);
  r_socket_unref (evtcp->socket);
  r_ev_io_clear (&evtcp->evio);
  r_free (evtcp);
}

static REvTCP *
r_ev_tcp_new_with_socket (RSocket * socket, REvLoop * loop)
{
  REvTCP * ret;

  if ((ret = r_mem_new0 (REvTCP)) != NULL) {
    r_ev_io_init (&ret->evio, loop, (RIOHandle)socket->handle,
        (RDestroyNotify)r_ev_tcp_free);
    ret->socket = socket;
    r_queue_init (&ret->qsend);
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
    /* Bind the socket to the loop's completion port so its overlapped ops
     * complete on this loop. */
    if (R_UNLIKELY (!r_ev_loop_iocp_associate (loop, (RIOHandle) socket->handle))) {
      r_ev_io_clear (&ret->evio);
      r_free (ret);
      ret = NULL;
    }
#endif
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

REvTCP *
r_ev_tcp_new_bind (const RSocketAddress * addr, REvLoop * loop)
{
  REvTCP * ret;

  if (R_UNLIKELY (addr == NULL)) return NULL;

  if ((ret = r_ev_tcp_new (r_socket_address_get_family (addr), loop)) != NULL)
    r_socket_bind (ret->socket, addr, TRUE);

  return ret;
}

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
/* ---- IOCP (completion / proactor) TCP path -------------------------------
 * Each posted overlapped op holds one ref on its REvTCP and one in-flight
 * count on the loop; its completion (success, EOS, error, or aborted close)
 * drops both. Re-arming ops (recv / accept) post afresh before dropping the
 * completing op's ref, so a continuously busy socket holds exactly one. */

#define R_EV_TCP_IOCP_SOCKET(evtcp)                                           \
  R_IO_HANDLE_TO_SOCKET_HANDLE ((evtcp)->socket->handle)
#define R_EV_TCP_IOCP_NACCEPT       4
#define R_EV_TCP_IOCP_ADDRLEN       ((DWORD) (sizeof (struct sockaddr_storage) + 16))

static LPFN_CONNECTEX r__ev_tcp_connectex = NULL;
static LPFN_ACCEPTEX  r__ev_tcp_acceptex  = NULL;

static rpointer
r_ev_tcp_iocp_load_ext (RSocket * socket, GUID guid)
{
  rpointer fn = NULL;
  DWORD bytes = 0;

  if (WSAIoctl (R_IO_HANDLE_TO_SOCKET_HANDLE (socket->handle),
        SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, (DWORD) sizeof (guid),
        &fn, (DWORD) sizeof (fn), &bytes, NULL, NULL) != 0)
    return NULL;
  return fn;
}

static LPFN_CONNECTEX
r_ev_tcp_iocp_connectex (RSocket * socket)
{
  if (r__ev_tcp_connectex == NULL) {
    GUID guid = WSAID_CONNECTEX;
    r__ev_tcp_connectex = (LPFN_CONNECTEX) r_ev_tcp_iocp_load_ext (socket, guid);
  }
  return r__ev_tcp_connectex;
}

static LPFN_ACCEPTEX
r_ev_tcp_iocp_acceptex (RSocket * socket)
{
  if (r__ev_tcp_acceptex == NULL) {
    GUID guid = WSAID_ACCEPTEX;
    r__ev_tcp_acceptex = (LPFN_ACCEPTEX) r_ev_tcp_iocp_load_ext (socket, guid);
  }
  return r__ev_tcp_acceptex;
}

static RSocketStatus
r_ev_tcp_iocp_status (DWORD err)
{
  switch (err) {
    case 0:                       return R_SOCKET_OK;
    case ERROR_OPERATION_ABORTED: return R_SOCKET_CANCELED;
    case WSAECONNRESET:           return R_SOCKET_CONN_RESET;
    case WSAECONNABORTED:         return R_SOCKET_CONN_ABORTED;
    case WSAECONNREFUSED:         return R_SOCKET_CONN_REFUSED;
    case WSAENOTCONN:             return R_SOCKET_NOT_CONNECTED;
    default:                      return R_SOCKET_ERROR;
  }
}

/* Authoritative result of a completed op: 0 on success (with @bytes set), else
 * the WSA error. */
static DWORD
r_ev_tcp_iocp_result (REvTCP * evtcp, REvIOCPOp * op, rsize * bytes)
{
  DWORD transferred = 0, flags = 0;

  if (WSAGetOverlappedResult (R_EV_TCP_IOCP_SOCKET (evtcp), &op->overlapped,
        &transferred, FALSE, &flags)) {
    if (bytes != NULL)
      *bytes = (rsize) transferred;
    return 0;
  }
  if (bytes != NULL)
    *bytes = 0;
  return (DWORD) WSAGetLastError ();
}

static rboolean r_ev_tcp_iocp_post_recv (REvTCP * evtcp);
static rboolean r_ev_tcp_iocp_post_send (REvTCP * evtcp);
static rboolean r_ev_tcp_iocp_post_accept (REvTCP * ltcp, REvTCPAccept * a);

static void
r_ev_tcp_iocp_recv_teardown (REvTCP * evtcp, RSocketStatus res)
{
  evtcp->iocp_recv_active = FALSE;
  if (res != R_SOCKET_OK && evtcp->error != NULL)
    evtcp->error (evtcp->error_data, evtcp, res);
  else
    evtcp->recv (evtcp->recv_data, NULL, evtcp);
}

/* Task-group delivery (r_ev_tcp_task_recv_start): the received buffer is
 * processed off the loop thread. The task carries a ref on the buffer and the
 * evtcp, both released (on the task thread) when the context is freed. No loop
 * 'done' callback is used, so the task is not an outstanding loop event -- the
 * re-armed WSARecv keeps the loop alive, and r_ev_tcp_recv_stop waits on the
 * last task. Each task chains on the previous, so they run in order. */
typedef struct {
  REvTCP * evtcp;
  RBuffer * buf;
} REvTCPRecvTaskCtx;

static void
r_ev_tcp_iocp_recv_task (rpointer data, RTaskQueue * queue, RTask * task)
{
  REvTCPRecvTaskCtx * ctx = data;
  (void) queue;
  (void) task;
  ctx->evtcp->recv (ctx->evtcp->recv_data, ctx->buf, ctx->evtcp);
}

static void
r_ev_tcp_iocp_recv_task_free (rpointer data)
{
  REvTCPRecvTaskCtx * ctx = data;
  r_buffer_unref (ctx->buf);
  r_ev_tcp_unref (ctx->evtcp);
  r_free (ctx);
}

static void
r_ev_tcp_iocp_recv_deliver (REvTCP * evtcp, RBuffer * buf)
{
  REvTCPRecvTaskCtx * ctx;
  RTask * task;

  if (!evtcp->iocp_recv_task) {
    evtcp->recv (evtcp->recv_data, buf, evtcp);
    r_buffer_unref (buf);
    return;
  }

  /* Populate the context before queuing: the task may start on another thread
   * the instant it is added. */
  if ((ctx = r_mem_new (REvTCPRecvTaskCtx)) != NULL) {
    ctx->evtcp = r_ev_tcp_ref (evtcp);
    ctx->buf = buf;   /* ownership transferred to the task */
    if ((task = r_ev_loop_add_task_full (evtcp->evio.loop, evtcp->taskgroup,
            r_ev_tcp_iocp_recv_task, NULL, ctx, r_ev_tcp_iocp_recv_task_free,
            evtcp->recv_task, NULL)) != NULL) {
      if (evtcp->recv_task != NULL)
        r_task_unref (evtcp->recv_task);
      evtcp->recv_task = task;
      return;
    }
    /* Queuing failed: undo without releasing buf (delivered inline below). */
    r_ev_tcp_unref (ctx->evtcp);
    r_free (ctx);
  }

  /* Could not offload: process inline rather than drop the data. */
  evtcp->recv (evtcp->recv_data, buf, evtcp);
  r_buffer_unref (buf);
}

static void
r_ev_tcp_iocp_recv_complete (REvIOCPOp * op, REvLoop * loop, rsize bytes)
{
  REvTCP * evtcp = op->data;
  RBuffer * buf = evtcp->iocp_recv_buf;
  rsize got = 0;
  DWORD err;
  (void) loop;
  (void) bytes;

  err = r_ev_tcp_iocp_result (evtcp, op, &got);
  r_buffer_unmap (buf, &evtcp->iocp_recv_map);
  evtcp->iocp_recv_buf = NULL;

  if (err != 0) {
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT" recv err %lu",
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp), (unsigned long) err);
    r_buffer_unref (buf);
    if (err != ERROR_OPERATION_ABORTED)
      r_ev_tcp_iocp_recv_teardown (evtcp, r_ev_tcp_iocp_status (err));
  } else if (got == 0) {
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT" EOS",
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
    r_buffer_unref (buf);
    r_ev_tcp_iocp_recv_teardown (evtcp, R_SOCKET_OK);
  } else {
    r_buffer_set_size (buf, got);
    r_ev_tcp_iocp_recv_deliver (evtcp, buf);
    if (evtcp->iocp_recv_active && !r_socket_is_closed (evtcp->socket))
      r_ev_tcp_iocp_post_recv (evtcp);
  }

  r_ev_tcp_unref (evtcp);
}

static rboolean
r_ev_tcp_iocp_post_recv (REvTCP * evtcp)
{
  RBuffer * buf;
  DWORD flags = 0;
  int res;

  if ((buf = evtcp->alloc (evtcp->recv_data, evtcp)) == NULL)
    return FALSE;
  if (!r_buffer_map (buf, &evtcp->iocp_recv_map, R_MEM_MAP_WRITE)) {
    r_buffer_unref (buf);
    return FALSE;
  }
  evtcp->iocp_recv_buf = buf;

  r_ev_iocp_op_init (&evtcp->iocp_recv, r_ev_tcp_iocp_recv_complete, evtcp);
  evtcp->iocp_recv.wbuf.buf = (CHAR *) evtcp->iocp_recv_map.data;
  evtcp->iocp_recv.wbuf.len = r_ev_iocp_wsabuf_len (evtcp->iocp_recv_map.size);
  r_ev_tcp_ref (evtcp);
  r_ev_loop_iocp_submit (evtcp->evio.loop);
  res = WSARecv (R_EV_TCP_IOCP_SOCKET (evtcp), &evtcp->iocp_recv.wbuf, 1, NULL, &flags,
      &evtcp->iocp_recv.overlapped, NULL);
  if (res == 0 || WSAGetLastError () == WSA_IO_PENDING)
    return TRUE;

  R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" WSARecv failed %d",
      evtcp->evio.loop, R_EV_IO_ARGS (evtcp), WSAGetLastError ());
  r_ev_loop_iocp_unsubmit (evtcp->evio.loop);
  r_buffer_unmap (buf, &evtcp->iocp_recv_map);
  r_buffer_unref (buf);
  evtcp->iocp_recv_buf = NULL;
  r_ev_tcp_unref (evtcp);
  return FALSE;
}

static void
r_ev_tcp_iocp_send_complete (REvIOCPOp * op, REvLoop * loop, rsize bytes)
{
  REvTCP * evtcp = op->data;
  REvTCPSendCtx * ctx = r_queue_peek (&evtcp->qsend);
  DWORD err;
  (void) loop;
  (void) bytes;

  evtcp->iocp_send_active = FALSE;
  err = r_ev_tcp_iocp_result (evtcp, op, NULL);
  if (ctx != NULL)
    r_buffer_unmap (ctx->buf, &evtcp->iocp_send_map);

  if (err == 0 && ctx != NULL) {
    r_queue_pop (&evtcp->qsend);
    if (ctx->done != NULL)
      ctx->done (ctx->data, ctx->buf, evtcp);
    r_ev_tcp_send_ctx_clear (ctx);
    r_free (ctx);
    /* Re-arm the next queued send; if it cannot be posted (e.g. the buffer
     * cannot be mapped), report rather than silently stalling the queue. */
    if (!r_socket_is_closed (evtcp->socket) &&
        !r_ev_tcp_iocp_post_send (evtcp) && evtcp->error != NULL)
      evtcp->error (evtcp->error_data, evtcp, R_SOCKET_ERROR);
  } else if (err != 0 && err != ERROR_OPERATION_ABORTED) {
    R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" send err %lu",
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp), (unsigned long) err);
    if (evtcp->error != NULL)
      evtcp->error (evtcp->error_data, evtcp, r_ev_tcp_iocp_status (err));
  }

  r_ev_tcp_unref (evtcp);
}

static rboolean
r_ev_tcp_iocp_post_send (REvTCP * evtcp)
{
  REvTCPSendCtx * ctx;
  int res;

  if ((ctx = r_queue_peek (&evtcp->qsend)) == NULL)
    return TRUE;
  if (!r_buffer_map (ctx->buf, &evtcp->iocp_send_map, R_MEM_MAP_READ))
    return FALSE;
  if (evtcp->iocp_send_map.size > (rsize) 0xFFFFFFFFu) {
    /* Too large for a single WSABUF; the stream send queue does not chunk. */
    r_buffer_unmap (ctx->buf, &evtcp->iocp_send_map);
    return FALSE;
  }

  r_ev_iocp_op_init (&evtcp->iocp_send, r_ev_tcp_iocp_send_complete, evtcp);
  evtcp->iocp_send.wbuf.buf = (CHAR *) evtcp->iocp_send_map.data;
  evtcp->iocp_send.wbuf.len = (ULONG) evtcp->iocp_send_map.size;
  evtcp->iocp_send_active = TRUE;
  r_ev_tcp_ref (evtcp);
  r_ev_loop_iocp_submit (evtcp->evio.loop);
  res = WSASend (R_EV_TCP_IOCP_SOCKET (evtcp), &evtcp->iocp_send.wbuf, 1, NULL, 0,
      &evtcp->iocp_send.overlapped, NULL);
  if (res == 0 || WSAGetLastError () == WSA_IO_PENDING)
    return TRUE;

  R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" WSASend failed %d",
      evtcp->evio.loop, R_EV_IO_ARGS (evtcp), WSAGetLastError ());
  r_ev_loop_iocp_unsubmit (evtcp->evio.loop);
  r_buffer_unmap (ctx->buf, &evtcp->iocp_send_map);
  evtcp->iocp_send_active = FALSE;
  r_ev_tcp_unref (evtcp);
  return FALSE;
}

static void
r_ev_tcp_iocp_accept_complete (REvIOCPOp * op, REvLoop * loop, rsize bytes)
{
  REvTCP * ltcp = op->data;
  REvTCPAccept * a = CONTAINING_RECORD (op, REvTCPAccept, op);
  RSocket * s = a->sock;
  DWORD err;
  (void) loop;
  (void) bytes;

  a->sock = NULL;
  err = r_ev_tcp_iocp_result (ltcp, op, NULL);

  if (err == 0) {
    REvTCP * newtcp;
    SOCKET ls = R_EV_TCP_IOCP_SOCKET (ltcp);

    /* Inherit the listening socket's properties on the accepted socket. */
    setsockopt (R_IO_HANDLE_TO_SOCKET_HANDLE (s->handle), SOL_SOCKET,
        SO_UPDATE_ACCEPT_CONTEXT, (const char *) &ls, (int) sizeof (ls));

    if ((newtcp = r_ev_tcp_new_with_socket (s, ltcp->evio.loop)) != NULL) {
      R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT" accept "R_EV_IO_FORMAT,
          ltcp->evio.loop, R_EV_IO_ARGS (ltcp), R_EV_IO_ARGS (newtcp));
      ltcp->connection (ltcp->accept_data, newtcp, ltcp);
      r_ev_tcp_unref (newtcp);
    } else {
      r_socket_unref (s);
    }
    if (!r_socket_is_closed (ltcp->socket))
      r_ev_tcp_iocp_post_accept (ltcp, a);
  } else {
    r_socket_unref (s);
    if (err != ERROR_OPERATION_ABORTED && !r_socket_is_closed (ltcp->socket))
      r_ev_tcp_iocp_post_accept (ltcp, a);
  }

  r_ev_tcp_unref (ltcp);
}

static rboolean
r_ev_tcp_iocp_post_accept (REvTCP * ltcp, REvTCPAccept * a)
{
  RSocket * s;
  DWORD recvd = 0;

  if ((s = r_socket_new (r_socket_get_family (ltcp->socket),
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)) == NULL)
    return FALSE;
  a->sock = s;

  r_ev_iocp_op_init (&a->op, r_ev_tcp_iocp_accept_complete, ltcp);
  r_ev_tcp_ref (ltcp);
  r_ev_loop_iocp_submit (ltcp->evio.loop);
  if (r__ev_tcp_acceptex (R_EV_TCP_IOCP_SOCKET (ltcp),
        R_IO_HANDLE_TO_SOCKET_HANDLE (s->handle), a->addr, 0,
        R_EV_TCP_IOCP_ADDRLEN, R_EV_TCP_IOCP_ADDRLEN, &recvd, &a->op.overlapped)
      || WSAGetLastError () == WSA_IO_PENDING)
    return TRUE;

  R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" AcceptEx failed %d",
      ltcp->evio.loop, R_EV_IO_ARGS (ltcp), WSAGetLastError ());
  r_ev_loop_iocp_unsubmit (ltcp->evio.loop);
  r_socket_unref (s);
  a->sock = NULL;
  r_ev_tcp_unref (ltcp);
  return FALSE;
}

/* ConnectEx requires a bound socket; bind to the wildcard address (best
 * effort: an already-bound socket simply keeps its binding). */
static void
r_ev_tcp_iocp_bind_any (REvTCP * evtcp)
{
  RSocketAddress * any;

  if (r_socket_get_family (evtcp->socket) == R_SOCKET_FAMILY_IPV6) {
    ruint8 zero[16] = { 0 };
    any = r_socket_address_ipv6_new_from_bytes (zero, 0);
  } else {
    any = r_socket_address_ipv4_new_uint32 (0, 0);
  }
  if (any != NULL) {
    r_socket_bind (evtcp->socket, any, FALSE);
    r_socket_address_unref (any);
  }
}

static void
r_ev_tcp_iocp_connect_complete (REvIOCPOp * op, REvLoop * loop, rsize bytes)
{
  REvTCP * evtcp = op->data;
  DWORD err;
  (void) loop;
  (void) bytes;

  err = r_ev_tcp_iocp_result (evtcp, op, NULL);
  if (err == 0) {
    setsockopt (R_EV_TCP_IOCP_SOCKET (evtcp), SOL_SOCKET,
        SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
  }
  R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT" connect err %lu",
      evtcp->evio.loop, R_EV_IO_ARGS (evtcp), (unsigned long) err);
  evtcp->connected (evtcp->connect_data, evtcp,
      err == 0 ? R_SOCKET_OK : r_ev_tcp_iocp_status (err));

  if (evtcp->connect_datanotify != NULL) {
    evtcp->connect_datanotify (evtcp->connect_data);
    evtcp->connect_datanotify = NULL;
  }
  r_ev_tcp_unref (evtcp);
}
#endif /* R_OS_WIN32 && !R_EV_USE_RPOLL */

rboolean
r_ev_tcp_close (REvTCP * evtcp, REvIOFunc close_cb, rpointer data, RDestroyNotify datanotify)
{
  R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT,
      evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  /* Cancel every in-flight overlapped op on the socket; each completes with
   * ERROR_OPERATION_ABORTED, drops its ref, and the socket is finally closed
   * when the last ref is released in r_ev_tcp_free -> r_socket_unref. */
  evtcp->iocp_recv_active = FALSE;
  CancelIoEx ((HANDLE) evtcp->socket->handle, NULL);
  /* Task delivery: drain the last dispatched buffer's task, as recv_stop does
   * -- otherwise closing during task-mode recv leaks the recv_task ref. */
  if (evtcp->recv_task != NULL) {
    r_task_wait (evtcp->recv_task);
    r_task_unref (evtcp->recv_task);
    evtcp->recv_task = NULL;
  }
  evtcp->evio.flags |= R_EV_IO_CLOSED;
  return r_ev_io_close ((REvIO *)evtcp, close_cb, data, datanotify);
#else
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

  /* Mark as closed, but close is actually happening in r_socket_free -> FIXME? */
  evtcp->evio.flags |= R_EV_IO_CLOSED;
  return r_ev_io_close ((REvIO *)evtcp, close_cb, data, datanotify);
#endif
}

RSocket *
r_ev_tcp_get_socket (const REvTCP * evtcp)
{
  return evtcp != NULL ? evtcp->socket : NULL;
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

static void r_ev_tcp_io_stop_after (rpointer data, rpointer ctx);

/* Readiness (reactor) backends only; the completion backend connects via
 * ConnectEx and never installs this watcher. */
#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_tcp_connected_cb (rpointer data, REvIOEvents events, REvIO * evio)
{
  REvTCP * evtcp = (REvTCP *)evio;

  if (events & (R_EV_IO_WRITABLE | R_EV_IO_ERROR)) {
    /* Make sure stop is called as part of after callbacks */
    r_ev_loop_add_cb_after (evio->loop, r_ev_tcp_io_stop_after,
        evio, NULL, evtcp->connect_iocb_ctx, NULL);
    evtcp->connect_iocb_ctx = NULL;

    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT, evio->loop, R_EV_IO_ARGS (evio));
    evtcp->connected (data, evtcp, r_socket_get_error (evtcp->socket));
  }
}
#endif

RSocketStatus
r_ev_tcp_connect (REvTCP * evtcp, const RSocketAddress * address,
    REvTCPConnectedFunc connected, rpointer data, RDestroyNotify datanotify)
{
  RSocketStatus ret;

  if (R_UNLIKELY (evtcp == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (connected == NULL)) return R_SOCKET_INVAL;

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  {
    LPFN_CONNECTEX connectex;

    if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;
    if ((connectex = r_ev_tcp_iocp_connectex (evtcp->socket)) == NULL)
      return R_SOCKET_NOT_SUPPORTED;

    r_ev_tcp_iocp_bind_any (evtcp);

    evtcp->connected = connected;
    evtcp->connect_data = data;
    evtcp->connect_datanotify = datanotify;
    r_ev_iocp_op_init (&evtcp->iocp_connect, r_ev_tcp_iocp_connect_complete, evtcp);
    r_ev_tcp_ref (evtcp);
    r_ev_loop_iocp_submit (evtcp->evio.loop);
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT, evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
    if (connectex (R_EV_TCP_IOCP_SOCKET (evtcp),
          (const struct sockaddr *) &address->addr, address->addrlen,
          NULL, 0, NULL, &evtcp->iocp_connect.overlapped) ||
        WSAGetLastError () == WSA_IO_PENDING)
      /* Connection is in progress; completes asynchronously via @connected,
       * matching the readiness backend's non-blocking connect contract. */
      return R_SOCKET_WOULD_BLOCK;

    /* Capture the error before logging: a log call can clobber the thread
     * last-error, and the status below must reflect ConnectEx, not the log. */
    {
      DWORD err = (DWORD) WSAGetLastError ();
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" ConnectEx failed %lu",
          evtcp->evio.loop, R_EV_IO_ARGS (evtcp), (unsigned long) err);
      ret = r_ev_tcp_iocp_status (err);
    }
    r_ev_loop_iocp_unsubmit (evtcp->evio.loop);
    evtcp->connected = NULL;
    evtcp->connect_datanotify = NULL;
    if (datanotify != NULL)
      datanotify (data);
    r_ev_tcp_unref (evtcp);
    return ret;
  }
#else
  if ((ret = r_socket_connect (evtcp->socket, address)) >= R_SOCKET_OK) {
    evtcp->connected = connected;
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT, evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
    if ((evtcp->connect_iocb_ctx = r_ev_io_start (&evtcp->evio, R_EV_IO_WRITABLE,
        r_ev_tcp_connected_cb, data, datanotify)) == NULL) {
      /* Could not watch the connecting socket; report failure to the
       * caller (connected will not fire) rather than crash. */
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT,
          evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
      if (datanotify != NULL)
        datanotify (data);
      evtcp->connected = NULL;
      ret = R_SOCKET_OOM;
    }
  }

  return ret;
#endif
}

/* Readiness backends only; the completion backend accepts via AcceptEx. */
#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
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
#endif

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

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  if (R_UNLIKELY (evtcp->iocp_accept != NULL)) return R_SOCKET_INVALID_OP;
  if (r_ev_tcp_iocp_acceptex (evtcp->socket) == NULL) return R_SOCKET_NOT_SUPPORTED;

  if ((ret = r_socket_listen_full (evtcp->socket, backlog)) >= R_SOCKET_OK) {
    ruint i;

    evtcp->connection = connection;
    evtcp->accept_data = data;
    evtcp->accept_datanotify = datanotify;
    evtcp->iocp_accept = r_mem_new0_n (REvTCPAccept, R_EV_TCP_IOCP_NACCEPT);
    evtcp->iocp_naccept = R_EV_TCP_IOCP_NACCEPT;
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT,
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
    for (i = 0; i < evtcp->iocp_naccept; i++)
      r_ev_tcp_iocp_post_accept (evtcp, &evtcp->iocp_accept[i]);
  }

  return ret;
#else
  if ((ret = r_socket_listen_full (evtcp->socket, backlog)) >= R_SOCKET_OK) {
    evtcp->connection = connection;
    R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT,
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
    if ((evtcp->listen_iocb_ctx = r_ev_io_start (&evtcp->evio, R_EV_IO_READABLE,
        r_ev_tcp_listen_cb, data, datanotify)) == NULL) {
      /* Could not watch the listening socket; report failure to the
       * caller rather than crash. */
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT,
          evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
      if (datanotify != NULL)
        datanotify (data);
      evtcp->connection = NULL;
      ret = R_SOCKET_OOM;
    }
  }

  return ret;
#endif
}

#define R_EV_TCP_BUFFER_SIZE        4096

static RBuffer *
r_ev_tcp_buffer_alloc_default (rpointer data, REvTCP * evtcp)
{
  (void) data;
  (void) evtcp;

  return r_buffer_new_alloc (NULL, R_EV_TCP_BUFFER_SIZE, NULL);
}

/* Stop receiving and notify the application that the stream is done.
 * @res is R_SOCKET_OK for a clean close (end-of-stream) and a failing
 * status for a socket error. With an error handler installed an error
 * is reported through it; otherwise (and always on a clean close) the
 * recv callback is invoked with a NULL buffer. The notified callback
 * may close and even unref evtcp; the ref taken for the deferred stop
 * keeps it alive across the call. */
static void
r_ev_tcp_recv_teardown (REvTCP * evtcp, RSocketStatus res)
{
  r_ev_loop_add_cb_after (evtcp->evio.loop, r_ev_tcp_io_stop_after,
      r_ev_tcp_ref (evtcp), r_ev_tcp_unref, evtcp->recv_iocb_ctx, NULL);
  evtcp->recv_iocb_ctx = NULL;
  if (evtcp->recv_task != NULL) {
    r_task_unref (evtcp->recv_task);
    evtcp->recv_task = NULL;
  }

  if (res != R_SOCKET_OK && evtcp->error != NULL)
    evtcp->error (evtcp->error_data, evtcp, res);
  else
    evtcp->recv (evtcp->recv_data, NULL, evtcp);
}

static void
r_ev_tcp_recv_iocb (REvTCP * evtcp)
{
  RBuffer * buf;
  RSocketStatus res = R_SOCKET_WOULD_BLOCK;
  rsize size;

  r_atomic_uint_store (&evtcp->recv_counter, 0);

  do {
    if (R_UNLIKELY (r_socket_is_closed (evtcp->socket)))
      break;
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
          R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT" EOS",
              evtcp->evio.loop, R_EV_IO_ARGS (evtcp));
          r_buffer_unref (buf);
          r_ev_tcp_recv_teardown (evtcp, R_SOCKET_OK);
          return;
        }
        break;
      case R_SOCKET_WOULD_BLOCK:
        break;
      default:
        R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" res %d",
            evtcp->evio.loop, R_EV_IO_ARGS (evtcp), res);
        break;
    }
    r_buffer_unref (buf);
  } while (res == R_SOCKET_OK);

  /* A socket error (anything but a would-block drain) tears the stream
   * down and reports, instead of silently stalling. */
  if (res != R_SOCKET_WOULD_BLOCK)
    r_ev_tcp_recv_teardown (evtcp, res);
}

static void r_ev_tcp_iocb (rpointer data, REvIOEvents events, REvIO * evio);

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void r_ev_tcp_send_iocb_ev (rpointer data, REvLoop * loop);
#endif

static void
r_ev_tcp_io_stop_after (rpointer data, rpointer ctx)
{
  r_ev_io_stop (data, ctx);
}

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
    if (evtcp->evio.flags & R_EV_IO_CLOSED)   /* DIAG #310 */
      R_LOG_WARNING ("DIAG310: send_iocb on CLOSED "R_EV_IO_FORMAT
          " res=%d sent=%"RSIZE_FMT" qsize=%"RSIZE_FMT, R_EV_IO_ARGS (evtcp),
          res, sent, (rsize) r_queue_size (&evtcp->qsend));
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
      /* The connection is broken: stop the writable watcher so it does
       * not spin, report the error, and leave the unsendable queue to be
       * released when the socket is closed / freed. */
      R_LOG_ERROR ("loop %p evio "R_EV_IO_FORMAT" res %d",
          evtcp->evio.loop, R_EV_IO_ARGS (evtcp), res);
      if (evtcp->send_iocb_ctx != NULL) {
        r_ev_loop_add_cb_after (evtcp->evio.loop, r_ev_tcp_io_stop_after,
            r_ev_tcp_ref (evtcp), r_ev_tcp_unref, evtcp->send_iocb_ctx, NULL);
        evtcp->send_iocb_ctx = NULL;
      }
      if (evtcp->error != NULL)
        evtcp->error (evtcp->error_data, evtcp, res);
      break;
    }
  }
}

static void
r_ev_tcp_error_iocb (REvTCP * evtcp)
{
  RSocketStatus err = r_socket_get_error (evtcp->socket);
  /* A poll-level error can carry no socket SO_ERROR: the handle went invalid at
   * the poll layer (e.g. it could not be associated for readiness) rather than
   * via an I/O op, so r_socket_get_error reads R_SOCKET_OK. Fail the connection
   * with a generic status anyway -- swallowing it stalls the stream, because
   * the poll layer re-raises the error on every iteration and nothing tears the
   * connection down. recv/send run earlier in this same dispatch and their
   * failure delivery is idempotent (req_fail / teardown), so reporting again
   * here is harmless. */
  if (err == R_SOCKET_OK)
    err = R_SOCKET_ERROR;
  R_LOG_DEBUG ("loop %p evio "R_EV_IO_FORMAT" err: %d",
      evtcp->evio.loop, R_EV_IO_ARGS (evtcp), err);
  if (evtcp->error != NULL)
    evtcp->error (evtcp->error_data, evtcp, err);
  else if (evtcp->recv_iocb_ctx != NULL)
    r_ev_tcp_recv_teardown (evtcp, err);
}

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_tcp_send_iocb_ev (rpointer data, REvLoop * loop)
{
  (void) loop;
  r_ev_tcp_send_iocb (data);
}
#endif

static void
r_ev_tcp_iocb (rpointer data, REvIOEvents events, REvIO * evio)
{
  (void) data;

  if (events & R_EV_IO_READABLE) r_ev_tcp_recv_iocb ((REvTCP *)evio);
  if (events & R_EV_IO_WRITABLE) r_ev_tcp_send_iocb ((REvTCP *)evio);
  if (events & R_EV_IO_ERROR) r_ev_tcp_error_iocb ((REvTCP *)evio);
}

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_tcp_recv_iocb_task (rpointer data, RTaskQueue * queue, RTask * task)
{
  (void) queue;
  (void) task;
  r_ev_tcp_recv_iocb (data);
}
#endif

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_tcp_task_recv_iocb (REvTCP * evtcp)
{
  RTask * task;

  if (r_atomic_uint_fetch_add (&evtcp->recv_counter, 1) > 0)
    return;

  if ((task = r_ev_loop_add_task_full (evtcp->evio.loop,
          evtcp->taskgroup, r_ev_tcp_recv_iocb_task, NULL,
          r_ev_tcp_ref (evtcp), r_ev_tcp_unref, evtcp->recv_task, NULL)) != NULL) {
    if (evtcp->recv_task != NULL)
      r_task_unref (evtcp->recv_task);
    evtcp->recv_task = task;
  } else {
    r_ev_tcp_unref (evtcp);
  }
}
#endif

#if !defined (R_OS_WIN32) || defined (R_EV_USE_RPOLL)
static void
r_ev_tcp_task_iocb (rpointer data, REvIOEvents events, REvIO * evio)
{
  (void) data;

  if (events & R_EV_IO_READABLE) r_ev_tcp_task_recv_iocb ((REvTCP *)evio);
  if (events & R_EV_IO_WRITABLE) r_ev_tcp_send_iocb ((REvTCP *)evio);
  if (events & R_EV_IO_ERROR) r_ev_tcp_error_iocb ((REvTCP *)evio);
}
#endif

rboolean
r_ev_tcp_recv_start (REvTCP * evtcp,
    REvTCPBufferAllocFunc alloc, REvTCPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (recv == NULL)) return FALSE;
  if (R_UNLIKELY (evtcp->recv_iocb_ctx != NULL)) return FALSE;

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  if (R_UNLIKELY (evtcp->iocp_recv_active)) return FALSE;
  if (alloc == NULL)
    alloc = r_ev_tcp_buffer_alloc_default;
  if (evtcp->recv_datanotify != NULL)
    evtcp->recv_datanotify (evtcp->recv_data);
  evtcp->alloc = alloc;
  evtcp->recv = recv;
  evtcp->recv_data = data;
  evtcp->recv_datanotify = datanotify;
  evtcp->iocp_recv_active = TRUE;
  if (R_UNLIKELY (!r_ev_tcp_iocp_post_recv (evtcp))) {
    evtcp->iocp_recv_active = FALSE;
    evtcp->recv = NULL;
    evtcp->recv_datanotify = NULL;
    if (datanotify != NULL)
      datanotify (data);
    return FALSE;
  }
  return TRUE;
#else
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
#endif
}

rboolean
r_ev_tcp_task_recv_start (REvTCP * evtcp, ruint taskgroup,
    REvTCPBufferAllocFunc alloc, REvTCPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (recv == NULL)) return FALSE;
  if (R_UNLIKELY (evtcp->recv_iocb_ctx != NULL)) return FALSE;
  if (R_UNLIKELY (!r_ev_io_validate_taskgroup (&evtcp->evio, taskgroup))) return FALSE;

#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  if (R_UNLIKELY (evtcp->iocp_recv_active)) return FALSE;
  if (alloc == NULL)
    alloc = r_ev_tcp_buffer_alloc_default;
  if (evtcp->recv_datanotify != NULL)
    evtcp->recv_datanotify (evtcp->recv_data);
  evtcp->taskgroup = taskgroup;
  evtcp->alloc = alloc;
  evtcp->recv = recv;
  evtcp->recv_data = data;
  evtcp->recv_datanotify = datanotify;
  evtcp->iocp_recv_active = TRUE;
  evtcp->iocp_recv_task = TRUE;
  if (R_UNLIKELY (!r_ev_tcp_iocp_post_recv (evtcp))) {
    evtcp->iocp_recv_active = FALSE;
    evtcp->iocp_recv_task = FALSE;
    evtcp->recv = NULL;
    evtcp->recv_datanotify = NULL;
    if (datanotify != NULL)
      datanotify (data);
    return FALSE;
  }
  return TRUE;
#else
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
#endif
}

rboolean
r_ev_tcp_recv_stop (REvTCP * evtcp)
{
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
  /* Stop re-arming and cancel any in-flight WSARecv; its completion arrives
   * with ERROR_OPERATION_ABORTED and simply drops the op ref. The recv user
   * data is released when the evtcp is freed (any pending completion may still
   * reference it). */
  evtcp->iocp_recv_active = FALSE;
  if (evtcp->iocp_recv_buf != NULL)
    CancelIoEx ((HANDLE) evtcp->socket->handle, &evtcp->iocp_recv.overlapped);
  /* Task delivery: wait for the last dispatched buffer to be processed. */
  if (evtcp->recv_task != NULL) {
    r_task_wait (evtcp->recv_task);
    r_task_unref (evtcp->recv_task);
    evtcp->recv_task = NULL;
  }
  return TRUE;
#else
  rboolean ret;

  ret = r_ev_io_stop (&evtcp->evio, evtcp->recv_iocb_ctx);
  evtcp->recv_iocb_ctx = NULL;
  if (evtcp->recv_task != NULL) {
    r_task_wait (evtcp->recv_task);
    r_task_unref (evtcp->recv_task);
    evtcp->recv_task = NULL;
  }

  return ret;
#endif
}

void
r_ev_tcp_set_error_handler (REvTCP * evtcp, REvTCPErrorFunc error,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (evtcp == NULL)) return;

  if (evtcp->error_datanotify != NULL)
    evtcp->error_datanotify (evtcp->error_data);
  evtcp->error = error;
  evtcp->error_data = data;
  evtcp->error_datanotify = datanotify;
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
    if (evtcp->evio.flags & R_EV_IO_CLOSED)   /* DIAG #310 */
      R_LOG_WARNING ("DIAG310: send queued on CLOSED "R_EV_IO_FORMAT" size=%"
          RSIZE_FMT, R_EV_IO_ARGS (evtcp), r_buffer_get_size (buf));

    R_LOG_TRACE ("loop %p evio "R_EV_IO_FORMAT" buf %p",
        evtcp->evio.loop, R_EV_IO_ARGS (evtcp), buf);
    if (r_queue_size (&evtcp->qsend) == 1) {
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)
      /* Post the head; subsequent sends drain in order as each completes. */
      ret = r_ev_tcp_iocp_post_send (evtcp);
#else
      ret = r_ev_loop_add_callback (evtcp->evio.loop, TRUE,
          r_ev_tcp_send_iocb_ev, r_ev_tcp_ref (evtcp), r_ev_tcp_unref);
#endif
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

