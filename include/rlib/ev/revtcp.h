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
#ifndef __R_EV_TCP_H__
#define __R_EV_TCP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/ev/revtcp.h
 * @brief Event-loop TCP source: connect, listen / accept, and
 * buffered async send / receive.
 */

#include <rlib/rtypes.h>

#include <rlib/ev/revio.h>
#include <rlib/ev/revloop.h>
#include <rlib/rbuffer.h>
#include <rlib/net/rsocketaddress.h>
#include <rlib/net/rsocket.h>
#include <rlib/rref.h>

/**
 * @defgroup r_evtcp Event-loop TCP
 * @ingroup r_ev
 *
 * @brief Asynchronous TCP sockets driven by an @ref REvLoop —
 * connect, listen / accept, and callback-based send / receive.
 *
 * Receiving uses a caller-supplied allocator callback (to provide the
 * @ref RBuffer each read fills) plus a receive callback. Callbacks fire on
 * the loop thread, except the @c _task_recv_start variant, which hands
 * received buffers to a task group for off-thread processing. Because
 * @ref r_ev_tcp_recv_stop / @ref r_ev_tcp_close drain the last such task
 * from the loop thread, a task-group receive callback must not block on work
 * that needs the loop thread.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted event-loop TCP socket. */
typedef struct REvTCP REvTCP;
/** @brief Allocate the buffer the next receive will fill. */
typedef RBuffer * (*REvTCPBufferAllocFunc) (rpointer data, REvTCP * evtcp);
/**
 * @brief Deliver a received / sent buffer. On the receive path a
 * @c NULL @p buf signals end-of-stream (a clean close, or — when no
 * error handler is installed — a receive error).
 */
typedef void (*REvTCPBufferFunc) (rpointer data, RBuffer * buf, REvTCP * evtcp);
/** @brief Connection-attempt result; @p status is 0 on success. */
typedef void (*REvTCPConnectedFunc) (rpointer data, REvTCP * evtcp, int status);
/** @brief Fired on a listening socket when a new connection @p newtcp is ready. */
typedef void (*REvTCPConnectionReadyFunc) (rpointer data, REvTCP * newtcp, REvTCP * listening);
/** @brief Fired on an asynchronous socket error; @p error is the failing @ref RSocketStatus. */
typedef void (*REvTCPErrorFunc) (rpointer data, REvTCP * evtcp, RSocketStatus error);

/** @brief Create an unconnected TCP socket of @p family on @p loop. */
R_API REvTCP * r_ev_tcp_new (RSocketFamily family, REvLoop * loop);
/** @brief Create a TCP socket already bound to @p addr. */
R_API REvTCP * r_ev_tcp_new_bind (const RSocketAddress * addr, REvLoop * loop);
/** @brief Close the socket; @p close_cb fires once closed. */
R_API rboolean r_ev_tcp_close (REvTCP * evtcp, REvIOFunc close_cb,
    rpointer data, RDestroyNotify datanotify);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_ev_tcp_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_ev_tcp_unref r_ref_unref

/** @brief The underlying socket (borrowed) for advanced socket configuration. */
R_API RSocket * r_ev_tcp_get_socket (const REvTCP * evtcp);
/** @brief Local address the socket is bound to. */
R_API RSocketAddress * r_ev_tcp_get_local_address (const REvTCP * evtcp);
/** @brief Remote (peer) address of a connected socket. */
R_API RSocketAddress * r_ev_tcp_get_remote_address (const REvTCP * evtcp);

/** @brief Bind to @p address; @p reuse sets @c SO_REUSEADDR. */
R_API RSocketStatus r_ev_tcp_bind (REvTCP * evtcp,
    const RSocketAddress * address, rboolean reuse);
/** @brief Synchronously accept one pending connection on a listening socket. */
R_API REvTCP * r_ev_tcp_accept (REvTCP * evtcp, RSocketStatus * res);
/** @brief Begin connecting to @p address; @p connected fires with the result. */
R_API RSocketStatus r_ev_tcp_connect (REvTCP * evtcp, const RSocketAddress * address,
    REvTCPConnectedFunc connected, rpointer data, RDestroyNotify datanotify);
/** @brief Listen with @p backlog; @p connection fires per incoming connection. */
R_API RSocketStatus r_ev_tcp_listen (REvTCP * evtcp, ruint8 backlog,
    REvTCPConnectionReadyFunc connection, rpointer data, RDestroyNotify datanotify);

/**
 * @brief Start receiving; @p alloc provides each buffer, @p recv
 * delivers the bytes read.
 */
R_API rboolean r_ev_tcp_recv_start (REvTCP * evtcp,
    REvTCPBufferAllocFunc alloc, REvTCPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify);
/** @brief Like @ref r_ev_tcp_recv_start but dispatches received buffers to @p taskgroup. */
R_API rboolean r_ev_tcp_task_recv_start (REvTCP * evtcp, ruint taskgroup,
    REvTCPBufferAllocFunc alloc, REvTCPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify);
/** @brief Stop receiving. */
R_API rboolean r_ev_tcp_recv_stop (REvTCP * evtcp);
/**
 * @brief Install a handler for asynchronous socket errors (a failed
 * receive or send, or an error event reported by the loop).
 *
 * On a receive error the handler is invoked in place of the @c recv
 * end-of-stream notification (a @c NULL buffer), so it can tell a
 * peer/socket failure apart from a clean close; with no handler
 * installed, a receive error falls back to that end-of-stream
 * notification.
 *
 * The handler may fire more than once for a connection (for example a
 * receive-path error followed by a separate error event), so it should
 * be idempotent — e.g. close the socket only once. Replaces any
 * previously installed handler (invoking the previous @p datanotify on
 * its data); pass @c NULL @p error to clear it.
 */
R_API void r_ev_tcp_set_error_handler (REvTCP * evtcp,
    REvTCPErrorFunc error, rpointer data, RDestroyNotify datanotify);
/** @brief Send @p buf without a completion callback. */
#define r_ev_tcp_send_and_forget(evtcp, buf) r_ev_tcp_send (evtcp, buf, NULL, NULL, NULL)
/** @brief Send @p buf; @p done fires when the write completes. */
R_API rboolean r_ev_tcp_send (REvTCP * evtcp, RBuffer * buf,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify);
/** @brief Send @p size bytes from @p buffer, taking ownership of it. */
R_API rboolean r_ev_tcp_send_take (REvTCP * evtcp, rpointer buffer, rsize size,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify);
/** @brief Send a copy of @p size bytes from @p buffer. */
R_API rboolean r_ev_tcp_send_dup (REvTCP * evtcp, rconstpointer buffer, rsize size,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify);

R_END_DECLS

/** @} */

#endif /* __R_EV_TCP_H__ */

