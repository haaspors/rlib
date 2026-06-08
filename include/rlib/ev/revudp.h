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
#ifndef __R_EV_UDP_H__
#define __R_EV_UDP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/ev/revudp.h
 * @brief Event-loop UDP source: bind and buffered async datagram
 * send / receive.
 */

#include <rlib/rtypes.h>

#include <rlib/ev/revloop.h>
#include <rlib/rbuffer.h>
#include <rlib/net/rsocket.h>
#include <rlib/net/rsocketaddress.h>
#include <rlib/rref.h>

/**
 * @defgroup r_evudp Event-loop UDP
 * @ingroup r_ev
 *
 * @brief Asynchronous UDP sockets driven by an @ref REvLoop —
 * bind and callback-based datagram send / receive.
 *
 * As with @ref r_evtcp, receiving pairs an allocator callback (to
 * supply each datagram's @ref RBuffer) with a receive callback that
 * also reports the sender address. Callbacks fire on the loop thread,
 * except the @c _task_recv_start variant, which dispatches to a task
 * group. Because @ref r_ev_udp_recv_stop drains the last such task from
 * the loop thread, a task-group receive callback must not block on work
 * that needs the loop thread.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted event-loop UDP socket. */
typedef struct REvUDP REvUDP;
/** @brief Allocate the buffer the next datagram will fill. */
typedef RBuffer * (*REvUDPBufferAllocFunc) (rpointer data, REvUDP * evudp);
/** @brief Deliver a datagram buffer; @p addr is the sender / destination. */
typedef void (*REvUDPBufferFunc) (rpointer data, RBuffer * buf, RSocketAddress * addr, REvUDP * evudp);
/** @brief Fired on an asynchronous socket error; @p error is the failing @ref RSocketStatus. */
typedef void (*REvUDPErrorFunc) (rpointer data, REvUDP * evudp, RSocketStatus error);

/** @brief Create a UDP socket of @p family on @p loop. */
R_API REvUDP * r_ev_udp_new (RSocketFamily family, REvLoop * loop);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_ev_udp_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_ev_udp_unref r_ref_unref

/** @brief Bind to @p address; @p reuse sets @c SO_REUSEADDR. */
R_API rboolean r_ev_udp_bind (REvUDP * evudp,
    const RSocketAddress * address, rboolean reuse);
/**
 * @brief Local address of the bound socket.
 *
 * Useful after binding an ephemeral port (port 0) to learn the OS-assigned
 * port. @return A new @ref RSocketAddress the caller must unref, or @c NULL.
 */
R_API RSocketAddress * r_ev_udp_get_local_address (const REvUDP * evudp);
/** @brief Start receiving datagrams; @p alloc supplies buffers, @p recv delivers them. */
R_API rboolean r_ev_udp_recv_start (REvUDP * evudp,
    REvUDPBufferAllocFunc alloc, REvUDPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify);
/** @brief Like @ref r_ev_udp_recv_start but dispatches received datagrams to @p taskgroup. */
R_API rboolean r_ev_udp_task_recv_start (REvUDP * evudp, ruint taskgroup,
    REvUDPBufferAllocFunc alloc, REvUDPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify);
/** @brief Stop receiving. */
R_API rboolean r_ev_udp_recv_stop (REvUDP * evudp);
/**
 * @brief Install a handler for asynchronous socket errors (a failed
 * receive or send, or an error event reported by the loop).
 *
 * Unlike TCP the datagram socket stays usable: a failed send drops just
 * that datagram and a receive error stops draining until the next
 * event.
 *
 * The handler may fire more than once (once per failed datagram, or a
 * receive error followed by a separate error event), so it should be
 * idempotent. Replaces any previously installed handler (invoking the
 * previous @p datanotify on its data); pass @c NULL @p error to clear it.
 */
R_API void r_ev_udp_set_error_handler (REvUDP * evudp,
    REvUDPErrorFunc error, rpointer data, RDestroyNotify datanotify);
/** @brief Send @p buf to @p address; @p done fires on completion. */
R_API rboolean r_ev_udp_send (REvUDP * evudp, RBuffer * buf,
    RSocketAddress * address, REvUDPBufferFunc done,
    rpointer data, RDestroyNotify datanotify);
/** @brief Send @p size bytes from @p buffer to @p address, taking ownership of @p buffer. */
R_API rboolean r_ev_udp_send_take (REvUDP * evudp, rpointer buffer, rsize size,
    RSocketAddress * address, REvUDPBufferFunc done,
    rpointer data, RDestroyNotify datanotify);

R_END_DECLS

/** @} */

#endif /* __R_EV_UDP_H__ */

