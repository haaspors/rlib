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
#ifndef __R_SOCKET_H__
#define __R_SOCKET_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/net/rsocket.h
 * @brief Refcounted high-level socket object with lifecycle tracking,
 * cached options and convenience getters / setters.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/rbuffer.h>

#include <rlib/net/rsocketaddress.h>
/* RSocket enums */
#include <rlib/net/riosocket.h>

R_BEGIN_DECLS

/**
 * @defgroup r_socket Sockets
 * @ingroup r_net
 *
 * @brief Refcounted wrapper around @ref r_iosocket with lifecycle
 * state, cached family / type / protocol and convenience accessors.
 *
 * Construct with @ref r_socket_new; the underlying OS handle is
 * created lazily but the @ref RSocket carries enough state that
 * callers can read it back later (@ref r_socket_get_family etc.).
 * Lifecycle flags (@ref RSocketFlag) are exposed via
 * @ref r_socket_get_flags plus the @c r_socket_is_* convenience
 * macros.
 *
 * Use @ref r_iosocket when you already hold an @c RIOHandle (typically
 * from the event loop) and just want a socket-shaped op; use
 * @ref r_socket when you need lifecycle management or want to keep
 * the address / family with the handle.
 *
 * @{
 */

/** @brief Lifecycle bits returned by @ref r_socket_get_flags. */
typedef enum {
  R_SOCKET_FLAG_INITIALIZED     = (1 << 0), /**< OS handle has been allocated. */
  R_SOCKET_FLAG_BLOCKING        = (1 << 1), /**< Socket is in blocking mode. */
  R_SOCKET_FLAG_CONNECTING      = (1 << 2), /**< @c connect() in progress (non-blocking). */
  R_SOCKET_FLAG_CONNECTED       = (1 << 3), /**< Connection established. */
  R_SOCKET_FLAG_CLOSED          = (1 << 4), /**< Socket has been closed. */
  R_SOCKET_FLAG_LISTENING       = (1 << 5), /**< Socket is in the listening state. */
} RSocketFlag;
/** @brief Bitwise-OR of @ref RSocketFlag values. */
typedef ruint32 RSocketFlags;

#if 0
typedef enum {
  R_SOCKET_MSG_NONE,
  R_SOCKET_MSG_OOB          = R_MSG_OOB,
  R_SOCKET_MSG_PEEK         = R_MSG_PEEK,
  R_SOCKET_MSG_DONTROUTE    = R_MSG_DONTROUTE,
} RSocketMsgFlags;
#endif

/** @brief Default backlog for @ref r_socket_listen. */
#define R_SOCKET_DEFAULT_BACKLOG          16

/** @brief Opaque, refcounted socket handle. */
typedef struct RSocket         RSocket;

/** @brief Create a new socket bound to the given family / type / protocol. */
R_API RSocket * r_socket_new (RSocketFamily family, RSocketType type, RSocketProtocol proto);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_socket_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_socket_unref  r_ref_unref

/** @brief @c TRUE iff @ref R_SOCKET_FLAG_CLOSED is set. */
#define r_socket_is_closed(socket) (r_socket_get_flags (socket) & R_SOCKET_FLAG_CLOSED)
/** @brief Negation of @ref r_socket_is_closed. */
#define r_socket_is_alive(socket) (!r_socket_is_closed (socket))
/** @brief @c TRUE iff @ref R_SOCKET_FLAG_CONNECTING is set. */
#define r_socket_is_connecting(socket) (r_socket_get_flags (socket) & R_SOCKET_FLAG_CONNECTING)
/** @brief @c TRUE iff @ref R_SOCKET_FLAG_CONNECTED is set. */
#define r_socket_is_connected(socket) (r_socket_get_flags (socket) & R_SOCKET_FLAG_CONNECTED)
/** @brief @c TRUE iff @ref R_SOCKET_FLAG_LISTENING is set. */
#define r_socket_is_listening(socket) (r_socket_get_flags (socket) & R_SOCKET_FLAG_LISTENING)

/** @name State accessors
 *  @{ */
/** @brief Return the OR of the current @ref RSocketFlag bits. */
R_API RSocketFlags r_socket_get_flags (const RSocket * socket);
/** @brief Return the address family this socket was created with. */
R_API RSocketFamily r_socket_get_family (const RSocket * socket);
/** @brief Return the socket type (stream / datagram / ...). */
R_API RSocketType r_socket_get_socket_type (const RSocket * socket);
/** @brief Return the transport protocol (TCP / UDP / ...). */
R_API RSocketProtocol r_socket_get_protocol (const RSocket * socket);

/** @brief Look up the local address; caller takes a reference. */
R_API RSocketAddress * r_socket_get_local_address (RSocket * socket);
/** @brief Look up the remote address; caller takes a reference. */
R_API RSocketAddress * r_socket_get_remote_address (RSocket * socket);
/** @} */

/** @name Option getters
 *  @{ */
/** @brief Read an @c int -typed socket option (@c SO_* / @c IPPROTO_*). */
R_API rboolean r_socket_get_option (RSocket * socket, int level, int optname, int * value);
/** @brief Return and clear the pending socket error code. */
R_API RSocketStatus r_socket_get_error (RSocket * socket);
/** @brief @c TRUE if the socket is in blocking mode. */
R_API rboolean r_socket_get_blocking (RSocket * socket);
/** @brief Read the @c SO_BROADCAST flag. */
R_API rboolean r_socket_get_broadcast (RSocket * socket);
/** @brief Read the @c SO_KEEPALIVE flag. */
R_API rboolean r_socket_get_keepalive (RSocket * socket);
/** @brief Read the per-family @c IP*_MULTICAST_LOOP flag. */
R_API rboolean r_socket_get_multicast_loop (RSocket * socket);
/** @brief Read the per-family multicast TTL. */
R_API ruint r_socket_get_multicast_ttl (RSocket * socket);
/** @brief Read the per-family unicast TTL. */
R_API ruint r_socket_get_ttl (RSocket * socket);
/** @} */

/** @name Option setters
 *  @{ */
/** @brief Set an @c int -typed socket option. */
R_API rboolean r_socket_set_option (RSocket * socket, int level, int optname, int value);
/** @brief Switch between blocking and non-blocking modes. */
R_API rboolean r_socket_set_blocking (RSocket * socket, rboolean blocking);
/** @brief Set the @c SO_BROADCAST flag. */
R_API rboolean r_socket_set_broadcast (RSocket * socket, rboolean broadcast);
/** @brief Set the @c SO_KEEPALIVE flag. */
R_API rboolean r_socket_set_keepalive (RSocket * socket, rboolean keepalive);
/** @brief Set the per-family multicast loopback flag. */
R_API rboolean r_socket_set_multicast_loop (RSocket * socket, rboolean loop);
/** @brief Set the per-family multicast TTL. */
R_API rboolean r_socket_set_multicast_ttl (RSocket * socket, ruint ttl);
/** @brief Set the per-family unicast TTL. */
R_API rboolean r_socket_set_ttl (RSocket * socket, ruint ttl);
/** @} */

/** @name Connection lifecycle
 *  @{ */
/** @brief Close @p socket; subsequent ops return @ref R_SOCKET_BAD. */
R_API RSocketStatus r_socket_close (RSocket * socket);
/**
 * @brief Bind @p socket to @p address.
 * @param socket  Socket to bind.
 * @param address Address to bind to.
 * @param reuse   @c TRUE sets @c SO_REUSEADDR before bind.
 */
R_API RSocketStatus r_socket_bind (RSocket * socket, const RSocketAddress * address, rboolean reuse);
/** @brief Convenience: listen with the default backlog. */
#define r_socket_listen(s)  r_socket_listen_full (s, R_SOCKET_DEFAULT_BACKLOG)
/** @brief Place @p socket into the listening state with a custom backlog. */
R_API RSocketStatus r_socket_listen_full (RSocket * socket, ruint8 backlog);
/**
 * @brief Accept the next incoming connection on a listening socket.
 * @param socket Listening socket.
 * @param res    Optional out-pointer that receives the status code.
 * @return New @ref RSocket for the accepted connection, or @c NULL on failure.
 */
R_API RSocket * r_socket_accept (RSocket * socket, RSocketStatus * res);
/** @brief Connect @p socket to @p address. */
R_API RSocketStatus r_socket_connect (RSocket * socket, const RSocketAddress * address);
/** @brief Shut down @p socket's read (@p rx) and/or write (@p tx) side. */
R_API RSocketStatus r_socket_shutdown (RSocket * socket, rboolean rx, rboolean tx);
/** @} */

/** @name Receive / send
 *  @{ */
/** @brief @c recv into a flat buffer; sets @p received to the byte count. */
R_API RSocketStatus r_socket_receive (RSocket * socket, ruint8 * buffer, rsize size, rsize * received);
/** @brief @c recvfrom variant; @p address is filled with the sender. */
R_API RSocketStatus r_socket_receive_from (RSocket * socket, RSocketAddress * address, ruint8 * buffer, rsize size, rsize * received);
/** @brief @c recvmsg variant; payload is appended to @p buf. */
R_API RSocketStatus r_socket_receive_message (RSocket * socket, RSocketAddress * address, RBuffer * buf, rsize * received);
/** @brief @c send from a flat buffer; sets @p sent to the byte count. */
R_API RSocketStatus r_socket_send (RSocket * socket, const ruint8 * buffer, rsize size, rsize * sent);
/** @brief @c sendto variant; @p address selects the destination. */
R_API RSocketStatus r_socket_send_to (RSocket * socket, const RSocketAddress * address, const ruint8 * buffer, rsize size, rsize * sent);
/** @brief @c sendmsg variant; payload comes from the chained @p buf. */
R_API RSocketStatus r_socket_send_message (RSocket * socket, const RSocketAddress * address, RBuffer * buf, rsize * sent);
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_SOCKET_H__ */


