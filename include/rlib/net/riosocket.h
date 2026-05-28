/* RLIB - Convenience library for useful things
 * Copyright (C) 2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_IO_SOCKET_H__
#define __R_IO_SOCKET_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/net/riosocket.h
 * @brief Socket-flavoured operations over @c RIOHandle: socket-style
 * @c bind / @c listen / @c connect / @c send / @c recv plus per-family
 * option getters and setters.
 */

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/net/rsocketaddress.h>

R_BEGIN_DECLS

/**
 * @defgroup r_iosocket Low-level socket operations on RIOHandle
 * @ingroup r_socket
 *
 * @brief BSD-socket-style operations that take a bare @c RIOHandle.
 *
 * This is the "raw" API @ref r_socket builds on; it returns
 * @ref RSocketStatus codes and does no refcounting or state tracking.
 * Use @ref r_socket when you want lifecycle management, a stored
 * family / type / protocol, cached options, and refcounted handles;
 * use this layer when you already hold an @c RIOHandle (typically
 * from the event loop) and just need a socket-shaped operation.
 *
 * The enums @ref RSocketType, @ref RSocketProtocol and
 * @ref RSocketStatus are shared between both layers.
 *
 * @{
 */

/** @brief Socket type (BSD @c SOCK_*). */
typedef enum
{
  R_SOCKET_TYPE_NONE      = 0,  /**< Uninitialised. */
  R_SOCKET_TYPE_STREAM    = 1,  /**< Reliable byte stream (TCP). */
  R_SOCKET_TYPE_DATAGRAM  = 2,  /**< Connectionless datagram (UDP). */
  R_SOCKET_TYPE_RAW       = 3,  /**< Raw socket (IP-layer). */
  R_SOCKET_TYPE_RDM       = 4,  /**< Reliable datagram. */
  R_SOCKET_TYPE_SEQPACKET = 5,  /**< Sequenced packet. */
} RSocketType;

/** @brief Transport protocol (BSD @c IPPROTO_*). */
typedef enum {
  R_SOCKET_PROTOCOL_UNKNOWN = -1, /**< Unknown / unsupported protocol. */
  R_SOCKET_PROTOCOL_DEFAULT = 0,  /**< OS-default for the chosen type. */
  R_SOCKET_PROTOCOL_TCP     = 6,  /**< TCP. */
  R_SOCKET_PROTOCOL_UDP     = 17, /**< UDP. */
  R_SOCKET_PROTOCOL_SCTP    = 132,/**< SCTP. */
} RSocketProtocol;

/** @brief Result of a socket operation. */
typedef enum {
  R_SOCKET_WOULD_BLOCK      =  1, /**< Non-blocking op needs retry. */
  R_SOCKET_OK               =  0, /**< Success. */
  R_SOCKET_INVAL            = -1, /**< Invalid argument. */
  R_SOCKET_OOM              = -2, /**< Allocation failed. */
  R_SOCKET_ERROR            = -3, /**< Generic / unmapped OS error. */
  R_SOCKET_INVALID_OP       = -4, /**< Op not valid in current state. */
  R_SOCKET_CANCELED         = -5, /**< Cancelled by caller. */
  R_SOCKET_BAD              = -6, /**< Bad handle. */
  R_SOCKET_NOT_BOUND        = -7, /**< Operation requires bind first. */
  R_SOCKET_NOT_CONNECTED    = -8, /**< Operation requires connect first. */
  R_SOCKET_CONN_ABORTED     = -9, /**< Peer aborted the connection. */
  R_SOCKET_CONN_REFUSED     = -10,/**< Peer refused the connection. */
  R_SOCKET_CONN_RESET       = -11,/**< Connection reset by peer. */
  R_SOCKET_NOT_SUPPORTED    = -12,/**< Op not supported on this platform. */
} RSocketStatus;


/**
 * @brief Open a new socket of the given family / type / protocol;
 * returns @c R_IO_HANDLE_INVALID on failure.
 */
R_API RIOHandle r_io_socket (RSocketFamily family, RSocketType type, RSocketProtocol proto);

/** @name Generic socket options
 *  @{ */
/** @brief Wrapper around @c getsockopt for @c int -typed options. */
R_API RSocketStatus r_io_get_socket_option (RIOHandle handle, int level, int optname, int * value);
/** @brief Wrapper around @c setsockopt for @c int -typed options. */
R_API RSocketStatus r_io_set_socket_option (RIOHandle handle, int level, int optname, int value);
/** @brief Read the pending @c SO_ERROR into @p error. */
R_API RSocketStatus r_io_get_socket_error (RIOHandle handle, RSocketStatus * error);
/** @brief Read the @c SO_ACCEPTCONN flag (@c TRUE if listening). */
R_API RSocketStatus r_io_get_socket_acceptconn (RIOHandle handle, rboolean * listening);
/** @brief Read the @c SO_BROADCAST flag. */
R_API RSocketStatus r_io_get_socket_broadcast (RIOHandle handle, rboolean * broadcast);
/** @brief Read the @c SO_KEEPALIVE flag. */
R_API RSocketStatus r_io_get_socket_keepalive (RIOHandle handle, rboolean * keepalive);
/** @brief Read the @c SO_REUSEADDR flag. */
R_API RSocketStatus r_io_get_socket_reuseaddr (RIOHandle handle, rboolean * reuse);
/** @brief Set the @c SO_BROADCAST flag. */
R_API RSocketStatus r_io_set_socket_broadcast (RIOHandle handle, rboolean broadcast);
/** @brief Set the @c SO_KEEPALIVE flag. */
R_API RSocketStatus r_io_set_socket_keepalive (RIOHandle handle, rboolean keepalive);
/** @brief Set the @c SO_REUSEADDR flag. */
R_API RSocketStatus r_io_set_socket_reuseaddr (RIOHandle handle, rboolean reuse);
/** @} */

/** @name Connection lifecycle
 *  @{ */
/** @brief Close @p handle. */
R_API RSocketStatus r_io_socket_close (RIOHandle handle);
/** @brief Bind @p handle to @p address. */
R_API RSocketStatus r_io_socket_bind (RIOHandle handle, const RSocketAddress * address);
/** @brief Convenience: listen with the default backlog. */
#define r_io_socket_listen(s)  r_io_socket_listen_full (s, R_SOCKET_DEFAULT_BACKLOG)
/** @brief Place @p handle into the listening state with a custom backlog. */
R_API RSocketStatus r_io_socket_listen_full (RIOHandle handle, ruint8 backlog);
/**
 * @brief Accept the next incoming connection.
 * @param handle Listening socket.
 * @param res    Optional out-pointer that receives the status code.
 * @return New handle for the accepted connection, or
 *         @c R_IO_HANDLE_INVALID on failure (see @p res).
 */
R_API RIOHandle r_io_socket_accept (RIOHandle handle, RSocketStatus * res);
/** @brief Connect @p handle to @p address. */
R_API RSocketStatus r_io_socket_connect (RIOHandle handle, const RSocketAddress * address);
/** @brief Shut down @p handle's read (@p rx) and/or write (@p tx) side. */
R_API RSocketStatus r_io_socket_shutdown (RIOHandle handle, rboolean rx, rboolean tx);
/** @} */

/** @name Receive / send
 *  @{ */
/** @brief @c recv into a flat buffer; sets @p received to the byte count. */
R_API RSocketStatus r_io_socket_receive (RIOHandle handle, rpointer buffer, rsize size, rsize * received);
/** @brief @c recvfrom variant; @p address is filled with the sender. */
R_API RSocketStatus r_io_socket_receive_from (RIOHandle handle, RSocketAddress * address, rpointer buffer, rsize size, rsize * received);
/** @brief @c recvmsg variant; payload is appended to @p buf. */
R_API RSocketStatus r_io_socket_receive_message (RIOHandle handle, RSocketAddress * address, RBuffer * buf, rsize * received);
/** @brief @c send from a flat buffer; sets @p sent to the byte count. */
R_API RSocketStatus r_io_socket_send (RIOHandle handle, rconstpointer buffer, rsize size, rsize * sent);
/** @brief @c sendto variant; @p address selects the destination. */
R_API RSocketStatus r_io_socket_send_to (RIOHandle handle, const RSocketAddress * address, rconstpointer buffer, rsize size, rsize * sent);
/** @brief @c sendmsg variant; payload comes from the chained @p buf. */
R_API RSocketStatus r_io_socket_send_message (RIOHandle handle, const RSocketAddress * address, RBuffer * buf, rsize * sent);
/** @} */

/** @name IPv4-specific options
 *  @{ */
/** @brief Read @c IP_MULTICAST_LOOP. */
R_API RSocketStatus r_io_get_socket_ipv4_multicast_loop (RIOHandle handle, rboolean * mloop);
/** @brief Read @c IP_MULTICAST_TTL. */
R_API RSocketStatus r_io_get_socket_ipv4_multicast_ttl (RIOHandle handle, int * mttl);
/** @brief Read @c IP_TTL. */
R_API RSocketStatus r_io_get_socket_ipv4_ttl (RIOHandle handle, int * ttl);
/** @brief Set @c IP_MULTICAST_LOOP. */
R_API RSocketStatus r_io_set_socket_ipv4_multicast_loop (RIOHandle handle, rboolean mloop);
/** @brief Set @c IP_MULTICAST_TTL. */
R_API RSocketStatus r_io_set_socket_ipv4_multicast_ttl (RIOHandle handle, int mttl);
/** @brief Set @c IP_TTL. */
R_API RSocketStatus r_io_set_socket_ipv4_ttl (RIOHandle handle, int ttl);
/** @} */

/** @name IPv6-specific options
 *  @{ */
/** @brief Read @c IPV6_MULTICAST_LOOP. */
R_API RSocketStatus r_io_get_socket_ipv6_multicast_loop (RIOHandle handle, rboolean * mloop);
/** @brief Read @c IPV6_MULTICAST_HOPS. */
R_API RSocketStatus r_io_get_socket_ipv6_multicast_ttl (RIOHandle handle, int * mttl);
/** @brief Read @c IPV6_UNICAST_HOPS. */
R_API RSocketStatus r_io_get_socket_ipv6_ttl (RIOHandle handle, int * ttl);
/** @brief Set @c IPV6_MULTICAST_LOOP. */
R_API RSocketStatus r_io_set_socket_ipv6_multicast_loop (RIOHandle handle, rboolean mloop);
/** @brief Set @c IPV6_MULTICAST_HOPS. */
R_API RSocketStatus r_io_set_socket_ipv6_multicast_ttl (RIOHandle handle, int mttl);
/** @brief Set @c IPV6_UNICAST_HOPS. */
R_API RSocketStatus r_io_set_socket_ipv6_ttl (RIOHandle handle, int ttl);
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_IO_SOCKET_H__ */

