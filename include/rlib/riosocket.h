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

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rsocketaddress.h>

R_BEGIN_DECLS

typedef enum
{
  R_SOCKET_TYPE_NONE      = 0,
  R_SOCKET_TYPE_STREAM    = 1,
  R_SOCKET_TYPE_DATAGRAM  = 2,
  R_SOCKET_TYPE_RAW       = 3,
  R_SOCKET_TYPE_RDM       = 4,
  R_SOCKET_TYPE_SEQPACKET = 5,
} RSocketType;

typedef enum {
  R_SOCKET_PROTOCOL_UNKNOWN = -1,
  R_SOCKET_PROTOCOL_DEFAULT = 0,
  R_SOCKET_PROTOCOL_TCP     = 6,
  R_SOCKET_PROTOCOL_UDP     = 17,
  R_SOCKET_PROTOCOL_SCTP    = 132,
} RSocketProtocol;

typedef enum {
  R_SOCKET_WOULD_BLOCK      =  1,
  R_SOCKET_OK               =  0,
  R_SOCKET_INVAL            = -1,
  R_SOCKET_OOM              = -2,
  R_SOCKET_ERROR            = -3,
  R_SOCKET_INVALID_OP       = -4,
  R_SOCKET_CANCELED         = -5,
  R_SOCKET_BAD              = -6,
  R_SOCKET_NOT_BOUND        = -7,
  R_SOCKET_NOT_CONNECTED    = -8,
  R_SOCKET_CONN_ABORTED     = -9,
  R_SOCKET_CONN_REFUSED     = -10,
  R_SOCKET_CONN_RESET       = -11,
  R_SOCKET_NOT_SUPPORTED    = -12,
} RSocketStatus;


R_API RIOHandle r_io_socket (RSocketFamily family, RSocketType type, RSocketProtocol proto);

R_API RSocketStatus r_io_get_socket_option (RIOHandle handle, int level, int optname, int * value);
R_API RSocketStatus r_io_set_socket_option (RIOHandle handle, int level, int optname, int value);

R_API RSocketStatus r_io_get_socket_error (RIOHandle handle, RSocketStatus * error);

R_API RSocketStatus r_io_get_socket_acceptconn (RIOHandle handle, rboolean * listening);
R_API RSocketStatus r_io_get_socket_broadcast (RIOHandle handle, rboolean * broadcast);
R_API RSocketStatus r_io_get_socket_keepalive (RIOHandle handle, rboolean * keepalive);
R_API RSocketStatus r_io_get_socket_reuseaddr (RIOHandle handle, rboolean * reuse);

R_API RSocketStatus r_io_set_socket_broadcast (RIOHandle handle, rboolean broadcast);
R_API RSocketStatus r_io_set_socket_keepalive (RIOHandle handle, rboolean keepalive);
R_API RSocketStatus r_io_set_socket_reuseaddr (RIOHandle handle, rboolean reuse);

/* Operations */
R_API RSocketStatus r_io_socket_close (RIOHandle handle);
R_API RSocketStatus r_io_socket_bind (RIOHandle handle, const RSocketAddress * address);
#define r_io_socket_listen(s)  r_io_socket_listen_full (s, R_SOCKET_DEFAULT_BACKLOG)
R_API RSocketStatus r_io_socket_listen_full (RIOHandle handle, ruint8 backlog);
R_API RIOHandle r_io_socket_accept (RIOHandle handle, RSocketStatus * res);
R_API RSocketStatus r_io_socket_connect (RIOHandle handle, const RSocketAddress * address);
R_API RSocketStatus r_io_socket_shutdown (RIOHandle handle, rboolean rx, rboolean tx);

/* Recv/Send */
R_API RSocketStatus r_io_socket_receive (RIOHandle handle, rpointer buffer, rsize size, rsize * received);
R_API RSocketStatus r_io_socket_receive_from (RIOHandle handle, RSocketAddress * address, rpointer buffer, rsize size, rsize * received);
R_API RSocketStatus r_io_socket_receive_message (RIOHandle handle, RSocketAddress * address, RBuffer * buf, rsize * received);
R_API RSocketStatus r_io_socket_send (RIOHandle handle, rconstpointer buffer, rsize size, rsize * sent);
R_API RSocketStatus r_io_socket_send_to (RIOHandle handle, const RSocketAddress * address, rconstpointer buffer, rsize size, rsize * sent);
R_API RSocketStatus r_io_socket_send_message (RIOHandle handle, const RSocketAddress * address, RBuffer * buf, rsize * sent);

/* IP spesific */
R_API RSocketStatus r_io_get_socket_ipv4_multicast_loop (RIOHandle handle, rboolean * mloop);
R_API RSocketStatus r_io_get_socket_ipv4_multicast_ttl (RIOHandle handle, int * mttl);
R_API RSocketStatus r_io_get_socket_ipv4_ttl (RIOHandle handle, int * ttl);
R_API RSocketStatus r_io_set_socket_ipv4_multicast_loop (RIOHandle handle, rboolean mloop);
R_API RSocketStatus r_io_set_socket_ipv4_multicast_ttl (RIOHandle handle, int mttl);
R_API RSocketStatus r_io_set_socket_ipv4_ttl (RIOHandle handle, int ttl);

R_API RSocketStatus r_io_get_socket_ipv6_multicast_loop (RIOHandle handle, rboolean * mloop);
R_API RSocketStatus r_io_get_socket_ipv6_multicast_ttl (RIOHandle handle, int * mttl);
R_API RSocketStatus r_io_get_socket_ipv6_ttl (RIOHandle handle, int * ttl);
R_API RSocketStatus r_io_set_socket_ipv6_multicast_loop (RIOHandle handle, rboolean mloop);
R_API RSocketStatus r_io_set_socket_ipv6_multicast_ttl (RIOHandle handle, int mttl);
R_API RSocketStatus r_io_set_socket_ipv6_ttl (RIOHandle handle, int ttl);

R_END_DECLS

#endif /* __R_IO_SOCKET_H__ */

