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

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>
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
  R_SOCKET_FLAG_INITIALIZED     = (1 << 0),
  R_SOCKET_FLAG_BLOCKING        = (1 << 1),
  R_SOCKET_FLAG_CONNECTING      = (1 << 2),
  R_SOCKET_FLAG_CONNECTED       = (1 << 3),
  R_SOCKET_FLAG_CLOSED          = (1 << 4),
  R_SOCKET_FLAG_LISTENING       = (1 << 5),
} RSocketFlag;
typedef ruint32 RSocketFlags;

typedef enum {
  R_SOCKET_WOULD_BLOCK      =  1,
  R_SOCKET_OK               =  0,
  R_SOCKET_INVAL            = -1,
  R_SOCKET_OOM              = -2,
  R_SOCKET_ERROR            = -3,
  R_SOCKET_INVALID_OP       = -4,
  R_SOCKET_NOT_BOUND        = -5,
  R_SOCKET_NOT_CONNECTED    = -6,
} RSocketStatus;

#if 0
typedef enum {
  R_SOCKET_MSG_NONE,
  R_SOCKET_MSG_OOB          = R_MSG_OOB,
  R_SOCKET_MSG_PEEK         = R_MSG_PEEK,
  R_SOCKET_MSG_DONTROUTE    = R_MSG_DONTROUTE,
} RSocketMsgFlags;
#endif

#define R_SOCKET_DEFAULT_BACKLOG          16

typedef struct _RSocket         RSocket;

R_API RSocket * r_socket_new (RSocketFamily family, RSocketType type, RSocketProtocol proto);
#define r_socket_ref    r_ref_ref
#define r_socket_unref  r_ref_unref

#define r_socket_is_closed(socket) (r_socket_get_flags (socket) & R_SOCKET_FLAG_CLOSED)
#define r_socket_is_alive(socket) (!r_socket_is_closed (socket))
#define r_socket_is_connecting(socket) (r_socket_get_flags (socket) & R_SOCKET_FLAG_CONNECTING)
#define r_socket_is_connected(socket) (r_socket_get_flags (socket) & R_SOCKET_FLAG_CONNECTED)
#define r_socket_is_listening(socket) (r_socket_get_flags (socket) & R_SOCKET_FLAG_LISTENING)

R_API RSocketFlags r_socket_get_flags (const RSocket * socket);
R_API RSocketFamily r_socket_get_family (const RSocket * socket);
R_API RSocketType r_socket_get_socket_type (const RSocket * socket);
R_API RSocketProtocol r_socket_get_protocol (const RSocket * socket);

R_API RSocketAddress * r_socket_get_local_address (RSocket * socket);
R_API RSocketAddress * r_socket_get_remote_address (RSocket * socket);

R_API rboolean r_socket_get_option (RSocket * socket, int level, int optname, int * value);
R_API rboolean r_socket_get_blocking (RSocket * socket);
R_API rboolean r_socket_get_broadcast (RSocket * socket);
R_API rboolean r_socket_get_keepalive (RSocket * socket);
R_API rboolean r_socket_get_multicast_loop (RSocket * socket);
R_API ruint r_socket_get_multicast_ttl (RSocket * socket);
R_API ruint r_socket_get_ttl (RSocket * socket);

R_API rboolean r_socket_set_option (RSocket * socket, int level, int optname, int value);
R_API rboolean r_socket_set_blocking (RSocket * socket, rboolean blocking);
R_API rboolean r_socket_set_broadcast (RSocket * socket, rboolean broadcast);
R_API rboolean r_socket_set_keepalive (RSocket * socket, rboolean keepalive);
R_API rboolean r_socket_set_multicast_loop (RSocket * socket, rboolean loop);
R_API rboolean r_socket_set_multicast_ttl (RSocket * socket, ruint ttl);
R_API rboolean r_socket_set_ttl (RSocket * socket, ruint ttl);

R_API RSocketStatus r_socket_close (RSocket * socket);
R_API RSocketStatus r_socket_bind (RSocket * socket, RSocketAddress * address, rboolean reuse);
#define r_socket_listen(s)  r_socket_listen_full (s, R_SOCKET_DEFAULT_BACKLOG)
R_API RSocketStatus r_socket_listen_full (RSocket * socket, ruint8 backlog);
R_API RSocketStatus r_socket_accept (RSocket * socket, RSocket ** newsock);
R_API RSocket * r_socket_accept_simple (RSocket * socket);
R_API RSocketStatus r_socket_connect (RSocket * socket, const RSocketAddress * address);
R_API RSocketStatus r_socket_shutdown (RSocket * socket, rboolean rx, rboolean tx);

R_API RSocketStatus r_socket_receive (RSocket * socket, ruint8 * buffer, rsize size, rsize * received);
R_API RSocketStatus r_socket_receive_from (RSocket * socket, RSocketAddress * address, ruint8 * buffer, rsize size, rsize * received);
R_API RSocketStatus r_socket_receive_message (RSocket * socket, RSocketAddress * address, RBuffer * buf, rsize * received);
R_API RSocketStatus r_socket_send (RSocket * socket, const ruint8 * buffer, rsize size, rsize * sent);
R_API RSocketStatus r_socket_send_to (RSocket * socket, const RSocketAddress * address, const ruint8 * buffer, rsize size, rsize * sent);
R_API RSocketStatus r_socket_send_message (RSocket * socket, const RSocketAddress * address, RBuffer * buf, rsize * sent);

R_END_DECLS

#endif /* __R_SOCKET_H__ */


