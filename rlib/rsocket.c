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
#include "rsocket-private.h"
#include "net/rnet-private.h"
#include "rlib-private.h"

#include <rlib/rio.h>
#include <rlib/rmem.h>

static void
r_socket_free (RSocket * socket)
{
  r_socket_close (socket);
  r_free (socket);
}

static RSocket *
r_socket_new_with_handle (RSocketHandle handle)
{
  RSocket * ret;

  if ((ret = r_mem_new (RSocket)) != NULL) {
    r_ref_init (ret, r_socket_free);

    ret->handle = handle;
    ret->flags = R_SOCKET_FLAG_INITIALIZED;

    r_socket_set_blocking (ret, FALSE);
  }

  return ret;
}

RSocket *
r_socket_new (RSocketFamily family, RSocketType type, RSocketProtocol proto)
{
  RSocket * ret;
  RSocketHandle handle;

  if ((handle = r_io_socket (family, type, proto)) == R_IO_HANDLE_INVALID)
    return NULL;

  if ((ret = r_socket_new_with_handle (handle)) != NULL) {
    ret->family = family;
    ret->type = type;
    ret->proto = proto;
  } else {
    r_io_socket_close (handle);
  }

  return ret;
}

RSocketFamily
r_socket_get_family (const RSocket * socket)
{
  return socket->family;
}

RSocketType
r_socket_get_socket_type (const RSocket * socket)
{
  return socket->type;
}

RSocketProtocol
r_socket_get_protocol (const RSocket * socket)
{
  return socket->proto;
}

RSocketFlags
r_socket_get_flags (const RSocket * socket)
{
  return socket->flags;
}

RSocketAddress *
r_socket_get_local_address (RSocket * socket)
{
  RSocketAddress * ret = NULL;

  if (R_UNLIKELY (socket == NULL)) return NULL;

#ifndef HAVE_MOCK_SOCKETS
  struct sockaddr_storage ss;
  socklen_t len = sizeof (struct sockaddr_storage);

  if (getsockname (socket->handle, (struct sockaddr *)&ss, &len) == 0)
    ret = r_socket_address_new_from_native (&ss, len);
#endif

  return ret;
}

RSocketAddress *
r_socket_get_remote_address (RSocket * socket)
{
  RSocketAddress * ret = NULL;

  if (R_UNLIKELY (socket == NULL)) return NULL;

#ifndef HAVE_MOCK_SOCKETS
  struct sockaddr_storage ss;
  socklen_t len = sizeof (struct sockaddr_storage);

  if (getpeername (socket->handle, (struct sockaddr *)&ss, &len) == 0) {
    ret = r_socket_address_new_from_native (&ss, len);
  }
#endif

  return ret;
}

rboolean
r_socket_get_option (RSocket * socket, int level, int optname, int * value)
{
  return r_io_get_socket_option (socket->handle, level, optname, value) == R_SOCKET_OK;
}

RSocketStatus
r_socket_get_error (RSocket * socket)
{
  RSocketStatus ret, res;

  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;

  if ((ret = r_io_get_socket_error (socket->handle, &res)) == R_SOCKET_OK)
    ret = res;

  return ret;
}

rboolean
r_socket_get_blocking (RSocket * socket)
{
  return (socket->flags & R_SOCKET_FLAG_BLOCKING) == R_SOCKET_FLAG_BLOCKING;
}

rboolean
r_socket_get_broadcast (RSocket * socket)
{
  rboolean ret = FALSE;
  r_io_get_socket_broadcast (socket->handle, &ret);
  return ret;
}

rboolean
r_socket_get_keepalive (RSocket * socket)
{
  rboolean ret = FALSE;
  r_io_get_socket_keepalive (socket->handle, &ret);
  return ret;
}

rboolean
r_socket_get_multicast_loop (RSocket * socket)
{
  rboolean ret = FALSE;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      r_io_get_socket_ipv4_multicast_loop (socket->handle, &ret);
      break;
    case R_SOCKET_FAMILY_IPV6:
      r_io_get_socket_ipv6_multicast_loop (socket->handle, &ret);
      break;
    default:
      break;
  }

  return ret;
}

ruint
r_socket_get_multicast_ttl (RSocket * socket)
{
  int val = 0;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      r_io_get_socket_ipv4_multicast_ttl (socket->handle, &val);
      break;
    case R_SOCKET_FAMILY_IPV6:
      r_io_get_socket_ipv6_multicast_ttl (socket->handle, &val);
      break;
    default:
      break;
  }

  return (ruint)MAX (val, 0);
}

ruint
r_socket_get_ttl (RSocket * socket)
{
  int val;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      r_io_get_socket_ipv4_ttl (socket->handle, &val);
      break;
    case R_SOCKET_FAMILY_IPV6:
      r_io_get_socket_ipv6_ttl (socket->handle, &val);
      break;
    default:
      return 0;
  }

  return (ruint)MAX (val, 0);
}

rboolean
r_socket_set_option (RSocket * socket, int level, int optname, int value)
{
  return r_io_set_socket_option (socket->handle, level, optname, value) == R_SOCKET_OK;
}

rboolean
r_socket_set_blocking (RSocket * socket, rboolean blocking)
{
  rboolean ret;
#if defined (HAVE_WINSOCK2)
  rulong val = !blocking;
  ret = (ioctlsocket (socket->handle, FIONBIO, &val) != SOCKET_ERROR);
#elif defined (R_OS_UNIX)
  ret = r_io_unix_set_nonblocking (socket->handle, !blocking);
#else
  ret = FALSE;
#endif

  if (ret) {
    if (blocking)
      socket->flags |= R_SOCKET_FLAG_BLOCKING;
    else
      socket->flags &= ~R_SOCKET_FLAG_BLOCKING;
  }

  return ret;
}

rboolean
r_socket_set_broadcast (RSocket * socket, rboolean broadcast)
{
  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;
  return r_io_set_socket_broadcast (socket->handle, broadcast) == R_SOCKET_OK;
}

rboolean
r_socket_set_keepalive (RSocket * socket, rboolean keepalive)
{
  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;
  return r_io_set_socket_keepalive (socket->handle, keepalive) == R_SOCKET_OK;
}

rboolean
r_socket_set_multicast_loop (RSocket * socket, rboolean loop)
{
  rboolean ret;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      ret = r_io_set_socket_ipv4_multicast_loop (socket->handle, loop);
      break;
    case R_SOCKET_FAMILY_IPV6:
      ret = r_io_set_socket_ipv6_multicast_loop (socket->handle, loop);
      break;
    default:
      ret = FALSE;
      break;
  }

  return ret;
}

rboolean
r_socket_set_multicast_ttl (RSocket * socket, ruint ttl)
{
  rboolean ret;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      ret = r_io_set_socket_ipv4_multicast_ttl (socket->handle, (int)ttl);
      break;
    case R_SOCKET_FAMILY_IPV6:
      ret = r_io_set_socket_ipv6_multicast_ttl (socket->handle, (int)ttl);
      break;
    default:
      ret = FALSE;
      break;
  }

  return ret;
}

rboolean
r_socket_set_ttl (RSocket * socket, ruint ttl)
{
  rboolean ret;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      ret = r_io_set_socket_ipv4_ttl (socket->handle, (int)ttl);
      break;
    case R_SOCKET_FAMILY_IPV6:
      ret = r_io_set_socket_ipv6_ttl (socket->handle, (int)ttl);
      break;
    default:
      ret = FALSE;
      break;
  }

  return ret;
}


RSocketStatus
r_socket_close (RSocket * socket)
{
  RSocketStatus ret;

  if (socket->handle != R_IO_HANDLE_INVALID) {
    ret = r_io_socket_close (socket->handle);
    socket->handle = R_IO_HANDLE_INVALID;
  } else {
    ret = R_SOCKET_OK;
  }

  socket->flags |= R_SOCKET_FLAG_CLOSED;

  return ret;
}

RSocketStatus
r_socket_bind (RSocket * socket, const RSocketAddress * address, rboolean reuse)
{
  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

  r_io_set_socket_reuseaddr (socket->handle, reuse);
#ifdef SO_REUSEPORT
  r_io_set_socket_option (socket->handle, SOL_SOCKET, SO_REUSEPORT,
      (reuse && socket->type == R_SOCKET_TYPE_DATAGRAM) ? 1 : 0);
#endif

  return r_io_socket_bind (socket->handle, address);
}

RSocketStatus
r_socket_listen_full (RSocket * socket, ruint8 backlog)
{
  RSocketStatus ret;

  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;

  if ((ret = r_io_socket_listen_full (socket->handle, backlog)) == R_SOCKET_OK)
    socket->flags |= R_SOCKET_FLAG_LISTENING;

  return ret;
}

RSocket *
r_socket_accept (RSocket * socket, RSocketStatus * res)
{
  RSocketHandle handle;
  RSocket * ret;

  if (R_UNLIKELY (socket == NULL)) {
    if (res != NULL)
      *res = R_SOCKET_INVAL;
    return NULL;
  }

  if ((handle = r_io_socket_accept (socket->handle, res)) != R_IO_HANDLE_INVALID) {
    if ((ret = r_socket_new_with_handle (handle)) != NULL) {
      ret->family = socket->family;
      ret->type = socket->type;
      ret->proto = socket->proto;

      ret->flags |= R_SOCKET_FLAG_CONNECTED;
    } else {
      r_io_socket_close (handle);
      if (res != NULL)
        *res = R_SOCKET_OOM;
    }
  } else {
    ret = NULL;
  }

  return ret;
}

RSocketStatus
r_socket_connect (RSocket * socket, const RSocketAddress * address)
{
  RSocketStatus ret;

  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

  socket->flags |= R_SOCKET_FLAG_CONNECTING;
  switch ((ret = r_io_socket_connect (socket->handle, address))) {
    case R_SOCKET_WOULD_BLOCK:
      break;
    case R_SOCKET_OK:
      socket->flags |= R_SOCKET_FLAG_CONNECTED;
    default:
      socket->flags &= ~R_SOCKET_FLAG_CONNECTING;
      break;
  }

  return ret;
}

RSocketStatus
r_socket_shutdown (RSocket * socket, rboolean rx, rboolean tx)
{
  RSocketStatus ret;

  if ((ret = r_io_socket_shutdown (socket->handle, rx, tx)) == R_SOCKET_OK) {
    if (rx && tx)
      socket->flags &= ~R_SOCKET_FLAG_CONNECTED;
  }

  return ret;
}

RSocketStatus
r_socket_receive (RSocket * socket, ruint8 * buffer, rsize size, rsize * received)
{
  return r_io_socket_receive (socket->handle, buffer, size, received);
}

RSocketStatus
r_socket_receive_from (RSocket * socket, RSocketAddress * address, ruint8 * buffer, rsize size, rsize * received)
{
  return r_io_socket_receive_from (socket->handle, address, buffer, size, received);
}

RSocketStatus
r_socket_receive_message (RSocket * socket, RSocketAddress * address,
    RBuffer * buffer, rsize * received)
{
  return r_io_socket_receive_message (socket->handle, address, buffer, received);
}

RSocketStatus
r_socket_send (RSocket * socket, const ruint8 * buffer, rsize size, rsize * sent)
{
  return r_io_socket_send (socket->handle, buffer, size, sent);
}

RSocketStatus
r_socket_send_to (RSocket * socket, const RSocketAddress * address,
    const ruint8 * buffer, rsize size, rsize * sent)
{
  return r_io_socket_send_to (socket->handle, address, buffer, size, sent);
}

RSocketStatus
r_socket_send_message (RSocket * socket, const RSocketAddress * address,
    RBuffer * buffer, rsize * sent)
{
  return r_io_socket_send_message (socket->handle, address, buffer, sent);
}

