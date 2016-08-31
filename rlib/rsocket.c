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
#include <rlib/rsocket.h>
#include "rnetworking-private.h"
#include "rlib-private.h"

#include <rlib/rfd.h>
#include <rlib/rmem.h>


struct _RSocket {
  RRef ref;

  RSocketHandle   handle;
  RSocketFamily   family;
  RSocketType     type;
  RSocketProtocol proto;
  RSocketFlags    flags;
};

static rboolean
r_socket_handle_close (RSocketHandle handle)
{
  int res;
  do {
#ifdef HAVE_WINSOCK2
    res = closesocket (handle);
#else
    res = close (handle);
#endif
  } while (res != 0 && R_SOCKET_ERRNO == EINTR);

  return res == 0;
}

static void
r_socket_free (RSocket * socket)
{
  r_socket_close (socket);
  r_free (socket);
}

static RSocketHandle
r_socket_handle_new (RSocketFamily family, RSocketType type, RSocketProtocol proto)
{
  RSocketHandle handle;
#ifdef HAVE_WINSOCK2
  handle = WSASocket (family, type, proto, NULL, 0, 0);
#else
#ifdef SOCK_CLOEXEC
  if ((handle = socket (family, type | SOCK_CLOEXEC, proto)) >= 0)
    return handle;

  if (errno == EINVAL || errno == EPROTOTYPE)
#endif
    handle = socket (family, type, proto);

#ifdef R_OS_UNIX
  if (handle >= 0)
    r_fd_unix_set_cloexec (handle, TRUE);
#endif
#endif

  return handle;
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

  if ((handle = r_socket_handle_new (family, type, proto)) == R_SOCKET_HANDLE_INVALID)
    return NULL;

  if ((ret = r_socket_new_with_handle (handle)) != NULL) {
    ret->family = family;
    ret->type = type;
    ret->proto = proto;
  } else {
    r_socket_handle_close (handle);
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
  struct sockaddr_storage ss;
  socklen_t len = sizeof (struct sockaddr_storage);

  if (getsockname (socket->handle, (struct sockaddr *)&ss, &len) == 0)
    ret = r_socket_address_new_from_native (&ss, len);

  return ret;
}

RSocketAddress *
r_socket_get_remote_address (RSocket * socket)
{
  RSocketAddress * ret = NULL;
  struct sockaddr_storage ss;
  socklen_t len = sizeof (struct sockaddr_storage);

  if (getpeername (socket->handle, (struct sockaddr *)&ss, &len) == 0) {
    ret = r_socket_address_new_from_native (&ss, len);
  }

  return ret;
}

rboolean
r_socket_get_option (RSocket * socket, int level, int optname, int * value)
{
  if (R_UNLIKELY (value == NULL)) return FALSE;

  socklen_t size = sizeof (int);
  *value = 0;
  if (getsockopt (socket->handle, level, optname, (rpointer)value, &size) != 0)
    return FALSE;

#if R_BYTE_ORDER == R_BIG_ENDIAN
  if (size != sizeof (int))
    *value >>= (8 * (sizeof (int) - size));
#endif

  return TRUE;
}

rboolean
r_socket_get_blocking (RSocket * socket)
{
  return (socket->flags & R_SOCKET_FLAG_BLOCKING) == R_SOCKET_FLAG_BLOCKING;
}

rboolean
r_socket_get_broadcast (RSocket * socket)
{
  int val;
  return r_socket_get_option (socket, SOL_SOCKET, SO_BROADCAST, &val) && !!val;
}

rboolean
r_socket_get_keepalive (RSocket * socket)
{
  int val;
  return r_socket_get_option (socket, SOL_SOCKET, SO_KEEPALIVE, &val) && !!val;
}

rboolean
r_socket_get_multicast_loop (RSocket * socket)
{
  int lvl, val;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      lvl = IPPROTO_IP;
      break;
    case R_SOCKET_FAMILY_IPV6:
      lvl = IPPROTO_IPV6;
      break;
    default:
      return FALSE;
  }

  return r_socket_get_option (socket, lvl, IP_MULTICAST_LOOP, &val) && !!val;
}

ruint
r_socket_get_multicast_ttl (RSocket * socket)
{
  rboolean res;
  int val;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      res = r_socket_get_option (socket, IPPROTO_IP, IP_MULTICAST_TTL, &val);
      break;
    case R_SOCKET_FAMILY_IPV6:
      res = r_socket_get_option (socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val);
      break;
    default:
      return 0;
  }

  return res ? MAX (val, 0) : 0;
}

ruint
r_socket_get_ttl (RSocket * socket)
{
  rboolean res;
  int val;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV4:
      res = r_socket_get_option (socket, IPPROTO_IP, IP_TTL, &val);
      break;
    case R_SOCKET_FAMILY_IPV6:
      res = r_socket_get_option (socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val);
      break;
    default:
      return 0;
  }

  return res ? MAX (val, 0) : 0;
}

rboolean
r_socket_set_option (RSocket * socket, int level, int optname, int value)
{
#ifdef HAVE_WINSOCK2
  return (setsockopt (socket->handle, level, optname,
        (rconstpointer)&value, sizeof (int)) == 0);
#else
  if (setsockopt (socket->handle, level, optname, &value, sizeof (int)) == 0)
    return TRUE;

#ifndef R_OS_LINUX
  /* Try to set value less than sizeof (int) */
  if (errno == EINVAL && value >= RINT8_MIN && value <= RINT8_MAX) {
#if R_BYTE_ORDER == R_BIG_ENDIAN
      value = value << (8 * (sizeof (int) - 1));
#endif
      if (setsockopt (socket->handle, level, optname, &value, 1) == 0)
        return TRUE;
    }
#endif

  return FALSE;
#endif
}

rboolean
r_socket_set_blocking (RSocket * socket, rboolean blocking)
{
  rboolean ret;
#ifdef HAVE_WINSOCK2
  rulong val = !blocking;
  ret = (ioctlsocket (socket->handle, FIONBIO, &val) != SOCKET_ERROR);
#else
  ret = r_fd_unix_set_nonblocking (socket->handle, !blocking);
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
  return r_socket_set_option (socket, SOL_SOCKET, SO_BROADCAST, (int)broadcast);
}

rboolean
r_socket_set_keepalive (RSocket * socket, rboolean keepalive)
{
  return r_socket_set_option (socket, SOL_SOCKET, SO_KEEPALIVE, (int)keepalive);
}

rboolean
r_socket_set_multicast_loop (RSocket * socket, rboolean loop)
{
  rboolean ret;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV6:
      if (!r_socket_set_option (socket, IPPROTO_IPV6, IP_MULTICAST_LOOP, loop))
        return FALSE;
      /* fall through */
    case R_SOCKET_FAMILY_IPV4:
      ret = r_socket_set_option (socket, IPPROTO_IP, IP_MULTICAST_LOOP, loop);
      break;
    default:
      return FALSE;
  }

  return ret;
}

rboolean
r_socket_set_multicast_ttl (RSocket * socket, ruint ttl)
{
  rboolean ret;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV6:
      if (!r_socket_set_option (socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, ttl))
        return FALSE;
      /* fall through */
    case R_SOCKET_FAMILY_IPV4:
      ret = r_socket_set_option (socket, IPPROTO_IP, IP_MULTICAST_TTL, ttl);
      break;
    default:
      return FALSE;
  }

  return ret;
}

rboolean
r_socket_set_ttl (RSocket * socket, ruint ttl)
{
  rboolean ret;

  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV6:
      if (!r_socket_set_option (socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ttl))
        return FALSE;
      /* fall through */
    case R_SOCKET_FAMILY_IPV4:
      ret = r_socket_set_option (socket, IPPROTO_IP, IP_TTL, ttl);
      break;
    default:
      return FALSE;
  }

  return ret;
}



static inline RSocketStatus
r_socket_errno_to_socket_status (void)
{
  int e;

  switch ((e = R_SOCKET_ERRNO)) {
#ifdef WSAEWOULDBLOCK
    case WSAEWOULDBLOCK:
    case WSAEINPROGRESS:
#endif
    case EAGAIN:
    case EINPROGRESS:
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
      return R_SOCKET_WOULD_BLOCK;
    case EDESTADDRREQ:
      return R_SOCKET_NOT_BOUND;
#ifdef WSAENOTCONN
    case WSAENOTCONN:
#endif
    case ENOTCONN:
      return R_SOCKET_NOT_CONNECTED;
#ifdef WSAEOPNOTSUPP
    case WSAEOPNOTSUPP:
#endif
    case EOPNOTSUPP:
      return R_SOCKET_INVALID_OP;
    default:
      return R_SOCKET_ERROR;
  }
}

RSocketStatus
r_socket_close (RSocket * socket)
{
  RSocketStatus ret;

  if (socket->handle != R_SOCKET_HANDLE_INVALID) {
    ret = r_socket_handle_close (socket->handle) ? R_SOCKET_OK : R_SOCKET_ERROR;
    socket->flags |= R_SOCKET_FLAG_CLOSED;
    socket->handle = R_SOCKET_HANDLE_INVALID;
  } else {
    ret = R_SOCKET_OK;
  }

  return ret;
}

RSocketStatus
r_socket_bind (RSocket * socket, const RSocketAddress * address, rboolean reuse)
{
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

  r_socket_set_option (socket, SOL_SOCKET, SO_REUSEADDR, !!reuse);
#ifdef SO_REUSEPORT
  r_socket_set_option (socket, SOL_SOCKET, SO_REUSEPORT,
      (reuse && socket->type == R_SOCKET_TYPE_DATAGRAM) ? 1 : 0);
#endif

  if (bind (socket->handle, (const struct sockaddr *)&address->addr, address->addrlen) == 0)
    return R_SOCKET_OK;

  return r_socket_errno_to_socket_status ();
}

RSocketStatus
r_socket_listen_full (RSocket * socket, ruint8 backlog)
{
  if (listen (socket->handle, MIN (backlog, 128)) == 0) {
    socket->flags |= R_SOCKET_FLAG_LISTENING;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
}

RSocketStatus
r_socket_accept (RSocket * socket, RSocket ** newsock)
{
  RSocketHandle handle;

  if (R_UNLIKELY (newsock == NULL)) return R_SOCKET_INVAL;

  /* FIXME: Use accept4 ?? */
  do {
    handle = accept (socket->handle, NULL, 0);
  } while (handle == R_SOCKET_HANDLE_INVALID && R_SOCKET_ERRNO == EINTR);

  if (handle != R_SOCKET_HANDLE_INVALID) {
    if ((*newsock = r_socket_new_with_handle (handle)) != NULL) {
      (*newsock)->family = socket->family;
      (*newsock)->type = socket->type;
      (*newsock)->proto = socket->proto;

      (*newsock)->flags |= R_SOCKET_FLAG_CONNECTED;
#ifdef HAVE_WINSOCK2
      WSAEventSelect (handle, NULL, 0);
#endif
#ifdef R_OS_UNIX
      r_fd_unix_set_cloexec (handle, TRUE);
#endif
      return R_SOCKET_OK;
    }

    r_socket_handle_close (handle);
    return R_SOCKET_OOM;
  }

  return r_socket_errno_to_socket_status ();
}

RSocket *
r_socket_accept_simple (RSocket * socket)
{
  RSocket * newsock;
  if (r_socket_accept (socket, &newsock) == R_SOCKET_OK)
    return newsock;

  return NULL;
}

RSocketStatus
r_socket_connect (RSocket * socket, const RSocketAddress * address)
{
  int res;
  RSocketStatus ret;

  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

  do {
    if ((res = connect (socket->handle, (struct sockaddr *)&address->addr, address->addrlen)) == 0) {
      socket->flags &= ~R_SOCKET_FLAG_CONNECTING;
      socket->flags |= R_SOCKET_FLAG_CONNECTED;
      return R_SOCKET_OK;
    }
  } while (res != 0 && R_SOCKET_ERRNO == EINTR);

  if ((ret = r_socket_errno_to_socket_status ()) == R_SOCKET_WOULD_BLOCK)
    socket->flags |= R_SOCKET_FLAG_CONNECTING;

  return ret;
}

RSocketStatus
r_socket_shutdown (RSocket * socket, rboolean rx, rboolean tx)
{
  int how;

  if (R_UNLIKELY (!rx && !tx)) return R_SOCKET_INVAL;

#ifdef HAVE_WINSOCK2
  if (rx && tx) how = SD_BOTH;
  else if (rx)  how = SD_RECEIVE;
  else          how = SD_SEND;
#else
  if (rx && tx) how = SHUT_RDWR;
  else if (rx)  how = SHUT_RD;
  else          how = SHUT_WR;
#endif

  if (shutdown (socket->handle, how) == 0) {
    if (rx && tx)
      socket->flags &= ~R_SOCKET_FLAG_CONNECTED;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
}

RSocketStatus
r_socket_receive (RSocket * socket, ruint8 * buffer, rsize size, rsize * received)
{
#ifdef HAVE_WINSOCK2
  int res;
#else
  rssize res;
#endif

  do {
    res = recv (socket->handle, buffer, size, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  if (res >= 0) {
    if (received != NULL)
      *received = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
}

RSocketStatus
r_socket_receive_from (RSocket * socket, RSocketAddress * address, ruint8 * buffer, rsize size, rsize * received)
{
#ifdef HAVE_WINSOCK2
  int res;
#else
  rssize res;
#endif

  do {
    res = recvfrom (socket->handle, buffer, size, 0,
        (struct sockaddr *)&address->addr, &address->addrlen);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  if (res >= 0) {
    if (received != NULL)
      *received = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
}

RSocketStatus
r_socket_receive_message (RSocket * socket, RSocketAddress * address,
    RBuffer * buf, rsize * received)
{
  rsize i, mem_count;
  RMemMapInfo * info;
#ifdef HAVE_WINSOCK2
  int res;
  LPWSABUF bufs;
  DWORD winrecv, winflags;
#else
  rssize res;
  struct msghdr msg;
#endif

  mem_count = r_buffer_mem_count (buf);

#ifdef HAVE_WINSOCK2
  bufs = r_alloca (mem_count * sizeof (WSABUF));
#else
  msg.msg_name = &address->addr;
  msg.msg_namelen = address->addrlen;
  msg.msg_iov = r_alloca (mem_count * sizeof (struct iovec));
  msg.msg_iovlen = mem_count;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
#endif

  info = r_alloca (mem_count * sizeof (RMemMapInfo));
  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buf, i);
    if (r_mem_map (mem, &info[i], R_MEM_MAP_WRITE)) {
#ifdef HAVE_WINSOCK2
      bufs[i].len = info[i].size;
      bufs[i].buf = info[i].data;
#else
      msg.msg_iov[i].iov_base = info[i].data;
      msg.msg_iov[i].iov_len = info[i].size;
#endif
    } else {
      /* WARNING */
#ifdef HAVE_WINSOCK2
      bufs[i].len = 0;
      bufs[i].buf = "";
#else
      msg.msg_iov[i].iov_base = "";
      msg.msg_iov[i].iov_len = 0;
#endif
    }
    r_mem_unref (mem);
  }

#ifdef HAVE_WINSOCK2
  winrecv = winflags = 0;
  res = WSARecvFrom (socket->handle, bufs, mem_count, &winrecv, &winflags,
      (struct sockaddr *)&address->addr, &address->addrlen, NULL, NULL);
#else
  do {
    res = recvmsg (socket->handle, &msg, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);
#endif

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buf, i);
    r_mem_unmap (mem, &info[i]);
    r_mem_unref (mem);
  }

#ifdef HAVE_WINSOCK2
  if (res != SOCKET_ERROR) {
    if (received != NULL)
      *received = (rsize)winrecv;
    return R_SOCKET_OK;
  }
#else
  if (res >= 0) {
    if (received != NULL)
      *received = (rsize)res;
    return R_SOCKET_OK;
  }
#endif

  return r_socket_errno_to_socket_status ();
}

RSocketStatus
r_socket_send (RSocket * socket, const ruint8 * buffer, rsize size, rsize * sent)
{
  rssize res;

  do {
    res = send (socket->handle, buffer, size, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  if (res >= 0) {
    if (sent != NULL)
      *sent = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
}

RSocketStatus
r_socket_send_to (RSocket * socket, const RSocketAddress * address,
    const ruint8 * buffer, rsize size, rsize * sent)
{
#ifdef HAVE_WINSOCK2
  int res;
#else
  rssize res;
#endif

  do {
    res = sendto (socket->handle, buffer, size, 0,
        (const struct sockaddr *)&address->addr, address->addrlen);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  if (res >= 0) {
    if (sent != NULL)
      *sent = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
}

RSocketStatus
r_socket_send_message (RSocket * socket, const RSocketAddress * address,
    RBuffer * buf, rsize * sent)
{
  rsize i, mem_count;
  RMemMapInfo * info;
#ifdef HAVE_WINSOCK2
  int res;
  LPWSABUF bufs;
  DWORD winsent;
#else
  rssize res;
  struct msghdr msg;
#endif

  mem_count = r_buffer_mem_count (buf);

#ifdef HAVE_WINSOCK2
  bufs = r_alloca (mem_count * sizeof (WSABUF));
#else
  msg.msg_name = (rpointer)&address->addr;
  msg.msg_namelen = address->addrlen;
  msg.msg_iovlen = mem_count;
  msg.msg_iov = r_alloca (msg.msg_iovlen * sizeof (struct iovec));
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
#endif

  info = r_alloca (mem_count * sizeof (RMemMapInfo));
  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buf, i);
    if (r_mem_map (mem, &info[i], R_MEM_MAP_READ)) {
#ifdef HAVE_WINSOCK2
      bufs[i].len = info[i].size;
      bufs[i].buf = info[i].data;
#else
      msg.msg_iov[i].iov_base = info[i].data;
      msg.msg_iov[i].iov_len = info[i].size;
#endif
    } else {
      /* WARNING */
#ifdef HAVE_WINSOCK2
      bufs[i].len = 0;
      bufs[i].buf = "";
#else
      msg.msg_iov[i].iov_base = "";
      msg.msg_iov[i].iov_len = 0;
#endif
    }
    r_mem_unref (mem);
  }

#ifdef HAVE_WINSOCK2
  winsent = 0;
  res = WSASendTo (socket->handle, bufs, mem_count, &winsent, 0,
      (const struct sockaddr *)&address->addr, (int)address->addrlen, NULL, NULL);
#else
  do {
    res = sendmsg (socket->handle, &msg, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);
#endif

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buf, i);
    r_mem_unmap (mem, &info[i]);
    r_mem_unref (mem);
  }

#ifdef HAVE_WINSOCK2
  if (res != SOCKET_ERROR) {
    if (sent != NULL)
      *sent = (rsize)winsent;
    return R_SOCKET_OK;
  }
#else
  if (res >= 0) {
    if (sent != NULL)
      *sent = (rsize)res;
    return R_SOCKET_OK;
  }
#endif

  return r_socket_errno_to_socket_status ();
}

