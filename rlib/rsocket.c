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

#include <rlib/file/rfd.h>
#include <rlib/rmem.h>


static inline RSocketStatus
r_socket_err_to_socket_status (int err)
{
  switch (err) {
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
    case EBADF:
      return R_SOCKET_BAD;
    case ECANCELED:
      return R_SOCKET_CANCELED;
    case EDESTADDRREQ:
      return R_SOCKET_NOT_BOUND;
#ifdef WSAENOTCONN
    case WSAENOTCONN:
#endif
    case ENOTCONN:
      return R_SOCKET_NOT_CONNECTED;
    case ECONNABORTED:
      return R_SOCKET_CONN_ABORTED;
    case ECONNREFUSED:
      return R_SOCKET_CONN_REFUSED;
    case ECONNRESET:
      return R_SOCKET_CONN_RESET;
#ifdef WSAEOPNOTSUPP
    case WSAEOPNOTSUPP:
#endif
    case EOPNOTSUPP:
      return R_SOCKET_INVALID_OP;
    case 0:
      return R_SOCKET_OK;
    default:
      return R_SOCKET_ERROR;
  }
}

static inline RSocketStatus
r_socket_errno_to_socket_status (void)
{
  return r_socket_err_to_socket_status (R_SOCKET_ERRNO);
}


static rboolean
r_socket_handle_close (RSocketHandle handle)
{
  int res;
  do {
#if defined (HAVE_WINSOCK2)
    res = closesocket (handle);
#elif defined (HAVE_POSIX_SOCKETS)
    res = close (handle);
#else
    res = ENOTSUP;
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
#elif defined (HAVE_POSIX_SOCKETS)
#ifdef SOCK_CLOEXEC
  if ((handle = socket (family, type | SOCK_CLOEXEC, proto)) >= 0)
    return handle;

  if (errno == EINVAL || errno == EPROTOTYPE)
    handle = socket (family, type, proto);
#else
  handle = socket (family, type, proto);
#ifdef R_OS_UNIX
  if (handle != R_SOCKET_HANDLE_INVALID)
    r_fd_unix_set_cloexec (handle, TRUE);
#endif
#endif
#else
  handle = R_SOCKET_HANDLE_INVALID;
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
  if (R_UNLIKELY (socket == NULL)) return FALSE;
  if (R_UNLIKELY (value == NULL)) return FALSE;

#ifdef HAVE_MOCK_SOCKETS
  (void) level;
  (void) optname;
  return FALSE;
#else
  socklen_t size = sizeof (int);
  *value = 0;
  if (getsockopt (socket->handle, level, optname, (rpointer)value, &size) != 0)
    return FALSE;

#if R_BYTE_ORDER == R_BIG_ENDIAN
  if (size != sizeof (int))
    *value >>= (8 * (sizeof (int) - size));
#endif

  return TRUE;
#endif
}

RSocketStatus
r_socket_get_error (RSocket * socket)
{
  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;

#ifdef HAVE_MOCK_SOCKETS
  return R_SOCKET_NOT_SUPPORTED;
#else
  int val = -1;
  r_socket_get_option (socket, SOL_SOCKET, SO_ERROR, &val);
  return r_socket_err_to_socket_status (val);
#endif
}

rboolean
r_socket_get_blocking (RSocket * socket)
{
  return (socket->flags & R_SOCKET_FLAG_BLOCKING) == R_SOCKET_FLAG_BLOCKING;
}

rboolean
r_socket_get_broadcast (RSocket * socket)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  return FALSE;
#else
  int val;
  return r_socket_get_option (socket, SOL_SOCKET, SO_BROADCAST, &val) && !!val;
#endif
}

rboolean
r_socket_get_keepalive (RSocket * socket)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  return FALSE;
#else
  int val;
  return r_socket_get_option (socket, SOL_SOCKET, SO_KEEPALIVE, &val) && !!val;
#endif
}

rboolean
r_socket_get_multicast_loop (RSocket * socket)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  return FALSE;
#else
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
#endif
}

ruint
r_socket_get_multicast_ttl (RSocket * socket)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  return 0;
#else
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
#endif
}

ruint
r_socket_get_ttl (RSocket * socket)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  return 0;
#else
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
#endif
}

rboolean
r_socket_set_option (RSocket * socket, int level, int optname, int value)
{
#ifdef HAVE_WINSOCK2
  return (setsockopt (socket->handle, level, optname,
        (rconstpointer)&value, sizeof (int)) == 0);
#elif defined (HAVE_POSIX_SOCKETS)
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
#else
  (void) socket;
  (void) level;
  (void) optname;
  (void) value;
  return FALSE;
#endif
}

rboolean
r_socket_set_blocking (RSocket * socket, rboolean blocking)
{
  rboolean ret;
#if defined (HAVE_WINSOCK2)
  rulong val = !blocking;
  ret = (ioctlsocket (socket->handle, FIONBIO, &val) != SOCKET_ERROR);
#elif defined (R_OS_UNIX)
  ret = r_fd_unix_set_nonblocking (socket->handle, !blocking);
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
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) broadcast;
  return FALSE;
#else
  return r_socket_set_option (socket, SOL_SOCKET, SO_BROADCAST, (int)broadcast);
#endif
}

rboolean
r_socket_set_keepalive (RSocket * socket, rboolean keepalive)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) keepalive;
  return FALSE;
#else
  return r_socket_set_option (socket, SOL_SOCKET, SO_KEEPALIVE, (int)keepalive);
#endif
}

rboolean
r_socket_set_multicast_loop (RSocket * socket, rboolean loop)
{
  rboolean ret;

#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) loop;
  ret = FALSE;
#else
  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV6:
      if (!r_socket_set_option (socket, IPPROTO_IPV6, IP_MULTICAST_LOOP, loop))
        return FALSE;
      /* fall through */
    case R_SOCKET_FAMILY_IPV4:
      ret = r_socket_set_option (socket, IPPROTO_IP, IP_MULTICAST_LOOP, loop);
      break;
    default:
      ret = FALSE;
      break;
  }
#endif

  return ret;
}

rboolean
r_socket_set_multicast_ttl (RSocket * socket, ruint ttl)
{
  rboolean ret;

#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) ttl;
  ret = FALSE;
#else
  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV6:
      if (!r_socket_set_option (socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, ttl))
        return FALSE;
      /* fall through */
    case R_SOCKET_FAMILY_IPV4:
      ret = r_socket_set_option (socket, IPPROTO_IP, IP_MULTICAST_TTL, ttl);
      break;
    default:
      ret = FALSE;
      break;
  }
#endif

  return ret;
}

rboolean
r_socket_set_ttl (RSocket * socket, ruint ttl)
{
  rboolean ret;

#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) ttl;
  ret = FALSE;
#else
  switch (socket->family) {
    case R_SOCKET_FAMILY_IPV6:
      if (!r_socket_set_option (socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ttl))
        return FALSE;
      /* fall through */
    case R_SOCKET_FAMILY_IPV4:
      ret = r_socket_set_option (socket, IPPROTO_IP, IP_TTL, ttl);
      break;
    default:
      ret = FALSE;
      break;
  }
#endif

  return ret;
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
  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

#ifdef HAVE_MOCK_SOCKETS
  (void) reuse;
  return R_SOCKET_NOT_SUPPORTED;
#else
  r_socket_set_option (socket, SOL_SOCKET, SO_REUSEADDR, !!reuse);
#ifdef SO_REUSEPORT
  r_socket_set_option (socket, SOL_SOCKET, SO_REUSEPORT,
      (reuse && socket->type == R_SOCKET_TYPE_DATAGRAM) ? 1 : 0);
#endif

  if (bind (socket->handle, (const struct sockaddr *)&address->addr, address->addrlen) == 0)
    return R_SOCKET_OK;

  return r_socket_errno_to_socket_status ();
#endif
}

RSocketStatus
r_socket_listen_full (RSocket * socket, ruint8 backlog)
{
  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;

#ifdef HAVE_MOCK_SOCKETS
  (void) backlog;
  return R_SOCKET_NOT_SUPPORTED;
#else
  if (listen (socket->handle, MIN (backlog, 128)) == 0) {
    socket->flags |= R_SOCKET_FLAG_LISTENING;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
#endif
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

#ifdef HAVE_MOCK_SOCKETS
  (void) handle;
  if (res != NULL)
    *res = R_SOCKET_NOT_SUPPORTED;
  ret = NULL;
#else
  /* FIXME: Use accept4 ?? */
  do {
    handle = accept (socket->handle, NULL, 0);
  } while (handle == R_SOCKET_HANDLE_INVALID && R_SOCKET_ERRNO == EINTR);

  if (handle != R_SOCKET_HANDLE_INVALID) {
    if ((ret = r_socket_new_with_handle (handle)) != NULL) {
      ret->family = socket->family;
      ret->type = socket->type;
      ret->proto = socket->proto;

      ret->flags |= R_SOCKET_FLAG_CONNECTED;
#ifdef HAVE_WINSOCK2
      WSAEventSelect (handle, NULL, 0);
#endif
#ifdef R_OS_UNIX
      r_fd_unix_set_cloexec (handle, TRUE);
#endif
    } else {
      r_socket_handle_close (handle);
      if (res != NULL)
        *res = R_SOCKET_OOM;
      return NULL;
    }
  } else {
    ret = NULL;
  }

  if (res != NULL) {
    if (ret == NULL)
      *res = r_socket_errno_to_socket_status ();
    else
      *res = R_SOCKET_OK;
  }
#endif

  return ret;
}

RSocketStatus
r_socket_connect (RSocket * socket, const RSocketAddress * address)
{
  int res;
  RSocketStatus ret;

  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

#ifdef HAVE_MOCK_SOCKETS
  (void) res;
  ret = R_SOCKET_NOT_SUPPORTED;
#else
  do {
    if ((res = connect (socket->handle, (struct sockaddr *)&address->addr, address->addrlen)) == 0) {
      socket->flags &= ~R_SOCKET_FLAG_CONNECTING;
      socket->flags |= R_SOCKET_FLAG_CONNECTED;
      return R_SOCKET_OK;
    }
  } while (res != 0 && R_SOCKET_ERRNO == EINTR);

  if ((ret = r_socket_errno_to_socket_status ()) == R_SOCKET_WOULD_BLOCK)
    socket->flags |= R_SOCKET_FLAG_CONNECTING;
#endif

  return ret;
}

RSocketStatus
r_socket_shutdown (RSocket * socket, rboolean rx, rboolean tx)
{
  int how;

  if (R_UNLIKELY (socket == NULL)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (!rx && !tx)) return R_SOCKET_INVAL;

#ifdef HAVE_MOCK_SOCKETS
  (void) how;
  return R_SOCKET_NOT_SUPPORTED;
#else
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
#endif
}

RSocketStatus
r_socket_receive (RSocket * socket, ruint8 * buffer, rsize size, rsize * received)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) buffer;
  (void) size;
  (void) received;
  return R_SOCKET_NOT_SUPPORTED;
#else
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
#endif
}

RSocketStatus
r_socket_receive_from (RSocket * socket, RSocketAddress * address, ruint8 * buffer, rsize size, rsize * received)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) address;
  (void) buffer;
  (void) size;
  (void) received;
  return R_SOCKET_NOT_SUPPORTED;
#else
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
#endif
}

RSocketStatus
r_socket_receive_message (RSocket * socket, RSocketAddress * address,
    RBuffer * buf, rsize * received)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) address;
  (void) buf;
  (void) received;
  return R_SOCKET_NOT_SUPPORTED;
#else
  rsize i, mem_count, b;
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
  if (address != NULL) {
    msg.msg_name = &address->addr;
    msg.msg_namelen = address->addrlen;
  } else {
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
  }
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
  if (address != NULL) {
    res = WSARecvFrom (socket->handle, bufs, mem_count, &winrecv, &winflags,
        (struct sockaddr *)&address->addr, &address->addrlen, NULL, NULL);
  } else {
    res = WSARecvFrom (socket->handle, bufs, mem_count, &winrecv, &winflags,
        NULL, 0, NULL, NULL);
  }
  b = res != SOCKET_ERROR ? (rsize)winrecv : 0;
#else
  do {
    res = recvmsg (socket->handle, &msg, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);
  if (address != NULL)
    address->addrlen = msg.msg_namelen;
  b = res > 0 ? (rsize)res : 0;
#endif

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buf, i);
    r_mem_unmap (mem, &info[i]);

    if (b >= mem->size) {
      b -= mem->size;
    } else {
      r_mem_resize (mem, mem->offset, b);
      b = 0;
    }
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
#endif
}

RSocketStatus
r_socket_send (RSocket * socket, const ruint8 * buffer, rsize size, rsize * sent)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) buffer;
  (void) size;
  (void) sent;
  return R_SOCKET_NOT_SUPPORTED;
#else
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
#endif
}

RSocketStatus
r_socket_send_to (RSocket * socket, const RSocketAddress * address,
    const ruint8 * buffer, rsize size, rsize * sent)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) address;
  (void) buffer;
  (void) size;
  (void) sent;
  return R_SOCKET_NOT_SUPPORTED;
#else
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
#endif
}

RSocketStatus
r_socket_send_message (RSocket * socket, const RSocketAddress * address,
    RBuffer * buf, rsize * sent)
{
#ifdef HAVE_MOCK_SOCKETS
  (void) socket;
  (void) address;
  (void) buf;
  (void) sent;
  return R_SOCKET_NOT_SUPPORTED;
#else
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
  if (address != NULL) {
    msg.msg_name = (rpointer)&address->addr;
    msg.msg_namelen = address->addrlen;
  } else {
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
  }
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
  if (address != NULL) {
    res = WSASendTo (socket->handle, bufs, mem_count, &winsent, 0,
        (const struct sockaddr *)&address->addr, (int)address->addrlen,
        NULL, NULL);
  } else {
    res = WSASendTo (socket->handle, bufs, mem_count, &winsent, 0, NULL, 0,
        NULL, NULL);
  }
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
#endif
}

