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

#include "config.h"
#include "rsocket-private.h"
#include <rlib/riosocket.h>

#include <rlib/rio.h>

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

RIOHandle
r_io_socket (RSocketFamily family, RSocketType type, RSocketProtocol proto)
{
  RIOHandle ret;
#ifdef HAVE_WINSOCK2
  ret = WSASocket (family, type, proto, NULL, 0, 0);
#elif defined (HAVE_POSIX_SOCKETS)
#ifdef SOCK_CLOEXEC
  if ((ret = socket (family, type | SOCK_CLOEXEC, proto)) != R_IO_HANDLE_INVALID ||
      (errno != EINVAL && errno != EPROTOTYPE))
    return ret;
#endif

  ret = socket (family, type, proto);
  if (ret != R_IO_HANDLE_INVALID)
    r_io_unix_set_cloexec (ret, TRUE);
#else
  ret = R_IO_HANDLE_INVALID;
#endif

  return ret;
}

RSocketStatus
r_io_get_socket_option (RIOHandle handle, int level, int optname, int * value)
{
#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  socklen_t size = sizeof (int);
#endif
  RSocketStatus ret;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (value == NULL)) return R_SOCKET_INVAL;
  *value = 0;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  if (getsockopt (handle, level, optname, (rpointer)value, &size) == 0) {
#if R_BYTE_ORDER == R_BIG_ENDIAN
    if (size != sizeof (int))
      *value >>= (8 * (sizeof (int) - size));
#endif
    ret = R_SOCKET_OK;
  } else {
    ret = r_socket_errno_to_socket_status ();
  }
#else
  (void) level;
  (void) optname;
  ret = R_SOCKET_NOT_SUPPORTED;
#endif

  return ret;
}

RSocketStatus
r_io_set_socket_option (RIOHandle handle, int level, int optname, int value)
{
  int res;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;

#ifdef HAVE_WINSOCK2
  res = setsockopt (handle, level, optname, (rconstpointer)&value, sizeof (int));
#elif defined (HAVE_POSIX_SOCKETS)
  res = setsockopt (handle, level, optname, &value, sizeof (int));

#ifndef R_OS_LINUX
  /* Try to set value less than sizeof (int) */
  if (res != 0 && errno == EINVAL && value >= RINT8_MIN && value <= RINT8_MAX) {
#if R_BYTE_ORDER == R_BIG_ENDIAN
    value = value << (8 * (sizeof (int) - 1));
#endif
    res = setsockopt (handle, level, optname, &value, 1);
  }
#endif

  return (res == 0) ? R_SOCKET_OK : r_socket_errno_to_socket_status ();
#else
  (void) level;
  (void) optname;
  (void) value;
  (void) res;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_get_socket_error (RIOHandle handle, RSocketStatus * error)
{
  RSocketStatus ret;
  int val = -1;

  if ((ret = r_io_get_socket_option (handle, SOL_SOCKET, SO_ERROR, &val)) == R_SOCKET_OK)
    *error = r_socket_err_to_socket_status (val);

  return ret;
}

static inline RSocketStatus
r_io_get_socket_option_bool (RIOHandle handle, int level, int optname, rboolean * b)
{
  RSocketStatus ret;
  int val = 0;

  if ((ret = r_io_get_socket_option (handle, level, optname, &val)) == R_SOCKET_OK)
    *b = (val != 0);

  return ret;
}

RSocketStatus
r_io_get_socket_acceptconn (RIOHandle handle, rboolean * listening)
{
  return r_io_get_socket_option_bool (handle, SOL_SOCKET, SO_ACCEPTCONN, listening);
}

RSocketStatus
r_io_get_socket_broadcast (RIOHandle handle, rboolean * broadcast)
{
  return r_io_get_socket_option_bool (handle, SOL_SOCKET, SO_BROADCAST, broadcast);
}

RSocketStatus
r_io_get_socket_keepalive (RIOHandle handle, rboolean * keepalive)
{
  return r_io_get_socket_option_bool (handle, SOL_SOCKET, SO_KEEPALIVE, keepalive);
}

RSocketStatus
r_io_get_socket_reuseaddr (RIOHandle handle, rboolean * reuse)
{
  return r_io_get_socket_option_bool (handle, SOL_SOCKET, SO_REUSEADDR, reuse);
}

RSocketStatus
r_io_set_socket_broadcast (RIOHandle handle, rboolean broadcast)
{
  return r_io_set_socket_option (handle, SOL_SOCKET, SO_BROADCAST, broadcast);
}

RSocketStatus
r_io_set_socket_keepalive (RIOHandle handle, rboolean keepalive)
{
  return r_io_set_socket_option (handle, SOL_SOCKET, SO_KEEPALIVE, keepalive);
}

RSocketStatus
r_io_set_socket_reuseaddr (RIOHandle handle, rboolean reuse)
{
  return r_io_set_socket_option (handle, SOL_SOCKET, SO_REUSEADDR, reuse);
}

RSocketStatus
r_io_socket_close (RIOHandle handle)
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

  return (res == 0) ? R_SOCKET_OK : r_socket_errno_to_socket_status ();
}

RSocketStatus
r_io_socket_bind (RIOHandle handle, const RSocketAddress * address)
{
  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  if (bind (handle, (const struct sockaddr *)&address->addr, address->addrlen) == 0)
    return R_SOCKET_OK;

  return r_socket_errno_to_socket_status ();
#else
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_socket_listen_full (RIOHandle handle, ruint8 backlog)
{
  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  if (listen (handle, MIN (backlog, 128)) == 0)
    return R_SOCKET_OK;

  return r_socket_errno_to_socket_status ();
#else
  (void) backlog;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RIOHandle
r_io_socket_accept (RIOHandle handle, RSocketStatus * res)
{
  RIOHandle ret;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) {
    if (res != NULL)
      *res = R_SOCKET_INVAL;
    return R_IO_HANDLE_INVALID;
  }

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  /* FIXME: Use accept4 ?? */
  do {
    ret = accept (handle, NULL, 0);
  } while (ret == R_IO_HANDLE_INVALID && R_SOCKET_ERRNO == EINTR);

  if (ret != R_SOCKET_HANDLE_INVALID) {
#ifdef HAVE_WINSOCK2
    WSAEventSelect (ret, NULL, 0);
#endif
#ifdef R_OS_UNIX
    r_io_unix_set_cloexec (ret, TRUE);
#endif
    if (res != NULL)
      *res = R_SOCKET_OK;
  } else if (res != NULL) {
    *res = r_socket_errno_to_socket_status ();
  }

#else
  if (res != NULL)
    *res = R_SOCKET_NOT_SUPPORTED;
  ret = R_IO_HANDLE_INVALID;
#endif

  return ret;
}

RSocketStatus
r_io_socket_connect (RIOHandle handle, const RSocketAddress * address)
{
  int res;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  do {
    if ((res = connect (handle, (struct sockaddr *)&address->addr, address->addrlen)) == 0)
      return R_SOCKET_OK;
  } while (res != 0 && R_SOCKET_ERRNO == EINTR);

  return r_socket_errno_to_socket_status ();
#else
  (void) res;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_socket_shutdown (RIOHandle handle, rboolean rx, rboolean tx)
{
  int how;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (!rx && !tx)) return R_SOCKET_INVAL;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
#ifdef HAVE_WINSOCK2
  if (rx && tx) how = SD_BOTH;
  else if (rx)  how = SD_RECEIVE;
  else          how = SD_SEND;
#else
  if (rx && tx) how = SHUT_RDWR;
  else if (rx)  how = SHUT_RD;
  else          how = SHUT_WR;
#endif

  if (shutdown (handle, how) == 0)
    return R_SOCKET_OK;

  return r_socket_errno_to_socket_status ();
#else
  (void) how;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_socket_receive (RIOHandle handle, rpointer buffer, rsize size, rsize * received)
{
#if defined (HAVE_WINSOCK2)
  int res;
#elif defined (HAVE_POSIX_SOCKETS)
  rssize res;
#endif

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  do {
    res = recv (handle, buffer, size, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  if (res >= 0) {
    if (received != NULL)
      *received = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
#else
  (void) buffer;
  (void) size;
  (void) received;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_socket_receive_from (RIOHandle handle, RSocketAddress * address, rpointer buffer, rsize size, rsize * received)
{
#if defined (HAVE_WINSOCK2)
  int res;
#elif defined (HAVE_POSIX_SOCKETS)
  rssize res;
#endif

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  do {
    res = recvfrom (handle, buffer, size, 0,
        (struct sockaddr *)&address->addr, &address->addrlen);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  if (res >= 0) {
    if (received != NULL)
      *received = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
#else
  (void) buffer;
  (void) size;
  (void) received;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_socket_receive_message (RIOHandle handle, RSocketAddress * address, RBuffer * buffer, rsize * received)
{
#if defined (HAVE_WINSOCK2)
  rsize i, mem_count, b;
  RMemMapInfo * info;
  int res;
  LPWSABUF bufs;
  DWORD winrecv, winflags;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (buffer == NULL)) return R_SOCKET_INVAL;

  mem_count = r_buffer_mem_count (buffer);
  info = r_alloca (mem_count * sizeof (RMemMapInfo));
  bufs = r_alloca (mem_count * sizeof (WSABUF));

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buffer, i);
    if (r_mem_map (mem, &info[i], R_MEM_MAP_WRITE)) {
      bufs[i].len = info[i].size;
      bufs[i].buf = info[i].data;
    } else {
      /* WARNING */
      bufs[i].len = 0;
      bufs[i].buf = "";
    }
    r_mem_unref (mem);
  }

  winrecv = winflags = 0;
  if (address != NULL) {
    res = WSARecvFrom (handle, bufs, mem_count, &winrecv, &winflags,
        (struct sockaddr *)&address->addr, &address->addrlen, NULL, NULL);
  } else {
    res = WSARecvFrom (handle, bufs, mem_count, &winrecv, &winflags,
        NULL, 0, NULL, NULL);
  }
  b = res != SOCKET_ERROR ? (rsize)winrecv : 0;

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buffer, i);
    r_mem_unmap (mem, &info[i]);

    if (b >= mem->size) {
      b -= mem->size;
    } else {
      r_mem_resize (mem, mem->offset, b);
      b = 0;
    }
    r_mem_unref (mem);
  }

  if (res != SOCKET_ERROR) {
    if (received != NULL)
      *received = (rsize)winrecv;
    return R_SOCKET_OK;
  }
  return r_socket_errno_to_socket_status ();
#elif defined (HAVE_POSIX_SOCKETS)
  rsize i, mem_count, b;
  RMemMapInfo * info;
  rssize res;
  struct msghdr msg;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (buffer == NULL)) return R_SOCKET_INVAL;

  mem_count = r_buffer_mem_count (buffer);
  info = r_alloca (mem_count * sizeof (RMemMapInfo));

  msg.msg_iov = r_alloca (mem_count * sizeof (struct iovec));
  msg.msg_iovlen = mem_count;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buffer, i);
    if (r_mem_map (mem, &info[i], R_MEM_MAP_WRITE)) {
      msg.msg_iov[i].iov_base = info[i].data;
      msg.msg_iov[i].iov_len = info[i].size;
    } else {
      /* WARNING */
      msg.msg_iov[i].iov_base = "";
      msg.msg_iov[i].iov_len = 0;
    }
    r_mem_unref (mem);
  }

  if (address != NULL) {
    msg.msg_name = &address->addr;
    msg.msg_namelen = address->addrlen;
  } else {
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
  }
  do {
    res = recvmsg (handle, &msg, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);
  if (address != NULL)
    address->addrlen = msg.msg_namelen;
  b = res > 0 ? (rsize)res : 0;

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buffer, i);
    r_mem_unmap (mem, &info[i]);

    if (b >= mem->size) {
      b -= mem->size;
    } else {
      r_mem_resize (mem, mem->offset, b);
      b = 0;
    }
    r_mem_unref (mem);
  }

  if (res >= 0) {
    if (received != NULL)
      *received = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
#else
  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (buffer == NULL)) return R_SOCKET_INVAL;
  (void) address;
  (void) received;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_socket_send (RIOHandle handle, rconstpointer buffer, rsize size, rsize * sent)
{
#if defined (HAVE_WINSOCK2)
  int res;
#elif defined (HAVE_POSIX_SOCKETS)
  rssize res;
#endif

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  do {
    res = send (handle, buffer, size, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  if (res >= 0) {
    if (sent != NULL)
      *sent = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
#else
  (void) buffer;
  (void) size;
  (void) sent;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_socket_send_to (RIOHandle handle, const RSocketAddress * address, rconstpointer buffer, rsize size, rsize * sent)
{
#if defined (HAVE_WINSOCK2)
  int res;
#elif defined (HAVE_POSIX_SOCKETS)
  rssize res;
#endif

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (address == NULL)) return R_SOCKET_INVAL;

#if defined (HAVE_WINSOCK2) || defined (HAVE_POSIX_SOCKETS)
  do {
    res = sendto (handle, buffer, size, 0,
        (const struct sockaddr *)&address->addr, address->addrlen);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  if (res >= 0) {
    if (sent != NULL)
      *sent = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
#else
  (void) buffer;
  (void) size;
  (void) sent;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_socket_send_message (RIOHandle handle, const RSocketAddress * address,
    RBuffer * buffer, rsize * sent)
{
#if defined (HAVE_WINSOCK2)
  rsize i, mem_count;
  RMemMapInfo * info;
  int res;
  LPWSABUF bufs;
  DWORD winsent;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (buffer == NULL)) return R_SOCKET_INVAL;

  mem_count = r_buffer_mem_count (buffer);
  info = r_alloca (mem_count * sizeof (RMemMapInfo));
  bufs = r_alloca (mem_count * sizeof (WSABUF));

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buffer, i);
    if (r_mem_map (mem, &info[i], R_MEM_MAP_READ)) {
      bufs[i].len = info[i].size;
      bufs[i].buf = info[i].data;
    } else {
      /* WARNING */
      bufs[i].len = 0;
      bufs[i].buf = "";
    }
    r_mem_unref (mem);
  }

  winsent = 0;
  if (address != NULL) {
    res = WSASendTo (handle, bufs, mem_count, &winsent, 0,
        (const struct sockaddr *)&address->addr, (int)address->addrlen,
        NULL, NULL);
  } else {
    res = WSASendTo (handle, bufs, mem_count, &winsent, 0, NULL, 0, NULL, NULL);
  }

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buffer, i);
    r_mem_unmap (mem, &info[i]);
    r_mem_unref (mem);
  }

  if (res != SOCKET_ERROR) {
    if (sent != NULL)
      *sent = (rsize)winsent;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
#elif defined (HAVE_POSIX_SOCKETS)
  rsize i, mem_count;
  RMemMapInfo * info;
  rssize res;
  struct msghdr msg;

  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (buffer == NULL)) return R_SOCKET_INVAL;

  mem_count = r_buffer_mem_count (buffer);
  info = r_alloca (mem_count * sizeof (RMemMapInfo));

  msg.msg_iovlen = mem_count;
  msg.msg_iov = r_alloca (msg.msg_iovlen * sizeof (struct iovec));
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buffer, i);
    if (r_mem_map (mem, &info[i], R_MEM_MAP_READ)) {
      msg.msg_iov[i].iov_base = info[i].data;
      msg.msg_iov[i].iov_len = info[i].size;
    } else {
      /* WARNING */
      msg.msg_iov[i].iov_base = "";
      msg.msg_iov[i].iov_len = 0;
    }
    r_mem_unref (mem);
  }

  if (address != NULL) {
    msg.msg_name = (rpointer)&address->addr;
    msg.msg_namelen = address->addrlen;
  } else {
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
  }
  do {
    res = sendmsg (handle, &msg, 0);
  } while (res < 0 && R_SOCKET_ERRNO == EINTR);

  for (i = 0; i < mem_count; i++) {
    RMem * mem = r_buffer_mem_peek (buffer, i);
    r_mem_unmap (mem, &info[i]);
    r_mem_unref (mem);
  }

  if (res >= 0) {
    if (sent != NULL)
      *sent = (rsize)res;
    return R_SOCKET_OK;
  }

  return r_socket_errno_to_socket_status ();
#else
  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return R_SOCKET_INVAL;
  if (R_UNLIKELY (buffer == NULL)) return R_SOCKET_INVAL;
  (void) address;
  (void) sent;
  return R_SOCKET_NOT_SUPPORTED;
#endif
}

RSocketStatus
r_io_get_socket_ipv4_multicast_loop (RIOHandle handle, rboolean * mloop)
{
  return r_io_get_socket_option_bool (handle, IPPROTO_IP, IP_MULTICAST_LOOP, mloop);
}

RSocketStatus
r_io_get_socket_ipv4_multicast_ttl (RIOHandle handle, int * mttl)
{
  return r_io_get_socket_option (handle, IPPROTO_IP, IP_MULTICAST_TTL, mttl);
}

RSocketStatus
r_io_get_socket_ipv4_ttl (RIOHandle handle, int * ttl)
{
  return r_io_get_socket_option (handle, IPPROTO_IP, IP_TTL, ttl);
}

RSocketStatus
r_io_set_socket_ipv4_multicast_loop (RIOHandle handle, rboolean mloop)
{
  return r_io_set_socket_option (handle, IPPROTO_IP, IP_MULTICAST_LOOP, mloop);
}

RSocketStatus
r_io_set_socket_ipv4_multicast_ttl (RIOHandle handle, int mttl)
{
  return r_io_set_socket_option (handle, IPPROTO_IP, IP_MULTICAST_TTL, mttl);
}

RSocketStatus
r_io_set_socket_ipv4_ttl (RIOHandle handle, int ttl)
{
  return r_io_set_socket_option (handle, IPPROTO_IP, IP_TTL, ttl);
}

RSocketStatus
r_io_get_socket_ipv6_multicast_loop (RIOHandle handle, rboolean * mloop)
{
  return r_io_get_socket_option_bool (handle, IPPROTO_IPV6, IP_MULTICAST_LOOP, mloop);
}

RSocketStatus
r_io_get_socket_ipv6_multicast_ttl (RIOHandle handle, int * mttl)
{
  return r_io_get_socket_option (handle, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, mttl);
}

RSocketStatus
r_io_get_socket_ipv6_ttl (RIOHandle handle, int * ttl)
{
  return r_io_get_socket_option (handle, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ttl);
}

RSocketStatus
r_io_set_socket_ipv6_multicast_loop (RIOHandle handle, rboolean mloop)
{
  return r_io_set_socket_option (handle, IPPROTO_IPV6, IP_MULTICAST_LOOP, mloop);
}

RSocketStatus
r_io_set_socket_ipv6_multicast_ttl (RIOHandle handle, int mttl)
{
  return r_io_set_socket_option (handle, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, mttl);
}

RSocketStatus
r_io_set_socket_ipv6_ttl (RIOHandle handle, int ttl)
{
  return r_io_set_socket_option (handle, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ttl);
}

