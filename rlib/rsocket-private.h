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

#ifndef __R_SOCKET_PRIV_H__
#define __R_SOCKET_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rsocket-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/rsocket.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/* FIXME: Do this by configuration? */
#if !defined (RLIB_HAVE_SOCKETS)
#define HAVE_MOCK_SOCKETS   1
#elif defined (R_OS_WIN32)
#define HAVE_WINSOCK2       1
#elif defined (HAVE_SYS_SOCKET_H)
#define HAVE_POSIX_SOCKETS  1
#else
#define HAVE_MOCK_SOCKETS   1
#endif

#if defined (HAVE_POSIX_SOCKETS)
#include <sys/socket.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#elif defined (HAVE_WINSOCK2)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wspiapi.h>
#pragma comment(lib, "Ws2_32.lib")
#endif

R_BEGIN_DECLS

#ifdef HAVE_WINSOCK2
#define R_SOCKET_HANDLE_INVALID   INVALID_SOCKET
typedef SOCKET RSocketHandle;
#define R_SOCKET_ERRNO            (WSAGetLastError ())
typedef int socklen_t;
#else
#define R_SOCKET_HANDLE_INVALID   -1
typedef int RSocketHandle;
#define R_SOCKET_ERRNO            errno

#if defined (HAVE_MOCK_SOCKETS)
struct in_addr {
  ruint32 s_addr;
};
struct in6_addr {
  ruint8 s6_addr[16];
};

struct sockaddr_in {
  RSocketFamily   sin_family;
  ruint16         sin_port;
  struct in_addr  sin_addr;
};
struct sockaddr_in6 {
  RSocketFamily   sin6_family;
  ruint16         sin6_port;
  ruint32         sin6_flowinfo;
  struct in6_addr sin6_addr;
  ruint32         sin6_scope_id;
};
struct sockaddr_storage {
  RSocketFamily   ss_family;
  char            ss_data[128 - sizeof(RSocketFamily)];
};
typedef int socklen_t;
#endif
#endif

struct _RSocket {
  RRef ref;

  RSocketHandle   handle;
  RSocketFamily   family;
  RSocketType     type;
  RSocketProtocol proto;
  RSocketFlags    flags;
};

struct _RSocketAddress {
  RRef ref;

  struct sockaddr_storage addr;
  socklen_t addrlen;
};

R_END_DECLS

#endif /* __R_SOCKET_PRIV_H__ */

