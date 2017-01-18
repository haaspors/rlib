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

/* FIXME: Do this by configuration? */
#ifdef R_OS_WIN32
#define HAVE_WINSOCK2
#endif

#ifdef HAVE_WINSOCK2
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wspiapi.h>
#pragma comment(lib, "Ws2_32.lib")
#endif

#ifdef R_OS_UNIX
#include <unistd.h>
#endif
#include <errno.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
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

