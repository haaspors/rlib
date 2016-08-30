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

#ifndef __R_NETWORKING_PRIV_H__
#define __R_NETWORKING_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rnetworking-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>

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

#ifdef R_OS_WIN32
#include <rlib/rmodule.h>
#endif
#include <rlib/rref.h>

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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
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

struct _RSocketAddress {
  RRef ref;

  struct sockaddr_storage addr;
  socklen_t addrlen;
};

#ifdef R_OS_WIN32
R_API_HIDDEN int (* r_win32_inet_pton) (int, const rchar *, rpointer);
R_API_HIDDEN const rchar * (* r_win32_inet_ntop) (int, rpointer, rchar *, size_t);

#if _WIN32_WINNT < 0x0600
#define inet_pton r_win32_inet_pton
#define inet_ntop r_win32_inet_ntop
#endif
#ifndef HAVE_INET_PTON
#define HAVE_INET_PTON            1
#endif
#endif


R_END_DECLS

#endif /* __R_NETWORKING_PRIV_H__ */

