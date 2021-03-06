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
#include "../rsocket-private.h"
#include "rnet-private.h"

#include <rlib/rstr.h>

#ifdef R_OS_WIN32
#include <rlib/rmodule.h>

static int __stdcall r_win32_sim_inet_pton (int family, const rchar * src, rpointer dst);
static const rchar * __stdcall r_win32_sim_inet_ntop (int family, rconstpointer src,
    rchar * dst, size_t size);
static RMODULE g_r_win32_ws2_32_dll = NULL;
#endif

void
r_networking_init (void)
{
#ifdef HAVE_WINSOCK2
  WORD req = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup (req, &wsaData);
#endif

#ifdef R_OS_WIN32
  if ((g_r_win32_ws2_32_dll = r_module_open ("ws2_32.dll", TRUE, NULL)) != NULL) {
    r_win32_inet_pton = r_module_lookup (g_r_win32_ws2_32_dll, "inet_pton");
    r_win32_inet_ntop = r_module_lookup (g_r_win32_ws2_32_dll, "inet_ntop");
  } else {
    r_win32_inet_pton = r_win32_sim_inet_pton;
    r_win32_inet_ntop = r_win32_sim_inet_ntop;
  }
#endif
}

void
r_networking_deinit (void)
{
#ifdef R_OS_WIN32
  if (g_r_win32_ws2_32_dll != NULL)
    r_module_close (g_r_win32_ws2_32_dll);
#endif
#ifdef HAVE_WINSOCK2
  WSACleanup ();
#endif
}

#ifdef R_OS_WIN32
static int __stdcall
r_win32_sim_inet_pton (int family, const rchar * src, rpointer dst)
{
  struct sockaddr_storage ss;
  int len = sizeof (ss);

  if (family != R_AF_INET && family != R_AF_INET6) {
    WSASetLastError (WSAEAFNOSUPPORT);
    return -1;
  }

  if (r_strchr (src, (int)':') == NULL) {
    struct sockaddr_in * sin = (struct sockaddr_in *)&ss;
    if (WSAStringToAddressA ((rchar *)src, R_AF_INET, NULL, (struct sockaddr *) &ss, &len) == 0) {
      r_memcpy (dst, &sin->sin_addr, sizeof (sin->sin_addr));
      return 1;
    }
  }

  if (r_strchr (src, (int)']') == NULL) {
    struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)&ss;
    if (WSAStringToAddressA ((rchar *)src, R_AF_INET6, NULL, (struct sockaddr *) &ss, &len) == 0) {
      r_memcpy (dst, &sin6->sin6_addr, sizeof (sin6->sin6_addr));
      return 1;
    }
  }

  return 0;
}

static const rchar * __stdcall
r_win32_sim_inet_ntop (int family, rconstpointer src, rchar * dst, size_t size)
{
  DWORD len, dstsize = (DWORD)size;
  struct sockaddr_storage ss;

  r_memset (&ss, 0, sizeof (ss));
  ss.ss_family = family;

  if (ss.ss_family == R_AF_INET) {
    struct sockaddr_in * sin = (struct sockaddr_in *) &ss;

    len = sizeof (struct sockaddr_in);
    r_memcpy (&sin->sin_addr, src, sizeof (sin->sin_addr));
  } else if (ss.ss_family == R_AF_INET6) {
    struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) &ss;

    len = sizeof (struct sockaddr_in6);
    r_memcpy (&sin6->sin6_addr, src, sizeof (sin6->sin6_addr));
  } else {
    WSASetLastError (WSAEAFNOSUPPORT);
    return NULL;
  }

  return WSAAddressToStringA ((struct sockaddr *) &ss, len, NULL,
      dst, &dstsize) == 0 ? dst : NULL;
}
#endif

