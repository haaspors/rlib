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

#ifndef __R_NET_PRIV_H__
#define __R_NET_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rnet-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

R_BEGIN_DECLS

#ifdef R_OS_WIN32
R_API_HIDDEN int (__stdcall * r_win32_inet_pton) (int, const rchar *, rpointer);
R_API_HIDDEN const rchar * (__stdcall * r_win32_inet_ntop) (int, rpointer, rchar *, size_t);
#endif

R_END_DECLS

#endif /* __R_NET_PRIV_H__ */

