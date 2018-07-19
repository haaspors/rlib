/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_RESOLVE_H__
#define __R_RESOLVE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rsocket.h>
#include <rlib/rsocketaddress.h>

R_BEGIN_DECLS

typedef enum {
  R_RESOLVE_IN_PROGRESS = -1,
  R_RESOLVE_OK = 0,
  R_RESOLVE_INVAL,
  R_RESOLVE_OOM,
  R_RESOLVE_BAD_HINTS,
  R_RESOLVE_BAD_FLAGS,
  R_RESOLVE_NO_DATA,
  R_RESOLVE_NOT_SUPPORTED,
  R_RESOLVE_ERROR,
} RResolveResult;

typedef enum {
  R_RESOLVE_ADDR_FLAG_PASSIVE     = R_AI_PASSIVE,
  R_RESOLVE_ADDR_FLAG_CANONNAME   = R_AI_CANONNAME,
  R_RESOLVE_ADDR_FLAG_NUMERICHOST = R_AI_NUMERICHOST,
  R_RESOLVE_ADDR_FLAG_V4MAPPED    = R_AI_V4MAPPED,
  R_RESOLVE_ADDR_FLAG_ALL         = R_AI_ALL,
  R_RESOLVE_ADDR_FLAG_ADDRCONFIG  = R_AI_ADDRCONFIG,
} RResolveAddrFlag;
typedef ruint32 RResolveAddrFlags;

typedef struct {
  RSocketFamily family;
  RSocketType type;
  RSocketProtocol protocol;
} RResolveHints;

typedef struct _RResolvedAddr RResolvedAddr;
struct _RResolvedAddr {
  RResolveHints hints;
  RSocketAddress * addr;
  RResolvedAddr * next;
};

R_API void r_resolved_addr_free (RResolvedAddr * addr);
R_API RResolvedAddr * r_resolve_sync (const rchar * host, const rchar * service,
    RResolveAddrFlags flags, const RResolveHints * hints, RResolveResult * res);


R_END_DECLS

#endif /* __R_RESOLVE_H__ */



