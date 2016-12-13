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
#ifndef __R_NET_TLS_CLIENT_H__
#define __R_NET_TLS_CLIENT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/crypto/rtlsciphersuite.h>
#include <rlib/net/proto/rtls.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

typedef struct _RTLSClient RTLSClient;

R_API RTLSClient * r_tls_client_new (RTLSVersion ver) R_ATTR_MALLOC;
#define r_tls_client_ref    r_ref_ref
#define r_tls_client_unref  r_ref_unref

R_END_DECLS

#endif /* __R_NET_TLS_CLIENT_H__ */

