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
#ifndef __R_NET_PROTO_TLS12_H__
#define __R_NET_PROTO_TLS12_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/proto/rtls12.h
 * @brief TLS <= 1.2 pseudo-random function (PRF).
 */

#include <rlib/net/proto/rtls.h>

/**
 * @addtogroup r_tls_proto
 * @{
 */

R_BEGIN_DECLS

/** @brief TLS pseudo-random function: expand @p secret into @p dst, fed a @c NULL-terminated list of seed chunks. */
typedef RTLSError (*RTLSPrfFunc) (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...);

/** @brief TLS 1.0 / 1.1 PRF (MD5+SHA1) over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_0_prf (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;
/** @brief TLS 1.2 PRF based on HMAC-SHA-224 over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_2_prf_sha224 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;
/** @brief TLS 1.2 PRF based on HMAC-SHA-256 over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_2_prf_sha256 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;
/** @brief TLS 1.2 PRF based on HMAC-SHA-384 over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_2_prf_sha384 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;
/** @brief TLS 1.2 PRF based on HMAC-SHA-512 over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_2_prf_sha512 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_TLS12_H__ */
