/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_NET_PROTO_TLS13_H__
#define __R_NET_PROTO_TLS13_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/proto/rtls13.h
 * @brief TLS 1.3 (RFC 8446) key schedule primitives.
 */

#include <rlib/rtypes.h>
#include <rlib/crypto/rmsgdigest.h>

/**
 * @addtogroup r_tls_proto
 * @{
 */

R_BEGIN_DECLS

/**
 * @brief HKDF-Expand-Label (RFC 8446, section 7.1).
 *
 * Expand @p secret into @p outlen bytes under a TLS 1.3 @c HkdfLabel built from
 * @p label (automatically prefixed with @c "tls13 ") and @p context.
 *
 * @param hash     Digest of the cipher suite (e.g. @c R_MSG_DIGEST_TYPE_SHA256).
 * @param secret   The secret to expand; @c HashLen bytes.
 * @param label    Label without the @c "tls13 " prefix (e.g. @c "key",
 *                 @c "derived", @c "c hs traffic"); 1..249 bytes.
 * @param labellen Length of @p label in bytes.
 * @param context  Context bytes (e.g. a transcript hash); may be @c NULL when
 *                 @p ctxlen is 0.
 * @param ctxlen   Length of @p context, at most 255.
 * @param out      Destination for @p outlen bytes.
 * @param outlen   Number of bytes to derive; 1..65535.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_tls13_expand_label (RMsgDigestType hash,
    const ruint8 * secret, const rchar * label, rsize labellen,
    const ruint8 * context, rsize ctxlen, ruint8 * out, rsize outlen);

/**
 * @brief Derive-Secret (RFC 8446, section 7.1).
 *
 * @c HKDF-Expand-Label(secret, label, transcript_hash, HashLen): derive a new
 * @c HashLen-byte secret bound to a handshake-transcript hash.
 *
 * @param hash            Digest of the cipher suite.
 * @param secret          The input secret; @c HashLen bytes.
 * @param label           Label without the @c "tls13 " prefix.
 * @param labellen        Length of @p label in bytes.
 * @param transcript_hash @c Transcript-Hash(messages); @c HashLen bytes.
 * @param out             Destination for the @c HashLen-byte derived secret.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_tls13_derive_secret (RMsgDigestType hash,
    const ruint8 * secret, const rchar * label, rsize labellen,
    const ruint8 * transcript_hash, ruint8 * out);

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_TLS13_H__ */
