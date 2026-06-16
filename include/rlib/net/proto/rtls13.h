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
#include <rlib/crypto/rcipher.h>
#include <rlib/net/proto/rtls.h>

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

/** @brief AEAD authentication tag size for the 1.3 cipher suites, in bytes. */
#define R_TLS13_AEAD_TAG_SIZE     16
/** @brief Maximum AEAD record-nonce length, in bytes. */
#define R_TLS13_AEAD_NONCE_MAX    16

/**
 * @brief Build the per-record AEAD nonce (RFC 8446, section 5.3).
 *
 * The 64-bit record @p seq is encoded big-endian, left-padded with zeros to
 * @p ivlen bytes, and XORed with the static write-IV @p iv.
 *
 * @param iv     Static write-IV from the key schedule; @p ivlen bytes.
 * @param ivlen  Nonce length (the AEAD's IV size); 1..@c R_TLS13_AEAD_NONCE_MAX.
 * @param seq    Record sequence number.
 * @param nonce  Destination for the @p ivlen-byte nonce.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_tls13_aead_nonce (const ruint8 * iv, rsize ivlen,
    ruint64 seq, ruint8 * nonce);

/**
 * @brief Protect a 1.3 record (RFC 8446, section 5.2).
 *
 * Appends the inner content type to @p content to form the @c TLSInnerPlaintext,
 * then AEAD-seals it with @p cipher under the nonce derived from @p iv and @p seq,
 * the @c additional_data being the @c TLSCiphertext record header. The resulting
 * @c encrypted_record (ciphertext followed by a @c R_TLS13_AEAD_TAG_SIZE tag) is
 * written to @p out; the caller frames it behind a 5-byte record header.
 *
 * @param cipher     AEAD cipher keyed with the write traffic key.
 * @param iv         Static write-IV; @p ivlen bytes.
 * @param ivlen      Nonce length.
 * @param seq        Record sequence number.
 * @param type       Real content type of @p content (@ref RTLSContentType).
 * @param content    Plaintext payload; @p contentlen bytes.
 * @param contentlen Payload length.
 * @param out        Destination for the @c encrypted_record.
 * @param outsize    Capacity of @p out in bytes.
 * @param outlen     Out: bytes written to @p out.
 * @return @c TRUE on success; @c FALSE on invalid arguments, too-small @p out,
 *  or a cipher failure.
 */
R_API rboolean r_tls13_record_protect (const RCryptoCipher * cipher,
    const ruint8 * iv, rsize ivlen, ruint64 seq,
    RTLSContentType type, const ruint8 * content, rsize contentlen,
    ruint8 * out, rsize outsize, rsize * outlen);

/**
 * @brief Unprotect a 1.3 record (RFC 8446, section 5.2).
 *
 * AEAD-opens @p record (the @c encrypted_record), strips the optional trailing
 * zero padding and the inner content-type byte, and yields the plaintext and its
 * real content type.
 *
 * @param cipher  AEAD cipher keyed with the read traffic key.
 * @param iv      Static read-IV; @p ivlen bytes.
 * @param ivlen   Nonce length.
 * @param seq     Record sequence number.
 * @param record  The @c encrypted_record (ciphertext + tag); @p reclen bytes.
 * @param reclen  Length of @p record.
 * @param out     Destination for the recovered plaintext.
 * @param outsize Capacity of @p out in bytes.
 * @param outlen  Out: plaintext length written to @p out.
 * @param type    Out: recovered content type (@ref RTLSContentType).
 * @return @c TRUE on success; @c FALSE on invalid arguments, authentication
 *  failure, an all-zero (typeless) plaintext, or too-small @p out.
 */
R_API rboolean r_tls13_record_unprotect (const RCryptoCipher * cipher,
    const ruint8 * iv, rsize ivlen, ruint64 seq,
    const ruint8 * record, rsize reclen,
    ruint8 * out, rsize outsize, rsize * outlen, RTLSContentType * type);

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_TLS13_H__ */
