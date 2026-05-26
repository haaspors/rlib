/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_BASE64_H__
#define __R_BASE64_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

/**
 * @defgroup r_base64 Base64 (RFC 4648)
 * @brief Base64 encoder / decoder. In-buffer and allocating
 * variants of each direction.
 * @{
 */

/**
 * @file rlib/rbase64.h
 * @brief Base64 encoding and decoding (RFC 4648).
 *
 * Two flavours of each direction: an in-buffer form (caller supplies
 * the destination) and an allocating form (returns a freshly
 * @c r_malloc'd buffer the caller @c r_free's). Encoding uses the
 * standard alphabet with @c '=' padding; decoding accepts the same
 * alphabet and ignores whitespace.
 */

R_BEGIN_DECLS

/**
 * @brief TRUE iff @p ch is a valid base64 alphabet character or @c '='.
 *
 * Whitespace and other characters return FALSE.
 */
R_API rboolean r_base64_is_valid_char (rchar ch);

/**
 * @name In-buffer encoding / decoding
 * @{
 */

/**
 * @brief Encode @p size bytes from @p src as base64 into @p dst.
 *
 * The output is NOT NUL-terminated; the returned length tells the
 * caller exactly how many bytes were written. Use the @c _dup
 * variant if you need a NUL-terminated string.
 *
 * @param dst   Destination buffer.
 * @param dsize Capacity of @p dst in bytes.
 * @param src   Source bytes.
 * @param size  Bytes to encode from @p src.
 * @return Number of bytes written to @p dst.
 */
R_API rsize r_base64_encode (rchar * dst, rsize dsize, rconstpointer src, rsize size);
/**
 * @brief Decode base64 @p src into @p dst.
 *
 * Whitespace in @p src is skipped. Decoding stops at the first
 * invalid character (a NUL counts as invalid).
 *
 * @param dst   Destination buffer.
 * @param dsize Capacity of @p dst in bytes.
 * @param src   Source base64 characters.
 * @param size  Bytes in @p src, or -1 to fall back to @c r_strlen.
 * @return Number of bytes written to @p dst.
 */
R_API rsize r_base64_decode (ruint8 * dst, rsize dsize, const rchar * src, rssize size);

/** @} */

/**
 * @name Allocating encoding / decoding
 *
 * Allocate the destination buffer and return it. *@p outsize (when
 * non-NULL) receives the output length. Caller @c r_free's the
 * returned buffer.
 * @{
 */

/**
 * @brief Encode @p size bytes from @p data as base64, returning a
 * NUL-terminated string.
 * @param data    Source bytes.
 * @param size    Bytes to encode.
 * @param outsize Receives the output length (excluding the NUL).
 * @return Freshly allocated NUL-terminated base64 string, or NULL.
 */
R_API rchar * r_base64_encode_dup (rconstpointer data, rsize size, rsize * outsize) R_ATTR_MALLOC;
/**
 * @brief Like r_base64_encode_dup but inserts a newline every
 * @p linesize characters.
 *
 * Useful for MIME-style line-wrapped base64. Pass @p linesize @c 0
 * for no wrapping (equivalent to the un-suffixed variant).
 */
R_API rchar * r_base64_encode_dup_full (rconstpointer data, rsize size, rsize linesize, rsize * outsize) R_ATTR_MALLOC;
/**
 * @brief Decode a base64 string into a freshly allocated byte buffer.
 * @param data    Source base64 characters.
 * @param size    Bytes in @p data, or -1 to fall back to @c r_strlen.
 * @param outsize Receives the output length.
 * @return Freshly allocated byte buffer, or NULL on failure.
 */
R_API ruint8 * r_base64_decode_dup (const rchar * data, rssize size, rsize * outsize) R_ATTR_MALLOC;

/** @} */

R_END_DECLS

/** @} */ /* r_base64 group */

#endif /* __R_BASE64_H__ */

