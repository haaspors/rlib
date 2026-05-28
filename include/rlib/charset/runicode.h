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
#ifndef __R_UNICODE_H__
#define __R_UNICODE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

/**
 * @defgroup r_unicode Unicode conversion
 * @brief UTF-8 / UTF-16 / UTF-32 encoding conversions.
 * @{
 */

/**
 * @file rlib/charset/runicode.h
 * @brief UTF-8 / UTF-16 / UTF-32 conversions.
 *
 * Two flavours of conversion: an in-buffer pair (caller supplies
 * the destination) and an allocating pair (returns a fresh buffer
 * the caller @c r_free's). Both pairs report partial-conversion
 * state via output pointers - useful for streaming, where a source
 * span might end mid-codepoint and the next chunk has to resume
 * from the last @c srcendptr.
 *
 * Code units are counted in their respective natural element type:
 * UTF-8 in @c rchar bytes, UTF-16 in @c runichar2 code units, and
 * UTF-32 in @c runichar4 code units.
 */

R_BEGIN_DECLS

/** @brief Unicode code point (0..0x10FFFF), one per "character". */
typedef ruint32   runichar;
/** @brief 32-bit code unit (UTF-32). Same as @c runichar. */
typedef ruint32   runichar4;
/** @brief 16-bit code unit (UTF-16). */
typedef ruint16   runichar2;

/**
 * @brief Status returned by the conversion functions.
 *
 * @c R_UNICODE_OK is the only success value; the rest signal
 * different failure modes the caller may want to recover from.
 */
typedef enum {
  R_UNICODE_OK = 0,                  /**< Conversion completed. */
  R_UNICODE_OOM,                     /**< Allocation failed (allocating variants). */
  R_UNICODE_INVAL,                   /**< Caller passed a bad argument. */
  R_UNICODE_OVERFLOW,                /**< Destination buffer too small. */
  R_UNICODE_INVALID_CODE_POINT,      /**< Source bytes don't form a valid codepoint. */
  R_UNICODE_INCOMPLETE_CODE_POINT,   /**< Source ended mid-codepoint; resume from @c srcendptr. */
} RUnicodeResult;

/**
 * @name In-buffer conversion
 *
 * Caller supplies the destination buffer. On @c R_UNICODE_OK the
 * @p dstoutsize out-pointer holds the number of code units written
 * (UTF-16 units for to_utf16, bytes for to_utf8). @p srcendptr
 * receives a pointer to the byte / code unit one past the last
 * consumed source element, which equals @c src + @c srcsize on
 * complete conversion and a position before the end on
 * @c R_UNICODE_INCOMPLETE_CODE_POINT.
 * @{
 */

/**
 * @brief Encode UTF-8 @p src into UTF-16 @p dst.
 *
 * @param dst        Destination UTF-16 buffer.
 * @param dstsize    Capacity of @p dst in @c runichar2 code units.
 * @param src        UTF-8 source bytes.
 * @param srcsize    Bytes in @p src, or -1 to fall back to @c r_strlen.
 * @param dstoutsize Receives the number of code units written.
 * @param srcendptr  Receives a pointer one past the last consumed byte.
 */
R_API RUnicodeResult r_utf8_to_utf16 (runichar2 * dst, rsize dstsize,
    const rchar * src, rssize srcsize, rsize * dstoutsize, rchar ** srcendptr);
/**
 * @brief Decode UTF-16 @p src into UTF-8 @p dst.
 *
 * @param dst        Destination UTF-8 buffer.
 * @param dstsize    Capacity of @p dst in bytes.
 * @param src        UTF-16 source code units.
 * @param srcsize    Code units in @p src.
 * @param dstoutsize Receives the number of bytes written.
 * @param srcendptr  Receives a pointer one past the last consumed code unit.
 */
R_API RUnicodeResult r_utf16_to_utf8 (rchar * dst, rsize dstsize,
    const runichar2 * src, rsize srcsize, rsize * dstoutsize, runichar2 ** srcendptr);

/**
 * @brief Encode UTF-8 @p src into UTF-32 @p dst.
 *
 * @param dst        Destination UTF-32 buffer.
 * @param dstsize    Capacity of @p dst in @c runichar4 code units
 *                   (one codepoint per unit, plus one for the
 *                   trailing NUL terminator).
 * @param src        UTF-8 source bytes.
 * @param srcsize    Bytes in @p src, or -1 to fall back to @c r_strlen.
 * @param dstoutsize Receives the number of code units written
 *                   (excluding the trailing NUL).
 * @param srcendptr  Receives a pointer one past the last consumed byte.
 */
R_API RUnicodeResult r_utf8_to_utf32 (runichar4 * dst, rsize dstsize,
    const rchar * src, rssize srcsize, rsize * dstoutsize, rchar ** srcendptr);
/**
 * @brief Decode UTF-32 @p src into UTF-8 @p dst.
 *
 * @param dst        Destination UTF-8 buffer.
 * @param dstsize    Capacity of @p dst in bytes (room for up to 4
 *                   bytes per codepoint plus the trailing NUL).
 * @param src        UTF-32 source code units.
 * @param srcsize    Code units in @p src.
 * @param dstoutsize Receives the number of bytes written.
 * @param srcendptr  Receives a pointer one past the last consumed code unit.
 */
R_API RUnicodeResult r_utf32_to_utf8 (rchar * dst, rsize dstsize,
    const runichar4 * src, rsize srcsize, rsize * dstoutsize, runichar4 ** srcendptr);
/**
 * @brief Encode UTF-16 @p src into UTF-32 @p dst.
 *
 * @param dst        Destination UTF-32 buffer.
 * @param dstsize    Capacity of @p dst in @c runichar4 code units
 *                   (plus one for the trailing NUL).
 * @param src        UTF-16 source code units.
 * @param srcsize    Code units in @p src.
 * @param dstoutsize Receives the number of code units written.
 * @param srcendptr  Receives a pointer one past the last consumed code unit.
 */
R_API RUnicodeResult r_utf16_to_utf32 (runichar4 * dst, rsize dstsize,
    const runichar2 * src, rsize srcsize, rsize * dstoutsize, runichar2 ** srcendptr);
/**
 * @brief Decode UTF-32 @p src into UTF-16 @p dst.
 *
 * Codepoints outside the BMP produce a surrogate pair.
 *
 * @param dst        Destination UTF-16 buffer.
 * @param dstsize    Capacity of @p dst in @c runichar2 code units
 *                   (room for up to 2 units per codepoint plus the
 *                   trailing NUL).
 * @param src        UTF-32 source code units.
 * @param srcsize    Code units in @p src.
 * @param dstoutsize Receives the number of code units written.
 * @param srcendptr  Receives a pointer one past the last consumed code unit.
 */
R_API RUnicodeResult r_utf32_to_utf16 (runichar2 * dst, rsize dstsize,
    const runichar4 * src, rsize srcsize, rsize * dstoutsize, runichar4 ** srcendptr);

/** @} */

/**
 * @name Allocating conversion
 *
 * Same conversions but the destination is allocated by the function
 * and returned. Caller @c r_free's. @p res, when non-NULL, receives
 * the same status code that the in-buffer variant would have
 * returned; @p retsize receives the output length in code units;
 * @p endptr receives the consumed-source pointer.
 * @{
 */

/**
 * @brief Allocate and encode UTF-8 @p src as UTF-16.
 * @return Freshly allocated UTF-16 buffer, or NULL on failure.
 */
R_API runichar2 * r_utf8_to_utf16_dup (const rchar * src, rssize srcsize,
    RUnicodeResult * res, rsize * retsize, rchar ** endptr) R_ATTR_MALLOC;
/**
 * @brief Allocate and decode UTF-16 @p src as UTF-8.
 * @return Freshly allocated UTF-8 buffer, or NULL on failure.
 */
R_API rchar * r_utf16_to_utf8_dup (const runichar2 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar2 ** endptr) R_ATTR_MALLOC;

/**
 * @brief Allocate and encode UTF-8 @p src as UTF-32.
 * @return Freshly allocated UTF-32 buffer, or NULL on failure.
 */
R_API runichar4 * r_utf8_to_utf32_dup (const rchar * src, rssize srcsize,
    RUnicodeResult * res, rsize * retsize, rchar ** endptr) R_ATTR_MALLOC;
/**
 * @brief Allocate and decode UTF-32 @p src as UTF-8.
 * @return Freshly allocated UTF-8 buffer, or NULL on failure.
 */
R_API rchar * r_utf32_to_utf8_dup (const runichar4 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar4 ** endptr) R_ATTR_MALLOC;
/**
 * @brief Allocate and encode UTF-16 @p src as UTF-32.
 * @return Freshly allocated UTF-32 buffer, or NULL on failure.
 */
R_API runichar4 * r_utf16_to_utf32_dup (const runichar2 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar2 ** endptr) R_ATTR_MALLOC;
/**
 * @brief Allocate and decode UTF-32 @p src as UTF-16.
 * @return Freshly allocated UTF-16 buffer, or NULL on failure.
 */
R_API runichar2 * r_utf32_to_utf16_dup (const runichar4 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar4 ** endptr) R_ATTR_MALLOC;

/** @} */

/**
 * @name Encoding validation
 *
 * Scan-only counterparts to the conversion functions. They apply the
 * same rejection rules - RFC 3629 §3 for UTF-8 (overlong / surrogate-
 * codepoint / out-of-range), surrogate-pairing for UTF-16, codepoint
 * range and surrogate-half for UTF-32 - but allocate nothing and
 * write no output. Useful when a caller already has the bytes in
 * their target encoding and only needs to confirm they are
 * well-formed before storing or forwarding them.
 *
 * On success returns @c R_UNICODE_OK and @c *endptr (when non-NULL)
 * points to the byte / code unit one past the input. On
 * @c R_UNICODE_INCOMPLETE_CODE_POINT @c *endptr points at the start
 * of the truncated sequence (resumable). On
 * @c R_UNICODE_INVALID_CODE_POINT @c *endptr points at the byte /
 * unit that triggered the rejection.
 * @{
 */

/**
 * @brief Validate a UTF-8 byte sequence per RFC 3629.
 *
 * @param src     UTF-8 bytes.
 * @param size    Bytes in @p src, or -1 to fall back to @c r_strlen.
 * @param endptr  Optional out-pointer; receives the consumed-source
 *                position per the rules above.
 */
R_API RUnicodeResult r_utf8_validate (const rchar * src, rssize size,
    rchar ** endptr);

/**
 * @brief Validate a UTF-16 code-unit sequence.
 *
 * Rejects lone high surrogates as @c R_UNICODE_INCOMPLETE_CODE_POINT
 * and lone low surrogates as @c R_UNICODE_INVALID_CODE_POINT, same
 * as @c r_utf16_to_utf8.
 *
 * @param src     UTF-16 code units.
 * @param size    Code units in @p src.
 * @param endptr  Optional out-pointer.
 */
R_API RUnicodeResult r_utf16_validate (const runichar2 * src, rsize size,
    runichar2 ** endptr);

/**
 * @brief Validate a UTF-32 code-point sequence.
 *
 * Rejects values >= 0x110000 and surrogate-half codepoints
 * (@c U+D800..U+DFFF) as @c R_UNICODE_INVALID_CODE_POINT.
 *
 * @param src     UTF-32 code points.
 * @param size    Code points in @p src.
 * @param endptr  Optional out-pointer.
 */
R_API RUnicodeResult r_utf32_validate (const runichar4 * src, rsize size,
    runichar4 ** endptr);

/** @} */

R_END_DECLS

/** @} */ /* r_unicode group */

#endif /* __R_UNICODE_H__ */
