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
 * @file rlib/charset/runicode.h
 * @brief UTF-8 / UTF-16 conversions.
 *
 * Two flavours of conversion: an in-buffer pair (caller supplies
 * the destination) and an allocating pair (returns a fresh buffer
 * the caller @c r_free's). Both pairs report partial-conversion
 * state via output pointers - useful for streaming, where a source
 * span might end mid-codepoint and the next chunk has to resume
 * from the last @c srcendptr.
 *
 * Code units are counted in their respective natural element type:
 * UTF-8 in @c rchar bytes, UTF-16 in @c runichar2 code units.
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

/** @} */

#if 0
/* TODO: UTF-32 conversions - prototypes sketched but not yet
 * implemented. Left as a placeholder so the namespace shape stays
 * visible. */
R_API runichar * r_utf8_to_uft32 (const rchar * str, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;
R_API rchar * r_utf32_to_uft8 (const runichar *, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;

R_API runichar * r_utf16_to_uft32 (const runichar2 * str, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;
R_API runichar2 * r_utf32_to_uft16 (const runichar *, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;
#endif

R_END_DECLS

#endif /* __R_UNICODE_H__ */
