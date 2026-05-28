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
 *
 * @note The in-buffer converters stop scanning the source when
 * they encounter an embedded zero code unit (@c '\0' for UTF-8 /
 * @c U+0000 for UTF-16 / UTF-32), even though @c U+0000 is a
 * valid Unicode scalar. This matches the C-string convention the
 * caller-supplied destination buffers are sized against: the
 * output is always NUL-terminated, and asking the converter to
 * pass through embedded @c U+0000 would make that contract
 * ambiguous. Callers that need to encode a literal @c U+0000
 * inside a string must split the input around the NUL and
 * convert each segment.
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

/**
 * @name Single-codepoint encode / decode
 *
 * Process exactly one codepoint at a time. Useful when the caller
 * is driving its own iteration loop (tokeniser, JSON unescape, etc.)
 * and doesn't want to allocate a converted copy of the whole input.
 * The same RFC 3629 / Unicode-Standard rejection rules apply:
 * overlong UTF-8, surrogate codepoints in UTF-8, and codepoints
 * @c >= 0x110000 are rejected as @c R_UNICODE_INVALID_CODE_POINT.
 *
 * @c R_UNICODE_INCOMPLETE_CODE_POINT signals a truncated source
 * sequence; @p *consumed (when non-NULL) is set to @c 0 so the
 * caller knows it must not advance past the partial bytes.
 * @{
 */

/**
 * @brief Decode one UTF-8 codepoint from @p src.
 *
 * @param src        UTF-8 bytes.
 * @param size       Bytes available in @p src.
 * @param uc         Out-pointer for the decoded codepoint; required.
 * @param consumed   Optional out-pointer for the number of bytes
 *                   consumed (1..4 on success; 0 on error).
 * @return @c R_UNICODE_OK on success.
 *         @c R_UNICODE_INVAL for NULL inputs / @p size == 0.
 *         @c R_UNICODE_INCOMPLETE_CODE_POINT if @p src ends mid-sequence.
 *         @c R_UNICODE_INVALID_CODE_POINT on malformed bytes,
 *         overlong forms, surrogate codepoints, or out-of-range
 *         codepoints.
 */
R_API RUnicodeResult r_utf8_decode_codepoint (const rchar * src, rsize size,
    runichar4 * uc, rsize * consumed);

/**
 * @brief Encode codepoint @p uc into UTF-8 at @p dst.
 *
 * @param uc       Unicode codepoint in @c [0, 0x110000).
 * @param dst      Destination byte buffer.
 * @param size     Capacity of @p dst.
 * @param written  Optional out-pointer for the number of bytes
 *                 emitted (1..4 on success).
 * @return @c R_UNICODE_OK on success.
 *         @c R_UNICODE_INVAL on NULL @p dst or @p size == 0.
 *         @c R_UNICODE_OVERFLOW if @p size is too small for the
 *         canonical encoding of @p uc.
 *         @c R_UNICODE_INVALID_CODE_POINT if @p uc is a surrogate
 *         or @c >= 0x110000.
 */
R_API RUnicodeResult r_utf8_encode_codepoint (runichar4 uc,
    rchar * dst, rsize size, rsize * written);

/**
 * @brief Decode one codepoint from UTF-16 @p src.
 *
 * @param src        UTF-16 code units.
 * @param size       Code units available in @p src.
 * @param uc         Out-pointer for the decoded codepoint; required.
 * @param consumed   Optional out-pointer for the number of code
 *                   units consumed (1 for BMP / 2 for surrogate
 *                   pair).
 * @return Same semantics as @c r_utf8_decode_codepoint, with
 *         @c R_UNICODE_INVALID_CODE_POINT for a lone low surrogate
 *         and @c R_UNICODE_INCOMPLETE_CODE_POINT for a high
 *         surrogate with no following low surrogate.
 */
R_API RUnicodeResult r_utf16_decode_codepoint (const runichar2 * src,
    rsize size, runichar4 * uc, rsize * consumed);

/**
 * @brief Encode codepoint @p uc into UTF-16 at @p dst.
 *
 * BMP codepoints write one code unit; supplementary codepoints
 * write a surrogate pair (two units).
 *
 * @param uc       Unicode codepoint in @c [0, 0x110000).
 * @param dst      Destination UTF-16 buffer.
 * @param size     Capacity of @p dst in code units.
 * @param written  Optional out-pointer for the number of code
 *                 units emitted (1 or 2).
 */
R_API RUnicodeResult r_utf16_encode_codepoint (runichar4 uc,
    runichar2 * dst, rsize size, rsize * written);

/** @} */

/**
 * @name Codepoint counting and advance
 *
 * Byte-/unit-oriented strings need codepoint-aware accessors when
 * callers care about user-visible character counts: column widths,
 * "first @c N characters", truncating without breaking a sequence.
 * These helpers walk the input one codepoint at a time using the
 * standard decoder, applying the same RFC 3629 rejection rules.
 * @{
 */

/**
 * @brief Count codepoints in a UTF-8 byte sequence.
 *
 * @param src     UTF-8 bytes.
 * @param size    Bytes in @p src, or @c -1 to fall back to
 *                @c r_strlen.
 * @param result  Optional out-pointer for the decode status. @c OK
 *                when every codepoint in @p src parsed; @c INVALID
 *                / @c INCOMPLETE on the first malformed sequence
 *                (the return value still reflects the number of
 *                codepoints successfully decoded before the error).
 * @return Number of codepoints decoded.
 */
R_API rsize r_utf8_strlen_codepoints (const rchar * src, rssize size,
    RUnicodeResult * result);

/**
 * @brief Advance past @p n codepoints in a UTF-8 byte sequence and
 * return the resulting position.
 *
 * @param src     UTF-8 bytes.
 * @param size    Bytes in @p src, or @c -1 to fall back to
 *                @c r_strlen.
 * @param n       Number of codepoints to advance.
 * @param result  Optional out-pointer for the decode status. @c OK
 *                when @p n codepoints were skipped; @c INVALID /
 *                @c INCOMPLETE on a malformed sequence;
 *                @c OVERFLOW if @p src ran out of bytes before
 *                @p n codepoints were reached.
 * @return Pointer one past the last codepoint skipped (or the byte
 *         that triggered the error / end-of-input).
 */
R_API const rchar * r_utf8_advance (const rchar * src, rssize size,
    rsize n, RUnicodeResult * result);

/**
 * @brief Count codepoints in a UTF-16 code-unit sequence. Surrogate
 * pairs count as one codepoint.
 */
R_API rsize r_utf16_strlen_codepoints (const runichar2 * src, rsize size,
    RUnicodeResult * result);

/** @} */

/**
 * @name Explicit-endianness UTF-16 / UTF-32 to UTF-8
 *
 * Wire-format text (ASN.1 @c BMPString, ASN.1 @c UniversalString,
 * XML / HTML preambles, anything serialised across a network) often
 * specifies UTF-16 or UTF-32 in a fixed byte order rather than
 * host order. These helpers take raw byte buffers, decode them in
 * the specified endianness, and emit canonical UTF-8 with the same
 * validation the @c r_utf16_to_utf8 / @c r_utf32_to_utf8 pair
 * applies. The conversion result is the standard
 * @c RUnicodeResult; failure modes match the host-order siblings.
 *
 * @c srcsize is measured in bytes for all four helpers; lengths that
 * aren't a multiple of the code-unit size (2 for UTF-16, 4 for
 * UTF-32) yield @c R_UNICODE_INVAL.
 * @{
 */

/** @brief Decode a UTF-16BE byte sequence into UTF-8. */
R_API RUnicodeResult r_utf16be_to_utf8 (rchar * dst, rsize dstsize,
    const ruint8 * src, rsize srcsize, rsize * dstoutsize,
    ruint8 ** srcendptr);
/** @brief Decode a UTF-16LE byte sequence into UTF-8. */
R_API RUnicodeResult r_utf16le_to_utf8 (rchar * dst, rsize dstsize,
    const ruint8 * src, rsize srcsize, rsize * dstoutsize,
    ruint8 ** srcendptr);
/** @brief Decode a UTF-32BE byte sequence into UTF-8. */
R_API RUnicodeResult r_utf32be_to_utf8 (rchar * dst, rsize dstsize,
    const ruint8 * src, rsize srcsize, rsize * dstoutsize,
    ruint8 ** srcendptr);
/** @brief Decode a UTF-32LE byte sequence into UTF-8. */
R_API RUnicodeResult r_utf32le_to_utf8 (rchar * dst, rsize dstsize,
    const ruint8 * src, rsize srcsize, rsize * dstoutsize,
    ruint8 ** srcendptr);

/** @brief Allocating UTF-16BE decode; caller frees with @c r_free. */
R_API rchar * r_utf16be_to_utf8_dup (const ruint8 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, ruint8 ** endptr) R_ATTR_MALLOC;
/** @brief Allocating UTF-16LE decode; caller frees with @c r_free. */
R_API rchar * r_utf16le_to_utf8_dup (const ruint8 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, ruint8 ** endptr) R_ATTR_MALLOC;
/** @brief Allocating UTF-32BE decode; caller frees with @c r_free. */
R_API rchar * r_utf32be_to_utf8_dup (const ruint8 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, ruint8 ** endptr) R_ATTR_MALLOC;
/** @brief Allocating UTF-32LE decode; caller frees with @c r_free. */
R_API rchar * r_utf32le_to_utf8_dup (const ruint8 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, ruint8 ** endptr) R_ATTR_MALLOC;

/** @} */

/**
 * @name ASCII codepoint classification
 *
 * Inline predicates that ask "is this codepoint @c < 0x80 and in
 * the named ASCII class?" - the C @c <ctype.h> contract without
 * the locale baggage. Anything outside the ASCII range returns
 * @c FALSE without consulting UCD tables, which keeps these usable
 * by parsers (JSON, ASN.1, HTTP, URL) that intentionally restrict
 * a token grammar to ASCII even when the surrounding text is
 * full Unicode.
 *
 * For real codepoint classification (Greek letters, Cyrillic digits,
 * fullwidth forms, ...) a future UCD-backed @c r_unichar_is_* family
 * would be the right layer. This module sticks to ASCII so callers
 * can pick their level of strictness explicitly.
 * @{
 */

/** @brief @c TRUE iff @p uc is in the 7-bit ASCII range @c [0, 0x80). */
static inline rboolean r_unichar_is_ascii (runichar4 uc)
{ return uc < 0x80u; }

/** @brief @c TRUE iff @p uc is an ASCII letter @c [A-Za-z]. */
static inline rboolean r_unichar_is_ascii_letter (runichar4 uc)
{ return ((uc | 0x20u) - 'a') < 26u; }

/** @brief @c TRUE iff @p uc is an ASCII decimal digit @c [0-9]. */
static inline rboolean r_unichar_is_ascii_digit (runichar4 uc)
{ return (uc - '0') < 10u; }

/** @brief @c TRUE iff @p uc is an ASCII letter or decimal digit. */
static inline rboolean r_unichar_is_ascii_alnum (runichar4 uc)
{ return r_unichar_is_ascii_letter (uc) || r_unichar_is_ascii_digit (uc); }

/** @brief @c TRUE iff @p uc is an ASCII hex digit @c [0-9A-Fa-f]. */
static inline rboolean r_unichar_is_ascii_hex_digit (runichar4 uc)
{
  return r_unichar_is_ascii_digit (uc) ||
      (((uc | 0x20u) - 'a') < 6u);
}

/** @brief @c TRUE iff @p uc is an ASCII whitespace character
 *  (@c '\\t' / @c '\\n' / @c '\\v' / @c '\\f' / @c '\\r' / @c ' '). */
static inline rboolean r_unichar_is_ascii_space (runichar4 uc)
{
  return uc == ' ' || (uc >= 0x09u && uc <= 0x0Du);
}

/** @brief @c TRUE iff @p uc is an ASCII control character
 *  (@c [0, 0x20) or @c 0x7F). */
static inline rboolean r_unichar_is_ascii_control (runichar4 uc)
{ return uc < 0x20u || uc == 0x7Fu; }

/** @brief @c TRUE iff @p uc is an ASCII printable character
 *  (@c [0x20, 0x7F), i.e. visible glyph plus space). */
static inline rboolean r_unichar_is_ascii_print (runichar4 uc)
{ return uc >= 0x20u && uc < 0x7Fu; }

/** @brief @c TRUE iff @p uc is ASCII punctuation - any ASCII
 *  printable that isn't a letter, digit, or space. */
static inline rboolean r_unichar_is_ascii_punct (runichar4 uc)
{
  return r_unichar_is_ascii_print (uc) && uc != ' ' &&
      !r_unichar_is_ascii_alnum (uc);
}

/** @} */

/**
 * @name WTF-8 conversion (UTF-8 + unpaired surrogates)
 *
 * WTF-8 ("Wobbly Transformation Format - 8") is the strict UTF-8
 * encoding extended to allow codepoints in @c [0xD800, 0xDFFF] -
 * unpaired UTF-16 surrogates - to be encoded as their natural
 * 3-byte UTF-8 forms (the @c ED @c A0-BF @c 80-BF range). This is
 * how the JVM serialises lone surrogates inside strings, how Wine
 * round-trips Windows filenames that contain malformed UTF-16, and
 * how some legacy MySQL @c utf8mb3 deployments store text.
 *
 * Strict UTF-8 per RFC 3629 §3 rejects these sequences (see
 * @c r_utf8_to_utf16 / @c r_utf8_validate). WTF-8 mode is opt-in
 * via this separate function family.
 *
 * Codepoints @c >= 0x110000 remain forbidden in WTF-8 - it is
 * still a valid-Unicode-scalars-only encoding, just with the
 * surrogate exclusion lifted. CESU-8 (which additionally encodes
 * supplementary codepoints as surrogate pairs of 3-byte sequences)
 * is not provided.
 * @{
 */

/**
 * @brief Decode a UTF-16 code-unit sequence into WTF-8.
 *
 * Lone surrogates are emitted as 3-byte UTF-8 sequences (their
 * canonical encoding ignoring the RFC 3629 prohibition). Properly
 * paired surrogates round-trip to a single 4-byte supplementary
 * UTF-8 sequence as usual.
 */
R_API RUnicodeResult r_utf16_to_wtf8 (rchar * dst, rsize dstsize,
    const runichar2 * src, rsize srcsize, rsize * dstoutsize,
    runichar2 ** srcendptr);

/**
 * @brief Decode a WTF-8 byte sequence into UTF-16.
 *
 * Surrogate codepoints encoded as 3-byte UTF-8 are passed through
 * to the UTF-16 output as their corresponding code units. Strict
 * UTF-8 input round-trips through this function unchanged.
 */
R_API RUnicodeResult r_wtf8_to_utf16 (runichar2 * dst, rsize dstsize,
    const rchar * src, rssize srcsize, rsize * dstoutsize,
    rchar ** srcendptr);

/** @brief Allocating UTF-16 -> WTF-8 sibling. */
R_API rchar * r_utf16_to_wtf8_dup (const runichar2 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar2 ** endptr) R_ATTR_MALLOC;
/** @brief Allocating WTF-8 -> UTF-16 sibling. */
R_API runichar2 * r_wtf8_to_utf16_dup (const rchar * src, rssize srcsize,
    RUnicodeResult * res, rsize * retsize, rchar ** endptr) R_ATTR_MALLOC;

/** @} */

/**
 * @name UCD-backed codepoint properties and simple case mapping
 *
 * Full-range counterparts to the ASCII-fast classifiers, plus the
 * simple-case-mapping accessors from UAX #44. Driven by a packed
 * lookup of the Unicode Character Database (General_Category column
 * plus the White_Space derived property) emitted by
 * @c tools/gen_unicode_props.py.
 *
 * "Simple" here is the 1:1 case mapping from
 * @c UnicodeData.txt columns 12 / 13 / 14: every input codepoint
 * maps to exactly one output codepoint. Full case mapping per
 * Unicode Standard §3.13 (Greek small final sigma, Turkic dotted
 * I, the @c ss / @c SS family from
 * @c SpecialCasing.txt) is a separate concern - it can change
 * string length and is locale-sensitive, so needs a different API
 * shape. Filed as a follow-up.
 *
 * Codepoints not present in the UCD (the @c Cn / unassigned range,
 * the surrogate halves @c U+D800 - @c U+DFFF) get @c General_Category
 * = @c Cn and return @c FALSE for every @c r_unichar_is_* classifier
 * except @c r_unichar_is_ascii. Simple case mapping returns the
 * input codepoint unchanged for any codepoint with no UCD entry.
 *
 * The classifiers below behave like their @c r_unichar_is_ascii_*
 * cousins but cover the full @c [0, 0x110000) range.
 * @{
 */

/** @brief @c TRUE iff @p uc is a letter (UAX #44 @c L* category). */
R_API rboolean r_unichar_is_letter (runichar4 uc);
/** @brief @c TRUE iff @p uc is a decimal digit (UAX #44 @c Nd). */
R_API rboolean r_unichar_is_digit (runichar4 uc);
/** @brief @c TRUE iff @p uc is a letter or decimal digit. */
R_API rboolean r_unichar_is_alnum (runichar4 uc);
/** @brief @c TRUE iff @p uc has the @c White_Space derived property
 *  per @c PropList.txt - covers @c [Z]* General_Category plus
 *  @c U+0009..U+000D, @c U+0085, etc. */
R_API rboolean r_unichar_is_space (runichar4 uc);
/** @brief @c TRUE iff @p uc is a control character (@c Cc). */
R_API rboolean r_unichar_is_control (runichar4 uc);
/** @brief @c TRUE iff @p uc is printable - any codepoint outside
 *  @c Cc, @c Cf, @c Cs, @c Co, @c Cn per the Unicode Standard
 *  recommendation. */
R_API rboolean r_unichar_is_print (runichar4 uc);
/** @brief @c TRUE iff @p uc is punctuation (UAX #44 @c P*). */
R_API rboolean r_unichar_is_punct (runichar4 uc);
/** @brief @c TRUE iff @p uc is a combining mark (UAX #44 @c M*). */
R_API rboolean r_unichar_is_mark (runichar4 uc);
/** @brief @c TRUE iff @p uc is a symbol (UAX #44 @c S*). */
R_API rboolean r_unichar_is_symbol (runichar4 uc);

/**
 * @brief Simple uppercase mapping per @c UnicodeData.txt column 12.
 *
 * @return @p uc with its @c Simple_Uppercase_Mapping applied, or
 *         @p uc unchanged if no mapping is defined.
 */
R_API runichar4 r_unichar_to_upper (runichar4 uc);
/**
 * @brief Simple lowercase mapping per @c UnicodeData.txt column 13.
 *
 * @return @p uc with its @c Simple_Lowercase_Mapping applied, or
 *         @p uc unchanged if no mapping is defined.
 */
R_API runichar4 r_unichar_to_lower (runichar4 uc);
/**
 * @brief Simple titlecase mapping per @c UnicodeData.txt column 14.
 *
 * @return @p uc with its @c Simple_Titlecase_Mapping applied, or
 *         @p uc unchanged if no mapping is defined. For most
 *         codepoints this equals the uppercase mapping; a small
 *         number of digraph-like characters have a distinct
 *         titlecase form (e.g. @c U+01F1 @c "DZ" -> @c U+01F2
 *         @c "Dz").
 */
R_API runichar4 r_unichar_to_title (runichar4 uc);

/** @} */

R_END_DECLS

/** @} */ /* r_unicode group */

#endif /* __R_UNICODE_H__ */
