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
#ifndef __R_STR_H__
#define __R_STR_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/data/rlist.h>
#include <stdarg.h>
#include <stdio.h>

/**
 * @file rlib/rstr.h
 * @brief NUL-terminated string utilities.
 *
 * Mostly thin wrappers around the C runtime's string functions, plus
 * rlib-specific helpers for pointer-and-size string views (RStrChunk),
 * key-value parsing (RStrKV), pattern matching, integer / float
 * parsing, ASCII string lists (rchar **), and printf / scanf
 * convenience.
 *
 * Functions in this header generally operate on @c rchar @c * strings;
 * a separate @c rssize size argument indicates that -1 means "scan to
 * the terminating NUL" while a non-negative value bounds the operation
 * regardless of NUL bytes within. Functions that take only a pointer
 * (no size) require a NUL-terminated input.
 */

R_BEGIN_DECLS

/**
 * @brief Compile-time string length, excluding the terminating NUL.
 *
 * Only meaningful on string literals or fixed-size arrays of @c rchar.
 * @param str A string literal or character array.
 * @return Length of @p str in bytes.
 */
#define R_STR_SIZEOF(str) (sizeof (str) - 1)

/**
 * @brief Expand a string literal into a (pointer, length) argument
 * pair suitable for functions that take a separate size.
 *
 * Convenience helper for call sites like
 * @c r_str_idx_of_str(haystack, -1, R_STR_WITH_SIZE_ARGS("needle"))
 * that avoids spelling the literal twice.
 *
 * @param str A string literal or character array.
 */
#define R_STR_WITH_SIZE_ARGS(str) (str), R_STR_SIZEOF (str)

/**
 * @brief Status code returned by the string-parsing helpers.
 *
 * Returned by the @c r_str_to_* numeric parsers, @c r_str_chunk_next_line,
 * and the @c r_str_kv_parse family.
 */
typedef enum {
  R_STR_PARSE_OK,        /**< Parse succeeded. */
  R_STR_PARSE_RANGE,     /**< Value parsed but is outside the target type's range. */
  R_STR_PARSE_INVAL,     /**< Input was malformed or no digits were consumed. */
} RStrParse;


/**
 * @name Length and errno descriptions
 *
 * Basic utilities used by the rest of this header. @c r_strlen
 * mirrors @c strlen; @c r_strerror is a thread-safe wrapper around
 * the C runtime's @c strerror.
 * @{
 */

/**
 * @brief Thread-safe wrapper around the C runtime's strerror.
 *
 * Writes the error description for @p errnum into @p buf (@p size
 * bytes, NUL-terminated) and returns either @p buf or, on GNU libc, a
 * static pointer with the same contents. Always returns a usable
 * string even when @p errnum is unknown to the C runtime.
 *
 * @param errnum   The errno value to describe.
 * @param buf      Caller-supplied output buffer.
 * @param size     Capacity of @p buf in bytes.
 * @return A pointer to a NUL-terminated description; either @p buf
 *         or, on platforms whose runtime returns a static string, that
 *         static pointer.
 */
R_API const rchar * r_strerror (int errnum, rchar * buf, rsize size);

/**
 * @brief Return the byte length of the NUL-terminated string @p str.
 *
 * Behaves like the standard C @c strlen.
 *
 * @param str A NUL-terminated string.
 * @return Number of bytes preceding the terminating NUL.
 */
R_API rsize r_strlen (const rchar * str);

/** @} */

/**
 * @name Comparison
 *
 * Match the standard C strcmp / strncmp semantics: a negative, zero
 * or positive result indicates @p a < @p b, @p a == @p b or
 * @p a > @p b respectively. The @c casecmp variants compare
 * case-insensitively in the ASCII range. The @c _size variants take
 * explicit lengths instead of requiring NUL termination; pass -1 on
 * either side to fall back to @c r_strlen.
 * @{
 */

/** @brief Convenience macro: TRUE iff @p a and @p b compare equal. */
#define r_str_equals(a,b) (r_strcmp (a, b) == 0)
/** @brief Case-insensitive byte-comparison of two NUL-terminated strings. */
R_API int r_strcasecmp (const rchar * a, const rchar * b);
/** @brief Case-insensitive byte-comparison with explicit sizes; -1 means NUL-terminated. */
R_API int r_strcasecmp_size (const rchar * a, rssize asize, const rchar * b, rssize bsize);
/** @brief Byte-comparison of two NUL-terminated strings. Behaves like @c strcmp. */
R_API int r_strcmp (const rchar * a, const rchar * b);
/** @brief Byte-comparison with explicit sizes; -1 means NUL-terminated. */
R_API int r_strcmp_size (const rchar * a, rssize asize, const rchar * b, rssize bsize);
/** @brief Case-insensitive byte-comparison of at most @p len bytes. */
R_API int r_strncasecmp (const rchar * a, const rchar * b, rsize len);
/** @brief Byte-comparison of at most @p len bytes. Behaves like @c strncmp. */
R_API int r_strncmp (const rchar * a, const rchar * b, rsize len);

/** @} */

/**
 * @name Prefix / suffix / substring tests
 *
 * Boolean predicates that don't return a position.
 * @{
 */

/**
 * @brief Test whether @p str begins with @p prefix.
 * @param str    NUL-terminated input string.
 * @param prefix NUL-terminated prefix to look for.
 * @return TRUE if @p str starts with @p prefix; FALSE otherwise.
 */
R_API rboolean r_str_has_prefix (const rchar * str, const rchar * prefix);
/**
 * @brief Test whether @p str contains @p sub anywhere.
 *
 * Convenience macro equivalent to
 * @c r_str_idx_of_str(str,-1,sub,-1) @c >= @c 0.
 */
#define r_str_has_substring(str, sub) (r_str_idx_of_str (str, -1, sub, -1) >= 0)
/**
 * @brief Test whether @p str ends with @p suffix.
 * @param str    NUL-terminated input string.
 * @param suffix NUL-terminated suffix to look for.
 * @return TRUE if @p str ends with @p suffix; FALSE otherwise.
 */
R_API rboolean r_str_has_suffix (const rchar * str, const rchar * suffix);

/** @} */

/**
 * @name Character / substring search
 *
 * The @c r_str* names mirror their C-stdlib equivalents
 * (@c strspn, @c strchr, @c strstr, etc.) and require NUL-terminated
 * input. The @c r_str_ptr_of_* / @c r_str_idx_of_* variants take an
 * explicit size (-1 = NUL-terminated) and return either a pointer
 * into @p str on match (or NULL on miss) or a byte index (or -1).
 * @{
 */

/**
 * @brief Locate the first occurrence of byte @p c in @p str, returning
 * its index.
 * @return Byte index of the match, or -1 if not found.
 */
R_API rssize r_str_idx_of_c (const rchar * str, rssize strsize, rchar c);
/**
 * @brief Index of the first byte in @p str that occurs in the set
 * @p c (the first @p chars bytes of which form the set).
 */
R_API rssize r_str_idx_of_c_any (const rchar * str, rssize strsize,
    const rchar * c, rssize chars);
/** @brief Case-insensitive variant of r_str_idx_of_c. */
R_API rssize r_str_idx_of_c_case (const rchar * str, rssize strsize, rchar c);
/** @brief Index of the first occurrence of @p sub inside @p str. */
R_API rssize r_str_idx_of_str (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize);
/** @brief Case-insensitive variant of r_str_idx_of_str. */
R_API rssize r_str_idx_of_str_case (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize);
/**
 * @brief Locate the first occurrence of byte @p c in @p str.
 * @param str     Input buffer.
 * @param strsize Size of @p str in bytes, or -1 to fall back to
 *                @c r_strlen.
 * @param c       Byte to find.
 * @return Pointer into @p str at the match, or NULL.
 */
R_API rchar * r_str_ptr_of_c (const rchar * str, rssize strsize, rchar c);
/**
 * @brief Locate the first occurrence in @p str of any byte from the
 * set @p c (the first @p chars bytes of which form the lookup set).
 * @param str     Input buffer.
 * @param strsize Bytes in @p str, or -1.
 * @param c       Pointer to the lookup set.
 * @param chars   Bytes in @p c, or -1.
 * @return Pointer into @p str at the match, or NULL.
 */
R_API rchar * r_str_ptr_of_c_any (const rchar * str, rssize strsize,
    const rchar * c, rssize chars);
/**
 * @brief Locate the first occurrence of @p sub inside @p str.
 * @param str     Input buffer.
 * @param strsize Bytes in @p str, or -1.
 * @param sub     Substring to search for.
 * @param subsize Bytes in @p sub, or -1.
 * @return Pointer into @p str at the match, or NULL.
 */
R_API rchar * r_str_ptr_of_str (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize);
/**
 * @brief Case-insensitive variant of r_str_ptr_of_str.
 *
 * Comparison is case-insensitive in the ASCII range; non-ASCII bytes
 * are compared verbatim.
 */
R_API rchar * r_str_ptr_of_str_case (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize);
/**
 * @brief Locate the first occurrence of @p c in @p str. Behaves like
 * @c strchr.
 * @return Pointer into @p str at the match, or NULL if not found.
 */
R_API rchar * r_strchr (const rchar * str, int c);
/**
 * @brief Length of the initial substring of @p str that contains no
 * bytes from @p cset. Behaves like @c strcspn.
 */
R_API rsize r_strcspn (const rchar * str, const rchar * cset);
/**
 * @brief Bounded variant of r_strchr; scans at most @p size bytes.
 * @return Pointer into @p str at the match, or NULL.
 */
R_API rchar * r_strnchr (const rchar * str, int c, rsize size);
/** @brief Bounded variant of r_strrchr; scans at most @p size bytes. */
R_API rchar * r_strnrchr (const rchar * str, int c, rsize size);
/** @brief Bounded variant of r_strstr; scans at most @p size bytes. */
R_API rchar * r_strnstr (const rchar * str, const rchar * sub, rsize size);
/**
 * @brief Locate the first byte in @p str that occurs in @p set.
 * Behaves like @c strpbrk.
 */
R_API rchar * r_strpbrk (const rchar * str, const rchar * set);
/**
 * @brief Locate the last occurrence of @p c in @p str. Behaves like
 * @c strrchr.
 */
R_API rchar * r_strrchr (const rchar * str, int c);
/**
 * @brief Length of the initial substring of @p str that consists
 * entirely of bytes from @p set. Behaves like @c strspn.
 */
R_API rsize r_strspn (const rchar * str, const rchar * set);
/**
 * @brief Locate the first occurrence of @p sub inside @p str.
 * Behaves like @c strstr.
 */
R_API rchar * r_strstr (const rchar * str, const rchar * sub);

/** @} */

/**
 * @name Copy and concatenate
 *
 * @c r_strcpy / @c r_strncpy / @c r_strcat / @c r_strncat behave
 * exactly as their standard C counterparts. @c r_stpcpy / @c r_stpncpy
 * return a pointer to the terminating NUL of the destination after
 * the copy, useful for chained appends.
 * @{
 */

/** @brief Like r_strcpy but returns the address of the NUL it wrote. */
R_API rchar * r_stpcpy (rchar * dst, const rchar * src);
/** @brief Like r_strncpy but returns the address of the NUL it wrote. */
R_API rchar * r_stpncpy (rchar * dst, const rchar * src, rsize len);
/** @brief Append @p src to @p dst. Behaves like @c strcat. */
R_API rchar * r_strcat (rchar * dst, const rchar * src);
/** @brief Copy @p src into @p dst including the terminating NUL. Behaves like @c strcpy. */
R_API rchar * r_strcpy (rchar * dst, const rchar * src);
/** @brief Append at most @p len bytes of @p src to @p dst. Behaves like @c strncat. */
R_API rchar * r_strncat (rchar * dst, const rchar * src, rsize len);
/** @brief Copy at most @p len bytes of @p src into @p dst. Behaves like @c strncpy. */
R_API rchar * r_strncpy (rchar * dst, const rchar * src, rsize len);

/** @} */

/**
 * @name Duplication
 *
 * All return freshly @c r_malloc'd buffers; caller @c r_free's. NULL
 * is returned on allocation failure (and, for r_strdup, when @p str
 * itself is NULL).
 * @{
 */

/** @brief Duplicate a NUL-terminated string. */
R_API rchar * r_strdup (const rchar * str);
/**
 * @brief Duplicate the first @p size bytes of @p str.
 * @param str  Input buffer to copy from.
 * @param size Bytes to copy, or -1 to fall back to r_strlen(str).
 */
R_API rchar * r_strdup_size (const rchar * str, rssize size);
/** @brief Duplicate @p str with leading and trailing @p chars removed. */
R_API rchar * r_strdup_strip (const rchar * str, const rchar * chars);
/** @brief Duplicate @p str with leading and trailing whitespace removed. */
R_API rchar * r_strdup_wstrip (const rchar * str);
/** @brief Duplicate at most @p n bytes of @p str (always NUL-terminated). */
R_API rchar * r_strndup (const rchar * str, rsize n);

/** @} */

/**
 * @name Strip
 *
 * In-place strip functions mutate @p str by NUL-truncating from the
 * trailing side and return a pointer somewhere inside @p str past
 * any leading match. The @c l*-prefixed variants only strip leading
 * characters and return a const pointer (the source isn't written).
 * The @c t*-prefixed variants only strip trailing characters.
 * @{
 */

/** @brief Skip leading @p chars; returns a pointer past them. */
R_API const rchar * r_str_lstrip (const rchar * str, const rchar * chars);
/** @brief Skip leading whitespace; returns a pointer past it. */
R_API const rchar * r_str_lwstrip (const rchar * str);
/** @brief Strip leading and trailing @p chars from @p str in place. */
R_API rchar * r_str_strip (rchar * str, const rchar * chars);
/** @brief Strip trailing @p chars from @p str in place. */
R_API rchar * r_str_tstrip (rchar * str, const rchar * chars);
/** @brief Strip trailing whitespace from @p str in place. */
R_API rchar * r_str_twstrip (rchar * str);
/** @brief Strip leading and trailing whitespace from @p str in place. */
R_API rchar * r_str_wstrip (rchar * str);

/** @} */

/**
 * @name Join and split
 *
 * Join and split helpers that allocate fresh buffers. Caller owns
 * the result and is responsible for @c r_free / @c r_strv_free.
 * @{
 */

/**
 * @brief Concatenate the variadic NUL-terminated strings, separating
 * them with @p delim, into a freshly allocated buffer.
 *
 * The variadic list is NULL-terminated; an empty list yields a
 * fresh empty string.
 */
R_API rchar * r_strjoin (const rchar * delim, ...) R_ATTR_NULL_TERMINATED;
/** @brief va_list flavour of r_strjoin. */
R_API rchar * r_strjoinv (const rchar * delim, va_list args);
/**
 * @brief Join into a caller-supplied buffer of @p size bytes.
 * @return @p str on success; output is always NUL-terminated.
 *         Truncates rather than failing if @p size is too small.
 */
R_API rchar * r_strnjoin (rchar * str, rsize size, const rchar * delim, ...) R_ATTR_NULL_TERMINATED;
/** @brief va_list flavour of r_strnjoin. */
R_API rchar * r_strnjoinv (rchar * str, rsize size, const rchar * delim, va_list args);
/**
 * @brief Split @p str on @p delim into a freshly allocated rchar**
 * string vector (NULL-terminated).
 *
 * @param str   NUL-terminated input string.
 * @param delim NUL-terminated separator string.
 * @param max   Upper bound on the number of pieces produced; 0 means
 *              unlimited. Use @c r_strv_free on the result.
 */
R_API rchar ** r_strsplit (const rchar * str, const rchar * delim, rsize max);

/** @} */

/**
 * @name printf-style formatting
 *
 * Thin wrappers around the C runtime's printf family. The @c r_sprintf
 * / @c r_vsprintf forms exist mostly to silence MSVC's deprecation
 * warning on plain @c sprintf; the rest match their standard
 * counterparts. @c r_asprintf / @c r_vasprintf allocate the output
 * buffer; @c r_strprintf / @c r_strvprintf return the allocated
 * buffer directly (caller @c r_free's).
 * @{
 */

/**
 * @brief Format into a freshly @c r_malloc'd buffer and store its
 * address at *@p str.
 *
 * @return Number of bytes written (excluding the terminating NUL),
 *         or a negative value on failure.
 */
R_API int     r_asprintf (rchar ** str, const rchar * fmt, ...) R_ATTR_PRINTF (2, 3);
/** @brief @c snprintf passthrough. */
#define r_snprintf      snprintf
#ifdef _MSC_VER
/* MSVC deprecates plain sprintf / vsprintf (C4996). Route through
 * the secure *_s variants using SIZE_MAX as the buffer size, which
 * skips the runtime bounds check and preserves the unbounded
 * semantics callers expect (they've already sized the buffer). */
/**
 * @brief @c sprintf-compatible wrapper. On MSVC routes through the
 * secure @c vsprintf_s to avoid the C4996 deprecation warning.
 */
static inline int r_sprintf (rchar * buf, const rchar * fmt, ...)
{
  va_list ap;
  int ret;
  va_start (ap, fmt);
  ret = vsprintf_s (buf, (size_t)-1, fmt, ap);
  va_end (ap);
  return ret;
}
/** @brief @c vsprintf-compatible wrapper; see r_sprintf. */
#define r_vsprintf(buf, fmt, ap)  vsprintf_s ((buf), (size_t)-1, (fmt), (ap))
#else
/** @brief @c sprintf passthrough on non-MSVC platforms. */
#define r_sprintf       sprintf
/** @brief @c vsprintf passthrough on non-MSVC platforms. */
#define r_vsprintf      vsprintf
#endif
/**
 * @brief Format into a freshly @c r_malloc'd buffer and return it.
 * @return The allocated string, or NULL on failure. Caller @c r_free's.
 */
R_API rchar * r_strprintf (const rchar * fmt, ...) R_ATTR_PRINTF (1, 2);
/** @brief va_list flavour of r_strprintf. */
R_API rchar * r_strvprintf (const rchar * fmt, va_list args) R_ATTR_PRINTF (1, 0);
/** @brief va_list flavour of r_asprintf. */
R_API int     r_vasprintf (rchar ** str, const rchar * fmt, va_list args) R_ATTR_PRINTF (2, 0);
/** @brief @c vsnprintf passthrough. */
#define r_vsnprintf     vsnprintf

/** @} */

/**
 * @name scanf-style scanning
 * @{
 */

/** @brief @c sscanf passthrough. */
R_API int     r_strscanf (const rchar * str, const rchar * fmt, ...) R_ATTR_SCANF (2, 3);
/** @brief va_list flavour of r_strscanf. */
R_API int     r_strvscanf (const rchar * str, const rchar * fmt, va_list args) R_ATTR_SCANF (2, 0);

/** @} */

/**
 * @name String-to-number parsing
 *
 * Each function parses an integer from @p str using base @p base
 * (2 through 36; 0 means autodetect via the standard 0 / 0x / 0b
 * prefixes). On success the parsed value is returned and, if
 * @p endptr is non-NULL, *@p endptr is set to one past the last
 * consumed character. On failure the return value is 0 (signed)
 * or 0 (unsigned), *@p endptr equals @p str, and *@p res (if
 * non-NULL) carries @c R_STR_PARSE_INVAL or @c R_STR_PARSE_RANGE.
 *
 * The fixed-width spellings are the source of truth; @c r_str_to_int
 * / @c r_str_to_uint and the @c r_strto* shortcut macros below
 * dispatch to the right width based on the host's @c int / @c long
 * size.
 * @{
 */

/**
 * @brief Parse a double-precision float from @p str.
 *
 * Accepts the same syntax as the C runtime's @c strtod. *@p res
 * (when non-NULL) is set as for the integer parsers.
 */
R_API rdouble r_str_to_double (const rchar * str, const rchar ** endptr, RStrParse * res);
/** @brief Single-precision counterpart of r_str_to_double. */
R_API rfloat r_str_to_float (const rchar * str, const rchar ** endptr, RStrParse * res);
/** @brief Parse an 8-bit signed integer from @p str. */
R_API rint8   r_str_to_int8   (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
/** @brief Parse a 16-bit signed integer from @p str. */
R_API rint16  r_str_to_int16  (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
/** @brief Parse a 32-bit signed integer from @p str. */
R_API rint32  r_str_to_int32  (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
/** @brief Parse a 64-bit signed integer from @p str. */
R_API rint64  r_str_to_int64  (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
/** @brief Parse an 8-bit unsigned integer from @p str. */
R_API ruint8  r_str_to_uint8  (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
/** @brief Parse a 16-bit unsigned integer from @p str. */
R_API ruint16 r_str_to_uint16 (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
/** @brief Parse a 32-bit unsigned integer from @p str. */
R_API ruint32 r_str_to_uint32 (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
/** @brief Parse a 64-bit unsigned integer from @p str. */
R_API ruint64 r_str_to_uint64 (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);

#if RLIB_SIZEOF_INT == 8
#define r_str_to_int   r_str_to_int64    /**< Parse an @c int (host-width). */
#define r_str_to_uint  r_str_to_uint64   /**< Parse an @c unsigned (host-width). */
#elif RLIB_SIZEOF_INT == 4
#define r_str_to_int   r_str_to_int32
#define r_str_to_uint  r_str_to_uint32
#elif RLIB_SIZEOF_INT == 2
#define r_str_to_int   r_str_to_int16
#define r_str_to_uint  r_str_to_uint16
#elif RLIB_SIZEOF_INT == 1
#define r_str_to_int   r_str_to_int8
#define r_str_to_uint  r_str_to_uint8
#endif

/** @brief @c strtod equivalent; drops the optional res argument. */
#define r_strtod(str, endptr) r_str_to_double (str, endptr, NULL)
/** @brief @c strtof equivalent; drops the optional res argument. */
#define r_strtof(str, endptr) r_str_to_float  (str, endptr, NULL)
#if RLIB_SIZEOF_LONG == 8
#define r_strtol(str, endptr, base)   r_str_to_int64 (str, endptr, base, NULL)   /**< @c strtol equivalent. */
#define r_strtoul(str, endptr, base)  r_str_to_uint64 (str, endptr, base, NULL)  /**< @c strtoul equivalent. */
#elif RLIB_SIZEOF_LONG == 4
#define r_strtol(str, endptr, base)   r_str_to_int32 (str, endptr, base, NULL)
#define r_strtoul(str, endptr, base)  r_str_to_uint32 (str, endptr, base, NULL)
#elif RLIB_SIZEOF_LONG == 2
#define r_strtol(str, endptr, base)   r_str_to_int16 (str, endptr, base, NULL)
#define r_strtoul(str, endptr, base)  r_str_to_uint16 (str, endptr, base, NULL)
#elif RLIB_SIZEOF_LONG == 1
#define r_strtol(str, endptr, base)   r_str_to_int8 (str, endptr, base, NULL)
#define r_strtoul(str, endptr, base)  r_str_to_uint8 (str, endptr, base, NULL)
#endif
/** @brief @c strtoll equivalent (always 64-bit). */
#define r_strtoll(str, endptr, base)  r_str_to_int64 (str, endptr, base, NULL)
/** @brief @c strtoull equivalent (always 64-bit). */
#define r_strtoull(str, endptr, base) r_str_to_uint64 (str, endptr, base, NULL)

/** @} */

/**
 * @name String chunk (pointer-and-size view)
 *
 * @c RStrChunk borrows its bytes from elsewhere - the chunk does not
 * own the storage and freeing it is up to the caller. Used by the
 * parsers and tokenisers in this header so they can return spans
 * without allocating, and by @c r_str_kv_* for key / value pairs.
 *
 * The macro shorthand for search and indexing methods (e.g.
 * @c r_str_chunk_idx_of_c) delegates to the non-chunk equivalents
 * in the "Character / substring search" group above.
 * @{
 */

/**
 * @brief Pointer-and-size view of a string region.
 */
typedef struct {
  rchar * str;     /**< First byte of the chunk; not NUL-terminated. */
  rsize size;      /**< Length of the chunk in bytes. */
} RStrChunk;
/** @brief Zero-initialiser for stack RStrChunk values. */
#define R_STR_CHUNK_INIT        { NULL, 0 }
/** @brief Duplicate the chunk's bytes into a fresh NUL-terminated string. */
#define r_str_chunk_dup(chunk)  r_strndup ((chunk)->str, (chunk)->size)
/** @brief Pointer one past the last byte of the chunk. */
#define r_str_chunk_end(chunk)  ((chunk)->str + (chunk)->size)

/** @brief Case-insensitive variant of r_str_chunk_cmp. */
R_API int r_str_chunk_casecmp (const RStrChunk * buf, const rchar * str, rssize size);
/**
 * @brief Compare a chunk against a (str, size) pair byte-for-byte.
 * @param buf  Chunk under test.
 * @param str  String to compare against.
 * @param size Bytes in @p str, or -1 to fall back to r_strlen.
 * @return Negative, zero, or positive as in @c r_strcmp.
 */
R_API int r_str_chunk_cmp (const RStrChunk * buf, const rchar * str, rssize size);
/**
 * @brief Test whether the chunk starts with the given prefix.
 * @param buf  Chunk under test.
 * @param str  Prefix to look for.
 * @param size Bytes in @p str, or -1 to fall back to r_strlen.
 */
R_API rboolean r_str_chunk_has_prefix (const RStrChunk * buf, const rchar * str, rssize size);
/** @brief Convenience: r_str_idx_of_c on the chunk's bytes. */
#define r_str_chunk_idx_of_c(buf, c)                r_str_idx_of_c ((buf)->str, (buf)->size, c)
/** @brief Convenience: r_str_idx_of_c_any on the chunk's bytes. */
#define r_str_chunk_idx_of_c_any(buf, c, chars)     r_str_idx_of_c_any ((buf)->str, (buf)->size, c, chars)
/** @brief Convenience: r_str_idx_of_c_case on the chunk's bytes. */
#define r_str_chunk_idx_of_c_case(buf, c)           r_str_idx_of_c_case ((buf)->str, (buf)->size, c)
/** @brief Convenience: r_str_idx_of_str on the chunk's bytes. */
#define r_str_chunk_idx_of_str(buf, sub, subsize)      r_str_idx_of_str ((buf)->str, (buf)->size, sub, subsize)
/** @brief Convenience: r_str_idx_of_str_case on the chunk's bytes. */
#define r_str_chunk_idx_of_str_case(buf, sub, subsize) r_str_idx_of_str_case ((buf)->str, (buf)->size, sub, subsize)
/** @brief Strip leading whitespace from the chunk in place. */
R_API void r_str_chunk_lwstrip (RStrChunk * buf);
/**
 * @brief Consume one line from @p buf into @p line.
 *
 * Updates @p buf->str / @p buf->size in place so successive calls
 * iterate the lines of the original chunk. Line terminators are not
 * included in @p line. Returns @c R_STR_PARSE_OK on success or
 * @c R_STR_PARSE_INVAL when @p buf is empty.
 */
R_API RStrParse r_str_chunk_next_line (const RStrChunk * buf, RStrChunk * line);
/** @brief Convenience: r_str_ptr_of_c on the chunk's bytes. */
#define r_str_chunk_ptr_of_c(buf, c)                r_str_ptr_of_c ((buf)->str, (buf)->size, c)
/** @brief Convenience: r_str_ptr_of_c_any on the chunk's bytes. */
#define r_str_chunk_ptr_of_c_any(buf, c, chars)     r_str_ptr_of_c_any ((buf)->str, (buf)->size, c, chars)
/** @brief Convenience: r_str_ptr_of_c_case on the chunk's bytes. */
#define r_str_chunk_ptr_of_c_case(buf, c)           r_str_ptr_of_c_case ((buf)->str, (buf)->size, c)
/** @brief Convenience: r_str_ptr_of_str on the chunk's bytes. */
#define r_str_chunk_ptr_of_str(buf, sub, subsize)      r_str_ptr_of_str ((buf)->str, (buf)->size, sub, subsize)
/** @brief Convenience: r_str_ptr_of_str_case on the chunk's bytes. */
#define r_str_chunk_ptr_of_str_case(buf, sub, subsize) r_str_ptr_of_str_case ((buf)->str, (buf)->size, sub, subsize)
/**
 * @brief Split @p buf into chunks using the NUL-terminated string
 * @p delim as the separator.
 *
 * The variadic arguments must be (RStrChunk *) pointers terminated
 * by a single NULL; each is filled with one piece of @p buf in order.
 *
 * @return Number of output chunks that were filled.
 */
R_API ruint r_str_chunk_split (RStrChunk * buf, const rchar * delim, ...) R_ATTR_NULL_TERMINATED;
/** @brief va_list flavour of r_str_chunk_split. */
R_API ruint r_str_chunk_splitv (RStrChunk * buf, const rchar * delim, va_list args);
/** @brief Strip leading and trailing whitespace from the chunk in place. */
R_API void r_str_chunk_wstrip (RStrChunk * buf);

/** @} */

/**
 * @name Key-value parsing
 *
 * @c RStrKV is a pair of chunks built from one @c key<delim>value
 * binding inside a larger string. Like @c RStrChunk, neither member
 * owns the underlying storage; freeing is up to whoever owns the
 * input buffer.
 * @{
 */

/**
 * @brief A pair of borrowed chunks representing one key / value
 * binding inside a larger string.
 *
 * Filled by the @c r_str_kv_parse family.
 */
typedef struct {
  RStrChunk key;     /**< Key chunk (left of the delimiter). */
  RStrChunk val;     /**< Value chunk (right of the delimiter). */
} RStrKV;
/** @brief Zero-initialiser for stack RStrKV values. */
#define R_STR_KV_INIT           { R_STR_CHUNK_INIT, R_STR_CHUNK_INIT }
/** @brief Duplicate the key chunk into a fresh NUL-terminated string. */
#define r_str_kv_dup_key(kv)    r_str_chunk_dup (&(kv)->key)
/** @brief Duplicate the value chunk into a fresh NUL-terminated string. */
#define r_str_kv_dup_value(kv)  r_str_chunk_dup (&(kv)->val)

/**
 * @brief Parse one @c key<delim>value pair starting at @p str.
 *
 * On success, @p kv->key and @p kv->val are filled with views into
 * @p str (no copies) and *@p endptr (when non-NULL) is set to one
 * past the consumed bytes. @p delim is a NUL-terminated string of
 * separator characters; the first occurrence of any of them ends
 * the key.
 *
 * @param kv     Receives the parsed key / value chunks.
 * @param str    Input buffer.
 * @param size   Bytes in @p str, or -1 to fall back to r_strlen.
 * @param delim  NUL-terminated set of separator characters.
 * @param endptr Optional out-pointer set to one past the consumed bytes.
 */
R_API RStrParse r_str_kv_parse (RStrKV * kv, const rchar * str, rssize size,
    const rchar * delim, const rchar ** endptr);
/**
 * @brief Parse a sequence of key / value pairs.
 *
 * @p kv must point to enough storage for the caller's expected
 * number of pairs. @p kvdelim separates keys from values within
 * each pair; @p delim separates pairs from each other. Sizes may be
 * -1 to fall back to r_strlen on each delimiter string.
 *
 * @return @c R_STR_PARSE_OK on success.
 */
R_API RStrParse r_str_kv_parse_multiple (RStrKV * kv, const rchar * str, rssize size,
    const rchar * kvdelim, rssize kvdsize, const rchar * delim, rssize dsize,
    const rchar ** endptr);

/**
 * @brief Test whether the KV's key matches @p key (first @p size
 * bytes; -1 = NUL-terminated).
 */
R_API rboolean r_str_kv_is_key (const RStrKV * kv, const rchar * key, rssize size);
/** @brief Test whether the KV's value matches @p val. */
R_API rboolean r_str_kv_is_value (const RStrKV * kv, const rchar * val, rssize size);

/** @} */

/**
 * @name Pattern matching
 *
 * Simple shell-style pattern matching (@c '?' single-byte wildcard,
 * @c '*' any-length wildcard). The detailed variant
 * (@c r_str_match_pattern) populates an @c RStrMatchResult with the
 * exact span each pattern token consumed; the simple variant just
 * returns TRUE / FALSE.
 * @{
 */

/**
 * @brief Token type produced by the pattern matcher.
 *
 * The same vocabulary as @c r_mem_scan_*: a pattern is a sequence of
 * literal-byte runs interleaved with single-byte and sized
 * wildcards.
 */
typedef enum {
  R_STR_TOKEN_NONE = -1,        /**< Sentinel for "unset" token type. */
  R_STR_TOKEN_CHARS,            /**< Literal byte run. */
  R_STR_TOKEN_WILDCARD,         /**< Single-byte wildcard ("?"). */
  R_STR_TOKEN_WILDCARD_SIZED,   /**< Multi-byte wildcard with an explicit length. */
  R_STR_TOKEN_COUNT             /**< Number of token types; not a value. */
} RStrTokenType;

/**
 * @brief Status code from r_str_match_pattern.
 *
 * Negative values are errors; @c R_STR_MATCH_RESULT_OK and
 * @c R_STR_MATCH_RESULT_NO_MATCH are the two regular outcomes.
 */
typedef enum {
  R_STR_MATCH_RESULT_INVAL             = -4,   /**< Caller passed a bad argument. */
  R_STR_MATCH_RESULT_OOM               = -3,   /**< Allocation for the result failed. */
  R_STR_MATCH_RESULT_INVALID_PATTERN   = -2,   /**< @p pattern didn't parse. */
  R_STR_MATCH_RESULT_PATTERN_NOT_IMPL  = -1,   /**< Recognised pattern token isn't yet supported. */
  R_STR_MATCH_RESULT_OK                =  0,   /**< Match found; result populated. */
  R_STR_MATCH_RESULT_NO_MATCH                  /**< Pattern parsed but didn't match. */
} RStrMatchResultType;

/**
 * @brief One token of a parsed pattern, paired with the matched span.
 */
typedef struct _RStrMatchToken {
  RStrTokenType type;     /**< Kind of token this entry came from. */
  const rchar * pattern;  /**< Pointer into the original pattern at this token's start. */
  RStrChunk chunk;        /**< Span of the input that this token matched. */
} RStrMatchToken;

/**
 * @brief Result of r_str_match_pattern.
 *
 * Variable-length: the @c token array is a flexible member sized to
 * @c tokens entries. Allocated by the matcher; caller @c r_free's.
 */
typedef struct _RStrMatchResult {
  rchar * ptr;            /**< Pointer into the input where the match starts. */
  rchar * end;            /**< Pointer one past the last matched byte. */
  rsize tokens;           /**< Number of entries in @c token. */
  RStrMatchToken token[0];/**< Per-token match spans. */
} RStrMatchResult;

/**
 * @brief Test whether @p str matches a simple shell-style pattern.
 *
 * Accepts @c '?' (single-byte wildcard) and @c '*' (any-length
 * wildcard) in @p pattern. Returns TRUE on match. Cheaper than
 * r_str_match_pattern when the caller only needs the boolean
 * answer.
 *
 * @param str     Input buffer.
 * @param size    Bytes in @p str, or -1 to fall back to r_strlen.
 * @param pattern NUL-terminated pattern with '?' / '*' wildcards.
 */
R_API rboolean r_str_match_simple_pattern (const rchar * str, rssize size,
    const rchar * pattern);
/**
 * @brief Match @p str against @p pattern and, on success, allocate a
 * detailed match-result record into *@p result.
 *
 * The record carries one @c RStrMatchToken per pattern token, giving
 * the exact input span each token matched. Caller @c r_free's
 * *@p result on success.
 *
 * @return One of @c R_STR_MATCH_RESULT_OK / @c _NO_MATCH; negative
 *         on error.
 */
R_API RStrMatchResultType r_str_match_pattern (const rchar * str, rssize size,
    const rchar * pattern, RStrMatchResult ** result);

/** @} */

/**
 * @name Memory dump and hex
 *
 * Helpers that render a byte buffer as printable text - either a
 * hex+ASCII dump suitable for logging, or a plain hex string for
 * serialisation. @c r_str_hex_to_binary / @c r_str_hex_mem invert the
 * hex variants.
 * @{
 */

/**
 * @brief Required bytes in the destination buffer to dump @p align
 * source bytes per line via @c r_str_mem_dump.
 */
#define R_STR_MEM_DUMP_SIZE(align) \
  ((align * 4) + (align / 4) + (RLIB_SIZEOF_VOID_P * 2) + 8)
/**
 * @brief Render @p src (@p size bytes) into the caller-supplied @p dst
 * as a hex+ASCII dump line.
 *
 * @p dst must be at least @c R_STR_MEM_DUMP_SIZE(align) bytes for
 * each line of @p align input bytes the caller wants emitted.
 */
R_API void r_str_dump (rchar * dst, const rchar * src, rsize size);
/**
 * @brief Decode hex digits from @p hex into a freshly allocated byte
 * buffer; stores the resulting size in *@p outsize.
 * @return The buffer, or NULL on failure. Caller @c r_free's.
 */
R_API ruint8 * r_str_hex_mem (const rchar * hex, rsize * outsize) R_ATTR_MALLOC;
/**
 * @brief Decode hex digits from @p hex into @p bin (capacity @p size
 * bytes).
 * @return Number of bytes written to @p bin.
 */
R_API rsize r_str_hex_to_binary (const rchar * hex, ruint8 * bin, rsize size);
/**
 * @brief Render @p size bytes from @p ptr into @p str as a multi-line
 * hex+ASCII dump.
 * @param str   Destination buffer.
 * @param ptr   Source bytes to render.
 * @param size  Number of bytes to consume from @p ptr.
 * @param align Number of source bytes per line; see R_STR_MEM_DUMP_SIZE
 *              for the destination capacity formula.
 * @return TRUE on success.
 */
R_API rboolean r_str_mem_dump (rchar * str, const ruint8 * ptr,
    rsize size, rsize align);
/**
 * @brief Like r_str_mem_dump but allocates the destination buffer.
 * @return Freshly allocated NUL-terminated dump; caller @c r_free's.
 */
R_API rchar * r_str_mem_dump_dup (const ruint8 * ptr,
    rsize size, rsize align);
/**
 * @brief Encode @p size bytes from @p ptr as a contiguous lowercase
 * hex string.
 * @return Freshly allocated NUL-terminated hex string.
 */
R_API rchar * r_str_mem_hex (const ruint8 * ptr, rsize size);
/**
 * @brief Encode @p ptr as hex with an arbitrary divider inserted
 * every @p interval bytes (e.g. ":" for "DE:AD:BE:EF").
 */
R_API rchar * r_str_mem_hex_full (const ruint8 * ptr, rsize size,
    const rchar * divider, rsize interval);

/** @} */

/**
 * @name String list / string vector
 *
 * Two flavours of list-of-strings. The @c r_str_list_* form returns
 * an @c RSList (singly linked list of @c rchar @c *). The @c r_strv_*
 * form returns a NULL-terminated @c rchar @c ** array. Both copy
 * the input strings; ownership of the result transfers to the
 * caller.
 * @{
 */

/**
 * @brief Build an RSList from a NULL-terminated variadic argument
 * list of NUL-terminated strings.
 */
R_API RSList * r_str_list_new (const rchar * str0, ...);
/** @brief va_list flavour of r_str_list_new. */
R_API RSList * r_str_list_newv (const rchar * str0, va_list args);
/**
 * @brief Build a NULL-terminated @c rchar** vector from a variadic
 * argument list of NUL-terminated strings.
 *
 * Use @c r_strv_free on the result.
 */
R_API rchar ** r_strv_new (const rchar * str0, ...);
/** @brief va_list flavour of r_strv_new. */
R_API rchar ** r_strv_newv (const rchar * str0, va_list args);
/** @brief Duplicate a string vector (each element and the vector itself). */
R_API rchar ** r_strv_copy (rchar * const * strv);

/** @brief TRUE iff @p strv contains a string equal to @p str. */
R_API rboolean r_strv_contains (rchar * const * strv, const rchar * str);
/** @brief Invoke @p func(s, @p user) for each string @c s in @p strv. */
R_API void r_strv_foreach (rchar ** strv, RFunc func, rpointer user);
/**
 * @brief Join the strings in @p strv with @p delim into a freshly
 * allocated buffer; caller @c r_free's.
 */
R_API rchar * r_strv_join (rchar * const * strv, const rchar * delim);
/** @brief Number of strings in @p strv (the trailing NULL excluded). */
R_API rsize r_strv_len (rchar * const * strv);

/** @brief Free a string vector built by r_strv_new and friends. */
R_API void r_strv_free (rchar ** strv);

/** @} */

R_END_DECLS

#endif /* __R_STR_H__ */

