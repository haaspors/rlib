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
#ifndef __R_STRING_H__
#define __R_STRING_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <stdarg.h>

/**
 * @defgroup r_string Mutable strings (RString)
 * @ingroup r_data
 * @brief Heap-allocated mutable string-builder type, complement to
 * the immutable @c rchar @c * helpers in @c rlib/rstr.h.
 * @{
 */

/**
 * @file rlib/data/rstring.h
 * @brief Mutable string-builder type.
 *
 * @c RString complements the immutable @c rchar @c * helpers in
 * @c rlib/rstr.h. Each instance owns a heap buffer that grows as
 * needed when bytes are appended / inserted / overwritten, so
 * callers don't have to chase capacity by hand. Construct with
 * @c r_string_new or @c r_string_new_sized; release with
 * @c r_string_free or, if you want to keep the inner @c rchar @c *
 * after, @c r_string_free_keep.
 *
 * The mutating functions return the resulting length so callers
 * can chain or detect failure (0 with no prior length is the only
 * ambiguous case; otherwise a non-zero result means the operation
 * was applied).
 */

R_BEGIN_DECLS

/** @brief Opaque heap-allocated mutable string. */
typedef struct RString RString;

/**
 * @name Lifecycle
 * @{
 */

/**
 * @brief Allocate an RString seeded from the NUL-terminated @p cstr.
 * @param cstr Initial contents; pass NULL for an empty string.
 * @return The allocated RString, or NULL on allocation failure.
 *         Caller @c r_string_free's.
 */
R_ATTR_WARN_UNUSED_RESULT
R_API RString * r_string_new (const rchar * cstr) R_ATTR_MALLOC;
/**
 * @brief Allocate an empty RString with @p size bytes of buffer
 * reserved up front.
 *
 * Useful when the caller knows roughly how much they're going to
 * append, to skip a few of the growth-doubling steps.
 *
 * @param size Initial buffer capacity in bytes (not including the
 *             terminating NUL).
 */
R_ATTR_WARN_UNUSED_RESULT
R_API RString * r_string_new_sized (rsize size) R_ATTR_MALLOC;

/** @brief Free the RString and its backing buffer. */
R_API void r_string_free (RString * str);
/**
 * @brief Free the RString struct but return its inner @c rchar @c *.
 *
 * Ownership of the returned buffer transfers to the caller, who
 * is responsible for @c r_free'ing it. Useful when the build-up
 * phase is over and the string proper is what gets handed
 * downstream.
 */
R_ATTR_WARN_UNUSED_RESULT
R_API rchar * r_string_free_keep (RString * str);

/** @} */

/**
 * @name Queries
 * @{
 */

/** @brief Current length in bytes (excluding the terminating NUL). */
R_API rsize r_string_length (RString * str);
/** @brief Capacity of the underlying buffer in bytes. */
R_API rsize r_string_alloc_size (RString * str);

/** @brief Byte-compare two @c RString contents. Behaves like @c r_strcmp. */
R_API int r_string_cmp (RString * str1, RString * str2);
/** @brief Byte-compare an @c RString against a NUL-terminated C string. */
R_API int r_string_cmp_cstr (RString * str, const rchar * cstr);

/** @} */

/**
 * @name Mutations
 *
 * All return the resulting length in bytes after the operation.
 * Family layout: reset → append* → prepend* → insert* → overwrite*
 * → truncate / erase. The @c _len variants take an explicit byte
 * count, useful for non-NUL-terminated source spans; the @c _printf
 * / @c _vprintf variants format their arguments via the C runtime's
 * printf into the build buffer in one step.
 * @{
 */

/**
 * @brief Discard the current contents and seed @p str from a fresh
 * NUL-terminated C string.
 * @param str  Target string.
 * @param cstr Replacement contents; pass NULL or "" to clear.
 * @return New length after the reset.
 */
R_API rsize r_string_reset (RString * str, const rchar * cstr);

/** @brief Append a single byte to @p str. */
R_API rsize r_string_append_c (RString * str, rchar c);
/** @brief Append a NUL-terminated C string to @p str. */
R_API rsize r_string_append (RString * str, const rchar * cstr);
/** @brief Append @p len bytes from @p cstr to @p str. */
R_API rsize r_string_append_len (RString * str, const rchar * cstr, rsize len);
/**
 * @brief printf-format and append the result to @p str.
 * @return New length after the append.
 */
R_API rsize r_string_append_printf (RString * str, const rchar * fmt, ...) R_ATTR_PRINTF (2, 3);
/** @brief va_list flavour of r_string_append_printf. */
R_API rsize r_string_append_vprintf (RString * str, const rchar * fmt, va_list ap) R_ATTR_PRINTF (2, 0);

/** @brief Prepend a NUL-terminated C string to the front of @p str. */
R_API rsize r_string_prepend (RString * str, const rchar * cstr);
/** @brief Prepend @p len bytes from @p cstr to the front of @p str. */
R_API rsize r_string_prepend_len (RString * str, const rchar * cstr, rsize len);
/** @brief printf-format and prepend the result to the front of @p str. */
R_API rsize r_string_prepend_printf (RString * str, const rchar * fmt, ...) R_ATTR_PRINTF (2, 3);
/** @brief va_list flavour of r_string_prepend_printf. */
R_API rsize r_string_prepend_vprintf (RString * str, const rchar * fmt, va_list ap) R_ATTR_PRINTF (2, 0);

/**
 * @brief Insert @p cstr at byte offset @p pos, sliding the existing
 * tail to the right.
 * @return New length after the insert.
 */
R_API rsize r_string_insert (RString * str, rsize pos, const rchar * cstr);
/** @brief Length-bounded variant of r_string_insert. */
R_API rsize r_string_insert_len (RString * str, rsize pos, const rchar * cstr, rsize len);
/**
 * @brief Overwrite bytes starting at @p pos with @p cstr.
 *
 * Unlike @c insert, no existing bytes shift; the string grows only
 * if the write extends past the current length.
 */
R_API rsize r_string_overwrite (RString * str, rsize pos, const rchar * cstr);
/** @brief Length-bounded variant of r_string_overwrite. */
R_API rsize r_string_overwrite_len (RString * str, rsize pos, const rchar * cstr, rsize len);

/** @brief Trim @p str to @p len bytes. No-op if it's already shorter. */
R_API rsize r_string_truncate (RString * str, rsize len);
/**
 * @brief Remove @p len bytes starting at byte offset @p pos.
 * @return New length after the erase.
 */
R_API rsize r_string_erase (RString * str, rsize pos, rsize len);

/** @} */

R_END_DECLS

/** @} */ /* r_string group */

#endif /* __R_STRING_H__ */

