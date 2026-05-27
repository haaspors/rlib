/* RLIB - Convenience library for useful things
 * Copyright (C) 2026  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

/**
 * @defgroup r_mem_ops Inline byte-buffer primitives
 * @ingroup r_mem
 * @brief Inline @c memcmp / @c memcpy / @c memmove / @c memset
 * wrappers with rlib's NULL-tolerant convention.
 *
 * These live in @c rlib/types/ rather than @c rlib/rmem.h because
 * @c rendianness.h's load / store helpers (@c r_load_be{16,32,64} et
 * al.) need them, and that header is processed earlier in the
 * include chain than @c rmem.h. The bulk of @c rmem.h's API
 * (allocators, vtables, scanners) continues to live there.
 *
 * Each function is a @c static @c inline wrapper around the
 * corresponding libc primitive plus rlib's NULL-tolerant convention.
 * The libc primitive is a "magic" intrinsic on every modern compiler
 * that gets replaced with inline @c movdqu / @c vld1q / @c rep
 * @c movs for known constant sizes, so wrapping the call site behind
 * a function-pointer indirection (or an extern @c R_API symbol)
 * would defeat the point.
 *
 * For the non-inline cousins:
 *  - @c r_memcmp_ct — constant-time compare, stays extern
 *  - @c r_memclear_secure — optimiser-resistant zero, stays extern
 *
 * both live in @c rmem.h.
 * @{
 */

/**
 * @file rlib/types/rmemops.h
 * @brief Inline byte-buffer primitives (see @ref r_mem_ops).
 */
#ifndef __R_MEM_OPS_H__
#define __R_MEM_OPS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <string.h>

R_BEGIN_DECLS

/**
 * @brief Lexicographically compare @p size bytes of @p a and @p b.
 *
 * Thin wrapper around libc @c memcmp with NULL-tolerant semantics:
 * a NULL pointer compares less than a non-NULL pointer, two NULLs
 * compare equal. For constant-time tag / digest comparison use
 * @c r_memcmp_ct from @c rmem.h instead.
 *
 * @param a    First buffer (may be @c NULL).
 * @param b    Second buffer (may be @c NULL).
 * @param size Number of bytes to compare.
 * @return Negative if @c a<b, positive if @c a>b, zero if equal.
 */
static inline int
r_memcmp (rconstpointer a, rconstpointer b, rsize size)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  return memcmp (a, b, size);
}

/**
 * @brief Fill @p size bytes at @p a with byte value @p v.
 *
 * Thin wrapper around libc @c memset. A @c NULL @p a is a no-op
 * (returns @c NULL). For wiping secret material use
 * @c r_memclear_secure from @c rmem.h - the optimiser is free to
 * elide regular @c r_memset on a buffer that's about to be freed.
 *
 * @param a    Destination buffer (may be @c NULL).
 * @param v    Byte value to write (low 8 bits used).
 * @param size Number of bytes to write.
 * @return @p a.
 */
static inline rpointer
r_memset (rpointer a, int v, rsize size)
{
  if (a != NULL)
    memset (a, v, size);
  return a;
}

/** @brief Convenience wrapper: @c r_memset @c (ptr, @c 0, @c size). */
#define r_memclear(ptr, size)   r_memset (ptr, 0, size)

/**
 * @brief Copy @p size bytes from @p src to @p dst.
 *
 * Thin wrapper around libc @c memcpy. Requires @p src and @p dst not
 * to overlap (use @c r_memmove if they might). A @c NULL @p src or
 * @c NULL @p dst is a no-op (returns @c NULL); otherwise returns
 * @p dst.
 *
 * @param dst  Destination buffer (may be @c NULL).
 * @param src  Source buffer (may be @c NULL).
 * @param size Number of bytes to copy.
 * @return @p dst if both pointers were non-NULL, @c NULL otherwise.
 */
static inline rpointer
r_memcpy (void * R_ATTR_RESTRICT dst,
    const void * R_ATTR_RESTRICT src, rsize size)
{
  if (dst != NULL && src != NULL)
    return memcpy (dst, src, size);
  return NULL;
}

/**
 * @brief Copy @p size bytes from @p src to @p dst, allowing overlap.
 *
 * Thin wrapper around libc @c memmove. Use when @p src and @p dst
 * may overlap; @c r_memcpy is faster when they're known disjoint.
 * A @c NULL pointer on either side is a no-op (returns @c NULL).
 *
 * @param dst  Destination buffer (may be @c NULL).
 * @param src  Source buffer (may be @c NULL).
 * @param size Number of bytes to copy.
 * @return @p dst if both pointers were non-NULL, @c NULL otherwise.
 */
static inline rpointer
r_memmove (rpointer dst, rconstpointer src, rsize size)
{
  if (dst != NULL && src != NULL)
    return memmove (dst, src, size);
  return NULL;
}

R_END_DECLS

/** @} */

#endif /* __R_MEM_OPS_H__ */
