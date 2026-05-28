/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_HASH_FUNCS_H__
#define __R_HASH_FUNCS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_hashfuncs Hash functions
 * @ingroup r_data
 *
 * @brief Default @c RHashFunc / @c REqualFunc implementations used
 * by @ref r_hashtable and @ref r_hashset when the caller doesn't
 * want to spell out a custom pair.
 *
 * @{
 */

/**
 * @file rlib/data/rhashfuncs.h
 * @brief Pre-built hash / equality function pairs for the common
 * key types (pointer-identity, NUL-terminated string).
 */

#include <rlib/rtypes.h>

/** @brief Sentinel returned by hash functions for "no value". */
#define R_HASH_EMPTY                            RSIZE_MAX

R_BEGIN_DECLS

/**
 * @brief Pointer-identity hash: treats @p data as an opaque
 * machine-word and returns it directly.
 *
 * Pair with @ref r_direct_equal for hashtables keyed by pointer
 * identity or by small integer values cast to @c rconstpointer.
 */
R_API rsize r_direct_hash (rconstpointer data);
/** @brief Pointer-identity equality: returns @c TRUE iff @c a == @c b. */
R_API rboolean r_direct_equal (rconstpointer a, rconstpointer b);
/**
 * @brief Hash a NUL-terminated C string.
 *
 * Walks @p data byte-by-byte until the terminator; pair with
 * @ref r_str_equal.
 */
R_API rsize r_str_hash (rconstpointer data);
/**
 * @brief Hash a byte string of caller-supplied length.
 *
 * Useful when the key isn't NUL-terminated. Pass @p size = @c -1
 * for the same behaviour as @ref r_str_hash.
 */
R_API rsize r_str_hash_sized (const rchar * data, rssize size);
/** @brief Equality for NUL-terminated C strings (via @c strcmp). */
R_API rboolean r_str_equal (rconstpointer a, rconstpointer b);

R_END_DECLS

/** @} */

#endif /* __R_HASH_FUNCS_H__ */

