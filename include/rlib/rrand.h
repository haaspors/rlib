/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_RAND_H__
#define __R_RAND_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rrand.h
 * @brief OS-entropy sources and seedable PRNGs (KISS, Mersenne Twister).
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>
#include <stdlib.h>

/**
 * @defgroup r_rand Random and pseudo-random
 *
 * @brief OS-backed entropy sources plus refcounted seedable PRNG
 * objects (KISS and Mersenne Twister).
 *
 * Use the @c r_rand_entropy_* helpers when you want true random
 * bytes for cryptographic purposes (they pull from
 * @c /dev/urandom or the equivalent OS facility). Use the
 * @ref RPrng family when you want a fast, deterministic
 * pseudo-random stream that can be seeded for reproducibility.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Read a 64-bit value from the OS entropy source. */
R_API ruint64 r_rand_entropy_u64 (void);
/** @brief Read a 32-bit value from the OS entropy source. */
R_API ruint32 r_rand_entropy_u32 (void);

/** @brief Seed the C-library @c rand() with @p seed. */
#define r_rand_std_srand(seed)    srand (seed)
/** @brief Single sample from the C-library @c rand(). */
#define r_rand_std_rand()         rand ()

/** @brief Opaque, refcounted PRNG handle. */
typedef struct RPrng RPrng;

/** @brief Default PRNG constructor (currently KISS). */
#define r_rand_prng_new           r_prng_new_kiss
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_prng_ref                r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_prng_unref              r_ref_unref

/** @brief Draw a 64-bit sample from @p prng. */
R_API ruint64 r_prng_get_u64 (RPrng * prng);
/** @brief Fill @p buf with @p size pseudo-random bytes from @p prng. */
R_API rboolean r_prng_fill (RPrng * prng, ruint8 * buf, rsize size);
/** @brief Like @ref r_prng_fill, but every byte is guaranteed non-zero. */
R_API rboolean r_prng_fill_nonzero (RPrng * prng, ruint8 * buf, rsize size);
/**
 * @brief Fill @p buf with @p size base64-alphabet characters; useful
 * for token / nonce generation.
 */
R_API rboolean r_prng_fill_base64 (RPrng * prng, rchar * buf, rsize size);


/** @name PRNG constructors
 *  @{ */
/** @brief KISS PRNG seeded from OS entropy. */
R_API RPrng * r_prng_new_kiss (void) R_ATTR_MALLOC;
/** @brief KISS PRNG with explicit four-component seed. */
R_API RPrng * r_prng_new_kiss_with_seed (ruint64 x, ruint64 y, ruint64 z,
    ruint64 c) R_ATTR_MALLOC;
/** @brief Mersenne Twister PRNG seeded from OS entropy. */
R_API RPrng * r_prng_new_mt (void) R_ATTR_MALLOC;
/** @brief Mersenne Twister PRNG seeded from a single 64-bit value. */
R_API RPrng * r_prng_new_mt_with_seed (ruint64 seed) R_ATTR_MALLOC;
/**
 * @brief Mersenne Twister PRNG seeded from an array of 64-bit values
 * (recommended for reproducing a specific state).
 */
R_API RPrng * r_prng_new_mt_with_seed_array (const ruint64 * array,
    rsize size) R_ATTR_MALLOC;
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_RAND_H__ */

