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
 * @brief OS-entropy sources plus cryptographic (ChaCha20 DRBG, system)
 * and statistical (KISS, Mersenne Twister) PRNGs.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>
#include <stdlib.h>

/**
 * @defgroup r_rand Random and pseudo-random
 *
 * @brief OS-backed entropy sources plus refcounted PRNG objects.
 *
 * Three tiers, by intended use:
 *
 *  - **Raw OS entropy** — @ref r_rand_entropy_fill (and the
 *    @ref r_rand_entropy_u32 / @ref r_rand_entropy_u64 scalar
 *    helpers) read straight from the OS CSPRNG (@c getrandom /
 *    @c getentropy, @c CryptGenRandom on Windows, or @c /dev/urandom
 *    as a fallback).
 *  - **Crypto-grade PRNG** — @ref r_prng_new_crypto (a ChaCha20 DRBG)
 *    and @ref r_prng_new_system (a direct OS pass-through). Use these
 *    for any key, nonce or secret.
 *  - **Statistical PRNGs** — @ref r_prng_new_kiss and
 *    @ref r_prng_new_mt are fast, well-distributed and seedable for
 *    reproducibility, but @b not cryptographically secure.
 *
 * @warning The KISS and Mersenne Twister PRNGs are statistical, not
 * cryptographic — their internal state is recoverable from their
 * output. Never use them for cryptographic keys or nonces; use
 * @ref r_prng_new_crypto instead.
 *
 * @note An individual @ref RPrng instance is not safe for concurrent
 * use: drawing from one updates its internal state without locking.
 * Give each thread its own instance, or serialise access.
 *
 * @{
 */

R_BEGIN_DECLS

/**
 * @brief Fill @p buf with @p size bytes of cryptographic-grade OS
 * entropy.
 *
 * Reads from the OS CSPRNG, preferring the @c getrandom / @c getentropy
 * syscalls (or @c CryptGenRandom on Windows) and falling back to
 * @c /dev/urandom.
 *
 * Unlike @ref r_rand_entropy_u32 / @ref r_rand_entropy_u64, this
 * makes no fallback: it returns @c FALSE if the OS source cannot
 * deliver the full request, so it is safe to use for keys and
 * nonces.
 *
 * @param buf  Destination buffer.
 * @param size Number of bytes to fill.
 * @return @c TRUE if all @p size bytes were filled from the OS source.
 */
R_API rboolean r_rand_entropy_fill (ruint8 * buf, rsize size);
/**
 * @brief Read a 64-bit value from the OS entropy source.
 * @note Falls back to a monotonic timestamp if the OS source is
 * unavailable, so it is suitable for seeding statistical PRNGs but
 * @b not for cryptographic use — prefer @ref r_rand_entropy_fill there.
 */
R_API ruint64 r_rand_entropy_u64 (void);
/**
 * @brief Read a 32-bit value from the OS entropy source.
 * @note Same monotonic-timestamp fallback caveat as
 * @ref r_rand_entropy_u64.
 */
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
/**
 * @brief Cryptographically-secure PRNG: a ChaCha20 DRBG seeded from
 * the OS entropy source and periodically reseeded.
 *
 * This is the recommended source for cryptographic keys and nonces.
 * It applies fast key erasure (forward secrecy) and reseeds from the
 * OS after a bounded number of output bytes, combining the throughput
 * of a userspace stream cipher with the unpredictability of the OS
 * entropy pool.
 *
 * @return A new PRNG, or @c NULL on allocation / entropy failure.
 */
R_API RPrng * r_prng_new_crypto (void) R_ATTR_MALLOC;
/**
 * @brief Cryptographically-secure PRNG that reads every output
 * directly from the OS entropy source (see @ref r_rand_entropy_fill).
 *
 * Slower than @ref r_prng_new_crypto but holds no userspace state.
 * Aborts the process if the OS source ever fails to deliver entropy,
 * so callers never silently receive predictable output.
 *
 * @return A new PRNG, or @c NULL on allocation failure.
 */
R_API RPrng * r_prng_new_system (void) R_ATTR_MALLOC;
/**
 * @brief KISS PRNG seeded from OS entropy.
 * @warning Statistical only — not cryptographically secure. Use
 * @ref r_prng_new_crypto for keys or nonces.
 */
R_API RPrng * r_prng_new_kiss (void) R_ATTR_MALLOC;
/** @brief KISS PRNG with explicit four-component seed. */
R_API RPrng * r_prng_new_kiss_with_seed (ruint64 x, ruint64 y, ruint64 z,
    ruint64 c) R_ATTR_MALLOC;
/**
 * @brief Mersenne Twister PRNG seeded from OS entropy.
 * @warning Statistical only — not cryptographically secure. Use
 * @ref r_prng_new_crypto for keys or nonces.
 */
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

