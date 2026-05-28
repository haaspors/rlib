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
#ifndef __R_MPINT_H__
#define __R_MPINT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_mpint Multi-precision integer (mpint)
 * @ingroup r_data
 *
 * @brief Heap-allocated big-integer @ref rmpint plus the
 * fixed-width Montgomery-form @ref RMpintFE companions used by
 * rlib's constant-time crypto primitives.
 *
 * The module has two layers:
 *
 *   - @ref rmpint — variable-width, heap-backed integer with a
 *     full arithmetic surface (add / sub / mul / div / mod / gcd /
 *     lcm / exp / expmod / invmod / primality). Most ops are
 *     variable-time; the @c _ct suffixed variants
 *     (@ref r_mpint_swap_ct, @ref r_mpint_get_digit_ct,
 *     @ref r_mpint_expmod_ct) avoid the most obvious timing
 *     leaks for the operations that handle secret material.
 *   - @ref RMpintFE — fixed-width inline-storage field element
 *     used by the ECC scalar-mul ladder. Storage is sized at
 *     compile time (@c R_MPINT_FE_MAX_DIGITS) so every primitive
 *     iterates exactly the modulus's digit count regardless of
 *     operand value, giving genuine constant-time arithmetic at
 *     the cycle-count level (no residual leak through
 *     @c r_mpint_clamp shrinking @c dig_used to the value's bit
 *     length).
 *
 * @ref RMpintFE_Big is the RSA-width parallel to @ref RMpintFE,
 * generated from the same template; the API mirrors the smaller
 * type byte-for-byte.
 *
 * @{
 */

/**
 * @file rlib/data/rmpint.h
 * @brief Multi-precision integer arithmetic plus fixed-width
 * Montgomery-form field elements (RMpintFE / RMpintFE_Big).
 */

#include <rlib/rtypes.h>

#include <rlib/rrand.h>

R_BEGIN_DECLS

/** @brief Default initial digit capacity for @ref r_mpint_init. */
#define RMPINT_DEF_DIGITS     64
/** @brief Default Miller-Rabin round count for @ref r_mpint_isprime. */
#define RMPINT_DEF_ISPRIME_T  8

/** @brief Digit machine word backing @ref rmpint storage. */
typedef ruint32         rmpint_digit;
/** @brief Double-width word for digit multiplications. */
typedef ruint64         rmpint_word;

/**
 * @brief Heap-backed multi-precision integer.
 *
 * Stores a sign-magnitude representation: the absolute value lives
 * in @c data[0 .. dig_used) (little-endian per-digit), with the
 * sign carried separately. @c dig_alloc is the allocated capacity;
 * the storage grows as values do.
 */
typedef struct {
  ruint16         dig_alloc;  /**< Allocated digit capacity. */
  ruint16         dig_used;   /**< Digits actually carrying value. */
  ruint32         sign;       /**< Non-zero for negative values. */
  /**
   * @brief Behaviour flags, currently only @c R_MPINT_FLAG_SECURE_CLEAR.
   *
   * Set @c R_MPINT_FLAG_SECURE_CLEAR on any mpint that carries a
   * secret (private scalars, nonces, intermediate plaintexts) so
   * the buffer is wiped via @c r_memclear_secure on
   * @ref r_mpint_clear, never leaking into freed heap.
   */
  ruint32         flags;
  rmpint_digit *  data;       /**< Digit array; little-endian. */
} rmpint;

/** @brief Flag: wipe @c data via @c r_memclear_secure on @ref r_mpint_clear. */
#define R_MPINT_FLAG_SECURE_CLEAR (1u << 0)

/** @brief Static initialiser for an empty (zero-valued) @ref rmpint. */
#define R_MPINT_INIT            { 0, 0, 0, 0, NULL }
/** @brief Initialise with the default digit capacity (@ref RMPINT_DEF_DIGITS). */
#define r_mpint_init(mpi)       r_mpint_init_size (mpi, RMPINT_DEF_DIGITS)

/** @name Initialisation, secure-clear handling and lifecycle
 *  @{ */

/** @brief Initialise @p mpi with a caller-chosen digit capacity. */
R_API void r_mpint_init_size (rmpint * mpi, ruint16 digits);
/**
 * @brief Initialise with the secure-clear flag set.
 *
 * Use this for any mpint that will hold secret material at any
 * point in its life - the flag is sticky across set / copy /
 * arithmetic, so callers only need to remember to use this at init
 * time.
 */
R_API void r_mpint_init_secure (rmpint * mpi);
/**
 * @brief One-shot init from raw bytes with the secure flag set,
 * so a key imported from a buffer never spends a moment with the
 * secure-clear flag clear.
 */
R_API void r_mpint_init_binary_secure (rmpint * mpi, rconstpointer data, rsize size);
/**
 * @brief One-shot init-from-copy with the secure flag set, for
 * cloning a key into a fresh secure-clear mpint.
 */
R_API void r_mpint_init_copy_secure (rmpint * mpi, const rmpint * b);
/**
 * @brief Flip @c R_MPINT_FLAG_SECURE_CLEAR on an existing mpint.
 *
 * Useful when an mpint was init'd via the non-secure constructors
 * (@ref r_mpint_init_binary / @ref r_mpint_init_copy /
 * @ref r_mpint_init_str) and only afterwards turns out to need
 * secure handling.
 */
R_API void r_mpint_set_secure_clear (rmpint * mpi);
/**
 * @brief Initialise @p dst with the default size and OR in
 * @c R_MPINT_FLAG_SECURE_CLEAR if any source in the
 * NULL-terminated argument list has it set.
 *
 * Scratch mpints inside arithmetic primitives use this so they
 * inherit the secure-clear treatment of whichever operand
 * contributed to them, without each call site repeating the
 * conditional.
 */
R_API void r_mpint_init_from (rmpint * dst, const rmpint * src1, ...)
    R_ATTR_NULL_TERMINATED;
/**
 * @brief Same as @ref r_mpint_init_from but with a caller-chosen
 * initial digit capacity, for call sites that allocate a
 * specifically-sized scratch up front.
 */
R_API void r_mpint_init_size_from (rmpint * dst, ruint16 digits,
    const rmpint * src1, ...) R_ATTR_NULL_TERMINATED;
/** @brief Initialise from a big-endian byte buffer. */
R_API void r_mpint_init_binary (rmpint * mpi, rconstpointer data, rsize size);
/**
 * @brief Initialise by parsing @p str in @p base.
 *
 * @param mpi     Destination.
 * @param str     ASCII digit string.
 * @param endptr  Out: pointer past the last consumed character (NULL to ignore).
 * @param base    Numeric base (2..16).
 */
R_API void r_mpint_init_str (rmpint * mpi, const rchar * str,
    const rchar ** endptr, ruint base);
/** @brief Initialise as a copy of @p src. */
R_API void r_mpint_init_copy (rmpint * dst, const rmpint * src);
/**
 * @brief Release @p mpi's digit storage.
 *
 * If @c R_MPINT_FLAG_SECURE_CLEAR is set, the buffer is wiped via
 * @c r_memclear_secure before being freed.
 */
R_API void r_mpint_clear (rmpint * mpi);

/** @} */

/** @name Binary / string conversion
 *  @{ */

/**
 * @brief Allocate a fresh big-endian byte buffer holding @p mpi's
 * absolute value.
 * @param mpi   The source value.
 * @param size  Out: length of the returned buffer.
 */
R_API ruint8 * r_mpint_to_binary_new (const rmpint * mpi, rsize * size) R_ATTR_MALLOC;
/**
 * @brief Write @p mpi's absolute value into a caller buffer.
 * @param mpi   The source value.
 * @param bin   Destination byte buffer.
 * @param size  On entry: buffer capacity. On success: bytes written.
 */
R_API rboolean r_mpint_to_binary (const rmpint * mpi, ruint8 * bin, rsize * size);
/**
 * @brief Write @p mpi's absolute value left-zero-padded to exactly
 * @p size bytes.
 *
 * Returns @c FALSE if the value doesn't fit in @p size bytes.
 */
R_API rboolean r_mpint_to_binary_with_size (const rmpint * mpi, ruint8 * bin, rsize size);
/** @brief Allocate a decimal string representation of @p mpi. Caller frees with @c r_free. */
R_API rchar * r_mpint_to_str (const rmpint * mpi);

/** @} */

/** @name Inline predicates and metadata accessors
 *  @{ */

/** @brief @c TRUE iff @p mpi is zero. */
#define r_mpint_iszero(mpi)       ((mpi)->dig_used == 0)
/** @brief @c TRUE iff the magnitude of @p mpi is even. */
#define r_mpint_iseven(mpi)       ((mpi)->dig_used > 0 && (((mpi)->data[0] & 1) == 0))
/** @brief @c TRUE iff the magnitude of @p mpi is odd. */
#define r_mpint_isodd(mpi)        ((mpi)->dig_used > 0 && (((mpi)->data[0] & 1) == 1))
/** @brief @c TRUE iff @p mpi is strictly negative. */
#define r_mpint_isneg(mpi)        ((mpi)->dig_used > 0 && (mpi)->sign)

/** @brief Number of digits @p mpi's magnitude occupies. */
#define r_mpint_digits_used(mpi)  (mpi)->dig_used
/** @brief Byte length of @p mpi's magnitude (without leading zeros). */
#define r_mpint_bytes_used(mpi)   ((ruint)((mpi)->dig_used > 0 ?              \
    (ruint)(((ruint)(mpi)->dig_used * sizeof (rmpint_digit)) -                \
    (ruint)RUINT32_CLZ (r_mpint_get_digit (mpi, (mpi)->dig_used - 1)) / 8) :  \
    ((ruint)0)))
/** @brief Bit length of @p mpi's magnitude. */
#define r_mpint_bits_used(mpi)    ((ruint)((mpi)->dig_used > 0 ?              \
    (ruint)(((ruint)(mpi)->dig_used * sizeof (rmpint_digit) * 8) -            \
    (ruint)RUINT32_CLZ (r_mpint_get_digit (mpi, (mpi)->dig_used - 1))) :      \
    ((ruint)0)))
/**
 * @brief Shrink @c dig_used until the leading digit is non-zero;
 * clear @c sign if the value is zero.
 *
 * Operations may leave trailing zero digits in place; @ref r_mpint_clamp
 * normalises the representation so predicates and serialisers see
 * the canonical bit-length.
 */
#define r_mpint_clamp(mpi)   R_STMT_START {                           \
  while ((mpi)->dig_used > 0 && (mpi)->data[(mpi)->dig_used-1] == 0)  \
    (mpi)->dig_used--;                                                \
  (mpi)->sign = (mpi)->dig_used > 0 ? (mpi)->sign : 0;                \
} R_STMT_END

/** @} */

/** @name Prime generation and testing
 *  @{ */

/**
 * @brief Generate a random prime of @p bits bits.
 *
 * @param mpi   Destination.
 * @param bits  Target bit length.
 * @param safe  If @c TRUE, generate a *safe* prime @c p with
 *              @c (p-1)/2 also prime.
 * @param prng  Randomness source.
 */
R_API rboolean r_mpint_gen_prime_full (rmpint * mpi, rsize bits, rboolean safe,
    RPrng * prng);
/** @brief Convenience: generate a (non-safe) prime. */
#define r_mpint_gen_prime(mpi, bits, prng) r_mpint_gen_prime_full (mpi, bits, FALSE, prng)

/**
 * @brief Result of a Miller-Rabin primality test.
 *
 * @c CERTAIN_PRIME is reserved for small values where trial
 * division reaches an exact verdict; larger primes are reported as
 * @c POSSIBLE_PRIME with a confidence proportional to the number of
 * rounds run.
 */
typedef enum {
  R_MPINT_ERROR = -1,           /**< Test failed (e.g. negative input). */
  R_MPINT_NON_PRIME = 0,        /**< Witness found - composite. */
  R_MPINT_CERTAIN_PRIME,        /**< Exactly prime (small / by trial division). */
  R_MPINT_POSSIBLE_PRIME,       /**< No witness in @p t rounds. */
} RMpintPrimeTest;

/**
 * @brief Miller-Rabin primality test with @p t rounds.
 *
 * The probability of a false @c POSSIBLE_PRIME verdict drops by a
 * factor of 4 per round.
 */
R_API RMpintPrimeTest r_mpint_isprime_t (const rmpint * mpi, ruint t);
/** @brief Convenience: @ref r_mpint_isprime_t with @ref RMPINT_DEF_ISPRIME_T rounds. */
#define r_mpint_isprime(mpi) r_mpint_isprime_t (mpi, RMPINT_DEF_ISPRIME_T)

/** @} */

/** @name Value-setting helpers
 *  @{ */

/** @brief Set @p mpi to zero (preserves capacity and flags). */
R_API void r_mpint_zero (rmpint * mpi);
/** @brief Copy @p b's value into @p mpi. */
R_API void r_mpint_set (rmpint * mpi, const rmpint * b);
/** @brief Set @p mpi from a big-endian byte buffer. */
R_API void r_mpint_set_binary (rmpint * mpi, rconstpointer data, rsize size);
/** @brief Set from a signed 32-bit value. */
R_API void r_mpint_set_i32 (rmpint * mpi, rint32 value);
/** @brief Set from an unsigned 32-bit value. */
R_API void r_mpint_set_u32 (rmpint * mpi, ruint32 value);
/** @brief Set from a signed 64-bit value. */
R_API void r_mpint_set_i64 (rmpint * mpi, rint64 value);
/** @brief Set from an unsigned 64-bit value. */
R_API void r_mpint_set_u64 (rmpint * mpi, ruint64 value);

/** @} */

/** @name Constant-time helpers
 *  @{ */

/**
 * @brief Constant-time conditional swap.
 *
 * If @p bit is non-zero, exchange the metadata and data pointer
 * of @p a and @p b; if zero, leave both untouched. Same execution
 * time and memory access pattern regardless of @p bit, so a
 * Montgomery ladder driven by it doesn't leak the scalar's bit
 * pattern through the per-step branch shape. Only the pointers
 * are swapped (not the contents of @c data), so this is O(1)
 * regardless of operand size.
 */
R_API void r_mpint_swap_ct (rmpint * a, rmpint * b, ruint32 bit);

/**
 * @brief Read a digit, treating reads past @c dig_used as zero.
 *
 * mpint operations promise that @c data[0 .. dig_used) carries
 * the value, but several producers (e.g. the final shr in
 * @ref r_mpint_div, and any path that shortens @c dig_used without
 * zeroing the now-unused tail) leave stale bytes behind in
 * @c data[dig_used .. dig_alloc). Without this clamp, consumers
 * that loop up to @c MAX(a->dig_used, b->dig_used) and read both
 * operands - notably @ref r_mpint_add with @p dst aliasing the
 * shorter operand - end up folding stale data into the result.
 */
#define r_mpint_get_digit(mpi, d) \
  ((d) < (mpi)->dig_used ? (mpi)->data[d] : (rmpint_digit)0)

/**
 * @brief Constant-time digit accessor.
 *
 * Reads @c mpi->data[d] iff @c d < dig_alloc (@c dig_alloc is a
 * public quantity), then masks the result with @c (d < dig_used).
 * The compare on @c dig_used is branchless, so the timing depends
 * only on @p d and @c dig_alloc, never on @c dig_used (which for
 * secret material like an RSA exponent would leak the active digit
 * count if read directly).
 *
 * Use this in any inner loop that indexes a secret mpint at
 * known-public positions; for non-secret material the plain
 * @ref r_mpint_get_digit is fine and faster on paths where the
 * typical @p d is far past @c dig_used.
 */
static inline rmpint_digit
r_mpint_get_digit_ct (const rmpint * mpi, ruint32 d)
{
  rmpint_digit value = (d < mpi->dig_alloc) ? mpi->data[d] : (rmpint_digit)0;
  ruint32 below = ((ruint32)d - (ruint32)mpi->dig_used) >> 31;
  rmpint_digit mask = (rmpint_digit)0 - (rmpint_digit)below;
  return value & mask;
}

/** @brief Count trailing zero bits in the magnitude of @p mpi. */
R_API ruint32 r_mpint_ctz (const rmpint * mpi);

/** @} */

/** @name Comparison
 *  @{ */

/** @brief Signed compare: returns <0 / 0 / >0 like @c memcmp. */
R_API int r_mpint_cmp (const rmpint * a, const rmpint * b);
/** @brief Unsigned (magnitude) compare. */
R_API int r_mpint_ucmp (const rmpint * a, const rmpint * b);
/** @brief Signed compare against a 32-bit value. */
R_API int r_mpint_cmp_i32 (const rmpint * a, rint32 b);
/** @brief Unsigned compare against a 32-bit value. */
R_API int r_mpint_ucmp_u32 (const rmpint * a, ruint32 b);

/** @} */

/** @name Basic arithmetic
 *  @{ */

/** @brief @c dst = a + b. */
R_API rboolean r_mpint_add (rmpint * dst, const rmpint * a, const rmpint * b);
/** @brief @c dst = a + b (b is a signed 32-bit immediate). */
R_API rboolean r_mpint_add_i32 (rmpint * dst, const rmpint * a, rint32 b);
/** @brief @c dst = a + b (b is an unsigned 32-bit immediate). */
R_API rboolean r_mpint_add_u32 (rmpint * dst, const rmpint * a, ruint32 b);

/** @brief @c dst = a - b. */
R_API rboolean r_mpint_sub (rmpint * dst, const rmpint * a, const rmpint * b);
/** @brief @c dst = a - b (b is a signed 32-bit immediate). */
R_API rboolean r_mpint_sub_i32 (rmpint * dst, const rmpint * a, rint32 b);
/** @brief @c dst = a - b (b is an unsigned 32-bit immediate). */
R_API rboolean r_mpint_sub_u32 (rmpint * dst, const rmpint * a, ruint32 b);

/** @brief @c dst = a << bits. */
R_API rboolean r_mpint_shl (rmpint * dst, const rmpint * a, ruint32 bits);
/** @brief @c dst = a >> bits. */
R_API rboolean r_mpint_shr (rmpint * dst, const rmpint * a, ruint32 bits);
/** @brief @c dst = a shifted left by @p d whole digits. */
R_API rboolean r_mpint_shl_digit (rmpint * dst, const rmpint * a, ruint16 d);
/** @brief @c dst = a shifted right by @p d whole digits. */
R_API rboolean r_mpint_shr_digit (rmpint * dst, const rmpint * a, ruint16 d);

/** @brief @c dst = a * b. */
R_API rboolean r_mpint_mul (rmpint * dst, const rmpint * a, const rmpint * b);
/** @brief @c dst = a * b (b is a signed 32-bit immediate). */
R_API rboolean r_mpint_mul_i32 (rmpint * dst, const rmpint * a, rint32 b);
/** @brief @c dst = a * b (b is an unsigned 32-bit immediate). */
R_API rboolean r_mpint_mul_u32 (rmpint * dst, const rmpint * a, ruint32 b);

/**
 * @brief Quotient + remainder of @c n / d.
 *
 * Either @p q or @p r may be @c NULL to discard that half.
 */
R_API rboolean r_mpint_div (rmpint * q, rmpint * r, const rmpint * n, const rmpint * d);
/** @brief Divide by a signed 32-bit divisor. */
R_API rboolean r_mpint_div_i32 (rmpint * q, rmpint * r, const rmpint * n, rint32 d);
/** @brief Divide by an unsigned 32-bit divisor. */
R_API rboolean r_mpint_div_u32 (rmpint * q, rmpint * r, const rmpint * n, ruint32 d);

/**
 * @brief @c dst = b^e for a small unsigned exponent @p e.
 *
 * For modular exponentiation see @ref r_mpint_expmod and the
 * constant-time variants.
 */
R_API rboolean r_mpint_exp (rmpint * dst, const rmpint * b, ruint16 e);

/** @brief Convenience: remainder-only division. */
#define r_mpint_mod(dst, n, d)            r_mpint_div (NULL, dst, n, d)
/** @brief Convenience: remainder-only division by signed 32-bit. */
#define r_mpint_mod_i32(dst, n, d)        r_mpint_div_i32 (NULL, dst, n, d)
/** @brief Convenience: remainder-only division by unsigned 32-bit. */
#define r_mpint_mod_u32(dst, n, d)        r_mpint_div_u32 (NULL, dst, n, d)

/** @brief Convenience: @c dst = (a * b) mod d. */
#define r_mpint_mulmod(dst, a, b, d)      (r_mpint_mul (dst, a, b) && r_mpint_mod (dst, dst, d))
/** @brief Convenience: @c dst = (a * b) mod d (signed immediate). */
#define r_mpint_mulmod_i32(dst, a, b, d)  (r_mpint_mul (dst, a, b) && r_mpint_mod_i32 (dst, dst, d))
/** @brief Convenience: @c dst = (a * b) mod d (unsigned immediate). */
#define r_mpint_mulmod_u32(dst, a, b, d)  (r_mpint_mul (dst, a, b) && r_mpint_mod_u32 (dst, dst, d))

/** @} */

/** @name Number-theoretic operations
 *  @{ */

/** @brief Modular inverse: @c dst = a^-1 mod m. */
R_API rboolean r_mpint_invmod (rmpint * dst, const rmpint * a, const rmpint * m);

/**
 * @brief Modular exponentiation: @c dst = b^e mod m.
 *
 * Variable-time on the exponent; not safe for secret exponents.
 * Use @ref r_mpint_expmod_ct for RSA / DSA private operations.
 */
R_API rboolean r_mpint_expmod (rmpint * dst, const rmpint * b, const rmpint * e, const rmpint * m);
/**
 * @brief Constant-time modular exponentiation.
 *
 * Iterates exactly @p exp_bits bits over the exponent and routes
 * the per-bit dispatch through @ref r_mpint_swap_ct rather than
 * secret-indexed lookups; the per-iteration Montgomery reduce
 * runs through the CT variant. The base @p b is treated as
 * non-secret: the initial lift into Montgomery form is
 * variable-time.
 *
 * @param dst       Destination.
 * @param b         Base (treated as non-secret).
 * @param e         Exponent (secret-safe).
 * @param m         Modulus (must be odd).
 * @param exp_bits  Must upper-bound the bit length of @p e -
 *                  silent truncation otherwise. @c bit_count(m) is
 *                  always safe; a tighter bound (e.g. @c bit_count(q)
 *                  for DSA's @c k<q) saves work. This is the one
 *                  timing channel the caller fully controls; pick
 *                  the same value across calls if uniformity matters.
 *
 * @note Residual leak: @ref rmpint backs the intermediates, so each
 * per-bit Mont mul iterates the intermediate value's @c dig_used.
 * That leaks the bit length of the partial product, not the
 * exponent. Removing this would require either a fixed-width type
 * sized for the modulus (cf. @ref RMpintFE for ECC) or non-clamping
 * @c rmpint variants. For DSA's mod-p path the leak is on
 * intermediate @c g^(partial-k) values, not on @c k directly.
 */
R_API rboolean r_mpint_expmod_ct (rmpint * dst, const rmpint * b,
    const rmpint * e, const rmpint * m, ruint exp_bits);
/**
 * @brief Compute the per-modulus Montgomery inverse
 * @c mp = -m^-1 mod 2^digit_bits.
 *
 * Used by @ref r_mpint_expmod_ct_with_mp and any other caller that
 * wants to cache @c mp once per modulus rather than recomputing on
 * every Montgomery operation. @p m must be odd.
 */
R_API rboolean r_mpint_montgomery_setup (rmpint_digit * mp, const rmpint * m);

/**
 * @brief Variant of @ref r_mpint_expmod_ct that takes the
 * per-modulus Montgomery inverse @p mp as input rather than
 * deriving it from @p m on every call.
 *
 * Callers that sign / decrypt repeatedly with the same modulus
 * (RSA private operations, DSA signing) cache @p mp on their key
 * struct - one @ref r_mpint_montgomery_setup at construction
 * instead of one per call. Same @p exp_bits semantics and
 * residual-leak behaviour as @ref r_mpint_expmod_ct.
 */
R_API rboolean r_mpint_expmod_ct_with_mp (rmpint * dst, const rmpint * b,
    const rmpint * e, const rmpint * m, rmpint_digit mp, ruint exp_bits);

/** @brief Greatest common divisor. */
R_API rboolean r_mpint_gcd (rmpint * dst, const rmpint * a, const rmpint * b);
/** @brief Least common multiple. */
R_API rboolean r_mpint_lcm (rmpint * dst, const rmpint * a, const rmpint * b);

/** @} */


/* =================================================================
 * Fixed-width Montgomery-form field elements (RMpintFE)
 *
 * Unlike rmpint, RMpintFE stores its digits inline in the struct
 * (no heap, no dig_used field) and every primitive iterates exactly
 * the modulus's digit count regardless of operand value. That gives
 * genuinely constant-time arithmetic at the cycle-count level - no
 * residual leak through r_mpint_clamp shrinking dig_used to the
 * value's bit length.
 *
 * Used by the ECC scalar-mul ladder (rlib/crypto/recurve.c). DSA
 * signing and RSA private operations want the same primitives. The
 * type is public so consumers outside rlib can reuse the same
 * audited implementation - same reason r_mpint_swap_ct and the rest
 * of the CT primitives live in this header.
 * =================================================================
 */

/**
 * @brief Maximum digit width for @ref RMpintFE.
 *
 * Sized for secp521r1 (17 32-bit digits) plus one headroom slot for
 * the Montgomery accumulator's top carry. DSA |q| (256 bits) fits
 * comfortably; RSA moduli do not - that's what @ref RMpintFE_Big is
 * for.
 */
#define R_MPINT_FE_MAX_DIGITS  18

/**
 * @brief Fixed-width inline-storage field element used by the ECC
 * scalar-mul ladder.
 *
 * Storage is the full @ref R_MPINT_FE_MAX_DIGITS regardless of the
 * modulus's actual digit count; primitives operate on the
 * @c n_digits prefix carried by @ref RMpintFEMontCtx.
 */
typedef struct {
  rmpint_digit d[R_MPINT_FE_MAX_DIGITS];
} RMpintFE;

/**
 * @brief Per-modulus Montgomery context.
 *
 * All @ref RMpintFE primitives take a pointer to one of these so
 * the modulus, its Montgomery inverse and the digit width don't
 * have to thread through every call site.
 */
typedef struct {
  RMpintFE p;                 /**< Modulus, in normal form. */
  rmpint_digit mp;            /**< @c -p^-1 mod @c 2^digit_bits. */
  ruint16 n_digits;           /**< Number of digits the modulus occupies. */
} RMpintFEMontCtx;

/**
 * @brief Maximum digit width for @ref RMpintFE_Big.
 *
 * Covers up to RSA-8192 (256 32-bit digits for the full modulus,
 * 128 for a CRT half) plus one carry-slot margin. Bump this if
 * you need RSA-16384 or wider.
 */
#define R_MPINT_FE_BIG_MAX_DIGITS  257

/**
 * @brief RSA-width parallel to @ref RMpintFE.
 *
 * The function bodies are generated from the same template as the
 * ECC width, so the two surfaces share one audited implementation -
 * only the storage width and the function-name prefix differ.
 */
typedef struct {
  rmpint_digit d[R_MPINT_FE_BIG_MAX_DIGITS];
} RMpintFE_Big;

/** @brief Per-modulus Montgomery context for @ref RMpintFE_Big. */
typedef struct {
  RMpintFE_Big p;             /**< Modulus, in normal form. */
  rmpint_digit mp;            /**< @c -p^-1 mod @c 2^digit_bits. */
  ruint16 n_digits;           /**< Number of digits the modulus occupies. */
} RMpintFE_BigMontCtx;

/** @name RMpintFE: per-modulus setup
 *
 * Both helpers are one-time costs paid by the caller before any FE
 * arithmetic; the resulting ctx + @c mont_r_squared are reusable
 * across as many FE operations as the modulus is in scope for.
 *  @{ */

/**
 * @brief Fill @p ctx (@c p, @c mp, @c n_digits) from an mpint
 * modulus.
 *
 * Returns @c FALSE if @p m is even or larger than
 * @ref R_MPINT_FE_MAX_DIGITS digits.
 */
R_API rboolean r_mpint_fe_mont_ctx_init (RMpintFEMontCtx * ctx, const rmpint * m);

/**
 * @brief Compute @c R^2 mod m for the supplied n-digit modulus
 * (@c R = 2^(32*n)).
 *
 * Used to feed @c mont_r_squared into @ref r_mpint_fe_mont_in /
 * @ref r_mpint_fe_invmod_mont.
 */
R_API rboolean r_mpint_fe_compute_r_squared (RMpintFE * out, const rmpint * m,
    ruint16 n);

/** @} */

/** @name RMpintFE: lifecycle / conversion
 *  @{ */

/** @brief Zero @p x's first @ref R_MPINT_FE_MAX_DIGITS digits. */
R_API void r_mpint_fe_zero (RMpintFE * x);
/** @brief Copy @c src -> @c dst (full width). */
R_API void r_mpint_fe_copy (RMpintFE * dst, const RMpintFE * src);
/** @brief Copy @c mpi -> @c fe, zero-padded to @p n digits. Truncates beyond @p n. */
R_API void r_mpint_fe_from_mpint (RMpintFE * fe, const rmpint * mpi, ruint16 n);
/**
 * @brief Copy @c fe -> @c mpi, ending with @ref r_mpint_clamp so
 * the mpint side stays canonical.
 *
 * Value-dependent, but the value has left the CT path by this
 * point - it's en route to a public output.
 */
R_API rboolean r_mpint_fe_to_mpint (rmpint * mpi, const RMpintFE * fe, ruint16 n);

/** @} */

/** @name RMpintFE: constant-time helpers (no field arithmetic)
 *  @{ */

/** @brief All-ones mask iff @p x's low @p n digits are zero; all-zeros otherwise. */
R_API rmpint_digit r_mpint_fe_iszero_ct (const RMpintFE * x, ruint16 n);
/**
 * @brief @c out := (mask == all-ones) ? a : b, digit-wise over @p n digits.
 *
 * Safe to alias @p out with @p a or @p b (digits read before write).
 */
R_API void r_mpint_fe_select_ct (RMpintFE * out, rmpint_digit mask,
    const RMpintFE * a, const RMpintFE * b, ruint16 n);
/** @brief Branchless XOR-swap of two FEs gated on @p bit. */
R_API void r_mpint_fe_swap_ct (RMpintFE * a, RMpintFE * b,
    ruint32 bit, ruint16 n);

/** @} */

/** @name RMpintFE: modular arithmetic mod p
 *
 * Inputs in @c [0, p), outputs in @c [0, p). Add / sub commute with
 * the Montgomery transform, so they work both for normal-form and
 * Mont-form operands.
 *  @{ */

/** @brief Modular addition. */
R_API void r_mpint_fe_add (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * b, const RMpintFEMontCtx * ctx);
/** @brief Modular subtraction. */
R_API void r_mpint_fe_sub (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * b, const RMpintFEMontCtx * ctx);

/**
 * @brief Montgomery multiplication via CIOS:
 * @c out := a * b * R^-1 mod p, where @c R = 2^(32 * n_digits).
 *
 * If @p a and @p b are in Mont form, @p out is too.
 */
R_API void r_mpint_fe_mul_mont (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * b, const RMpintFEMontCtx * ctx);
/** @brief Montgomery squaring. */
R_API void r_mpint_fe_sqr_mont (RMpintFE * out, const RMpintFE * a,
    const RMpintFEMontCtx * ctx);

/**
 * @brief Lift from normal form into Montgomery form.
 *
 * Needs @c mont_r_squared (= @c R^2 mod p) precomputed by the
 * caller via @ref r_mpint_fe_compute_r_squared - it lives outside
 * @ref RMpintFEMontCtx because not every caller needs it.
 */
R_API void r_mpint_fe_mont_in (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * mont_r_squared, const RMpintFEMontCtx * ctx);
/** @brief Lift from Montgomery form back into normal form. */
R_API void r_mpint_fe_mont_out (RMpintFE * out, const RMpintFE * a,
    const RMpintFEMontCtx * ctx);

/** @} */

/** @name RMpintFE: derived operations
 *  @{ */

/**
 * @brief Fermat-based modular inversion in Mont form:
 * @c out := a_M^(p-2) mod p (also in Mont form).
 *
 * Requires @c p prime and @c a coprime to @c p (@c a == 0 returns 0).
 *
 * @param out             Destination, in Mont form.
 * @param a_M             Input in Mont form.
 * @param p_minus_2       (p - 2), in Mont form.
 * @param p_minus_2_bits  Bit length of @c (p - 2); drives the
 *                        inner exponentiation loop.
 * @param mont_r_squared  @c R^2 mod p, in Mont form.
 * @param ctx             Per-modulus Montgomery context.
 */
R_API void r_mpint_fe_invmod_mont (RMpintFE * out, const RMpintFE * a_M,
    const RMpintFE * p_minus_2, ruint p_minus_2_bits,
    const RMpintFE * mont_r_squared, const RMpintFEMontCtx * ctx);

/** @} */

/** @name RMpintFE: wide (non-modular) primitives
 *
 * Used by the RSA CRT recombination to assemble the final
 * plaintext outside any single field.
 *  @{ */

/** @brief Wide multiply (operands of different digit widths). */
R_API void r_mpint_fe_mul_ct (RMpintFE * out, const RMpintFE * a, ruint16 a_n,
    const RMpintFE * b, ruint16 b_n);
/** @brief Wide add. */
R_API void r_mpint_fe_add_ct (RMpintFE * out, const RMpintFE * a, ruint16 a_n,
    const RMpintFE * b, ruint16 b_n);
/**
 * @brief Conditional-subtract-once reduce: @c out = (a < p) ? a : a - p.
 *
 * Useful only when the caller can guarantee @c a < 2p; the RSA CRT
 * case (@c m2 mod p with @c m2 < q < 2p) qualifies.
 */
R_API void r_mpint_fe_mod_ct (RMpintFE * out, const RMpintFE * a,
    const RMpintFEMontCtx * ctx);

/** @} */

/** @name RMpintFE_Big: counterparts to the RMpintFE primitives
 *
 * Function semantics match the @ref RMpintFE primitives above
 * byte-for-byte (they are emitted from the same template); only
 * the storage width and the type / function name spellings differ.
 * The ctx / r-squared / exponent-bits inputs are the same role;
 * consult the @ref RMpintFE comments above for details.
 *  @{ */

/** @brief See @ref r_mpint_fe_mont_ctx_init. */
R_API rboolean r_mpint_fe_big_mont_ctx_init (RMpintFE_BigMontCtx * ctx,
    const rmpint * m);
/** @brief See @ref r_mpint_fe_compute_r_squared. */
R_API rboolean r_mpint_fe_big_compute_r_squared (RMpintFE_Big * out,
    const rmpint * m, ruint16 n);

/** @brief See @ref r_mpint_fe_zero. */
R_API void r_mpint_fe_big_zero (RMpintFE_Big * x);
/** @brief See @ref r_mpint_fe_copy. */
R_API void r_mpint_fe_big_copy (RMpintFE_Big * dst, const RMpintFE_Big * src);
/** @brief See @ref r_mpint_fe_from_mpint. */
R_API void r_mpint_fe_big_from_mpint (RMpintFE_Big * fe, const rmpint * mpi,
    ruint16 n);
/** @brief See @ref r_mpint_fe_to_mpint. */
R_API rboolean r_mpint_fe_big_to_mpint (rmpint * mpi, const RMpintFE_Big * fe,
    ruint16 n);

/** @brief See @ref r_mpint_fe_iszero_ct. */
R_API rmpint_digit r_mpint_fe_big_iszero_ct (const RMpintFE_Big * x, ruint16 n);
/** @brief See @ref r_mpint_fe_select_ct. */
R_API void r_mpint_fe_big_select_ct (RMpintFE_Big * out, rmpint_digit mask,
    const RMpintFE_Big * a, const RMpintFE_Big * b, ruint16 n);
/** @brief See @ref r_mpint_fe_swap_ct. */
R_API void r_mpint_fe_big_swap_ct (RMpintFE_Big * a, RMpintFE_Big * b,
    ruint32 bit, ruint16 n);

/** @brief See @ref r_mpint_fe_add. */
R_API void r_mpint_fe_big_add (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_Big * b, const RMpintFE_BigMontCtx * ctx);
/** @brief See @ref r_mpint_fe_sub. */
R_API void r_mpint_fe_big_sub (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_Big * b, const RMpintFE_BigMontCtx * ctx);

/** @brief See @ref r_mpint_fe_mul_mont. */
R_API void r_mpint_fe_big_mul_mont (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_Big * b, const RMpintFE_BigMontCtx * ctx);
/** @brief See @ref r_mpint_fe_sqr_mont. */
R_API void r_mpint_fe_big_sqr_mont (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_BigMontCtx * ctx);

/** @brief See @ref r_mpint_fe_mont_in. */
R_API void r_mpint_fe_big_mont_in (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_Big * mont_r_squared, const RMpintFE_BigMontCtx * ctx);
/** @brief See @ref r_mpint_fe_mont_out. */
R_API void r_mpint_fe_big_mont_out (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_BigMontCtx * ctx);

/** @brief See @ref r_mpint_fe_invmod_mont. */
R_API void r_mpint_fe_big_invmod_mont (RMpintFE_Big * out,
    const RMpintFE_Big * a_M,
    const RMpintFE_Big * p_minus_2, ruint p_minus_2_bits,
    const RMpintFE_Big * mont_r_squared, const RMpintFE_BigMontCtx * ctx);

/** @brief See @ref r_mpint_fe_mul_ct. */
R_API void r_mpint_fe_big_mul_ct (RMpintFE_Big * out,
    const RMpintFE_Big * a, ruint16 a_n,
    const RMpintFE_Big * b, ruint16 b_n);
/** @brief See @ref r_mpint_fe_add_ct. */
R_API void r_mpint_fe_big_add_ct (RMpintFE_Big * out,
    const RMpintFE_Big * a, ruint16 a_n,
    const RMpintFE_Big * b, ruint16 b_n);
/** @brief See @ref r_mpint_fe_mod_ct. */
R_API void r_mpint_fe_big_mod_ct (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_BigMontCtx * ctx);

/**
 * @brief Modular exponentiation in Z_m: @c dst = base^exp mod m.
 *
 * @p base is reduced mod @p m internally if needed (variable-time
 * on @p base; for RSA the base is the public ciphertext, so the
 * reduce isn't a leak). The exponent flows through a 4-bit windowed
 * Montgomery exponentiation with constant-time table lookup via
 * FE_Big primitives - no @c dig_used residual on intermediate
 * values the way @ref r_mpint_expmod_ct has, since FE_Big storage
 * is fixed-width.
 *
 * @param dst             Destination (in @ref rmpint form).
 * @param base            Base (public).
 * @param exp             Exponent (secret-safe).
 * @param m               Modulus (must be odd).
 * @param ctx             Per-modulus Montgomery context for @p m.
 * @param mont_r_squared  @c R^2 mod m.
 * @param exp_bits        Drives the iteration count: the loop runs
 *                  exactly @c ceil(exp_bits / 4) windows regardless
 *                  of the exponent's actual bit length, so callers
 *                  wanting a uniform timing profile across keys can
 *                  pass the modulus's bit length (or any constant
 *                  >= the exponent's true bit length).
 */
R_API rboolean r_mpint_fe_big_expmod_ct (rmpint * dst,
    const rmpint * base, const rmpint * exp, const rmpint * m,
    const RMpintFE_BigMontCtx * ctx,
    const RMpintFE_Big * mont_r_squared, ruint exp_bits);

/** @} */

R_END_DECLS

/** @} */

#endif /* __R_MPINT_H__ */
