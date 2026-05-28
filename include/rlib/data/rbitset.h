/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_BITSET_H__
#define __R_BITSET_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_bitset Bitset
 * @ingroup r_data
 *
 * @brief Fixed-width array of bits stored as a flexible-array
 * @c rbsword tail, with the usual set / get / popcount / clz / ctz
 * surface plus AND / OR / XOR / NOT compound operations.
 *
 * Use @ref r_bitset_init_stack to put the bitset on the call stack
 * via @c alloca, or @ref r_bitset_init_heap for a heap allocation
 * that the caller frees with @c r_free.
 *
 * @{
 */

/**
 * @file rlib/data/rbitset.h
 * @brief Fixed-width bitset with bit / byte / word accessors and
 * bitwise compound operations.
 */

#include <rlib/rtypes.h>
#include <rlib/rmem.h>

R_BEGIN_DECLS

/** @brief Machine word backing @ref RBitset storage (64 bits). */
typedef ruint64 rbsword;
/**
 * @brief Per-bit visitor signature for @ref r_bitset_foreach.
 *
 * @param bit   Index of the bit being visited.
 * @param user  Caller-supplied cookie.
 */
typedef void (*RBitsetFunc) (rsize bit, rpointer user);

/**
 * @brief Fixed-width bitset.
 *
 * @c data is a flexible array of @ref rbsword backing the bits.
 * Construct via @ref r_bitset_init_stack or @ref r_bitset_init_heap;
 * never resize after construction.
 */
typedef struct {
  rsize   bits;         /**< Bit-capacity. */
  rsize   words;        /**< @c rbsword count rounded up from @c bits. */
  rbsword data[0];      /**< Flexible-array storage. */
} RBitset;

/**
 * @brief Stack-allocate an @ref RBitset of @p BITS bits via @c alloca.
 *
 * Use only inside a function; the storage is freed when the
 * function returns.
 */
#define r_bitset_init_stack(BS, BITS)                                         \
    (((BS) = r_alloca0 (sizeof (RBitset) + sizeof (rbsword) * (1 + (BITS - 1) / (sizeof (rbsword) * 8)))) != NULL && \
    ((BS)->bits = (BITS)) > 0 &&                                              \
    ((BS)->words = (1 + (BITS - 1) / (sizeof (rbsword) * 8))) > 0)
/**
 * @brief Heap-allocate an @ref RBitset of @p BITS bits; caller frees
 * with @c r_free.
 */
#define r_bitset_init_heap(BS, BITS)                                          \
    (((BS) = r_malloc0 (sizeof (RBitset) + sizeof (rbsword) * (1 + (BITS - 1) / (sizeof (rbsword) * 8)))) != NULL && \
    ((BS)->bits = (BITS)) > 0 &&                                              \
    ((BS)->words = (1 + (BITS - 1) / (sizeof (rbsword) * 8))) > 0)

/**
 * @brief Allocate a bitset from a packed binary blob.
 *
 * @p size bytes of @p data become @p size * 8 bits of bitset.
 */
R_API RBitset * r_bitset_new_from_binary (rconstpointer data, rsize size);
/** @brief Copy @p src into @p dest (both must have the same bit count). */
R_API rboolean r_bitset_copy (RBitset * dest, const RBitset * src);
/** @brief Set or clear a single bit. */
R_API rboolean r_bitset_set_bit (RBitset * bitset, rsize bit, rboolean set);
/** @brief Set or clear each bit listed in @p bits. */
R_API rboolean r_bitset_set_bits (RBitset * bitset,
    const rsize * bits, rsize count, rboolean set);
/** @brief Convenience: clear every bit. */
#define r_bitset_clear(bs)  r_bitset_set_all (bs, FALSE)
/** @brief Set every bit to @p set. */
R_API rboolean r_bitset_set_all (RBitset * bitset, rboolean set);
/** @brief Set or clear @p n consecutive bits starting at @p bit. */
R_API rboolean r_bitset_set_n_bits_at (RBitset * bitset, rsize n, rsize bit, rboolean set);
/** @brief Write an 8-bit value starting at bit position @p bit. */
R_API rboolean r_bitset_set_u8_at (RBitset * bitset, ruint8 u8, rsize bit);
/** @brief Write a 16-bit value starting at bit position @p bit. */
R_API rboolean r_bitset_set_u16_at (RBitset * bitset, ruint16 u16, rsize bit);
/** @brief Write a 32-bit value starting at bit position @p bit. */
R_API rboolean r_bitset_set_u32_at (RBitset * bitset, ruint32 u32, rsize bit);
/** @brief Write a 64-bit value starting at bit position @p bit. */
R_API rboolean r_bitset_set_u64_at (RBitset * bitset, ruint64 u64, rsize bit);
/**
 * @brief Parse a human-readable bitset spec (e.g.
 * @c "0,3-5,17") into @p bitset.
 *
 * @param bitset  Destination (caller-sized).
 * @param str     The text spec.
 * @param bits    Out: highest bit index touched.
 */
R_API rboolean r_bitset_set_from_human_readable (RBitset * bitset, const rchar * str, rsize * bits);
/** @brief Same as @ref r_bitset_set_from_human_readable but reads the spec from @p file. */
R_API rboolean r_bitset_set_from_human_readable_file (RBitset * bitset, const rchar * file, rsize * bits);
/** @brief Convenience: in-place complement. */
#define r_bitset_inv(bs)  r_bitset_not (bs, bs)
/** @brief In-place right shift by @p count bits. */
R_API rboolean r_bitset_shr (RBitset * a, ruint count);
/** @brief In-place left shift by @p count bits. */
R_API rboolean r_bitset_shl (RBitset * a, ruint count);

/** @brief Read an 8-bit value starting at bit position @p bit. */
R_API ruint8  r_bitset_get_u8_at  (const RBitset * bitset, rsize bit);
/** @brief Read a 16-bit value starting at bit position @p bit. */
R_API ruint16 r_bitset_get_u16_at (const RBitset * bitset, rsize bit);
/** @brief Read a 32-bit value starting at bit position @p bit. */
R_API ruint32 r_bitset_get_u32_at (const RBitset * bitset, rsize bit);
/** @brief Read a 64-bit value starting at bit position @p bit. */
R_API ruint64 r_bitset_get_u64_at (const RBitset * bitset, rsize bit);
/**
 * @brief Render the set bits as a human-readable string
 * (e.g. @c "0,3-5,17").
 *
 * Caller frees with @c r_free.
 */
R_API rchar * r_bitset_to_human_readable (const RBitset * bitset);

/** @brief @c TRUE iff @p bit is set. */
R_API rboolean r_bitset_is_bit_set (const RBitset * bitset, rsize bit);
/** @brief Number of set bits. */
R_API rsize r_bitset_popcount (const RBitset * bitset);
/** @brief Count leading zeros (from the high bit). */
R_API rsize r_bitset_clz (const RBitset * bitset);
/** @brief Count trailing zeros (from bit 0). */
R_API rsize r_bitset_ctz (const RBitset * bitset);

/**
 * @brief Invoke @p func once for every bit equal to @p set
 * (TRUE = visit set bits, FALSE = visit clear bits).
 */
R_API void r_bitset_foreach (const RBitset * bitset, rboolean set,
    RBitsetFunc func, rpointer user);

/** @brief @c dest = ~src. */
R_API rboolean r_bitset_not (RBitset * dest, const RBitset * src);
/** @brief @c dest = a | b. */
R_API rboolean r_bitset_or (RBitset * dest, const RBitset * a, const RBitset * b);
/** @brief @c dest = a ^ b. */
R_API rboolean r_bitset_xor (RBitset * dest, const RBitset * a, const RBitset * b);
/** @brief @c dest = a & b. */
R_API rboolean r_bitset_and (RBitset * dest, const RBitset * a, const RBitset * b);

R_END_DECLS

/** @} */

#endif /* __R_BITSET_H__ */

