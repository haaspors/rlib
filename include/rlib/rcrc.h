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
#ifndef __R_CRC_H__
#define __R_CRC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

/**
 * @file rlib/rcrc.h
 * @brief CRC32 checksum variants.
 *
 * Three 32-bit CRC flavours over arbitrary byte buffers, each in
 * one-shot and streaming form:
 *
 *  - **CRC32** - IEEE 802.3 / zlib / PNG (polynomial 0x04C11DB7,
 *    reflected).
 *  - **CRC32C** - Castagnoli, used by SCTP, iSCSI, Btrfs, etc.
 *    (polynomial 0x1EDC6F41, reflected).
 *  - **CRC32 bzip2** - non-reflected variant used by bzip2
 *    (polynomial 0x04C11DB7).
 *
 * The @c _update functions take a running CRC value so callers can
 * checksum bytes incrementally; seed the first call with
 * @c R_CRC32_INIT. The macro shorthands (@c r_crc32 / @c r_crc32c /
 * @c r_crc32bzip2) wrap the one-shot case.
 */

/** @brief Seed value for an empty / unstarted CRC32 stream. */
#define R_CRC32_INIT              0

R_BEGIN_DECLS

/** @brief One-shot CRC32 (IEEE) over @p buf / @p size bytes. */
#define r_crc32(buf, size)        r_crc32_update (R_CRC32_INIT, buf, size)
/** @brief One-shot CRC32C (Castagnoli) over @p buf / @p size bytes. */
#define r_crc32c(buf, size)       r_crc32c_update (R_CRC32_INIT, buf, size)
/** @brief One-shot CRC32 bzip2 over @p buf / @p size bytes. */
#define r_crc32bzip2(buf, size)   r_crc32bzip2_update (R_CRC32_INIT, buf, size)

/**
 * @brief Extend a CRC32 (IEEE) running checksum with another chunk
 * of @p size bytes from @p buffer.
 *
 * Seed the running value with @c R_CRC32_INIT on the first call.
 *
 * @param crc     Current running CRC (use @c R_CRC32_INIT to start).
 * @param buffer  Next chunk of bytes to feed.
 * @param size    Bytes in @p buffer.
 * @return Updated CRC value.
 */
R_API ruint32 r_crc32_update (ruint32 crc, rconstpointer buffer, rsize size);
/**
 * @brief Extend a CRC32C (Castagnoli) running checksum.
 *
 * Same seeding and arguments as @c r_crc32_update.
 */
R_API ruint32 r_crc32c_update (ruint32 crc, rconstpointer buffer, rsize size);
/**
 * @brief Extend a CRC32 bzip2 (non-reflected) running checksum.
 *
 * Same seeding and arguments as @c r_crc32_update.
 */
R_API ruint32 r_crc32bzip2_update (ruint32 crc, rconstpointer buffer, rsize size);

R_END_DECLS

#endif /* __R_CRC_H__ */

