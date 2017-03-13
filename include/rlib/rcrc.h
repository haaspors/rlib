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

#define R_CRC32_INIT              0

R_BEGIN_DECLS

#define r_crc32(buf, size)        r_crc32_update (R_CRC32_INIT, buf, size)
#define r_crc32c(buf, size)       r_crc32c_update (R_CRC32_INIT, buf, size)
#define r_crc32bzip2(buf, size)   r_crc32bzip2_update (R_CRC32_INIT, buf, size)

R_API ruint32 r_crc32_update (ruint32 crc, rconstpointer buffer, rsize size);
R_API ruint32 r_crc32c_update (ruint32 crc, rconstpointer buffer, rsize size);
R_API ruint32 r_crc32bzip2_update (ruint32 crc, rconstpointer buffer, rsize size);

R_END_DECLS

#endif /* __R_CRC_H__ */

