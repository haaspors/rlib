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
#ifndef __R_BITOPS_H__
#define __R_BITOPS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/* This header is included by rtypes.h (@ bottom of file) */

R_BEGIN_DECLS

#if defined(_MSC_VER)
#include <intrin.h>

ruint __inline RUINT_CLZ (ruint x)
{
  ruint lz;
  return (_BitScanReverse (&lz, x)) ? 31 - lz : 32;
}

ruint __inline RUINT_CTZ (ruint x)
{
  ruint tz;
  return (_BitScanForward (&tz, x)) ? tz : 32;
}

rulong __inline RULONG_CLZ (rulong x)
{
  rulong lz;
  return (_BitScanReverse64 (&lz, x)) ? 63 - lz : 64;
}

rulong __inline RULONG_CTZ (rulong x)
{
  rulong tz;
  return (_BitScanForward64 (&tz, x)) ? tz : 64;
}
#define RUINT_POPCOUNT(x)       (ruint)__popcnt (x)
#define RUINT_PARITY(x)         (__popcnt (x) & 1)
#define RULONG_POPCOUNT(x)      (ruint)__popcnt64 (x)
#define RULONG_PARITY(x)        (__popcnt64 (x) & 1)
#define RULONGLONG_CLZ(x)       RULONG_CLZ (x)
#define RULONGLONG_CTZ(x)       RULONG_CTZ (x)
#define RULONGLONG_POPCOUNT(x)  RULONG_POPCOUNT (x)
#define RULONGLONG_PARITY(x)    RULONG_PARITY (x)
#elif defined(__GNUC__)
#define RUINT_CLZ(x)            ((x) ? (ruint)__builtin_clz (x) : sizeof (ruint) * 8)
#define RUINT_CTZ(x)            ((x) ? (ruint)__builtin_ctz (x) : sizeof (ruint) * 8)
#define RUINT_POPCOUNT(x)       (ruint)__builtin_popcount (x)
#define RUINT_PARITY(x)         __builtin_parity (x)
#define RULONG_CLZ(x)           ((x) ? (ruint)__builtin_clzl (x) : sizeof (rulong) * 8)
#define RULONG_CTZ(x)           ((x) ? (ruint)__builtin_ctzl (x) : sizeof (rulong) * 8)
#define RULONG_POPCOUNT(x)      (ruint)__builtin_popcountl (x)
#define RULONG_PARITY(x)        __builtin_parityl (x)
#define RULONGLONG_CLZ(x)       ((x) ? (ruint)__builtin_clzll (x) : sizeof (long long) * 8)
#define RULONGLONG_CTZ(x)       ((x) ? (ruint)__builtin_ctzll (x) : sizeof (long long) * 8)
#define RULONGLONG_POPCOUNT(x)  (ruint)__builtin_popcountll (x)
#define RULONGLONG_PARITY(x)    __builtin_parityll (x)
#endif

#if RLIB_SIZEOF_LONG == 8
#define RUINT64_CLZ(x)          RULONG_CLZ (x)
#define RUINT64_CTZ(x)          RULONG_CTZ (x)
#define RUINT64_POPCOUNT(x)     RULONG_POPCOUNT (x)
#define RUINT64_PARITY(x)       RULONG_PARITY (x)
#else
#define RUINT64_CLZ(x)          RULONGLONG_CLZ (x)
#define RUINT64_CTZ(x)          RULONGLONG_CTZ (x)
#define RUINT64_POPCOUNT(x)     RULONGLONG_POPCOUNT (x)
#define RUINT64_PARITY(x)       RULONGLONG_PARITY (x)
#endif

#if RLIB_SIZEOF_INT == 4
#define RUINT32_CLZ(x)          RUINT_CLZ (x)
#define RUINT32_CTZ(x)          RUINT_CTZ (x)
#define RUINT32_POPCOUNT(x)     RUINT_POPCOUNT (x)
#define RUINT32_PARITY(x)       RUINT_PARITY (x)
#elif RLIB_SIZEOF_LONG == 4
#define RUINT32_CLZ(x)          RULONG_CLZ (x)
#define RUINT32_CTZ(x)          RULONG_CTZ (x)
#define RUINT32_POPCOUNT(x)     RULONG_POPCOUNT (x)
#define RUINT32_PARITY(x)       RULONG_PARITY (x)
#else
#define RUINT32_CLZ(x)          (RUINT64_CLZ (x & RUINT32_MAX) - 32)
#define RUINT32_CTZ(x)          RUINT64_CTZ (x & RUINT32_MAX)
#define RUINT32_POPCOUNT(x)     RUINT64_POPCOUNT (x & RUINT32_MAX)
#define RUINT32_PARITY(x)       RUINT64_PARITY (x & RUINT32_MAX)
#endif

#if RLIB_SIZEOF_INT == 2
#define RUINT16_CLZ(x)          RUINT_CLZ (x)
#define RUINT16_CTZ(x)          RUINT_CTZ (x)
#define RUINT16_POPCOUNT(x)     RUINT_POPCOUNT (x)
#define RUINT16_PARITY(x)       RUINT_PARITY (x)
#elif RLIB_SIZEOF_LONG == 2
#define RUINT16_CLZ(x)          RULONG_CLZ (x)
#define RUINT16_CTZ(x)          RULONG_CTZ (x)
#define RUINT16_POPCOUNT(x)     RULONG_POPCOUNT (x)
#define RUINT16_PARITY(x)       RULONG_PARITY (x)
#else
#define RUINT16_CLZ(x)          (RUINT32_CLZ (x & RUINT16_MAX) - 16)
#define RUINT16_CTZ(x)          RUINT32_CTZ (x & RUINT16_MAX)
#define RUINT16_POPCOUNT(x)     RUINT32_POPCOUNT (x & RUINT16_MAX)
#define RUINT16_PARITY(x)       RUINT32_PARITY (x & RUINT16_MAX)
#endif

#define RUINT8_CLZ(x)           (RUINT32_CLZ (x & RUINT8_MAX) - 24)
#define RUINT8_CTZ(x)           RUINT32_CTZ (x & RUINT8_MAX)
#define RUINT8_POPCOUNT(x)      RUINT32_POPCOUNT (x & RUINT8_MAX)
#define RUINT8_PARITY(x)        RUINT32_PARITY (x & RUINT8_MAX)

#if RLIB_SIZEOF_SIZE_T == 8
#define RSIZE_CLZ(x)            RUINT64_CLZ (x)
#define RSIZE_CTZ(x)            RUINT64_CTZ (x)
#define RSIZE_POPCOUNT(x)       RUINT64_POPCOUNT (x)
#define RSIZE_PARITY(x)         RUINT64_PARITY (x)
#elif RLIB_SIZEOF_SIZE_T == 4
#define RSIZE_CLZ(x)            RUINT32_CLZ (x)
#define RSIZE_CTZ(x)            RUINT32_CTZ (x)
#define RSIZE_POPCOUNT(x)       RUINT32_POPCOUNT (x)
#define RSIZE_PARITY(x)         RUINT32_PARITY (x)
#elif RLIB_SIZEOF_SIZE_T == 2
#define RSIZE_CLZ(x)            RUINT16_CLZ (x)
#define RSIZE_CTZ(x)            RUINT16_CTZ (x)
#define RSIZE_POPCOUNT(x)       RUINT16_POPCOUNT (x)
#define RSIZE_PARITY(x)         RUINT16_PARITY (x)
#endif

R_END_DECLS

#endif /* __R_BITOPS_H__ */
