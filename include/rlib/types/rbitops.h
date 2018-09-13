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

#if RLIB_SIZEOF_LONG == 4
rulong __inline RULONGLONG_CLZ (ruint64 x)
{
  ruint y[2] = { x & RUINT32_MAX, x >> 32 };
  rulong lz;

  return (_BitScanReverse (&lz, y[1])) ? 31 - lz :
    ((_BitScanReverse (&lz, y[0])) ? 63 - lz : 64);
}

rulong __inline RULONGLONG_CTZ (ruint64 x)
{
  ruint y[2] = { x & RUINT32_MAX, x >> 32 };
  rulong tz;

  return (_BitScanForward (&tz, y[0])) ? tz :
    ((_BitScanForward (&tz, y[1])) ? tz + 32 : 64);
}
#else
rulong __inline RULONGLONG_CLZ (ruint64 x)
{
  rulong lz;
  return (_BitScanReverse64 (&lz, x)) ? 63 - lz : 64;
}

rulong __inline RULONGLONG_CTZ (ruint64 x)
{
  rulong tz;
  return (_BitScanForward64 (&tz, x)) ? tz : 64;
}
#endif

#define RUINT_POPCOUNT(x)       (ruint)__popcnt (x)
#define RUINT_PARITY(x)         (__popcnt (x) & 1)
#if RLIB_SIZEOF_LONG == 4
ruint __inline RULONGLONG_POPCOUNT (ruint64 x)
{
  ruint y[2] = { x & RUINT32_MAX, x >> 32 };
  return (ruint)__popcnt (y[0]) + __popcnt (y[1]);
}

rboolean __inline RULONGLONG_PARITY (ruint64 x)
{
  ruint y[2] = { x & RUINT32_MAX, x >> 32 };
  return ((__popcnt (y[0]) + __popcnt (y[1])) & 1) != 0;
}
#else
#define RULONGLONG_POPCOUNT(x)  (ruint)__popcnt64 (x)
#define RULONGLONG_PARITY(x)    (__popcnt64 (x) & 1)
#endif
#if RLIB_SIZEOF_LONG == 4
#define RULONG_CLZ(x)           RUINT_CLZ (x)
#define RULONG_CTZ(x)           RUINT_CTZ (x)
#define RULONG_POPCOUNT(x)      RUINT_POPCOUNT (x)
#define RULONG_PARITY(x)        RUINT_PARITY (x)
#else
#define RULONG_CLZ(x)           RULONGLONG_CLZ (x)
#define RULONG_CTZ(x)           RULONGLONG_CTZ (x)
#define RULONG_POPCOUNT(x)      RULONGLONG_POPCOUNT (x)
#define RULONG_PARITY(x)        RULONGLONG_PARITY (x)
#endif

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
#define RUINT64_SHL(x, n)       (((x) & RUINT64_MAX) << ((n) & 63))
#define RUINT64_SHR(x, n)       (((x) & RUINT64_MAX) >> ((n) & 63))
#define RUINT64_ROTL(x, n)      (RUINT64_SHL (x, n) | RUINT64_SHR (x, 64-(n)))
#define RUINT64_ROTR(x, n)      (RUINT64_SHR (x, n) | RUINT64_SHL (x, 64-(n)))


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
#define RUINT32_SHL(x, n)       (((x) & RUINT32_MAX) << ((n) & 31))
#define RUINT32_SHR(x, n)       (((x) & RUINT32_MAX) >> ((n) & 31))
#define RUINT32_ROTL(x, n)      (RUINT32_SHL (x, n) | RUINT32_SHR (x, 32-(n)))
#define RUINT32_ROTR(x, n)      (RUINT32_SHR (x, n) | RUINT32_SHL (x, 32-(n)))

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
#define RUINT16_CTZ(x)          MIN (RUINT32_CTZ (x & RUINT16_MAX), 16)
#define RUINT16_POPCOUNT(x)     RUINT32_POPCOUNT (x & RUINT16_MAX)
#define RUINT16_PARITY(x)       RUINT32_PARITY (x & RUINT16_MAX)
#endif
#define RUINT16_SHL(x, n)       (((x) & RUINT16_MAX) << ((n) & 15))
#define RUINT16_SHR(x, n)       (((x) & RUINT16_MAX) >> ((n) & 15))
#define RUINT16_ROTL(x, n)      (RUINT16_SHL (x, n) | RUINT16_SHR (x, 16-(n)))
#define RUINT16_ROTR(x, n)      (RUINT16_SHR (x, n) | RUINT16_SHL (x, 16-(n)))

#define RUINT8_CLZ(x)           (RUINT32_CLZ (x & RUINT8_MAX) - 24)
#define RUINT8_CTZ(x)           MIN (RUINT32_CTZ (x & RUINT8_MAX), 8)
#define RUINT8_POPCOUNT(x)      RUINT32_POPCOUNT (x & RUINT8_MAX)
#define RUINT8_PARITY(x)        RUINT32_PARITY (x & RUINT8_MAX)
#define RUINT8_SHL(x, n)        (((x) & RUINT8_MAX) << ((n) & 7))
#define RUINT8_SHR(x, n)        (((x) & RUINT8_MAX) >> ((n) & 7))
#define RUINT8_ROTL(x, n)       (RUINT8_SHL (x, n) | RUINT8_SHR (x, 8-(n)))
#define RUINT8_ROTR(x, n)       (RUINT8_SHR (x, n) | RUINT8_SHL (x, 8-(n)))

#if RLIB_SIZEOF_SIZE_T == 8
#define RSIZE_CLZ(x)            RUINT64_CLZ (x)
#define RSIZE_CTZ(x)            RUINT64_CTZ (x)
#define RSIZE_POPCOUNT(x)       RUINT64_POPCOUNT (x)
#define RSIZE_PARITY(x)         RUINT64_PARITY (x)
#define RSIZE_SHL(x, n)         RUINT64_SHL (x, n)
#define RSIZE_SHR(x, n)         RUINT64_SHR (x, n)
#define RSIZE_ROTL(x, n)        RUINT64_ROTL (x, n)
#define RSIZE_ROTR(x, n)        RUINT64_ROTR (x, n)
#elif RLIB_SIZEOF_SIZE_T == 4
#define RSIZE_CLZ(x)            RUINT32_CLZ (x)
#define RSIZE_CTZ(x)            RUINT32_CTZ (x)
#define RSIZE_POPCOUNT(x)       RUINT32_POPCOUNT (x)
#define RSIZE_PARITY(x)         RUINT32_PARITY (x)
#define RSIZE_SHL(x, n)         RUINT32_SHL (x, n)
#define RSIZE_SHR(x, n)         RUINT32_SHR (x, n)
#define RSIZE_ROTL(x, n)        RUINT32_ROTL (x, n)
#define RSIZE_ROTR(x, n)        RUINT32_ROTR (x, n)
#elif RLIB_SIZEOF_SIZE_T == 2
#define RSIZE_CLZ(x)            RUINT16_CLZ (x)
#define RSIZE_CTZ(x)            RUINT16_CTZ (x)
#define RSIZE_POPCOUNT(x)       RUINT16_POPCOUNT (x)
#define RSIZE_PARITY(x)         RUINT16_PARITY (x)
#define RSIZE_SHL(x, n)         RUINT16_SHL (x, n)
#define RSIZE_SHR(x, n)         RUINT16_SHR (x, n)
#define RSIZE_ROTL(x, n)        RUINT16_ROTL (x, n)
#define RSIZE_ROTR(x, n)        RUINT16_ROTR (x, n)
#endif

R_END_DECLS

#endif /* __R_BITOPS_H__ */
