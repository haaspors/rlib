/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_ENDIANNESS_H__
#define __R_ENDIANNESS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

R_BEGIN_DECLS

#define R_LITTLE_ENDIAN         1234
#define R_BIG_ENDIAN            4321

/* If your compiler doesn't support __BYTE_ORDER__ this doesn't work! */
#if !defined(__BYTE_ORDER__) && !defined(_MSC_VER)
#warning "__BYTE_ORDER__ not defined"
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define R_BYTE_ORDER R_BIG_ENDIAN

#define RINT16_TO_BE(val)   ((rint16)  (val))
#define RUINT16_TO_BE(val)  ((ruint16) (val))
#define RINT16_TO_LE(val)   ((rint16) RUINT16_BSWAP (val))
#define RUINT16_TO_LE(val)  (RUINT16_BSWAP (val))
#define RINT32_TO_BE(val)   ((rint32)  (val))
#define RUINT32_TO_BE(val)  ((ruint32) (val))
#define RINT32_TO_LE(val)   ((rint32) RUINT32_BSWAP (val))
#define RUINT32_TO_LE(val)  (RUINT32_BSWAP (val))
#define RINT64_TO_BE(val)   ((rint64)  (val))
#define RUINT64_TO_BE(val)  ((ruint64) (val))
#define RINT64_TO_LE(val)   ((rint64) RUINT64_BSWAP (val))
#define RUINT64_TO_LE(val)  (RUINT64_BSWAP (val))
#else
#if !defined(_MSC_VER) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "__BYTE_ORDER__ is not supported"
#endif
#define R_BYTE_ORDER R_LITTLE_ENDIAN

#define RINT16_TO_LE(val)     ((rint16)  (val))
#define RUINT16_TO_LE(val)    ((ruint16) (val))
#define RINT16_TO_BE(val)     ((rint16) RUINT16_BSWAP (val))
#define RUINT16_TO_BE(val)    (RUINT16_BSWAP (val))
#define RINT32_TO_LE(val)     ((rint32)  (val))
#define RUINT32_TO_LE(val)    ((ruint32) (val))
#define RINT32_TO_BE(val)     ((rint32) RUINT32_BSWAP (val))
#define RUINT32_TO_BE(val)    (RUINT32_BSWAP (val))
#define RINT64_TO_LE(val)     ((rint64)  (val))
#define RUINT64_TO_LE(val)    ((ruint64) (val))
#define RINT64_TO_BE(val)     ((rint64) RUINT64_BSWAP (val))
#define RUINT64_TO_BE(val)    (RUINT64_BSWAP (val))
#endif

#if RLIB_SIZEOF_SIZE_T == 8
#define RSIZE_TO_LE(val)      ((rsize)  RUINT64_TO_LE (val))
#define RSSIZE_TO_LE(val)     ((rssize) RINT64_TO_LE  (val))
#define RSIZE_TO_BE(val)      ((rsize)  RUINT64_TO_BE (val))
#define RSSIZE_TO_BE(val)     ((rssize) RINT64_TO_BE  (val))
#elif RLIB_SIZEOF_SIZE_T == 4
#define RSIZE_TO_LE(val)      ((rsize)  RUINT32_TO_LE (val))
#define RSSIZE_TO_LE(val)     ((rssize) RINT32_TO_LE  (val))
#define RSIZE_TO_BE(val)      ((rsize)  RUINT32_TO_BE (val))
#define RSSIZE_TO_BE(val)     ((rssize) RINT32_TO_BE  (val))
#elif RLIB_SIZEOF_SIZE_T == 2
#define RSIZE_TO_LE(val)      ((rsize)  RUINT16_TO_LE (val))
#define RSSIZE_TO_LE(val)     ((rssize) RINT16_TO_LE  (val))
#define RSIZE_TO_BE(val)      ((rsize)  RUINT16_TO_BE (val))
#define RSSIZE_TO_BE(val)     ((rssize) RINT16_TO_BE  (val))
#endif

#if RLIB_SIZEOF_LONG == 8
#define RULONG_TO_LE(val)     ((rulong) RUINT64_TO_LE (val))
#define RLONG_TO_LE(val)      ((rlong)  RINT64_TO_LE  (val))
#define RULONG_TO_BE(val)     ((rulong) RUINT64_TO_BE (val))
#define RLONG_TO_BE(val)      ((rlong)  RINT64_TO_BE  (val))
#elif RLIB_SIZEOF_LONG == 4
#define RULONG_TO_LE(val)     ((rulong) RUINT32_TO_LE (val))
#define RLONG_TO_LE(val)      ((rlong)  RINT32_TO_LE  (val))
#define RULONG_TO_BE(val)     ((rulong) RUINT32_TO_BE (val))
#define RLONG_TO_BE(val)      ((rlong)  RINT32_TO_BE  (val))
#elif RLIB_SIZEOF_LONG == 2
#define RULONG_TO_LE(val)     ((rulong) RUINT16_TO_LE (val))
#define RLONG_TO_LE(val)      ((rlong)  RINT16_TO_LE  (val))
#define RULONG_TO_BE(val)     ((rulong) RUINT16_TO_BE (val))
#define RLONG_TO_BE(val)      ((rlong)  RINT16_TO_BE  (val))
#endif

#if RLIB_SIZEOF_INTMAX == 8
#define RUINTMAX_TO_LE(val)   ((rulong) RUINT64_TO_LE (val))
#define RINTMAX_TO_LE(val)    ((rlong)  RINT64_TO_LE  (val))
#define RUINTMAX_TO_BE(val)   ((rulong) RUINT64_TO_BE (val))
#define RINTMAX_TO_BE(val)    ((rlong)  RINT64_TO_BE  (val))
#elif RLIB_SIZEOF_INTMAX == 4
#define RUINTMAX_TO_LE(val)   ((rulong) RUINT32_TO_LE (val))
#define RINTMAX_TO_LE(val)    ((rlong)  RINT32_TO_LE  (val))
#define RUINTMAX_TO_BE(val)   ((rulong) RUINT32_TO_BE (val))
#define RINTMAX_TO_BE(val)    ((rlong)  RINT32_TO_BE  (val))
#elif RLIB_SIZEOF_INTMAX == 2
#define RUINTMAX_TO_LE(val)   ((rulong) RUINT16_TO_LE (val))
#define RINTMAX_TO_LE(val)    ((rlong)  RINT16_TO_LE  (val))
#define RUINTMAX_TO_BE(val)   ((rulong) RUINT16_TO_BE (val))
#define RINTMAX_TO_BE(val)    ((rlong)  RINT16_TO_BE  (val))
#endif

#if RLIB_SIZEOF_INT == 8
#define RUINT_TO_LE(val)      ((rulong) RUINT64_TO_LE (val))
#define RINT_TO_LE(val)       ((rlong)  RINT64_TO_LE  (val))
#define RUINT_TO_BE(val)      ((rulong) RUINT64_TO_BE (val))
#define RINT_TO_BE(val)       ((rlong)  RINT64_TO_BE  (val))
#elif RLIB_SIZEOF_INT == 4
#define RUINT_TO_LE(val)      ((rulong) RUINT32_TO_LE (val))
#define RINT_TO_LE(val)       ((rlong)  RINT32_TO_LE  (val))
#define RUINT_TO_BE(val)      ((rulong) RUINT32_TO_BE (val))
#define RINT_TO_BE(val)       ((rlong)  RINT32_TO_BE  (val))
#elif RLIB_SIZEOF_INT == 2
#define RUINT_TO_LE(val)      ((rulong) RUINT16_TO_LE (val))
#define RINT_TO_LE(val)       ((rlong)  RINT16_TO_LE  (val))
#define RUINT_TO_BE(val)      ((rulong) RUINT16_TO_BE (val))
#define RINT_TO_BE(val)       ((rlong)  RINT16_TO_BE  (val))
#endif

#define RINT16_FROM_LE(val)   (RINT16_TO_LE   (val))
#define RUINT16_FROM_LE(val)  (RUINT16_TO_LE  (val))
#define RINT16_FROM_BE(val)   (RINT16_TO_BE   (val))
#define RUINT16_FROM_BE(val)  (RUINT16_TO_BE  (val))
#define RINT32_FROM_LE(val)   (RINT32_TO_LE   (val))
#define RUINT32_FROM_LE(val)  (RUINT32_TO_LE  (val))
#define RINT32_FROM_BE(val)   (RINT32_TO_BE   (val))
#define RUINT32_FROM_BE(val)  (RUINT32_TO_BE  (val))
#define RINT64_FROM_LE(val)   (RINT64_TO_LE   (val))
#define RUINT64_FROM_LE(val)  (RUINT64_TO_LE  (val))
#define RINT64_FROM_BE(val)   (RINT64_TO_BE   (val))
#define RUINT64_FROM_BE(val)  (RUINT64_TO_BE  (val))
#define RLONG_FROM_LE(val)    (RLONG_TO_LE    (val))
#define RULONG_FROM_LE(val)   (RULONG_TO_LE   (val))
#define RLONG_FROM_BE(val)    (RLONG_TO_BE    (val))
#define RULONG_FROM_BE(val)   (RULONG_TO_BE   (val))
#define RINT_FROM_LE(val)     (RINT_TO_LE     (val))
#define RUINT_FROM_LE(val)    (RUINT_TO_LE    (val))
#define RINT_FROM_BE(val)     (RINT_TO_BE     (val))
#define RUINT_FROM_BE(val)    (RUINT_TO_BE    (val))
#define RSIZE_FROM_LE(val)    (RSIZE_TO_LE    (val))
#define RSSIZE_FROM_LE(val)   (RSSIZE_TO_LE   (val))
#define RSIZE_FROM_BE(val)    (RSIZE_TO_BE    (val))
#define RSSIZE_FROM_BE(val)   (RSSIZE_TO_BE   (val))


#define r_ntohl(val)          (RUINT32_FROM_BE  (val))
#define r_ntohs(val)          (RUINT16_FROM_BE  (val))
#define r_htonl(val)          (RUINT32_TO_BE    (val))
#define r_htons(val)          (RUINT16_TO_BE    (val))

R_END_DECLS

#endif /* __R_ENDIANNESS_H__ */
