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
#ifndef __R_TYPES_H__
#define __R_TYPES_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rconfig.h>
#include <rlib/rmacros.h>

#include <limits.h>
#include <float.h>

R_BEGIN_DECLS

typedef int                     rboolean;
typedef float                   rfloat;
typedef double                  rdouble;

#define R_E                 2.718281828459045235360287471352662497757247093700
#define R_LN2               0.693147180559945309417232121458176568075500134360
#define R_LN10              2.302585092994045684017991454684364207601101488629
#define R_LOG_2_BASE10      0.301029995663981195213738894724493026768189881462
#define R_PI                3.141592653589793238462643383279502884197169399375
#define R_SQRT2             1.414213562373095048801688724209698078569671875377

typedef char                    rchar;
typedef short                   rshort;
typedef long                    rlong;
typedef char                    rschar;
typedef short                   rsshort;
typedef long                    rslong;
typedef int                     rsint;
typedef unsigned char           ruchar;
typedef unsigned short          rushort;
typedef unsigned long           rulong;
typedef unsigned int            ruint;

#define RFLOAT_MIN              FLT_MIN
#define RFLOAT_MAX              FLT_MAX
#define RDOUBLE_MIN             DBL_MIN
#define RDOUBLE_MAX             DBL_MAX
#define RSHORT_MIN              SHRT_MIN
#define RSHORT_MAX              SHRT_MAX
#define RUSHORT_MAX             USHRT_MAX
#define RINT_MIN                INT_MIN
#define RINT_MAX                INT_MAX
#define RUINT_MAX               UINT_MAX
#define RLONG_MIN               LONG_MIN
#define RLONG_MAX               LONG_MAX
#define RULONG_MAX              ULONG_MAX

/* All r[u]intN typedefs in rconfig.h */
#define RINT8_MIN               ((rint8)   0x80)
#define RINT8_MAX               ((rint8)   0x7f)
#define RUINT8_MAX              ((ruint8)  0xff)
#define RINT16_MIN              ((rint16)  0x8000)
#define RINT16_MAX              ((rint16)  0x7fff)
#define RUINT16_MAX             ((ruint16) 0xffff)
#define RINT32_MIN              ((rint32)  0x80000000)
#define RINT32_MAX              ((rint32)  0x7fffffff)
#define RUINT32_MAX             ((ruint32) 0xffffffff)
#define RINT64_MIN              ((rint64) RINT64_CONSTANT(0x8000000000000000))
#define RINT64_MAX              RINT64_CONSTANT(0x7fffffffffffffff)
#define RUINT64_MAX             RUINT64_CONSTANT(0xffffffffffffffffU)

/* r[s]size typedefs in rconfig.h */
typedef rint64                  roffset;
#define ROFFSET_MIN             RINT64_MIN
#define ROFFSET_MAX             RINT64_MAX

#define ROFFSET_MODIFIER        RINT64_MODIFIER
#define ROFFSET_FMT             RINT64_FMT
#define ROFFSET_CONSTANT(val)   RINT64_CONSTANT(val)

/* r[u]intptr typedefs in rconfig.h */
typedef void*                   rpointer;
typedef const void*             rconstpointer;
#define RPOINTER_TO_INT(p)      ((rsint) (rintptr) (p))
#define RPOINTER_TO_UINT(p)     ((ruint) (ruintptr) (p))
#define RPOINTER_TO_SIZE(p)     ((rsize) (p))
#define RINT_TO_POINTER(i)      ((rpointer) (rintptr) (i))
#define RUINT_TO_POINTER(u)     ((rpointer) (ruintptr) (u))
#define RSIZE_TO_POINTER(s)     ((rpointer) (rsize) (s))

/* Clock and time related */
typedef ruint64                 RClockTime;
typedef rint64                  RClockTimeDiff;
#define R_CLOCK_TIME_NONE       ((RClockTime) -1)

#define R_LITTLE_ENDIAN         1234
#define R_BIG_ENDIAN            4321

/* Function prototypes */
typedef void (*RDestroyNotify) (rpointer ptr);
typedef void (*RFunc) (rpointer data, rpointer user);
typedef rboolean (*RFuncReturn) (rpointer data, rpointer user);

R_END_DECLS

#endif /* __R_TYPES_H__ */
