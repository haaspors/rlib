/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/types/rmacros.h>
/* *** Some headers are included at the bottom of this file! *** */

#include <limits.h>
#include <float.h>

R_BEGIN_DECLS

typedef int                     rboolean;
typedef float                   rfloat;
typedef double                  rdouble;

#define RFLOAT_MIN              FLT_MIN
#define RFLOAT_MAX              FLT_MAX
#define RDOUBLE_MIN             DBL_MIN
#define RDOUBLE_MAX             DBL_MAX
#if defined(_MSC_VER)
#define RFLOAT_INFINITY         ((rfloat)(1e+300 * 1e+300))
#define RFLOAT_NAN              (RFLOAT_INFINITY * 0.0f)
#define RDOUBLE_INFINITY        ((rdouble)(1e+300 * 1e+300))
#define RDOUBLE_NAN             (RDOUBLE_INFINITY * 0.0)
#elif defined(__GNUC__)
#define RFLOAT_INFINITY         (__builtin_huge_valf())
#define RFLOAT_NAN              (__builtin_nanf("0x7fc00000"))
#define RDOUBLE_INFINITY        (__builtin_huge_val())
#define RDOUBLE_NAN             ((rdouble)RFLOAT_NAN)
#else
#define RFLOAT_INFINITY         ((rfloat)1e500)
#define RFLOAT_NAN              (__nan())
#define RDOUBLE_INFINITY        ((rdouble)1e500)
#define RDOUBLE_NAN             ((rdouble)RFLOAT_NAN)
#endif

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

#define RCHAR_MIN               CHAR_MIN
#define RCHAR_MAX               CHAR_MAX
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
#define RUINT64_MAX             RUINT64_CONSTANT(0xffffffffffffffff)

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
#define R_CLOCK_TIME_INFINITE   R_CLOCK_TIME_NONE

/* IO Handle */
#if defined (R_OS_WIN32)
typedef rpointer RIOHandle;
#define R_IO_HANDLE_FMT       "p"
#define R_IO_HANDLE_INVALID   INVALID_HANDLE_VALUE
#else
typedef int RIOHandle;
#define R_IO_HANDLE_FMT       "i"
#define R_IO_HANDLE_INVALID   -1
#endif


/* Function prototypes */
typedef void (*RDestroyNotify) (rpointer ptr);
typedef void (*RFunc) (rpointer data, rpointer user);
typedef int (*RCmpFunc) (rconstpointer a, rconstpointer b);
typedef rboolean (*REqualFunc) (rconstpointer a, rconstpointer b);
typedef rsize (*RHashFunc) (rconstpointer key);
typedef void (*RKeyValueFunc) (rpointer key, rpointer value, rpointer user);
typedef void (*RStrKeyValueFunc) (const rchar * key, rpointer value, rpointer user);
typedef rboolean (*RFuncReturn) (rpointer data, rpointer user);
typedef rboolean (*RKeyValueFuncReturn) (rpointer key, rpointer value, rpointer user);
typedef void (*RFuncUniversal) ();
typedef rpointer (*RFuncUniversalReturn) ();


R_END_DECLS

#include <rlib/types/rendianness.h>
#include <rlib/types/rbitops.h>

#endif /* __R_TYPES_H__ */
