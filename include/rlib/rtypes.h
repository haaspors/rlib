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

/**
 * @defgroup r_types Foundational types
 * @brief Type aliases (@c rint32, @c rsize, @c rchar, @c rpointer,
 * ...) every other rlib header builds on.
 * @{
 */

/**
 * @file rlib/rtypes.h
 * @brief Foundational type aliases used by every rlib header.
 *
 * rlib spells its primitive types with an @c r prefix
 * (@c rint32, @c rsize, @c rchar, @c rpointer, ...) so callers can
 * grep for the project's surface and so the size-suffixed names
 * map predictably to the bit widths their compilers would otherwise
 * negotiate via @c stdint.h. The fixed-width @c rXX / @c ruXX
 * typedefs live in the build-generated @c rlib/rconfig.h; the
 * native-width ones (@c rchar, @c rshort, ...) live here.
 */

R_BEGIN_DECLS

/**
 * @name Boolean type
 * @{
 */
/** @brief Boolean type (typedef'd to @c int). */
typedef int                     rboolean;
/** @} */

/**
 * @name Floating-point types and constants
 * @{
 */
/** @brief Single-precision floating point. */
typedef float                   rfloat;
/** @brief Double-precision floating point. */
typedef double                  rdouble;

/** @brief Smallest positive normalised @c rfloat. */
#define RFLOAT_MIN              FLT_MIN
/** @brief Largest finite @c rfloat. */
#define RFLOAT_MAX              FLT_MAX
/** @brief Smallest positive normalised @c rdouble. */
#define RDOUBLE_MIN             DBL_MIN
/** @brief Largest finite @c rdouble. */
#define RDOUBLE_MAX             DBL_MAX
/* The platform-specific spellings of infinity / NaN below are
 * documented identically on every branch; Doxygen picks whichever
 * branch is active under its preprocessor config, so the comments
 * have to live on all three so the symbols show up no matter which
 * branch survives. */
#if defined(_MSC_VER)
/** @brief +infinity as @c rfloat. */
#define RFLOAT_INFINITY         ((rfloat)(1e+300 * 1e+300))
/** @brief Quiet NaN as @c rfloat. */
#define RFLOAT_NAN              (RFLOAT_INFINITY * 0.0f)
/** @brief +infinity as @c rdouble. */
#define RDOUBLE_INFINITY        ((rdouble)(1e+300 * 1e+300))
/** @brief Quiet NaN as @c rdouble. */
#define RDOUBLE_NAN             (RDOUBLE_INFINITY * 0.0)
#elif defined(__GNUC__)
/** @brief +infinity as @c rfloat. */
#define RFLOAT_INFINITY         (__builtin_huge_valf())
/** @brief Quiet NaN as @c rfloat. */
#define RFLOAT_NAN              (__builtin_nanf("0x7fc00000"))
/** @brief +infinity as @c rdouble. */
#define RDOUBLE_INFINITY        (__builtin_huge_val())
/** @brief Quiet NaN as @c rdouble. */
#define RDOUBLE_NAN             ((rdouble)RFLOAT_NAN)
#else
/** @brief +infinity as @c rfloat. */
#define RFLOAT_INFINITY         ((rfloat)1e500)
/** @brief Quiet NaN as @c rfloat. */
#define RFLOAT_NAN              (__nan())
/** @brief +infinity as @c rdouble. */
#define RDOUBLE_INFINITY        ((rdouble)1e500)
/** @brief Quiet NaN as @c rdouble. */
#define RDOUBLE_NAN             ((rdouble)RFLOAT_NAN)
#endif

/** @brief Euler's number, e. */
#define R_E                 2.718281828459045235360287471352662497757247093700
/** @brief Natural log of 2. */
#define R_LN2               0.693147180559945309417232121458176568075500134360
/** @brief Natural log of 10. */
#define R_LN10              2.302585092994045684017991454684364207601101488629
/** @brief log_10 of 2. */
#define R_LOG_2_BASE10      0.301029995663981195213738894724493026768189881462
/** @brief pi. */
#define R_PI                3.141592653589793238462643383279502884197169399375
/** @brief Square root of 2. */
#define R_SQRT2             1.414213562373095048801688724209698078569671875377
/** @} */

/**
 * @name Native-width integer types
 *
 * Aliases for the C native types whose width depends on the host
 * (@c char, @c short, @c int, @c long). Use the fixed-width
 * @c rXX / @c ruXX names from @c rlib/rconfig.h when the size
 * needs to be predictable.
 * @{
 */
/** @brief Default character type (@c char). */
typedef char                    rchar;
/** @brief Default short type (@c short). */
typedef short                   rshort;
/** @brief Default long type (@c long). */
typedef long                    rlong;
/** @brief Explicit-signed char (same as @c rchar on rlib's targets). */
typedef char                    rschar;
/** @brief Explicit-signed short. */
typedef short                   rsshort;
/** @brief Explicit-signed long. */
typedef long                    rslong;
/** @brief Explicit-signed int. */
typedef int                     rsint;
/** @brief Unsigned char. */
typedef unsigned char           ruchar;
/** @brief Unsigned short. */
typedef unsigned short          rushort;
/** @brief Unsigned long. */
typedef unsigned long           rulong;
/** @brief Unsigned int. */
typedef unsigned int            ruint;

#define RCHAR_MIN               CHAR_MIN     /**< Minimum value of @c rchar. */
#define RCHAR_MAX               CHAR_MAX     /**< Maximum value of @c rchar. */
#define RSHORT_MIN              SHRT_MIN     /**< Minimum value of @c rshort. */
#define RSHORT_MAX              SHRT_MAX     /**< Maximum value of @c rshort. */
#define RUSHORT_MAX             USHRT_MAX    /**< Maximum value of @c rushort. */
#define RINT_MIN                INT_MIN      /**< Minimum value of @c rsint. */
#define RINT_MAX                INT_MAX      /**< Maximum value of @c rsint. */
#define RUINT_MAX               UINT_MAX     /**< Maximum value of @c ruint. */
#define RLONG_MIN               LONG_MIN     /**< Minimum value of @c rlong. */
#define RLONG_MAX               LONG_MAX     /**< Maximum value of @c rlong. */
#define RULONG_MAX              ULONG_MAX    /**< Maximum value of @c rulong. */
/** @} */

/**
 * @name Fixed-width integer types
 *
 * Exact-width signed and unsigned integers. The typedefs themselves
 * are emitted into the build-generated @c rlib/rconfig.h (the host's
 * @c short / @c int / @c long widths are probed at configure time so
 * the sizes are guaranteed); they are documented here, where every
 * caller already includes them via @c rlib/rtypes.h.
 * @{
 */
#ifdef RLIB_DOXYGEN
/* Doxygen-only mirror of the typedefs emitted into rlib/rconfig.h.
 * Never compiled (RLIB_DOXYGEN is defined only by the Doxyfile). */
typedef signed char    rint8;    /**< @brief Signed 8-bit integer. */
typedef signed short   rint16;   /**< @brief Signed 16-bit integer. */
typedef signed int     rint32;   /**< @brief Signed 32-bit integer. */
typedef signed long    rint64;   /**< @brief Signed 64-bit integer. */
typedef signed long    rintmax;  /**< @brief Widest signed integer the host supports. */
typedef unsigned char  ruint8;   /**< @brief Unsigned 8-bit integer. */
typedef unsigned short ruint16;  /**< @brief Unsigned 16-bit integer. */
typedef unsigned int   ruint32;  /**< @brief Unsigned 32-bit integer. */
typedef unsigned long  ruint64;  /**< @brief Unsigned 64-bit integer. */
typedef unsigned long  ruintmax; /**< @brief Widest unsigned integer the host supports. */
#endif
/** @} */

/**
 * @name Fixed-width integer limits
 *
 * The @c MIN / @c MAX constants for the @ref rint8 / @ref ruint8 /
 * ... types. The typedefs live in @c rlib/rconfig.h (chosen per host
 * so the sizes are guaranteed); the constants live here so a single
 * include of @c rlib/rtypes.h covers both.
 * @{
 */
/** @brief Minimum value of @c rint8. */
#define RINT8_MIN               ((rint8)   0x80)
/** @brief Maximum value of @c rint8. */
#define RINT8_MAX               ((rint8)   0x7f)
/** @brief Maximum value of @c ruint8. */
#define RUINT8_MAX              ((ruint8)  0xff)
/** @brief Minimum value of @c rint16. */
#define RINT16_MIN              ((rint16)  0x8000)
/** @brief Maximum value of @c rint16. */
#define RINT16_MAX              ((rint16)  0x7fff)
/** @brief Maximum value of @c ruint16. */
#define RUINT16_MAX             ((ruint16) 0xffff)
/** @brief Minimum value of @c rint32. */
#define RINT32_MIN              ((rint32)  0x80000000)
/** @brief Maximum value of @c rint32. */
#define RINT32_MAX              ((rint32)  0x7fffffff)
/** @brief Maximum value of @c ruint32. */
#define RUINT32_MAX             ((ruint32) 0xffffffff)
/** @brief Minimum value of @c rint64. */
#define RINT64_MIN              ((rint64) RINT64_CONSTANT(0x8000000000000000))
/** @brief Maximum value of @c rint64. */
#define RINT64_MAX              RINT64_CONSTANT(0x7fffffffffffffff)
/** @brief Maximum value of @c ruint64. */
#define RUINT64_MAX             RUINT64_CONSTANT(0xffffffffffffffff)
/** @} */

/**
 * @name Size and file-offset types
 *
 * @c rsize / @c rssize (unsigned and signed pointer-sized) are
 * typedef'd in @c rlib/rconfig.h. @c roffset is a 64-bit signed
 * offset used for file / stream positions, large enough to address
 * past the 32-bit boundary on platforms that need it.
 * @{
 */
#ifdef RLIB_DOXYGEN
typedef unsigned long           rsize;  /**< @brief Unsigned pointer-sized size type (like @c size_t). */
typedef signed long             rssize; /**< @brief Signed pointer-sized size type (like @c ssize_t). */
#endif
/** @brief 64-bit signed file / stream offset. */
typedef rint64                  roffset;
/** @brief Minimum value of @c roffset. */
#define ROFFSET_MIN             RINT64_MIN
/** @brief Maximum value of @c roffset. */
#define ROFFSET_MAX             RINT64_MAX

/** @brief printf length modifier for @c roffset. */
#define ROFFSET_MODIFIER        RINT64_MODIFIER
/** @brief printf format specifier for @c roffset. */
#define ROFFSET_FMT             RINT64_FMT
/** @brief Suffix a literal as an @c roffset value. */
#define ROFFSET_CONSTANT(val)   RINT64_CONSTANT(val)
/** @} */

/**
 * @name Pointer types
 *
 * @c rpointer / @c rconstpointer alias @c void @c * / @c const
 * @c void @c *. The conversion macros cast through @c rintptr /
 * @c ruintptr / @c rsize to silence pedantic warnings about
 * pointer / integer conversions on platforms where the widths
 * happen to mismatch.
 *
 * @c rintptr / @c ruintptr (signed / unsigned integers wide enough
 * to hold a pointer, like @c intptr_t / @c uintptr_t) are typedef'd
 * in @c rlib/rconfig.h.
 * @{
 */
#ifdef RLIB_DOXYGEN
typedef signed long             rintptr;  /**< @brief Signed integer wide enough to hold a pointer (like @c intptr_t). */
typedef unsigned long           ruintptr; /**< @brief Unsigned integer wide enough to hold a pointer (like @c uintptr_t). */
#endif
/** @brief Generic pointer (alias for @c void @c *). */
typedef void*                   rpointer;
/** @brief Generic const pointer (alias for @c const @c void @c *). */
typedef const void*             rconstpointer;
/** @brief Reinterpret a pointer as an @c rsint. */
#define RPOINTER_TO_INT(p)      ((rsint) (rintptr) (p))
/** @brief Reinterpret a pointer as a @c ruint. */
#define RPOINTER_TO_UINT(p)     ((ruint) (ruintptr) (p))
/** @brief Reinterpret a pointer as an @c rsize. */
#define RPOINTER_TO_SIZE(p)     ((rsize) (p))
/** @brief Reinterpret an @c rsint as a pointer. */
#define RINT_TO_POINTER(i)      ((rpointer) (rintptr) (i))
/** @brief Reinterpret a @c ruint as a pointer. */
#define RUINT_TO_POINTER(u)     ((rpointer) (ruintptr) (u))
/** @brief Reinterpret an @c rsize as a pointer. */
#define RSIZE_TO_POINTER(s)     ((rpointer) (rsize) (s))
/** @} */

/**
 * @name Clock time
 *
 * Monotonic timestamps and durations expressed as @c ruint64
 * nanoseconds. The sentinel @c R_CLOCK_TIME_NONE doubles as an
 * "infinite" wait value.
 * @{
 */
/** @brief Unsigned 64-bit timestamp / duration, in nanoseconds. */
typedef ruint64                 RClockTime;
/** @brief Signed clock-time difference. */
typedef rint64                  RClockTimeDiff;
/** @brief Sentinel value for "no time" / "invalid time". */
#define R_CLOCK_TIME_NONE       ((RClockTime) -1)
/** @brief Alias for @c R_CLOCK_TIME_NONE used as a "wait forever" sentinel. */
#define R_CLOCK_TIME_INFINITE   R_CLOCK_TIME_NONE
/** @} */

/**
 * @name I/O handle
 *
 * Cross-platform OS I/O handle: a Windows @c HANDLE pointer on
 * Win32, a POSIX @c int file descriptor everywhere else.
 * @{
 */
#if defined (R_OS_WIN32)
/** @brief OS I/O handle (Win32 @c HANDLE on Windows; @c int fd elsewhere). */
typedef rpointer RIOHandle;
/** @brief printf format specifier for an @c RIOHandle. */
#define R_IO_HANDLE_FMT           "p"
/** @brief Sentinel for "no handle". */
#define R_IO_HANDLE_INVALID       INVALID_HANDLE_VALUE
/** @brief Convert an @c rpointer to an @c RIOHandle. */
#define RPOINTER_TO_IO_HANDLE(p)  (p)
/** @brief Convert an @c RIOHandle to an @c rpointer. */
#define RIO_HANDLE_TO_POINTER(h)  (h)
#else
typedef int RIOHandle;
#define R_IO_HANDLE_FMT       "i"
#define R_IO_HANDLE_INVALID   -1
#define RPOINTER_TO_IO_HANDLE(p)  RPOINTER_TO_INT (p)
#define RIO_HANDLE_TO_POINTER(h)  RINT_TO_POINTER (h)
#endif
/** @} */


/**
 * @name Function-pointer prototypes
 *
 * Common callback shapes used across rlib's container / iterator
 * APIs. Library users typically don't write these typedefs out -
 * they pass function pointers that match the shape into the call
 * sites that ask for them.
 * @{
 */
/** @brief Destructor callback: free / release the value at @p ptr. */
typedef void (*RDestroyNotify) (rpointer ptr);
/** @brief Generic iteration callback over (data, user) pairs. */
typedef void (*RFunc) (rpointer data, rpointer user);
/** @brief Comparison callback returning <0 / 0 / >0 for @p a vs @p b. */
typedef int (*RCmpFunc) (rconstpointer a, rconstpointer b);
/** @brief Equality predicate. */
typedef rboolean (*REqualFunc) (rconstpointer a, rconstpointer b);
/** @brief Hash function over an opaque key. */
typedef rsize (*RHashFunc) (rconstpointer key);
/** @brief Iteration callback over (key, value, user) triples. */
typedef void (*RKeyValueFunc) (rpointer key, rpointer value, rpointer user);
/** @brief Iteration callback over (const char *key, value, user). */
typedef void (*RStrKeyValueFunc) (const rchar * key, rpointer value, rpointer user);
/**
 * @brief Iteration callback that can short-circuit by returning FALSE.
 */
typedef rboolean (*RFuncReturn) (rpointer data, rpointer user);
/** @brief Key-value iteration callback that can short-circuit. */
typedef rboolean (*RKeyValueFuncReturn) (rpointer key, rpointer value, rpointer user);
/**
 * @brief Type-erased function pointer used as a "any callable"
 * placeholder before downcasting to the actual signature.
 *
 * Casting between this and a real function-pointer type is
 * well-defined; casting through @c void @c * would not be.
 */
typedef void (*RFuncUniversal) ();
/** @brief Type-erased function pointer that returns an @c rpointer. */
typedef rpointer (*RFuncUniversalReturn) ();
/** @} */


R_END_DECLS

/** @} */ /* r_types group */

#include <rlib/types/rmemops.h>
#include <rlib/types/rendianness.h>
#include <rlib/types/rbitops.h>

#endif /* __R_TYPES_H__ */
