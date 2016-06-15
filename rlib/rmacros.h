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
#ifndef __R_MACROS_H__
#define __R_MACROS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#if defined(__GNUC__) && __GNUC__ < 4
#error Please use a modern GNU compatible compiler
#endif

#include <stddef.h>

#ifdef __GNUC__
#define R_GNUC_PREREQ(x, y) \
  ((__GNUC__ == (x) && __GNUC_MINOR__ >= (y)) || (__GNUC__ > (x)))
#else
#define R_GNUC_PREREQ(x, y) 0
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#define R_API_EXPORT __declspec(dllexport)
#define R_API_IMPORT __declspec(dllimport)
#define R_API_HIDDEN
#elif defined(__GNUC__)
#define R_API_EXPORT __attribute__ ((visibility ("default")))
#define R_API_IMPORT __attribute__ ((visibility ("default")))
#define R_API_HIDDEN __attribute__ ((visibility ("hidden")))
#else
#define R_API_EXPORT
#define R_API_IMPORT
#define R_API_HIDDEN
#endif

#if defined(RLIB_STLIB)
#define R_API
#elif defined(RLIB_COMPILATION)
#define R_API R_API_EXPORT
#else
#define R_API R_API_IMPORT
#endif

#ifndef NULL
#ifdef __cplusplus
#define NULL  (0L)
#else
#define NULL  ((void*) 0)
#endif
#endif

#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE  (!FALSE)
#endif

#undef  MAX
#undef  MIN
#undef  ABS
#undef  CLAMP

#define MAX(a, b)       (((a) > (b)) ? (a) : (b))
#define MIN(a, b)       (((a) < (b)) ? (a) : (b))
#define ABS(a)          (((a) < 0) ? -(a) : (a))
#define CLAMP(x, l, h)  (((x) > (h)) ? (h) : (((x) < (l)) ? (l) : (x)))

#define R_N_ELEMENTS(a)               (sizeof (a) / sizeof ((a)[0]))

#define R_STRINGIFY_ARG(str)          #str
#define R_STRINGIFY(str)              R_STRINGIFY_ARG (str)
#define R_PASTE_ARGS(a1, a2)          a1 ## a2
#define R_PASTE(a1, a2)               R_PASTE_ARGS (a1, a2)

#define R_STRLOC        __FILE__ ":" R_STRINGIFY (__LINE__)
#if defined (__GNUC__) && defined (__cplusplus)
#define R_STRFUNC     ((const char*) (__PRETTY_FUNCTION__))
#elif defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define R_STRFUNC     ((const char*) (__func__))
#elif defined (__GNUC__) || defined(_MSC_VER)
#define R_STRFUNC     ((const char*) (__FUNCTION__))
#else
#define R_STRFUNC     ((const char*) ("???"))
#endif

#ifdef  __cplusplus
#define R_BEGIN_DECLS  extern "C" {
#define R_END_DECLS    }
#else
#define R_BEGIN_DECLS
#define R_END_DECLS
#endif

#define R_STMT_START  do
#ifndef _MSC_VER
#define R_STMT_END    while (0)
#else
#define R_STMT_END \
    __pragma(warning(push)) \
    __pragma(warning(disable:4127)) \
    while(0) \
    __pragma(warning(pop))
#endif

#if defined(__GNUC__)
#define R_INITIALIZER(f)   static void __attribute__((constructor)) f (void)
#define R_DEINITIALIZER(f) static void __attribute__((destructor))  f (void)
#elif defined(_MSC_VER)
#define R_INITIALIZER(f)                                                    \
  static void __cdecl f (void);                                             \
  __pragma(section(".CRT$XCU",read))                                        \
  __declspec(allocate(".CRT$XCU")) void (__cdecl*f##_)(void) = f;           \
  static void __cdecl f (void)
#define R_DEINITIALIZER(f)                                                  \
  static void __cdecl f (void);                                             \
  static void __cdecl f##_atexit (void) { atexit (f); }                     \
  __pragma(section(".CRT$XCU",read))                                        \
  __declspec(allocate(".CRT$XCU")) void (__cdecl*f##_)(void) = f##_atexit;  \
  static void __cdecl f (void)
#else
#error Your compiler does not support initializers/deinitializers
#endif

#if defined(__GNUC__) && defined(__OPTIMIZE__)
#define R_LIKELY(expr)      __builtin_expect(!!(expr), 1)
#define R_UNLIKELY(expr)    __builtin_expect(!!(expr), 0)
#else
#define R_LIKELY(expr)      (expr)
#define R_UNLIKELY(expr)    (expr)
#endif

#if defined(__GNUC__)
#if __MACH__
#define R_ATTR_DATA_SECTION(sec)   __attribute__((section("__DATA,"sec)))
#define R_ATTR_CODE_SECTION(sec)   __attribute__((section("__TEXT,"sec)))
#else
#define R_ATTR_DATA_SECTION(sec)   __attribute__((section(sec)))
#define R_ATTR_CODE_SECTION(sec)   __attribute__((section(sec)))
#endif
#elif defined(_MSC_VER)
#define R_ATTR_DATA_SECTION(sec)            \
  __pragma(section(sec,read,write))         \
  __declspec(allocate(sec))
#define R_ATTR_CODE_SECTION(sec)   __declspec(code_seg(sec))
#else
#error Your compiler does not support data/code/text section attributes
#endif

#if defined(__GNUC__)
#define R_ATTR_WARN_UNUSED_RESULT     __attribute__((warn_unused_result))
#elif defined(_MSC_VER) && (_MSC_VER >= 1700)
#define R_ATTR_WARN_UNUSED_RESULT     _Check_return_
#else
#define R_ATTR_WARN_UNUSED_RESULT
#endif

#if defined(__GNUC__)
#define R_ATTR_NORETURN               __attribute__((__noreturn__))
#define R_ATTR_WEAK                   __attribute__((weak))
#define R_ATTR_ALIGN(a)               __attribute__((aligned(a)))
#elif defined(_MSC_VER)
#define R_ATTR_NORETURN               __declspec(noreturn)
#define R_ATTR_WEAK                   __declspec(selectany)
#define R_ATTR_ALIGN(a)               __declspec(align(a))
#else
#define R_ATTR_NORETURN
#define R_ATTR_WEAK
#define R_ATTR_ALIGN(a)
#endif

#if defined(__GNUC__)
#define R_ATTR_UNUSED                 __attribute__((__unused__))
#define R_ATTR_CONST                  __attribute__((__const__))
#define R_ATTR_PURE                   __attribute__((__pure__))
#define R_ATTR_MALLOC                 __attribute__((__malloc__))
#define R_ATTR_FORMAT_ARG(arg_idx)    __attribute__((__format_arg__ (arg_idx)))
#define R_ATTR_PRINTF(fmt_idx, arg_idx) \
  __attribute__((__format__ (__printf__, fmt_idx, arg_idx)))
#define R_ATTR_SCANF(fmt_idx, arg_idx)  \
  __attribute__((__format__ (__scanf__, fmt_idx, arg_idx)))
#else
#define R_ATTR_UNUSED
#define R_ATTR_CONST
#define R_ATTR_PURE
#define R_ATTR_MALLOC
#define R_ATTR_FORMAT_ARG(arg_idx)
#define R_ATTR_PRINTF(fmt_idx, arg_idx)
#define R_ATTR_SCANF(fmt_idx, arg_idx)
#endif

#if defined(__clang__)
#define R_ATTR_RESTRICT __restrict__
#elif defined(__GNUC__)
#define R_ATTR_RESTRICT __restrict__
#elif defined(_MSC_VER)
#define R_ATTR_RESTRICT __restrict
#else
#define R_ATTR_RESTRICT
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif
#ifndef __has_extension
#define __has_extension __has_feature
#endif

#if  (defined(__clang__) && __has_feature(__alloc_size__)) || \
    (!defined(__clang__) && R_GNUC_PREREQ(4, 3))
#define R_ATTR_ALLOC_SIZE_ARG(x)    __attribute__((__alloc_size__(x)))
#define R_ATTR_ALLOC_SIZE_ARGS(x,y) __attribute__((__alloc_size__(x,y)))
#else
#define R_ATTR_ALLOC_SIZE_ARG(x)
#define R_ATTR_ALLOC_SIZE_ARGS(x,y)
#endif

#endif /* __R_MACROS_H__ */
