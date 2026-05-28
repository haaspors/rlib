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

/**
 * @defgroup r_macros Portability macros
 * @ingroup r_types
 *
 * @brief Compiler-portability shims and small utility macros used
 * throughout rlib.
 *
 * Everything here resolves to a compiler-specific spelling (GCC /
 * Clang attributes, MSVC @c __declspec, or an empty fallback) so the
 * rest of the codebase can use one name regardless of toolchain:
 * symbol-visibility decoration (@ref R_API), function / variable
 * attributes (the @c R_ATTR_* family), branch hints, constructors,
 * and the usual @c MIN / @c MAX / stringify helpers.
 *
 * @{
 */

/**
 * @file rlib/types/rmacros.h
 * @brief Compiler-portability macros and small utility macros.
 */

#if defined(__GNUC__) && __GNUC__ < 4
#error Please use a modern GNU compatible compiler
#endif

#include <stddef.h>

/** @brief @c TRUE if compiling with GCC @p x.@p y or newer (@c 0 elsewhere). */
#ifdef __GNUC__
#define R_GNUC_PREREQ(x, y) \
  ((__GNUC__ == (x) && __GNUC_MINOR__ >= (y)) || (__GNUC__ > (x)))
#else
#define R_GNUC_PREREQ(x, y) 0
#endif

/** @name Symbol visibility
 *  @{ */
#if defined(_WIN32) || defined(__CYGWIN__)
/** @brief Mark a symbol as exported from the shared library. */
#define R_API_EXPORT __declspec(dllexport)
/** @brief Mark a symbol as imported from the shared library. */
#define R_API_IMPORT __declspec(dllimport)
/** @brief Mark a symbol as hidden (not exported). */
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

/**
 * @brief Public-API decoration: resolves to @c R_API_EXPORT while
 * building rlib and @c R_API_IMPORT for consumers.
 */
#if defined(RLIB_COMPILATION)
#define R_API R_API_EXPORT
#else
#define R_API R_API_IMPORT
#endif
/** @} */

/** @name Common constants
 *  @{ */
/** @brief Null pointer constant (defined only if absent). */
#ifndef NULL
#ifdef __cplusplus
#define NULL  (0L)
#else
#define NULL  ((void*) 0)
#endif
#endif

/** @brief Boolean false (@c 0). */
#ifndef FALSE
#define FALSE (0)
#endif
/** @brief Boolean true (@c !FALSE). */
#ifndef TRUE
#define TRUE  (!FALSE)
#endif
/** @} */

#undef  MAX
#undef  MIN
#undef  ABS
#undef  CLAMP

/** @name Arithmetic helpers
 *
 * Argument-evaluating macros (no type checking) — beware passing
 * expressions with side effects.
 *  @{ */
/** @brief Larger of @p a and @p b. */
#define MAX(a, b)       (((a) > (b)) ? (a) : (b))
/** @brief Smaller of @p a and @p b. */
#define MIN(a, b)       (((a) < (b)) ? (a) : (b))
/** @brief Absolute value of @p a. */
#define ABS(a)          (((a) < 0) ? -(a) : (a))
/** @brief Clamp @p x to the inclusive range [@p l, @p h]. */
#define CLAMP(x, l, h)  (((x) > (h)) ? (h) : (((x) < (l)) ? (l) : (x)))

/** @brief Number of elements in a fixed-size array @p a. */
#define R_N_ELEMENTS(a)               (sizeof (a) / sizeof ((a)[0]))
/** @} */

/** @name Token manipulation
 *  @{ */
/** @brief Stringify @p str without macro expansion. */
#define R_STRINGIFY_ARG(str)          #str
/** @brief Stringify @p str after macro expansion. */
#define R_STRINGIFY(str)              R_STRINGIFY_ARG (str)
/** @brief Token-paste @p a1 and @p a2 without macro expansion. */
#define R_PASTE_ARGS(a1, a2)          a1 ## a2
/** @brief Token-paste @p a1 and @p a2 after macro expansion. */
#define R_PASTE(a1, a2)               R_PASTE_ARGS (a1, a2)

/** @brief Source location string @c "file:line". */
#define R_STRLOC        __FILE__ ":" R_STRINGIFY (__LINE__)
/** @brief Current function name as a string (compiler-specific spelling). */
#if defined (__GNUC__) && defined (__cplusplus)
#define R_STRFUNC     ((const char*) (__PRETTY_FUNCTION__))
#elif defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define R_STRFUNC     ((const char*) (__func__))
#elif defined (__GNUC__) || defined(_MSC_VER)
#define R_STRFUNC     ((const char*) (__FUNCTION__))
#else
#define R_STRFUNC     ((const char*) ("???"))
#endif
/** @} */

/** @name Declaration and statement wrappers
 *  @{ */
/** @brief Open an @c extern @c "C" block under C++ (no-op in C). */
#ifdef  __cplusplus
#define R_BEGIN_DECLS  extern "C" {
/** @brief Close an @ref R_BEGIN_DECLS block. */
#define R_END_DECLS    }
#else
#define R_BEGIN_DECLS
#define R_END_DECLS
#endif

/** @brief Start a brace-free multi-statement macro body; pair with @ref R_STMT_END. */
#define R_STMT_START  do
/** @brief End an @ref R_STMT_START body (suppresses MSVC C4127 on the @c while(0)). */
#ifndef _MSC_VER
#define R_STMT_END    while (0)
#else
#define R_STMT_END \
    __pragma(warning(push)) \
    __pragma(warning(disable:4127)) \
    while(0) \
    __pragma(warning(pop))
#endif
/** @} */

/** @name Initializers and branch hints
 *  @{ */
#if defined(__GNUC__)
/** @brief Declare a function @p f that runs before @c main (static constructor). */
#define R_INITIALIZER(f)   static void __attribute__((constructor)) f (void)
/** @brief Declare a function @p f that runs at process exit (static destructor). */
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

/** @brief Hint that @p expr is likely true (branch-prediction). */
#if defined(__GNUC__) && defined(__OPTIMIZE__)
#define R_LIKELY(expr)      __builtin_expect(!!(expr), 1)
/** @brief Hint that @p expr is likely false (branch-prediction). */
#define R_UNLIKELY(expr)    __builtin_expect(!!(expr), 0)
#else
#define R_LIKELY(expr)      (expr)
#define R_UNLIKELY(expr)    (expr)
#endif
/** @} */

/** @name Section, function, and variable attributes
 *
 * Each resolves to the GCC/Clang attribute, the MSVC equivalent, or
 * nothing on toolchains that lack it.
 *  @{ */
#if defined(__GNUC__)
#if __MACH__
/** @brief Place a variable in the named writable data @p sec(tion). */
#define R_ATTR_DATA_SECTION(sec)   __attribute__((section("__DATA," sec)))
/** @brief Place a function in the named code/text @p sec(tion). */
#define R_ATTR_CODE_SECTION(sec)   __attribute__((section("__TEXT," sec)))
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

/** @brief Warn if a function's return value is ignored. */
#if defined(__GNUC__)
#define R_ATTR_WARN_UNUSED_RESULT     __attribute__((warn_unused_result))
#elif defined(_MSC_VER) && (_MSC_VER >= 1700)
#define R_ATTR_WARN_UNUSED_RESULT     _Check_return_
#else
#define R_ATTR_WARN_UNUSED_RESULT
#endif

/** @brief Mark a function as never returning. */
#if defined(__GNUC__)
#define R_ATTR_NORETURN               __attribute__((__noreturn__))
/** @brief Allow duplicate definitions to be merged (weak symbol). */
#define R_ATTR_WEAK                   __attribute__((weak))
/** @brief Align a variable / type to @p a bytes. */
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

/** @brief Mark an intentional @c switch fall-through. */
#if defined(__clang__) || R_GNUC_PREREQ(7, 0)
#define R_ATTR_FALLTHROUGH            __attribute__((fallthrough))
#else
#define R_ATTR_FALLTHROUGH            ((void)0)
#endif

/** @brief Mark a variadic function as requiring a @c NULL sentinel. */
#if defined(__GNUC__)
#define R_ATTR_NULL_TERMINATED        __attribute__((__sentinel__))
/** @brief Suppress unused-symbol warnings. */
#define R_ATTR_UNUSED                 __attribute__((__unused__))
/** @brief Mark a function as pure with no memory reads (@c const). */
#define R_ATTR_CONST                  __attribute__((__const__))
/** @brief Mark a function as side-effect-free (@c pure). */
#define R_ATTR_PURE                   __attribute__((__pure__))
/** @brief Mark a function as returning newly-allocated memory. */
#define R_ATTR_MALLOC                 __attribute__((__malloc__))
/** @brief Mark parameter @p arg_idx as a format string passed through verbatim. */
#define R_ATTR_FORMAT_ARG(arg_idx)    __attribute__((__format_arg__ (arg_idx)))
/** @brief Enable @c printf-style format checking (@p fmt_idx, @p arg_idx are 1-based). */
#define R_ATTR_PRINTF(fmt_idx, arg_idx) \
  __attribute__((__format__ (__printf__, fmt_idx, arg_idx)))
/** @brief Enable @c scanf-style format checking. */
#define R_ATTR_SCANF(fmt_idx, arg_idx)  \
  __attribute__((__format__ (__scanf__, fmt_idx, arg_idx)))
#else
#define R_ATTR_NULL_TERMINATED
#define R_ATTR_UNUSED
#define R_ATTR_CONST
#define R_ATTR_PURE
#define R_ATTR_MALLOC
#define R_ATTR_FORMAT_ARG(arg_idx)
#define R_ATTR_PRINTF(fmt_idx, arg_idx)
#define R_ATTR_SCANF(fmt_idx, arg_idx)
#endif

/** @brief Pointer-aliasing hint (@c restrict) in the compiler's spelling. */
#if defined(__clang__)
#define R_ATTR_RESTRICT __restrict__
#elif defined(__GNUC__)
#define R_ATTR_RESTRICT __restrict__
#elif defined(_MSC_VER)
#define R_ATTR_RESTRICT __restrict
#else
#define R_ATTR_RESTRICT
#endif
/** @} */

/** @name Feature-test fallbacks
 *  Define the Clang feature-test builtins as @c 0 on compilers that lack them.
 *  @{ */
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
/** @brief Mark parameter @p x as the allocation size (single-argument form). */
#define R_ATTR_ALLOC_SIZE_ARG(x)    __attribute__((__alloc_size__(x)))
/** @brief Mark parameters @p x, @p y as the allocation size (count × size form). */
#define R_ATTR_ALLOC_SIZE_ARGS(x,y) __attribute__((__alloc_size__(x,y)))
#else
#define R_ATTR_ALLOC_SIZE_ARG(x)
#define R_ATTR_ALLOC_SIZE_ARGS(x,y)
#endif
/** @} */

/** @} */ /* r_macros */

#endif /* __R_MACROS_H__ */
