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
#ifndef __R_ASSERT_H__
#define __R_ASSERT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rassert.h
 * @brief Assertion macros and typed comparison helpers used by both
 * production code and the test runner.
 */

#include <rlib/rtypes.h>
#include <rlib/rassert-internal.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>
#include <stdarg.h>

/**
 * @defgroup r_assert Assertions
 * @ingroup r_test
 *
 * @brief Compile-on / compile-off assertion macros plus typed
 * comparison helpers that print the actual operand values on
 * failure.
 *
 * The @c r_assert_cmp* family prints both operand values when the
 * comparison fails, which is far more useful than a bare boolean
 * assertion. Pick the variant matching your operand type:
 * @ref r_assert_cmpint, @ref r_assert_cmpuint, @ref r_assert_cmpptr,
 * @ref r_assert_cmpstr, @ref r_assert_cmpmem, @ref r_assert_cmpbuf, ...
 *
 * @c r_assert_logs_* additionally check that a log message was
 * emitted on the side; these go through the @ref r_log
 * "keep-last" capture framework so they have non-zero overhead.
 *
 * Assertion failures funnel into @ref r_test_assertion, which is
 * what the test runner traps to record a failed test.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Assert that @p expr is truthy; abort with a diagnostic if not. */
#define r_assert(expr)                          _R_ASSERT (expr)
/** @brief Abort with "should not be reached"; used in dead-code branches. */
#define r_assert_not_reached()                  _R_ASSERT_VA ("<-- should not be reached")

/** @name Typed comparisons
 *  Each macro fires on failure with both operand values rendered.
 *  @p cmp is a comparison operator literal (@c ==, @c <, etc.).
 *  @{ */
/** @brief Compare two signed integers. */
#define r_assert_cmpint(n1, cmp, n2)            _R_ASSERT_CMP (n1,cmp,n2,rintmax,"%"RINTMAX_FMT,#n1,#n2)
/** @brief Compare two unsigned integers. */
#define r_assert_cmpuint(n1, cmp, n2)           _R_ASSERT_CMP (n1,cmp,n2,ruintmax,"%"RUINTMAX_FMT,#n1,#n2)
/** @brief Compare two unsigned integers, rendered in hex. */
#define r_assert_cmphex(n1, cmp, n2)            _R_ASSERT_CMP (n1,cmp,n2,ruintmax,"%"RINTMAX_MODIFIER"x",#n1,#n2)
/** @brief Compare two pointers. */
#define r_assert_cmpptr(n1, cmp, n2)            _R_ASSERT_CMP (n1,cmp,n2,rpointer,"%p",#n1,#n2)
/** @brief Compare two single-precision floats. */
#define r_assert_cmpfloat(n1, cmp, n2)          _R_ASSERT_CMP (n1,cmp,n2,rfloat,"%.9f",#n1,#n2)
/** @brief Compare two double-precision floats. */
#define r_assert_cmpdouble(n1, cmp, n2)         _R_ASSERT_CMP (n1,cmp,n2,rdouble,"%.9f",#n1,#n2)
/** @brief Compare two NUL-terminated strings (@c strcmp). */
#define r_assert_cmpstr(s1, cmp, s2)            _R_ASSERT_CMPSTR (s1, cmp, s2, #s1, #s2)
/** @brief Compare two strings up to @p s bytes (@c strncmp). */
#define r_assert_cmpstrn(s1, cmp, s2, s)        _R_ASSERT_CMPSTRN (s1, cmp, s2, s, #s1, #s2)
/** @brief Compare two strings of given lengths (each can have embedded NULs). */
#define r_assert_cmpstrsize(s1, l1, cmp, s2, l2)_R_ASSERT_CMPSTRSIZE (s1, l1, cmp, s2, l2, #s1, #s2)
/** @brief Compare two @p s-byte memory regions (@c memcmp). */
#define r_assert_cmpmem(m1, cmp, m2, s)         _R_ASSERT_CMPMEM (m1, cmp, m2, s, #m1, #m2)
/** @brief Compare two memory regions with explicit sizes. */
#define r_assert_cmpmemsize(m1, s1, cmp, m2, s2)_R_ASSERT_CMPMEMSIZE (m1, s1, cmp, m2, s2, #m1, #m2)
/** @brief Compare two RBuffer byte ranges, same size. */
#define r_assert_cmpbuf(b1, o1, cmp, b2, o2, s) _R_ASSERT_CMPBUFSIZE (b1, o1, s, cmp, b2, o2, s, #b1, #b2)
/** @brief Compare two RBuffer byte ranges with explicit sizes. */
#define r_assert_cmpbufsize(b1, o1, s1, cmp, b2, o2, s2) _R_ASSERT_CMPBUFSIZE (b1, o1, s1, cmp, b2, o2, s2, #b1, #b2)
/** @brief Compare an RBuffer range against a flat memory region. */
#define r_assert_cmpbufmem(b, o, s, cmp, m, ms) _R_ASSERT_CMPBUFMEM (b, o, s, cmp, m, ms, #b, #m)
/** @brief Compare an RBuffer range against a string with explicit length. */
#define r_assert_cmpbufstr(b, o, s, cmp, str, ss) _R_ASSERT_CMPBUFSTR (b, o, s, cmp, (str), ss, #b, #str)
/** @brief Compare an RBuffer range against a string literal. */
#define r_assert_cmpbufsstr(b, o, s, cmp, str)  _R_ASSERT_CMPBUFSTR (b, o, s, cmp, (str), R_STR_SIZEOF (str), #b, #str)
/** @} */

/** @name Log-message assertions
 *
 * Assert that @p expr is truthy AND that a log message matching the
 * given filter was emitted during the call. Backed by the
 * @c RLogKeepLast capture framework, which adds per-log overhead.
 *  @{ */
/** @brief Expect a log message in category @p cat. */
#define r_assert_logs_cat(expr, cat)            _R_ASSERT_LOG (expr,  cat, 0, NULL)
/** @brief Expect a log message at level @p l. */
#define r_assert_logs_level(expr, l)            _R_ASSERT_LOG (expr, NULL, l, NULL)
/** @brief Expect a log message with payload @p msg. */
#define r_assert_logs_msg(expr, msg)            _R_ASSERT_LOG (expr, NULL, 0,  msg)
/** @brief Expect a log message matching all three filters. */
#define r_assert_logs_full(expr, cat, l, msg)   _R_ASSERT_LOG (expr,  cat, l,  msg)
/** @} */


/**
 * @brief Failure entry point: emits a diagnostic and aborts (or
 * @c longjmp's back into the test runner if one is active).
 *
 * Called from the macros above; not normally invoked directly.
 */
R_API R_ATTR_NORETURN void r_test_assertion (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, ...) R_ATTR_PRINTF (5, 6);
/** @brief @c va_list variant of @ref r_test_assertion. */
R_API R_ATTR_NORETURN void r_test_assertionv (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, va_list args) R_ATTR_PRINTF (5, 0);
/** @brief Variant of @ref r_test_assertion that takes a pre-formatted message. */
R_API R_ATTR_NORETURN void r_test_assertion_msg (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg);

R_END_DECLS

/** @} */

#endif /* __R_ASSERT_H__ */

