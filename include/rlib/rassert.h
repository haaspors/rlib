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

#include <rlib/rtypes.h>
#include <rlib/rassert-internal.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>
#include <stdarg.h>

R_BEGIN_DECLS

#define r_assert(expr)                          _R_ASSERT (expr)
#define r_assert_not_reached()                  _R_ASSERT_VA ("<-- should not be reached")
#define r_assert_cmpint(n1, cmp, n2)            _R_ASSERT_CMP (n1,cmp,n2,rintmax,"%"RINTMAX_FMT,#n1,#n2)
#define r_assert_cmpuint(n1, cmp, n2)           _R_ASSERT_CMP (n1,cmp,n2,ruintmax,"%"RUINTMAX_FMT,#n1,#n2)
#define r_assert_cmphex(n1, cmp, n2)            _R_ASSERT_CMP (n1,cmp,n2,ruintmax,"%"RINTMAX_MODIFIER"x",#n1,#n2)
#define r_assert_cmpptr(n1, cmp, n2)            _R_ASSERT_CMP (n1,cmp,n2,rpointer,"%p",#n1,#n2)
#define r_assert_cmpfloat(n1, cmp, n2)          _R_ASSERT_CMP (n1,cmp,n2,rfloat,"%.9f",#n1,#n2)
#define r_assert_cmpdouble(n1, cmp, n2)         _R_ASSERT_CMP (n1,cmp,n2,rdouble,"%.9f",#n1,#n2)
#define r_assert_cmpstr(s1, cmp, s2)            _R_ASSERT_CMPSTR (s1, cmp, s2, #s1, #s2)
#define r_assert_cmpstrn(s1, cmp, s2, s)        _R_ASSERT_CMPSTRN (s1, cmp, s2, s, #s1, #s2)
#define r_assert_cmpstrsize(s1, l1, cmp, s2, l2)_R_ASSERT_CMPSTRSIZE (s1, l1, cmp, s2, l2, #s1, #s2)
#define r_assert_cmpmem(m1, cmp, m2, s)         _R_ASSERT_CMPMEM (m1, cmp, m2, s, #m1, #m2)
#define r_assert_cmpmemsize(m1, s1, cmp, m2, s2)_R_ASSERT_CMPMEMSIZE (m1, s1, cmp, m2, s2, #m1, #m2)
#define r_assert_cmpbuf(b1, o1, cmp, b2, o2, s) _R_ASSERT_CMPBUFSIZE (b1, o1, s, cmp, b2, o2, s, #b1, #b2)
#define r_assert_cmpbufsize(b1, o1, s1, cmp, b2, o2, s2) _R_ASSERT_CMPBUFSIZE (b1, o1, s1, cmp, b2, o2, s2, #b1, #b2)
#define r_assert_cmpbufmem(b, o, s, cmp, m, ms) _R_ASSERT_CMPBUFMEM (b, o, s, cmp, m, ms, #b, #m)
#define r_assert_cmpbufstr(b, o, s, cmp, str, ss) _R_ASSERT_CMPBUFMEM (b, o, s, cmp, (str), ss, #b, #str)
#define r_assert_cmpbufsstr(b, o, s, cmp, str)  _R_ASSERT_CMPBUFMEM (b, o, s, cmp, (str), R_STR_SIZEOF (str), #b, #str)

/* NOTE that r_assert_log* uses the RLogKeepLast framework which could affect performance */
#define r_assert_logs_cat(expr, cat)            _R_ASSERT_LOG (expr,  cat, 0, NULL)
#define r_assert_logs_level(expr, l)            _R_ASSERT_LOG (expr, NULL, l, NULL)
#define r_assert_logs_msg(expr, msg)            _R_ASSERT_LOG (expr, NULL, 0,  msg)
#define r_assert_logs_full(expr, cat, l, msg)   _R_ASSERT_LOG (expr,  cat, l,  msg)


R_API R_ATTR_NORETURN void r_test_assertion (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, ...) R_ATTR_PRINTF (5, 6);
R_API R_ATTR_NORETURN void r_test_assertionv (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, va_list args) R_ATTR_PRINTF (5, 0);
R_API R_ATTR_NORETURN void r_test_assertion_msg (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg);

R_END_DECLS

#endif /* __R_ASSERT_H__ */

