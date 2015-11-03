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
#ifndef __R_ASSERT_H__
#define __R_ASSERT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rassert-internal.h>
#include <rlib/rstr.h>
#include <stdarg.h>

R_BEGIN_DECLS

#define r_assert(expr)                  R_ASSERT_STMT (expr, "%s", "%u", #expr, (rboolean)(expr))
#define r_assert_not_reached()          R_ASSERT_VA ("<-- should not be reached")
#define r_assert_cmpint(n1, cmp, n2)    R_ASSERT_CMP (n1,cmp,n2,rintmax,"%"RINTMAX_FMT,#n1,#n2)
#define r_assert_cmpuint(n1, cmp, n2)   R_ASSERT_CMP (n1,cmp,n2,ruintmax,"%"RUINTMAX_FMT,#n1,#n2)
#define r_assert_cmphex(n1, cmp, n2)    R_ASSERT_CMP (n1,cmp,n2,ruintmax,"%"RINTMAX_MODIFIER"x",#n1,#n2)
#define r_assert_cmpptr(n1, cmp, n2)    R_ASSERT_CMP (n1,cmp,n2,rpointer,"%p",#n1,#n2)
#define r_assert_cmpfloat(n1, cmp, n2)  R_ASSERT_CMP (n1,cmp,n2,rfloat,"%.9f",#n1,#n2)
#define r_assert_cmpdouble(n1, cmp, n2) R_ASSERT_CMP (n1,cmp,n2,rdouble,"%.9f",#n1,#n2)
#define r_assert_cmpstr(s1, cmp, s2)    R_ASSERT_CMPSTR (s1, cmp, s2, #s1, #s2)
#define r_assert_cmpmem(m1, cmp, m2, s) R_ASSERT_CMPMEM (m1, cmp, m2, s, #m1, #m2)


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
