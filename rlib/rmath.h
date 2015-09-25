/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */

#ifndef __R_MATH_H__
#define __R_MATH_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_API int     r_int_gcd    (int a,      int b);
R_API ruint   r_uint_gcd   (ruint a,    ruint b);
R_API rint64  r_int64_gcd  (rint64 a,   rint64 b);
R_API ruint64 r_uint64_gcd (ruint64 a,  ruint64 b);

#endif /* __R_MATH_H__ */
