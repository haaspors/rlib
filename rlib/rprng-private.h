/* RLIB - Convenience library for useful things
 * Copyright (C) 2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_PRNG_PRIV_H__
#define __R_PRNG_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rprng-private.h should only be used internally in rlib!"
#endif

#include <rlib/rrand.h>

R_BEGIN_DECLS

typedef ruint64 (*RPrngGetFunc) (RPrng * prng);

struct _RPrng {
  RRef ref;
  RPrngGetFunc get;
  ruint64 data[0];
};

R_API_HIDDEN RPrng * r_prng_new (RPrngGetFunc get, rsize size);

R_END_DECLS

#endif /* __R_PRNG_PRIV_H__ */

