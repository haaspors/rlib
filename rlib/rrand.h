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
#ifndef __R_RAND_H__
#define __R_RAND_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>
#include <stdlib.h>

R_BEGIN_DECLS

R_API ruint64 r_rand_entropy_u64 (void);
R_API ruint32 r_rand_entropy_u32 (void);

#define r_rand_std_srand(seed)    srand (seed)
#define r_rand_std_rand()         rand ()

typedef struct _RPrng RPrng;

#define r_rand_prng_new           r_prng_new_kiss
#define r_rand_prng_ref           r_ref_ref
#define r_rand_prng_unref         r_ref_unref

R_API ruint64 r_rand_prng_get (RPrng * prng);


/* Spesific PRNG implementations */
R_API RPrng * r_prng_new_kiss (void) R_ATTR_MALLOC;
R_API RPrng * r_prng_new_kiss_with_seed (ruint64 x, ruint64 y, ruint64 z,
    ruint64 c) R_ATTR_MALLOC;
R_API RPrng * r_prng_new_mt (void) R_ATTR_MALLOC;
R_API RPrng * r_prng_new_mt_with_seed (ruint64 seed) R_ATTR_MALLOC;
R_API RPrng * r_prng_new_mt_with_seed_array (const ruint64 * array,
    rsize size) R_ATTR_MALLOC;

R_END_DECLS

#endif /* __R_RAND_H__ */

