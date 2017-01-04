/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_HASH_PRIV_H__
#define __R_HASH_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rhash-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>

#define R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE(idx)     ((rsize)1 << (idx + 3))

R_BEGIN_DECLS

R_API_HIDDEN extern const rsize r_hash_size_primes[RLIB_SIZEOF_SIZE_T * 8 - 2];

R_END_DECLS

#endif /* __R_HASH_PRIV_H__ */

