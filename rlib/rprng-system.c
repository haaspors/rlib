/* RLIB - Convenience library for useful things
 * Copyright (C) 2026  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include "config.h"
#include "rprng-private.h"

#include <stdlib.h>

/* A PRNG that draws every output directly from the OS entropy source.
 * There is deliberately no fallback: if the OS cannot deliver entropy
 * we abort rather than hand back a predictable value, since the whole
 * point of this PRNG is that its output is unguessable. */
static ruint64
r_prng_system_get (RPrng * prng)
{
  ruint64 ret;

  (void) prng;

  if (R_UNLIKELY (!r_rand_entropy_fill ((ruint8 *)&ret, sizeof (ret))))
    abort ();

  return ret;
}

RPrng *
r_prng_new_system (void)
{
  return r_prng_new (r_prng_system_get, 0);
}
