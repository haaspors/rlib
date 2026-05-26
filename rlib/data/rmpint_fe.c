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

/* Fixed-width Montgomery field-element arithmetic. The function
 * bodies live in rmpint_fe_template.h and are instantiated once per
 * (type, ctx, max-digits) tuple by the blocks below. RMpintFE is the
 * ECC width used by recurve.c / rdsa.c; the template is structured so
 * additional widths (e.g. RSA-sized) can be added by repeating the
 * #define / #include / #undef block.
 *
 * Why a template: RMpintFE is stored inline in the struct, so a single
 * MAX_DIGITS large enough for RSA-8192 would inflate every ECC FE to
 * ~1 KB and stretch every tail-clear loop in the ECC ladder. Keeping
 * the ECC width tight while still sharing one audited implementation
 * needs either two parallel .c files (drift risk) or a templated
 * header (this approach).
 *
 * Originally factored out of rlib/crypto/recurve.c (item 4 of #100) so
 * DSA signing and RSA private-key operations can share the same
 * audited constant-time implementation. */

#include "config.h"
#include "rmpint-private.h"

#include <rlib/rmem.h>

/* Instantiation #1: ECC / DSA width. R_MPINT_FE_MAX_DIGITS covers
 * secp521r1 (17 32-bit digits) with one carry slot. */
#define FE_TYPE   RMpintFE
#define FE_CTX    RMpintFEMontCtx
#define FE_FN(n)  r_mpint_fe_ ## n
#define FE_MAX    R_MPINT_FE_MAX_DIGITS
#include "rmpint_fe_template.h"
#undef FE_TYPE
#undef FE_CTX
#undef FE_FN
#undef FE_MAX
