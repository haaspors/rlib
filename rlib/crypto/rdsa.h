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
#ifndef __R_CRYPTO_DSA_H__
#define __R_CRYPTO_DSA_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rkey.h>
#include <rlib/rmpint.h>

R_BEGIN_DECLS

#define R_DSA_STR     "DSA"

R_API RCryptoKey * r_dsa_pub_key_new (const rmpint * p, const rmpint * q,
    const rmpint * g, const rmpint * y);
R_API RCryptoKey * r_dsa_pub_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer q, rsize qsize, rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize);

R_END_DECLS

#endif /* __R_CRYPTO_DSA_H__ */




