/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_DH_H__
#define __R_CRYPTO_DH_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rkey.h>
#include <rlib/data/rmpint.h>
#include <rlib/rrand.h>

R_BEGIN_DECLS

#define R_DH_STR     "DH"

R_API RCryptoKey * r_dh_pub_key_new (const rmpint * p, const rmpint * g,
    const rmpint * y) R_ATTR_MALLOC;
R_API RCryptoKey * r_dh_pub_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize) R_ATTR_MALLOC;

R_API RCryptoKey * r_dh_priv_key_new (const rmpint * p, const rmpint * g,
    const rmpint * y, const rmpint * x) R_ATTR_MALLOC;
R_API RCryptoKey * r_dh_priv_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize,
    rconstpointer x, rsize xsize) R_ATTR_MALLOC;

/* Pick a random x in [2, p-2] and derive y = g^x mod p. Caller owns the
 * returned key. */
R_API RCryptoKey * r_dh_priv_key_new_gen (const rmpint * p, const rmpint * g,
    RPrng * prng) R_ATTR_MALLOC;

R_API rboolean r_dh_pub_key_get_p (const RCryptoKey * key, rmpint * p);
R_API rboolean r_dh_pub_key_get_g (const RCryptoKey * key, rmpint * g);
R_API rboolean r_dh_pub_key_get_y (const RCryptoKey * key, rmpint * y);
R_API rboolean r_dh_priv_key_get_x (const RCryptoKey * key, rmpint * x);

/* Compute the shared secret peer_pub.y ^ priv.x mod priv.p and write it
 * to out as a left-zero-padded big-endian byte string sized to match p.
 * The two keys must share the same (p, g) group; the peer's y is also
 * range-checked to be in (1, p-1). On entry *outsize is the capacity of
 * out; on success it is updated to the number of bytes written. */
R_API RCryptoResult r_dh_compute_shared (const RCryptoKey * priv,
    const RCryptoKey * peer_pub, ruint8 * out, rsize * outsize);

R_END_DECLS

#endif /* __R_CRYPTO_DH_H__ */
