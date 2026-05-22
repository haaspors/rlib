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
#ifndef __R_CRYPTO_ECC_H__
#define __R_CRYPTO_ECC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/rkey.h>
#include <rlib/rrand.h>

R_BEGIN_DECLS

#define R_ECDSA_STR     "ECDSA"
#define R_ECDH_STR      "ECDH"

R_API RCryptoKey * r_ecdsa_pub_key_new (REcurveID curve,
    rconstpointer ecp, rsize ecpsize) R_ATTR_MALLOC;
R_API RCryptoKey * r_ecdh_pub_key_new (REcurveID curve,
    rconstpointer ecp, rsize ecpsize) R_ATTR_MALLOC;
R_API RCryptoKey * r_ecdsa_priv_key_new (REcurveID curve,
    rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize) R_ATTR_MALLOC;
R_API RCryptoKey * r_ecdh_priv_key_new (REcurveID curve,
    rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize) R_ATTR_MALLOC;
R_API REcurveID r_ecc_key_get_curve (const RCryptoKey * key);
R_API rboolean r_ecc_priv_key_get_scalar (const RCryptoKey * key,
    const ruint8 ** scalar, rsize * scalarsize);

/* Pick a random d in [1, n-1] for `curve` and produce a private ECDH
 * key whose public point is Q = d * G. Caller owns the returned key.
 * If `prng` is NULL a fresh system PRNG is used. */
R_API RCryptoKey * r_ecdh_priv_key_new_gen (REcurveID curve,
    RPrng * prng) R_ATTR_MALLOC;

/* Retrieve the affine public point Q for an ECDSA or ECDH key. Returns
 * FALSE if `key` doesn't carry a parsed point (e.g. an ECDSA key built
 * from an encoding the math layer can't yet decode). */
R_API rboolean r_ecc_key_get_q (const RCryptoKey * key, REcurveAffinePoint * q);

/* Compute the ECDH shared secret X-coordinate (peer_pub.Q * priv.d).x
 * and write it as a left-zero-padded big-endian byte string sized to
 * the curve's coord_bytes. The two keys must use the same named curve;
 * the peer's point is on-curve checked (it was validated at key
 * construction, but private-key paths that derived Q internally also
 * need to refuse the identity). On entry *outsize is the capacity of
 * out; on success it is updated to the number of bytes written. */
R_API RCryptoResult r_ecdh_compute_shared (const RCryptoKey * priv,
    const RCryptoKey * peer_pub, ruint8 * out, rsize * outsize);

R_END_DECLS

#endif /* __R_CRYPTO_ECC_H__ */

