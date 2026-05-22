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

R_END_DECLS

#endif /* __R_CRYPTO_ECC_H__ */

