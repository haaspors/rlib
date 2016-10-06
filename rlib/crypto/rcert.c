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

#include "config.h"
#include <rlib/crypto/rcert.h>

#include <rlib/crypto/rcrypto-private.h>

void
r_crypto_cert_destroy (RCryptoCert * cert)
{
  if (cert->pk != NULL)
    r_crypto_key_unref (cert->pk);
}

RCryptoCertType
r_crypto_cert_get_type (const RCryptoCert * cert)
{
  return cert->type;
}

const rchar *
r_crypto_cert_get_strtype (const RCryptoCert * cert)
{
  return cert->strtype;
}

const ruint8 *
r_crypto_cert_get_signature (const RCryptoCert * cert,
    RCryptoSignAlgo * signalgo, rsize * signbits)
{
  if (signbits != NULL)
    *signbits = cert->signbits;
  if (signalgo != NULL)
    *signalgo = cert->signalgo;

  return cert->sign;
}

ruint64
r_crypto_cert_get_valid_from (const RCryptoCert * cert)
{
  return cert->valid_from;
}

ruint64
r_crypto_cert_get_valid_to (const RCryptoCert * cert)
{
  return cert->valid_to;
}

RCryptoKey *
r_crypto_cert_get_public_key (const RCryptoCert * cert)
{
  if (cert != NULL && cert->pk != NULL)
    return r_crypto_key_ref (cert->pk);
  return NULL;
}
