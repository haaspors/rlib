/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rcrypto-private.h"

void
r_crypto_cert_destroy (RCryptoCert * cert)
{
  if (cert->pk != NULL)
    r_crypto_key_unref (cert->pk);
  if (cert->certdata != NULL)
    r_buffer_unref (cert->certdata);
  r_free (cert->sign);
}

void
r_crypto_cert_clear_data (RCryptoCert * cert)
{
  r_buffer_unref (cert->certdata);
  cert->certdata = NULL;
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
    RMsgDigestType * signalgo, rsize * signbits)
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

RCryptoResult
r_crypto_cert_export (const RCryptoCert * cert, RAsn1BinEncoder * enc)
{
  return cert->export (cert, enc);
}

RBuffer *
r_crypto_cert_get_data_buffer (const RCryptoCert * cert)
{
  RAsn1BinEncoder * enc;
  RBuffer * ret = NULL;

  if (R_UNLIKELY (cert == NULL)) return NULL;

  if (cert->certdata != NULL) {
    ret = r_buffer_ref (cert->certdata);
  } else if ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)) != NULL) {
    if (r_crypto_cert_export (cert, enc) == R_CRYPTO_OK)
      r_asn1_bin_encoder_get_buffer (enc, &ret);

    r_asn1_bin_encoder_unref (enc);
  }

  return ret;
}

ruint8 *
r_crypto_cert_dup_data (const RCryptoCert * cert, rsize * size)
{
  ruint8 * ret;
  RBuffer * buf;

  if (R_UNLIKELY (cert == NULL)) return NULL;

  if ((buf = r_crypto_cert_get_data_buffer (cert)) != NULL) {
    ret = r_buffer_extract_dup_all (buf, size);
    r_buffer_unref (buf);
  } else {
    ret = NULL;
  }

  return ret;
}

RCryptoResult
r_crypto_cert_fingerprint (const RCryptoCert * cert,
    ruint8 * buf, rsize size, RMsgDigestType type, rsize * out)
{
  RCryptoResult ret;
  RMsgDigest * md;

  if (R_UNLIKELY (cert == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_CRYPTO_INVAL;
  if (size < r_msg_digest_type_size (type)) return R_CRYPTO_BUFFER_TOO_SMALL;

  ret = R_CRYPTO_ERROR;
  if ((md = r_msg_digest_new (type)) != NULL) {
    RBuffer * b;
    if ((b = r_crypto_cert_get_data_buffer (cert)) != NULL) {
      RMemMapInfo info = R_MEM_MAP_INFO_INIT;
      if (r_buffer_map (b, &info, R_MEM_MAP_READ)) {
        if (r_msg_digest_update (md, info.data, info.size) &&
            r_msg_digest_get_data (md, buf, size, out))
          ret = R_CRYPTO_OK;
        r_buffer_unmap (b, &info);
      }
      r_buffer_unref (b);
    }
    r_msg_digest_free (md);
  }

  return ret;
}

rchar *
r_crypto_cert_fingerprint_str (const RCryptoCert * cert, RMsgDigestType type,
    const rchar * divider, rsize interval)
{
  rchar * ret;
  RMsgDigest * md;

  if (R_UNLIKELY (cert == NULL)) return NULL;

  ret = NULL;
  if ((md = r_msg_digest_new (type)) != NULL) {
    RBuffer * b;
    if ((b = r_crypto_cert_get_data_buffer (cert)) != NULL) {
      RMemMapInfo info = R_MEM_MAP_INFO_INIT;
      if (r_buffer_map (b, &info, R_MEM_MAP_READ)) {
        if (r_msg_digest_update (md, info.data, info.size))
          ret = r_msg_digest_get_hex_full (md, divider, interval);
        r_buffer_unmap (b, &info);
      }
      r_buffer_unref (b);
    }
    r_msg_digest_free (md);
  }

  return ret;
}
