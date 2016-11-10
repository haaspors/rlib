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
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rcrypto-private.h>

#include <rlib/crypto/rdsa.h>
#include <rlib/crypto/recc.h>
#include <rlib/crypto/rrsa.h>

#include <rlib/asn1/roid.h>
#include <rlib/rbase64.h>
#include <rlib/rmem.h>
#include <rlib/rmemfile.h>
#include <rlib/rstr.h>

#include <string.h>

void
r_crypto_key_destroy (RCryptoKey * key)
{
  (void) key;
}

RCryptoKeyType
r_crypto_key_get_type (const RCryptoKey * key)
{
  return key->type;
}

RCryptoAlgorithm
r_crypto_key_get_algo (const RCryptoKey * key)
{
  return key->algo->algo;
}

const rchar *
r_crypto_key_get_strtype (const RCryptoKey * key)
{
  return key->algo->strtype;
}

ruint
r_crypto_key_get_bitsize (const RCryptoKey * key)
{
  return key->bits;
}

RCryptoResult
r_crypto_key_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, rpointer out, rsize * outsize)
{
  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (out == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (prng == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->encrypt == NULL)) return R_CRYPTO_NOT_AVAILABLE;

  return key->algo->encrypt (key, prng, data, size, out, outsize);
}

RCryptoResult
r_crypto_key_decrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, rpointer out, rsize * outsize)
{
  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (out == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (prng == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->decrypt == NULL)) return R_CRYPTO_NOT_AVAILABLE;

  return key->algo->decrypt (key, prng, data, size, out, outsize);
}

RCryptoResult
r_crypto_key_sign (const RCryptoKey * key, RPrng * prng, RHashType hashtype,
    rconstpointer hash, rsize hashsize, rpointer sig, rsize * sigsize)
{
  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (hash == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (sig == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (prng == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->sign == NULL)) return R_CRYPTO_NOT_AVAILABLE;

  return key->algo->sign (key, prng, hashtype, hash, hashsize, sig, sigsize);
}

RCryptoResult
r_crypto_key_verify (const RCryptoKey * key, RHashType hashtype,
    rconstpointer hash, rsize hashsize, rconstpointer sig, rsize sigsize)
{
  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (hash == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (sig == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->verify == NULL)) return R_CRYPTO_NOT_AVAILABLE;

  return key->algo->verify (key, hashtype, hash, hashsize, sig, sigsize);
}

RCryptoResult
r_crypto_key_to_asn1 (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (enc == NULL)) return R_CRYPTO_INVAL;

  return key->algo->export (key, enc);
}

RCryptoKey *
r_crypto_key_import_ssh_public_key_file (const rchar * file)
{
  RMemFile * memfile;
  RCryptoKey * ret;

  if ((memfile = r_mem_file_new (file, R_MEM_PROT_READ, FALSE)) != NULL) {
    ret = r_crypto_key_import_ssh_public_key (r_mem_file_get_mem (memfile),
        r_mem_file_get_size (memfile));
    r_mem_file_unref (memfile);
  } else {
    ret = NULL;
  }

  return ret;
}

static rboolean
r_crypto_key_decode_bin_lv (const ruint8 ** v, rsize * l,
    const ruint8 ** data, rsize * size)
{
  if (*size <= sizeof (ruint32))
    return FALSE;

  *l = RUINT32_FROM_BE (*(ruint32 *)*data);
  if (*l + sizeof (ruint32) > *size)
    return FALSE;

  *v = *data + sizeof (ruint32);
  *data += *l + sizeof (ruint32);
  *size -= *l + sizeof (ruint32);
  return TRUE;
}

static RCryptoKey *
r_crypto_key_decode_bin_rsa_pub (const ruint8 * keydata, rsize size)
{
  const ruint8 * nptr, * eptr;
  rsize nsize, esize;
  RCryptoKey * ret = NULL;

  if (r_crypto_key_decode_bin_lv (&eptr, &esize, &keydata, &size) &&
      r_crypto_key_decode_bin_lv (&nptr, &nsize, &keydata, &size))
    ret = r_rsa_pub_key_new_binary (nptr, nsize, eptr, esize);

  return ret;
}

static RCryptoKey *
r_crypto_key_decode_bin_dsa_pub (const ruint8 * keydata, rsize size)
{
  const ruint8 * pptr, * qptr, * gptr, * yptr;
  rsize psize, qsize, gsize, ysize;
  RCryptoKey * ret = NULL;

  if (r_crypto_key_decode_bin_lv (&pptr, &psize, &keydata, &size) &&
      r_crypto_key_decode_bin_lv (&qptr, &qsize, &keydata, &size) &&
      r_crypto_key_decode_bin_lv (&gptr, &gsize, &keydata, &size) &&
      r_crypto_key_decode_bin_lv (&yptr, &ysize, &keydata, &size)) {
    ret = r_dsa_pub_key_new_binary (pptr, psize, qptr, qsize,
        gptr, gsize, yptr, ysize);
  }

  return ret;
}

RCryptoKey *
r_crypto_key_import_ssh_public_key (const rchar * data, rsize size)
{
  const rchar * next;
  RCryptoKey * ret = NULL;

  if (R_UNLIKELY (data == NULL))
    return NULL;

  if (size == 0)
    size = r_strlen (data);

  if ((next = memchr (data, ' ', size)) != NULL) {
    ruint8 * keydata;

    size -= (++next - data);
    if ((keydata = r_base64_decode (next, size, &size)) != NULL &&
        size > sizeof (ruint32)) {
      rsize algsize = RUINT32_FROM_BE (*(ruint32 *)keydata);
      ruint8 * algptr = keydata + sizeof (ruint32);

      if (algsize + sizeof (ruint32) < size) {
        ruint8 * bindata = algptr + algsize;
        rsize binsize = size - (algsize + sizeof (ruint32));
        if (algsize == 7 && r_memcmp (algptr, "ssh-rsa", 7) == 0) {
          ret = r_crypto_key_decode_bin_rsa_pub (bindata, binsize);
        } else if (algsize == 7 && r_memcmp (algptr, "ssh-dsa", 7) == 0) {
          ret = r_crypto_key_decode_bin_dsa_pub (bindata, binsize);
        }
      }

      r_free (keydata);
    }
  }

  return ret;
}

RCryptoKey *
r_crypto_key_from_asn1_public_key (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  RCryptoKey * ret = NULL;

  if (R_UNLIKELY (dec == NULL || tlv == NULL))
    return NULL;

  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return NULL;

  if (r_asn1_bin_decoder_into (dec, tlv) == R_ASN1_DECODER_OK) {
    if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER)) {

      if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_RSA_OID_RSA_ENCRYPTION)) {
        rmpint n, e;
        r_mpint_init (&n);
        r_mpint_init (&e);
        r_asn1_bin_decoder_out (dec, tlv);
        if (r_asn1_bin_decoder_into (dec, tlv) == R_ASN1_DECODER_OK) {
          if (r_asn1_bin_decoder_into (dec, tlv) == R_ASN1_DECODER_OK) {
            if (r_asn1_bin_tlv_parse_integer_mpint (tlv, &n) == R_ASN1_DECODER_OK &&
                r_asn1_bin_decoder_next (dec, tlv) == R_ASN1_DECODER_OK &&
                r_asn1_bin_tlv_parse_integer_mpint (tlv, &e) == R_ASN1_DECODER_OK) {
              ret = r_rsa_pub_key_new (&n, &e);
            }
            r_asn1_bin_decoder_out (dec, tlv);
          }
          r_asn1_bin_decoder_out (dec, tlv);
        }
        r_mpint_clear (&e);
        r_mpint_clear (&n);
      } else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_X9CM_OID_DSA)) {
        rmpint p, q, g, y;
        r_mpint_init (&p);
        r_mpint_init (&q);
        r_mpint_init (&g);
        r_mpint_init (&y);

        r_asn1_bin_decoder_next (dec, tlv);
        if (R_ASN1_BIN_TLV_ID_PC (tlv) == R_ASN1_ID_CONSTRUCTED &&
            r_asn1_bin_decoder_into (dec, tlv) == R_ASN1_DECODER_OK) {
          if (R_ASN1_BIN_TLV_ID_TAG (tlv) == R_ASN1_ID_INTEGER) {
            r_asn1_bin_tlv_parse_integer_mpint (tlv, &p);
            r_asn1_bin_decoder_next (dec, tlv);
          }
          if (R_ASN1_BIN_TLV_ID_TAG (tlv) == R_ASN1_ID_INTEGER) {
            r_asn1_bin_tlv_parse_integer_mpint (tlv, &q);
            r_asn1_bin_decoder_next (dec, tlv);
          }
          if (R_ASN1_BIN_TLV_ID_TAG (tlv) == R_ASN1_ID_INTEGER) {
            r_asn1_bin_tlv_parse_integer_mpint (tlv, &g);
            r_asn1_bin_decoder_next (dec, tlv);
          }
          r_asn1_bin_decoder_out (dec, tlv);
        }
        r_asn1_bin_decoder_out (dec, tlv);
        if (r_asn1_bin_decoder_into (dec, tlv) == R_ASN1_DECODER_OK) {
          if (r_asn1_bin_tlv_parse_integer_mpint (tlv, &y) == R_ASN1_DECODER_OK)
            ret = r_dsa_pub_key_new_full (&p, &q, &g, &y);
          r_asn1_bin_decoder_out (dec, tlv);
        }
        r_mpint_clear (&p);
        r_mpint_clear (&q);
        r_mpint_clear (&g);
        r_mpint_clear (&y);
      } else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_X9_62_OID_EC_PUB_KEY)) {
        REcNamedCurve curve;

        r_asn1_bin_decoder_next (dec, tlv);

        if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER) &&
            r_ecc_parse_named_curve (&curve, tlv->value, tlv->len)) {
          r_asn1_bin_decoder_out (dec, tlv);
          if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BIT_STRING))
            ret = r_ecdsa_pub_key_new (curve, tlv->value + 1, tlv->len - 1);
        } else {
          r_asn1_bin_decoder_out (dec, tlv);
        }
      } else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_CERTICOM_OID_ECDH_PUB_KEY)) {
        REcNamedCurve curve;

        r_asn1_bin_decoder_next (dec, tlv);

        if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER) &&
            r_ecc_parse_named_curve (&curve, tlv->value, tlv->len)) {
          r_asn1_bin_decoder_out (dec, tlv);
          if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BIT_STRING))
            ret = r_ecdh_pub_key_new (curve, tlv->value + 1, tlv->len - 1);
        } else {
          r_asn1_bin_decoder_out (dec, tlv);
        }
      } else {
        r_asn1_bin_decoder_out (dec, tlv);
      }
    } else {
      r_asn1_bin_decoder_out (dec, tlv);
    }
  }

  r_asn1_bin_decoder_out (dec, tlv);
  return ret;
}

