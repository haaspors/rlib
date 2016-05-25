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
#include <rlib/crypto/rrsa.h>
#include <rlib/crypto/rdsa.h>
#include <rlib/asn1/roid.h>
#include <rlib/rbase64.h>
#include <rlib/rmem.h>
#include <rlib/rmemfile.h>
#include <rlib/rstr.h>

#include <string.h>

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
r_crypto_key_import_asn1_public_key (RAsn1DerDecoder * dec)
{
  RCryptoKey * ret;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  rchar * oid = NULL;

  if (R_UNLIKELY (dec == NULL))
    return NULL;

  if (r_asn1_der_decoder_next (dec, &tlv) == R_ASN1_DECODER_OK &&
      r_asn1_der_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK &&
      r_asn1_der_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK &&
      r_asn1_der_tlv_parse_oid_to_dot (&tlv, &oid) == R_ASN1_DECODER_OK &&
      r_asn1_der_decoder_out (dec, &tlv) == R_ASN1_DECODER_OK &&
      r_asn1_der_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) {

    if (r_str_equals (oid, R_RSA_OID_RSA_ENCRYPTION)) {
      rmpint n, e;
      r_mpint_init (&n);
      r_mpint_init (&e);
      if (r_asn1_der_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK &&
          r_asn1_der_tlv_parse_mpint (&tlv, &n) == R_ASN1_DECODER_OK &&
          r_asn1_der_decoder_next (dec, &tlv) == R_ASN1_DECODER_OK &&
          r_asn1_der_tlv_parse_mpint (&tlv, &e) == R_ASN1_DECODER_OK) {
        ret = r_rsa_pub_key_new (&n, &e);
      } else {
        ret = NULL;
      }
      r_mpint_clear (&e);
      r_mpint_clear (&n);
    } else {
      ret = NULL;
    }
  } else {
    ret = NULL;
  }

  r_free (oid);
  return ret;
}

