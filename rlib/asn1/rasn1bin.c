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
#include <rlib/asn1/rasn1-private.h>
#include <rlib/asn1/roid.h>

#include <rlib/rstr.h>
#include <rlib/rstring.h>
#include <rlib/rtime.h>

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_boolean (const RAsn1BinTLV * tlv, rboolean * value)
{
  if (R_UNLIKELY (tlv == NULL || value == NULL))
    return R_ASN1_DECODER_INVALID_ARG;

  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BOOLEAN)) {
    if (tlv->len == 1) {
      *value = *tlv->value != 0;
      return R_ASN1_DECODER_OK;
    } else {
      return R_ASN1_DECODER_OVERFLOW;
    }
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_integer_bits (const RAsn1BinTLV * tlv,
    ruint * bits, rboolean * unsign)
{
  if (R_UNLIKELY (tlv == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_UNLIKELY (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_INTEGER)))
    return R_ASN1_DECODER_WRONG_TYPE;

  if (unsign != NULL)
    *unsign = (tlv->value[0] & 0x80) == 0;

  if (bits != NULL) {
    *bits = tlv->len * 8;
    if (tlv->value[0] == 0)
      *bits -= 8;
  }

  return R_ASN1_DECODER_OK;
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_integer_i32 (const RAsn1BinTLV * tlv, rint32 * value)
{
  if (R_UNLIKELY (tlv == NULL || value == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_INTEGER) ||
      R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_ENUMERATED)) {
    ruint32 u = 0;
    const ruint8 * ptr = tlv->value;
    const ruint8 * end = tlv->value + tlv->len;
    ruint bits = tlv->len * 8;
    if (tlv->value[0] == 0) {
      bits -= 8;
      ptr++;
    }

    if (R_UNLIKELY (bits > sizeof (u) * 8))
      return R_ASN1_DECODER_OVERFLOW;
    if (bits == sizeof (u) * 8 && *ptr & 0x80)
      return R_ASN1_DECODER_OVERFLOW;

    if ((tlv->value[0] & 0x80) == 0) {
      while (ptr < end)
        u = (u << 8) | *ptr++;
      *value = u;
    } else {
      while (ptr < end)
        u = (u << 8) | (*ptr++ ^ 0xFF);
      *value = -(rint32)++u;
    }
    return R_ASN1_DECODER_OK;
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_integer_u32 (const RAsn1BinTLV * tlv, ruint32 * value)
{
  if (R_UNLIKELY (tlv == NULL || value == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_INTEGER) ||
      R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_ENUMERATED)) {
    ruint32 u = 0;
    const ruint8 * ptr = tlv->value;
    const ruint8 * end = tlv->value + tlv->len;
    ruint bits = tlv->len * 8;
    if (tlv->value[0] == 0) {
      bits -= 8;
      ptr++;
    } else if (tlv->value[0] & 0x80) {
      return R_ASN1_DECODER_OVERFLOW;
    }

    if (R_UNLIKELY (bits > sizeof (u) * 8))
      return R_ASN1_DECODER_OVERFLOW;

    while (ptr < end)
      u = (u << 8) | *ptr++;
    *value = u;
    return R_ASN1_DECODER_OK;
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_integer_i64 (const RAsn1BinTLV * tlv, rint64 * value)
{
  if (R_UNLIKELY (tlv == NULL || value == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_INTEGER)) {
    ruint64 u = 0;
    const ruint8 * ptr = tlv->value;
    const ruint8 * end = tlv->value + tlv->len;
    ruint bits = tlv->len * 8;
    if (tlv->value[0] == 0) {
      bits -= 8;
      ptr++;
    }

    if (R_UNLIKELY (bits > sizeof (u) * 8))
      return R_ASN1_DECODER_OVERFLOW;
    if (bits == sizeof (u) * 8 && *ptr & 0x80)
      return R_ASN1_DECODER_OVERFLOW;

    if ((tlv->value[0] & 0x80) == 0) {
      while (ptr < end)
        u = (u << 8) | *ptr++;
      *value = u;
    } else {
      while (ptr < end)
        u = (u << 8) | (*ptr++ ^ 0xFF);
      *value = -(rint32)++u;
    }
    return R_ASN1_DECODER_OK;
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_integer_u64 (const RAsn1BinTLV * tlv, ruint64 * value)
{
  if (R_UNLIKELY (tlv == NULL || value == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_INTEGER)) {
    ruint64 u = 0;
    const ruint8 * ptr = tlv->value;
    const ruint8 * end = tlv->value + tlv->len;
    ruint bits = tlv->len * 8;
    if (tlv->value[0] == 0) {
      bits -= 8;
      ptr++;
    } else if (tlv->value[0] & 0x80) {
      return R_ASN1_DECODER_OVERFLOW;
    }

    if (R_UNLIKELY (bits > sizeof (u) * 8))
      return R_ASN1_DECODER_OVERFLOW;

    while (ptr < end)
      u = (u << 8) | *ptr++;
    *value = u;
    return R_ASN1_DECODER_OK;
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_integer_mpint (const RAsn1BinTLV * tlv, rmpint * value)
{
  if (R_UNLIKELY (tlv == NULL || value == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_INTEGER)) {
    r_mpint_clear (value);
    r_mpint_init_binary (value, tlv->value, tlv->len);
    if (*tlv->value & 0x80) {
      /* TODO: if negative?? */
      return R_ASN1_DECODER_OVERFLOW;
    }
    return R_ASN1_DECODER_OK;
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_oid (const RAsn1BinTLV * tlv, ruint32 * varray, rsize * len)
{
  if (R_UNLIKELY (tlv == NULL || varray == NULL || len == NULL || *len < 2))
    return R_ASN1_DECODER_INVALID_ARG;

  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER)) {
    rsize idx = 0;
    ruint64 cur;
    const ruint8 * ptr, * end = tlv->value + tlv->len;

    for (ptr = tlv->value, cur = 0, idx = 0; ptr < end; ptr++) {
      cur = (cur << 7) | (*ptr & 0x7F);

      if (cur > RUINT32_MAX)
        return R_ASN1_DECODER_OVERFLOW;

      if (!(*ptr & 0x80)) {
        if (idx == 0) {
          ruint32 v;
          varray[idx++] = v = MIN (cur / 40, 2);
          varray[idx++] = cur - (v * 40);
        } else {
          if (idx >= *len)
            return R_ASN1_DECODER_OVERFLOW;
          varray[idx++] = (ruint32)cur;
        }
        cur = 0;
      }
    }

    /* last octet should not have 0x80bit/msb set! */
    if (cur > 0)
      return R_ASN1_DECODER_EOS;

    *len = idx;
    return R_ASN1_DECODER_OK;
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_oid_to_dot (const RAsn1BinTLV * tlv, rchar ** dot)
{
  RAsn1DecoderStatus ret;
  ruint32 v[16];
  rsize len = R_N_ELEMENTS (v);

  if (R_UNLIKELY (tlv == NULL || dot == NULL))
    return R_ASN1_DECODER_INVALID_ARG;

  if ((ret = r_asn1_bin_tlv_parse_oid (tlv, v, &len)) == R_ASN1_DECODER_OK) {
    *dot = r_asn1_oid_to_dot (v, len);
  }

  return ret;
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_oid_to_hash_type (const RAsn1BinTLV * tlv, RHashType * ht)
{
  if (R_UNLIKELY (ht == NULL)) return R_ASN1_DECODER_INVALID_ARG;
  if (R_UNLIKELY (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER)))
    return R_ASN1_DECODER_WRONG_TYPE;

  if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_RSA_OID_MD5_WITH_RSA))
    *ht = R_HASH_TYPE_MD5;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_RSA_OID_SHA1_WITH_RSA))
    *ht = R_HASH_TYPE_SHA1;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OID_DIGEST_ALG_SHA256))
    *ht = R_HASH_TYPE_SHA256;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OID_DIGEST_ALG_SHA384))
    *ht = R_HASH_TYPE_SHA384;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OID_DIGEST_ALG_SHA512))
    *ht = R_HASH_TYPE_SHA512;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OID_DIGEST_ALG_SHA224))
    *ht = R_HASH_TYPE_SHA224;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_RSA_OID_SHA256_WITH_RSA))
    *ht = R_HASH_TYPE_SHA256;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_RSA_OID_SHA384_WITH_RSA))
    *ht = R_HASH_TYPE_SHA384;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_RSA_OID_SHA512_WITH_RSA))
    *ht = R_HASH_TYPE_SHA512;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_RSA_OID_SHA224_WITH_RSA))
    *ht = R_HASH_TYPE_SHA224;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_X9CM_OID_DSA_WITH_SHA1))
    *ht = R_HASH_TYPE_SHA1;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OIW_SECSIG_OID_SHA1_FIPS))
    *ht = R_HASH_TYPE_SHA1;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OIW_SECSIG_OID_SHA1_RSA))
    *ht = R_HASH_TYPE_SHA1;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OIW_SECSIG_OID_SHA1_DSA))
    *ht = R_HASH_TYPE_SHA1;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OIW_SECSIG_OID_MD5_RSA))
    *ht = R_HASH_TYPE_MD5;
  else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_OIW_SECSIG_OID_MD5_RSA_SIG))
    *ht = R_HASH_TYPE_MD5;
  else
    *ht = R_HASH_TYPE_NONE;

  return R_ASN1_DECODER_OK;;
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_time (const RAsn1BinTLV * tlv, ruint64 * time)
{
  ruint16 y;
  ruint8 m, d, hh, mm, ss;
  const rchar * ptr, * end;

  if (R_UNLIKELY (tlv == NULL || time == NULL))
    return R_ASN1_DECODER_INVALID_ARG;

  ptr = (const rchar *)tlv->value;
  end = (const rchar *)&tlv->value[tlv->len];
  if (R_ASN1_BIN_TLV_ID_TAG (tlv) == R_ASN1_ID_UTC_TIME) {
    ruint8 yy;
    int res;

    if (tlv->len < 10)
      return R_ASN1_DECODER_OVERFLOW;

    // YYMMDDhhmm[ss]
    if (tlv->len >= 12) {
      res = r_strscanf (ptr, "%2hhu%2hhu%2hhu%2hhu%2hhu%2hhu",
          &yy, &m, &d, &hh, &mm, &ss);
    } else {
      res = r_strscanf (ptr, "%2hhu%2hhu%2hhu%2hhu%2hhu",
          &yy, &m, &d, &hh, &mm);
    }
    switch (res) {
      case 5:
        ss = 0;
      case 6:
        y = (ruint16)yy + ((yy < 70) ? 2000 : 1900);
        break;
      default:
        return R_ASN1_DECODER_OVERFLOW;
    }

    ptr += res * 2;
    if (ptr == end - 1 && *ptr == 'Z')
      ptr++;
  } else if (R_ASN1_BIN_TLV_ID_TAG (tlv) == R_ASN1_ID_GENERALIZED_TIME) {
    ruint16 fff;

    if (tlv->len < 10)
      return R_ASN1_DECODER_OVERFLOW;

    // YYYYMMDDhh[mm[ss[.fff]]]
    if (r_strscanf (ptr, "%4hu%2hhu%2hhu%2hhu", &y, &m, &d, &hh) != 4)
      return R_ASN1_DECODER_OVERFLOW;
    ptr += 4 + 2 + 2 + 2;
    mm = ss = 0;
    if (end - ptr > 2) {
      if (*ptr == '-' || *ptr == '+') {
        goto done;
      } else if (r_strscanf (ptr, "%2hhu", &mm) == 1) {
        ptr += 2;
        if (end - ptr > 2) {
          if (*ptr == '-' || *ptr == '+') {
            goto done;
          } else if (r_strscanf (ptr, "%2hhu", &ss) == 1) {
            ptr += 2;
            if (end - ptr > 3 && *ptr == '.' && r_strscanf (ptr, ".%3hu", &fff) == 1)
              ptr += 4;
          }
        }
      }
    }

    if (end - ptr == 1 && *ptr == 'Z') {
      ptr++;
    } else if (ptr == end) {
      /* TODO: Adjust for Local time */
    }
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }

done:
  *time = r_time_create_unix_time (y, m, d, hh, mm, ss);

  if (ptr == end - 5) {
    ruint8 hd, md;
    if (r_strscanf (&ptr[1], "%2hhu%2hhu", &hd, &md) != 2)
      return R_ASN1_DECODER_OVERFLOW;

    if (*ptr == '+')
      *time -= hd * 3600 + md * 60;
    else if (*ptr == '-')
      *time += hd * 3600 + md * 60;
    else
      return R_ASN1_DECODER_WRONG_TYPE;
  } else if (ptr != end) {
    return R_ASN1_DECODER_OVERFLOW;
  }

  return R_ASN1_DECODER_OK;
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_bit_string (const RAsn1BinTLV * tlv, RBitset ** bitset)
{
  if (R_UNLIKELY (tlv == NULL || bitset == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_UNLIKELY (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BIT_STRING)))
    return R_ASN1_DECODER_WRONG_TYPE;
  if (R_UNLIKELY (tlv->len < 2))
    return R_ASN1_DECODER_OVERFLOW;

  if ((*bitset = r_bitset_new_from_binary (&tlv->value[1], tlv->len - sizeof (ruint8))) == NULL)
    return R_ASN1_DECODER_OOM;

  r_bitset_shr (*bitset, tlv->value[0]);
  (*bitset)->bsize -= tlv->value[0];

  return R_ASN1_DECODER_OK;
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_bit_string_bits (const RAsn1BinTLV * tlv, rsize * bits)
{
  if (R_UNLIKELY (tlv == NULL || bits == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_UNLIKELY (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BIT_STRING)))
    return R_ASN1_DECODER_WRONG_TYPE;

  *bits = (tlv->len - sizeof (ruint8)) * 8 - tlv->value[0];
  return R_ASN1_DECODER_OK;
}

static const rchar *
r_asn1_bin_tlv_parse_x500_name (const RAsn1BinTLV * tlv)
{
  const struct x500attrtype {
    const rchar * name;
    const rchar * oid;
    rsize oidsize;
  } x500_attr_table[] = {
    { "CN",     R_ASN1_OID_ARGS (R_ID_AT_OID_COMMON_NAME) },
    { "SN",     R_ASN1_OID_ARGS (R_ID_AT_OID_SURNAME) },
    { "C",      R_ASN1_OID_ARGS (R_ID_AT_OID_CUNTRY_NAME) },
    { "L",      R_ASN1_OID_ARGS (R_ID_AT_OID_LOCALITY_NAME) },
    { "ST",     R_ASN1_OID_ARGS (R_ID_AT_OID_STATE_OR_PROVINCE_NAME) },
    { "STREET", R_ASN1_OID_ARGS (R_ID_AT_OID_STREET_ADDRESS) },
    { "O",      R_ASN1_OID_ARGS (R_ID_AT_OID_ORGANIZATION_NAME) },
    { "OU",     R_ASN1_OID_ARGS (R_ID_AT_OID_ORGANIZATIONAL_UNIT_NAME) },
    { "UID",    R_ASN1_OID_ARGS (R_PSS_OID_USER_ID) },
    { "DC",     R_ASN1_OID_ARGS (R_PSS_OID_DOMAIN_COMPONENT) },
  };

  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER)) {
    rsize i;
    for (i = 0; i < R_N_ELEMENTS (x500_attr_table); i++) {
      if (r_asn1_oid_bin_equals_full (tlv->value, tlv->len,
            x500_attr_table[i].oid, x500_attr_table[i].oidsize)) {
        return x500_attr_table[i].name;
      }
    }
  }

  return NULL;
}

static RAsn1DecoderStatus
r_asn1_bin_tlv_parse_attribute_type_and_value (RAsn1BinDecoder * dec,
    RAsn1BinTLV * tlv, RString * strbld)
{
  RAsn1DecoderStatus ret;
  const rchar * t, * v;
  rsize vlen;

  /* AttributeType */
  if ((t = r_asn1_bin_tlv_parse_x500_name (tlv)) == NULL)
    return R_ASN1_DECODER_WRONG_TYPE;

  /* AttributeValue */
  if ((ret = r_asn1_bin_decoder_next (dec, tlv)) != R_ASN1_DECODER_OK)
    return ret;
  switch (R_ASN1_BIN_TLV_ID_TAG (tlv)) {
    case R_ASN1_ID_PRINTABLE_STRING:
    case R_ASN1_ID_VISIBLE_STRING:
    case R_ASN1_ID_IA5_STRING:
      v = (const rchar *)tlv->value;
      vlen = tlv->len;
      break;
    default:
      return R_ASN1_DECODER_WRONG_TYPE;
  }

  if (r_string_length (strbld) > 0)
    r_string_prepend_printf (strbld, "%s=%.*s,", t, (int)vlen, v);
  else
    r_string_prepend_printf (strbld, "%s=%.*s", t, (int)vlen, v);

  return R_ASN1_DECODER_OK;
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_distinguished_name (RAsn1BinDecoder * dec,
    RAsn1BinTLV * tlv, rchar ** name)
{
  RAsn1DecoderStatus ret;

  if ((ret = r_asn1_bin_decoder_into (dec, tlv)) == R_ASN1_DECODER_OK) {
    RString * strbld = r_string_new_sized (256);

    while (ret == R_ASN1_DECODER_OK &&
        R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SET) &&
        r_asn1_bin_decoder_into (dec, tlv) == R_ASN1_DECODER_OK) {

      /* AttributeTypeAndValue */
      if (r_asn1_bin_decoder_into (dec, tlv) == R_ASN1_DECODER_OK) {
        ret = r_asn1_bin_tlv_parse_attribute_type_and_value (dec, tlv, strbld);
        r_asn1_bin_decoder_out (dec, tlv);
        if (ret != R_ASN1_DECODER_OK) {
          r_asn1_bin_decoder_out (dec, tlv);
          break;
        }
      }

      ret = r_asn1_bin_decoder_out (dec, tlv);
    }

    if (R_ASN1_DECODER_STATUS_SUCCESS (ret)) {
      ret = r_asn1_bin_decoder_out (dec, tlv);
      *name = r_string_free_keep (strbld);
    } else {
      r_string_free (strbld);
      *name = NULL;
    }
  }

  return ret;
}

static void
r_asn1_bin_decoder_free (RAsn1BinDecoder * dec)
{
  r_slist_destroy_full (dec->stack, r_free);
  r_free (dec->free);
  if (dec->file != NULL)
    r_mem_file_unref (dec->file);
  r_free (dec);
}

RAsn1BinDecoder *
r_asn1_bin_decoder_new (RAsn1EncodingRules enc, const ruint8 * data, rsize size)
{
  RAsn1BinDecoder * ret;

  if (data != NULL && size > 0 && enc < R_ASN1_ENCODING_RULES_COUNT) {
    if ((ret = r_mem_new (RAsn1BinDecoder)) != NULL) {
      r_ref_init (ret, r_asn1_bin_decoder_free);
      ret->file = NULL;
      ret->free = NULL;
      ret->data = data;
      ret->size = size;
      ret->stack = NULL;

      switch (enc) {
        case R_ASN1_BER:
          ret->next = r_asn1_ber_decoder_next;
          ret->into = r_asn1_ber_decoder_into;
          ret->out = r_asn1_ber_decoder_out;
          break;
        case R_ASN1_DER:
          ret->next = r_asn1_der_decoder_next;
          ret->into = r_asn1_der_decoder_into;
          ret->out = r_asn1_der_decoder_out;
          break;
        default:
          break;
      }
    }
  } else {
    ret = NULL;
  }

  return ret;
}

RAsn1BinDecoder *
r_asn1_bin_decoder_new_with_data (RAsn1EncodingRules enc, ruint8 * data, rsize size)
{
  RAsn1BinDecoder * ret;

  if ((ret = r_asn1_bin_decoder_new (enc, data, size)) != NULL)
    ret->free = data;

  return ret;
}

RAsn1BinDecoder *
r_asn1_bin_decoder_new_file (RAsn1EncodingRules enc, const rchar * file)
{
  RMemFile * memfile;
  RAsn1BinDecoder * ret;

  if ((memfile = r_mem_file_new (file, R_MEM_PROT_READ, FALSE)) != NULL) {
    ret = r_asn1_bin_decoder_new (enc, r_mem_file_get_mem (memfile),
        r_mem_file_get_size (memfile));
    ret->file = memfile;
  } else {
    ret = NULL;
  }

  return ret;
}

RAsn1DecoderStatus
r_asn1_bin_decoder_next (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  if (R_UNLIKELY (dec == NULL || tlv == NULL)) return R_ASN1_DECODER_INVALID_ARG;
  return dec->next (dec, tlv);
}

RAsn1DecoderStatus
r_asn1_bin_decoder_into (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  if (R_UNLIKELY (dec == NULL || tlv == NULL)) return R_ASN1_DECODER_INVALID_ARG;
  return dec->into (dec, tlv);
}

RAsn1DecoderStatus
r_asn1_bin_decoder_out (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  if (R_UNLIKELY (dec == NULL || tlv == NULL)) return R_ASN1_DECODER_INVALID_ARG;
  return dec->out (dec, tlv);
}

