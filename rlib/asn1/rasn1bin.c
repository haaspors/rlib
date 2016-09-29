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
r_asn1_bin_tlv_parse_integer (const RAsn1BinTLV * tlv, rint32 * value)
{
  if (R_UNLIKELY (tlv == NULL || value == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_INTEGER) ||
      R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_ENUMERATED)) {
    ruint32 u = 0;
    rsize size;
    const ruint8 * ptr;

    if (R_UNLIKELY ((size = tlv->len) > sizeof (ruint32)))
      return R_ASN1_DECODER_OVERFLOW;

    ptr = tlv->value;
    if ((*tlv->value & 0x80) == 0) {
      while (size-- > 0)
        u = (u << 8) | *ptr++;
      *value = u;
    } else {
      while (size-- > 0)
        u = (u << 8) | (*ptr++ ^ 0xFF);
      *value = -(rint32)++u;
    }
    return R_ASN1_DECODER_OK;
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

RAsn1DecoderStatus
r_asn1_bin_tlv_parse_mpint (const RAsn1BinTLV * tlv, rmpint * value)
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
          varray[idx++] = cur / 40;
          varray[idx++] = cur % 40;
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
r_asn1_bin_tlv_parse_bit_string_bits (const RAsn1BinTLV * tlv, rsize * bits)
{
  if (R_UNLIKELY (tlv == NULL || bits == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_UNLIKELY (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BIT_STRING)))
    return R_ASN1_DECODER_WRONG_TYPE;

  *bits = (tlv->len - sizeof (ruint8)) * 8 - tlv->value[0];
  return R_ASN1_DECODER_OK;
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

