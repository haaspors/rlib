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
r_asn1_bin_tlv_parse_oid (const RAsn1BinTLV * tlv, ruint32 * varray, rsize * size)
{
  if (R_UNLIKELY (tlv == NULL || varray == NULL || size == NULL || *size < 2))
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
          if (idx >= *size)
            return R_ASN1_DECODER_OVERFLOW;
          varray[idx++] = (ruint32)cur;
        }
        cur = 0;
      }
    }

    /* last octet should not have 0x80bit/msb set! */
    if (cur > 0)
      return R_ASN1_DECODER_EOS;

    *size = idx;
    return R_ASN1_DECODER_OK;
  } else {
    return R_ASN1_DECODER_WRONG_TYPE;
  }
}

