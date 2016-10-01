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
#include <rlib/rmem.h>

static RAsn1DecoderStatus
r_asn1_ber_parse_length (const ruint8 * ptr, rsize * lensize, rsize * ret)
{
  if (*lensize > 0) {
    if (*ptr == R_ASN1_BIN_LENGTH_INDEFINITE) {
      *lensize = 1;
      *ret = 0;
    } else if (*ptr & R_ASN1_BIN_LENGTH_INDEFINITE) {
      /* definite long form */
      rsize i;

      if ((*ptr & 0x7f) > *lensize)
        return R_ASN1_DECODER_OVERFLOW;

      *lensize = *ptr++ & 0x7f;
      for (*ret = i = 0; i < *lensize; i++)
        *ret = (*ret << 8) | *ptr++;
      (*lensize)++;
    } else {
      /* definite short form */
      *lensize = 1;
      *ret = (rsize)*ptr;
    }

    return R_ASN1_DECODER_OK;
  }

  return R_ASN1_DECODER_OVERFLOW;
}

static RAsn1DecoderStatus
r_asn1_ber_tlv_init (RAsn1BinTLV * tlv, const ruint8 * start, rsize size)
{
  rsize lensize;
  RAsn1DecoderStatus ret;

  if (size < 2)
    return R_ASN1_DECODER_OVERFLOW;

  lensize = size - 1;
  if ((ret = r_asn1_ber_parse_length (start + 1, &lensize, &tlv->len)) ==
      R_ASN1_DECODER_OK) {
    tlv->start = start;
    tlv->value = start + 1 + lensize;
  }
  return ret;
}

RAsn1DecoderStatus
r_asn1_ber_decoder_next (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  RAsn1DecoderStatus ret;
  RSList * lst;

  if (R_UNLIKELY (dec == NULL || tlv == NULL))
    return R_ASN1_DECODER_INVALID_ARG;

  lst = dec->stack;
  if (tlv->value == NULL) {
    ret = r_asn1_ber_tlv_init (tlv, dec->data, dec->size);
  } else if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_EOC)) {
    if (lst != NULL) {
      ret = R_ASN1_DECODER_EOC;
    } else if (R_ASN1_BIN_TLV_NEXT (tlv) > dec->data + dec->size) {
      ret = R_ASN1_DECODER_OVERFLOW;
    } else if (R_ASN1_BIN_TLV_NEXT (tlv) == dec->data + dec->size) {
      r_memset (tlv, 0, sizeof (RAsn1BinTLV));
      ret = R_ASN1_DECODER_EOS;
    } else {
      ret = r_asn1_ber_tlv_init (tlv, R_ASN1_BIN_TLV_NEXT (tlv),
          dec->data + dec->size - R_ASN1_BIN_TLV_NEXT (tlv));
    }
  } else if (lst != NULL && ((RAsn1BinTLV *)r_list_data (lst))->len > 0 &&
      R_ASN1_BIN_TLV_NEXT (tlv) >= R_ASN1_BIN_TLV_NEXT ((RAsn1BinTLV *)r_list_data (lst))) {
    if (R_ASN1_BIN_TLV_NEXT (tlv) == R_ASN1_BIN_TLV_NEXT ((RAsn1BinTLV *)r_list_data (lst)))
      ret = R_ASN1_DECODER_EOC;
    else
      ret = R_ASN1_DECODER_OVERFLOW;
  } else if (tlv->len == 0) {
    if ((ret = r_asn1_ber_decoder_into (dec, tlv)) == R_ASN1_DECODER_OK)
      ret = r_asn1_ber_decoder_out (dec, tlv);
  } else {
    if (R_ASN1_BIN_TLV_NEXT (tlv) > dec->data + dec->size) {
      ret = R_ASN1_DECODER_OVERFLOW;
    } else if (R_ASN1_BIN_TLV_NEXT (tlv) == dec->data + dec->size) {
      r_memset (tlv, 0, sizeof (RAsn1BinTLV));
      ret = R_ASN1_DECODER_EOS;
    } else {
      ret = r_asn1_ber_tlv_init (tlv, R_ASN1_BIN_TLV_NEXT (tlv),
          dec->data + dec->size - R_ASN1_BIN_TLV_NEXT (tlv));
    }
  }

  if (ret == R_ASN1_DECODER_OK) {
    if (R_ASN1_BIN_TLV_NEXT (tlv) > dec->data + dec->size)
      ret = R_ASN1_DECODER_OVERFLOW;
  } else if (ret == R_ASN1_DECODER_EOS) {
    if (dec->stack != NULL)
      ret = R_ASN1_DECODER_OVERFLOW;
  }

  return ret;
}

RAsn1DecoderStatus
r_asn1_ber_decoder_into (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  const ruint8 * ptr;
  rsize size;

  if (R_UNLIKELY (dec == NULL || tlv == NULL || tlv->value == NULL))
    return R_ASN1_DECODER_INVALID_ARG;

  if ((size = tlv->len) == 0)
    size = (rsize)(dec->data + dec->size - tlv->value);

  if (*tlv->start & R_ASN1_ID_CONSTRUCTED) {
    ptr = tlv->value;
  } else if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OCTET_STRING)) {
    ptr = tlv->value;
  } else if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BIT_STRING)) {
    /* This skips over the octet describing unused bits */
    if (size-- < 2)
      return R_ASN1_DECODER_OVERFLOW;

    ptr = tlv->value;
    if (*ptr++ > 0) /* unused bits must be 0 */
      return R_ASN1_DECODER_NOT_CONSTRUCTED;
  } else {
    return R_ASN1_DECODER_NOT_CONSTRUCTED;
  }

  dec->stack = r_slist_prepend (dec->stack,
      r_memdup (tlv, sizeof (RAsn1BinTLV)));
  return r_asn1_ber_tlv_init (tlv, ptr, size);
}

RAsn1DecoderStatus
r_asn1_ber_decoder_out (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  RSList * lst;
  RAsn1BinTLV * up;
  RAsn1DecoderStatus ret;

  if (R_UNLIKELY (dec == NULL || tlv == NULL))
    return R_ASN1_DECODER_INVALID_ARG;
  if (R_UNLIKELY ((lst = dec->stack) == NULL))
    return R_ASN1_DECODER_INVALID_ARG;

  up = r_slist_data (lst);
  if (up->len > 0) {
    dec->stack = r_slist_next (dec->stack);
    if (R_ASN1_BIN_TLV_NEXT (up) < dec->data + dec->size) {
      if (dec->stack == NULL || ((RAsn1BinTLV *)r_list_data (dec->stack))->len == 0 ||
          R_ASN1_BIN_TLV_NEXT (up) < R_ASN1_BIN_TLV_NEXT ((RAsn1BinTLV *)r_list_data (dec->stack))) {
        ret = r_asn1_ber_tlv_init (tlv, R_ASN1_BIN_TLV_NEXT (up),
            dec->data + dec->size - R_ASN1_BIN_TLV_NEXT (up));
      } else {
        ret = R_ASN1_DECODER_EOC;
      }
    } else {
      r_memset (tlv, 0, sizeof (RAsn1BinTLV));
      ret = R_ASN1_DECODER_EOS;
    }

    r_slist_free1_full (lst, r_free);
  } else {
    do {
      ret = r_asn1_ber_decoder_next (dec, tlv);
    } while (ret == R_ASN1_DECODER_OK);

    if (ret == R_ASN1_DECODER_EOC) {
      dec->stack = r_slist_next (dec->stack);
      r_slist_free1_full (lst, r_free);
      if (R_ASN1_BIN_TLV_NEXT (tlv) == dec->data + dec->size) {
        r_memset (tlv, 0, sizeof (RAsn1BinTLV));
        ret = R_ASN1_DECODER_EOS;
      } else {
        ret = r_asn1_ber_tlv_init (tlv, R_ASN1_BIN_TLV_NEXT (tlv),
            dec->data + dec->size - R_ASN1_BIN_TLV_NEXT (tlv));
      }
    }
  }

  return ret;
}

