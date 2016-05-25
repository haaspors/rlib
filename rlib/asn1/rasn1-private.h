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
#ifndef __R_ASN1_PRIVATE_H__
#define __R_ASN1_PRIVATE_H__

#if !defined(RLIB_COMPILATION)
#error "rasn1-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>
#include <rlib/asn1/rasn1.h>
#include <rlib/rlist.h>
#include <rlib/rmemfile.h>

R_BEGIN_DECLS

#define R_ASN1_BIN_TLV_NEXT(tlv) ((tlv)->value + (tlv)->len)

typedef RAsn1DecoderStatus (*RAsn1BinDecoderOperation) (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);

struct _RAsn1BinDecoder
{
  RRef ref;

  RMemFile * file;
  ruint8 * free;
  const ruint8 * data;
  rsize size;

  RSList * stack;

  RAsn1BinDecoderOperation next, into, out;
};


R_API_HIDDEN RAsn1DecoderStatus r_asn1_ber_decoder_next (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);
R_API_HIDDEN RAsn1DecoderStatus r_asn1_ber_decoder_into (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);
R_API_HIDDEN RAsn1DecoderStatus r_asn1_ber_decoder_out (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);

R_API_HIDDEN RAsn1DecoderStatus r_asn1_der_decoder_next (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);
R_API_HIDDEN RAsn1DecoderStatus r_asn1_der_decoder_into (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);
R_API_HIDDEN RAsn1DecoderStatus r_asn1_der_decoder_out (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);

R_END_DECLS

#endif /* __R_ASN1_PRIVATE_H__ */

