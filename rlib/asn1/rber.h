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
#ifndef __R_ASN1_BER_H__
#define __R_ASN1_BER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/asn1/rasn1.h>

R_BEGIN_DECLS

typedef struct _RAsn1BinDecoder RAsn1BerDecoder;

R_API RAsn1BerDecoder * r_asn1_ber_decoder_new_file (const rchar * file);
R_API RAsn1BerDecoder * r_asn1_ber_decoder_new (const ruint8 * data, rsize size);
R_API RAsn1BerDecoder * r_asn1_ber_decoder_ref (RAsn1BerDecoder * dec);
R_API void r_asn1_ber_decoder_unref (RAsn1BerDecoder * dec);

R_API RAsn1DecoderStatus r_asn1_ber_decoder_next (RAsn1BerDecoder * dec, RAsn1BinTLV * tlv);
R_API RAsn1DecoderStatus r_asn1_ber_decoder_into (RAsn1BerDecoder * dec, RAsn1BinTLV * tlv);
R_API RAsn1DecoderStatus r_asn1_ber_decoder_out (RAsn1BerDecoder * dec, RAsn1BinTLV * tlv);

/* TODO: Add callback/events based decoder/parser (like a SAX parser) */
/*R_API rboolean r_asn1_ber_decoder_decode_events (RAsn1BerDecoder * dec,*/
    /*RFunc primary, RFunc start, RFunc end);*/

#define r_asn1_ber_tlv_parse_boolean  r_asn1_bin_tlv_parse_boolean
#define r_asn1_ber_tlv_parse_integer  r_asn1_bin_tlv_parse_integer
#define r_asn1_ber_tlv_parse_mpint    r_asn1_bin_tlv_parse_mpint
#define r_asn1_ber_tlv_parse_oid      r_asn1_bin_tlv_parse_oid

R_END_DECLS

#endif /* __R_ASN1_BER_H__ */

