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
#ifndef __R_ASN1_H__
#define __R_ASN1_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rmpint.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

/* ASN.1 identifier */
#define R_ASN1_ID(c, pc, tag) (((c) & R_ASN1_ID_CLASS_MASK) | \
    ((pc) & R_ASN1_ID_PC_MASK) | ((tag) & R_ASN1_ID_TAG_MASK))
#define R_ASN1_UNIVERSAL_ID(pc, tag)  R_ASN1_ID (R_ASN1_ID_UNIVERSAL, pc, tag)

#define R_ASN1_ID_CLASS_MASK              0xc0
typedef enum {
  R_ASN1_ID_UNIVERSAL                   = 0x00,
  R_ASN1_ID_APPLICATION                 = 0x40,
  R_ASN1_ID_CONTEXT                     = 0x80,
  R_ASN1_ID_PRIVATE                     = 0xc0,
} RAsn1IdClass;

#define R_ASN1_ID_PC_MASK                 0x20
#define R_ASN1_ID_PRIMITIVE               0x00
#define R_ASN1_ID_CONSTRUCTED             0x20

#define R_ASN1_ID_TAG_MASK                0x1F
typedef enum {
  R_ASN1_ID_EOC                         = 0x00,
  R_ASN1_ID_BOOLEAN                     = 0x01,
  R_ASN1_ID_INTEGER                     = 0x02,
  R_ASN1_ID_BIT_STRING                  = 0x03,
  R_ASN1_ID_OCTET_STRING                = 0x04,
  R_ASN1_ID_NULL                        = 0x05,
  R_ASN1_ID_OBJECT_IDENTIFIER           = 0x06,
  R_ASN1_ID_OBJECT_DESCRIPTOR           = 0x07,
  R_ASN1_ID_EXTERNAL                    = 0x08,
  R_ASN1_ID_REAL                        = 0x09,
  R_ASN1_ID_ENUMERATED                  = 0x0a,
  R_ASN1_ID_EMBEDDED_PDV                = 0x0b,
  R_ASN1_ID_UTF8_STRING                 = 0x0c,
  R_ASN1_ID_RELATIVE_OID                = 0x0d,
  R_ASN1_ID_RESERVED_0x0e               = 0x0e,
  R_ASN1_ID_RESERVED_0x0f               = 0x0f,
  R_ASN1_ID_SEQUENCE                    = 0x10,
  R_ASN1_ID_SET                         = 0x11,
  R_ASN1_ID_NUMERIC_STRING              = 0x12,
  R_ASN1_ID_PRINTABLE_STRING            = 0x13,
  R_ASN1_ID_T61_STRING                  = 0x14,
  R_ASN1_ID_VIDEOTEX_STRING             = 0x15,
  R_ASN1_ID_IA5_STRING                  = 0x16,
  R_ASN1_ID_UTC_TIME                    = 0x17,
  R_ASN1_ID_GENERALIZED_TIME            = 0x18,
  R_ASN1_ID_GRAPHIC_STRING              = 0x19,
  R_ASN1_ID_VISIBLE_STRING              = 0x1a,
  R_ASN1_ID_GENERAL_STRING              = 0x1b,
  R_ASN1_ID_UNIVERSAL_STRING            = 0x1c,
  R_ASN1_ID_CHARACTER_STRING            = 0x1d,
  R_ASN1_ID_BMP_STRING                  = 0x1e,
} RAsn1IdTag;

/* ASN.1 binary length octets */
#define R_ASN1_BIN_LENGTH_INDEFINITE      0x80

/* ASN.1 Decoder status */
typedef enum {
  R_ASN1_DECODER_EOS                    = -2,
  R_ASN1_DECODER_EOC                    = -1,
  R_ASN1_DECODER_OK                     = 0,
  R_ASN1_DECODER_INVALID_ARG,
  R_ASN1_DECODER_WRONG_TYPE,
  R_ASN1_DECODER_OVERFLOW,
  R_ASN1_DECODER_INDEFINITE,
  R_ASN1_DECODER_NOT_CONSTRUCTED,
} RAsn1DecoderStatus;

/* ASN.1 binary Type-Length-Value */
#define R_ASN1_BIN_TLV_INIT           { NULL, 0, NULL }
#define R_ASN1_BIN_TLV_ID_CLASS(tlv)  (*(tlv)->start & R_ASN1_ID_CLASS_MASK)
#define R_ASN1_BIN_TLV_ID_PC(tlv)     (*(tlv)->start & R_ASN1_ID_PC_MASK)
#define R_ASN1_BIN_TLV_ID_TAG(tlv)    (*(tlv)->start & R_ASN1_ID_TAG_MASK)
#define R_ASN1_BIN_TLV_ID_IS_TAG(tlv, tag)  (*(tlv)->start == (tag))
#define R_ASN1_BIN_TLV_ID_IS_EOC(tlv)       R_ASN1_BIN_TLV_ID_IS_TAG(tlv, R_ASN1_ID_EOC)

typedef struct _RAsn1BinTLV {
  const ruint8 *  start;  /* Type   (first octet of tlv) */
  rsize           len;    /* Length (parsed) */
  const ruint8 *  value;  /* Value  (pointer to first value octet) */
} RAsn1BinTLV;

R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_boolean (const RAsn1BinTLV * tlv, rboolean * value);
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_integer (const RAsn1BinTLV * tlv, rint32 * value);
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_mpint (const RAsn1BinTLV * tlv, rmpint * value);
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_oid (const RAsn1BinTLV * tlv, ruint32 * varray, rsize * size);
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_oid_to_dot (const RAsn1BinTLV * tlv, rchar ** dot);
/* TODO: Add parsing of strings, time and ... */

R_END_DECLS

#endif /* __R_ASN1_H__ */

