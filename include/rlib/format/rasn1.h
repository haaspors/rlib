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
#ifndef __R_ASN1_ASN1_H__
#define __R_ASN1_ASN1_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/format/rasn1.h
 * @brief ASN.1 BER / DER encoder and decoder; consumed by the X.509,
 * PKCS and other crypto-side parsers.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rbitset.h>
#include <rlib/data/rmpint.h>

#include <rlib/rbuffer.h>
#include <rlib/crypto/rmsgdigest.h>

/**
 * @defgroup r_format File formats
 *
 * @brief Structured-data encoding formats: ASN.1 (BER / DER) and
 * JSON, today; XML / YAML / MessagePack / CBOR codecs would slot in
 * here as they land.
 *
 * Two children:
 *
 *   - @ref r_asn1 — ASN.1 binary encoder / decoder and the OID
 *     registry, used heavily by the crypto subsystem.
 *   - @ref r_json — JSON value tree plus streaming parser.
 */

/**
 * @defgroup r_asn1 ASN.1 BER / DER
 * @ingroup r_format
 *
 * @brief Encoder and decoder for ASN.1 in Basic and Distinguished
 * Encoding Rules, plus the object-identifier (OID) registry that
 * goes with them.
 *
 * Consumed heavily by @c r_crypto (X.509 certificates, PKCS#1 / #8
 * key formats, PEM bodies) but the encoding itself is general -
 * SNMP, LDAP, OCSP and many other on-disk and on-wire formats use
 * the same primitives.
 *
 * @{
 */

R_BEGIN_DECLS

/* ASN.1 identifier */
#define R_ASN1_ID(c, pc, tag) (((c) & R_ASN1_ID_CLASS_MASK) | \
    ((pc) & R_ASN1_ID_PC_MASK) | ((tag) & R_ASN1_ID_TAG_MASK))
#define R_ASN1_UNIVERSAL_ID(pc, tag)  R_ASN1_ID (R_ASN1_ID_UNIVERSAL, pc, tag)

#define R_ASN1_ID_CLASS_MASK              0xc0
/** @brief ASN.1 identifier class (top two bits of the first identifier octet). */
typedef enum {
  R_ASN1_ID_UNIVERSAL                   = 0x00, /**< Standard ASN.1 type. */
  R_ASN1_ID_APPLICATION                 = 0x40, /**< Application-specific type. */
  R_ASN1_ID_CONTEXT                     = 0x80, /**< Context-specific type (typical for X.509 extensions). */
  R_ASN1_ID_PRIVATE                     = 0xc0, /**< Private type. */
} RAsn1IdClass;

#define R_ASN1_ID_PC_MASK                 0x20
#define R_ASN1_ID_PRIMITIVE               0x00
#define R_ASN1_ID_CONSTRUCTED             0x20

#define R_ASN1_ID_TAG_MASK                0x1F
/**
 * @brief Universal ASN.1 type tags (low five bits of the first
 * identifier octet for the @c R_ASN1_ID_UNIVERSAL class).
 */
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

/** @brief Decoder operation result code; see @c R_ASN1_DECODER_STATUS_* macros for classification. */
typedef enum {
  R_ASN1_DECODER_EOS                    = -2,
  R_ASN1_DECODER_EOC                    = -1,
  R_ASN1_DECODER_OK                     = 0,
  R_ASN1_DECODER_INVALID_ARG,
  R_ASN1_DECODER_OOM,
  R_ASN1_DECODER_PARSE_ERROR,
  R_ASN1_DECODER_WRONG_TYPE,
  R_ASN1_DECODER_OVERFLOW,
  R_ASN1_DECODER_INDEFINITE,
  R_ASN1_DECODER_NOT_CONSTRUCTED,
} RAsn1DecoderStatus;
#define R_ASN1_DECODER_STATUS_ERROR(s)      ((s) >  R_ASN1_DECODER_OK)
#define R_ASN1_DECODER_STATUS_SUCCESS(s)    ((s) <= R_ASN1_DECODER_OK)

/** @brief Encoder operation result code. */
typedef enum {
  R_ASN1_ENCODER_OK                     = 0,
  R_ASN1_ENCODER_INVALID_ARG,
  R_ASN1_ENCODER_OOM,
  R_ASN1_ENCODER_INDEFINITE,
  R_ASN1_ENCODER_NOT_CONSTRUCTED,
} RAsn1EncoderStatus;

/* ASN.1 binary Type-Length-Value */
#define R_ASN1_BIN_TLV_INIT           { NULL, 0, NULL }
#define R_ASN1_BIN_TLV_ID_CLASS(tlv)  (*(tlv)->start & R_ASN1_ID_CLASS_MASK)
#define R_ASN1_BIN_TLV_ID_PC(tlv)     (*(tlv)->start & R_ASN1_ID_PC_MASK)
#define R_ASN1_BIN_TLV_ID_TAG(tlv)    (*(tlv)->start & R_ASN1_ID_TAG_MASK)
#define R_ASN1_BIN_TLV_IS_ID(tlv, tag)(*(tlv)->start == (tag))
#define R_ASN1_BIN_TLV_ID_IS_TAG(tlv, tag)  (R_ASN1_BIN_TLV_ID_TAG (tlv) == (tag))

/**
 * @brief One ASN.1 Tag-Length-Value record located inside the
 * decoder's input buffer.
 *
 * Pointers are non-owning aliases into the buffer @c RAsn1BinDecoder
 * was constructed over. Use the @c r_asn1_bin_tlv_parse_* family to
 * interpret @c value as a boolean / integer / OID / string / etc.
 */
typedef struct RAsn1BinTLV {
  const ruint8 *  start;  /**< Type — first octet of the TLV. */
  rsize           len;    /**< Length of the value, parsed from the L bytes. */
  const ruint8 *  value;  /**< Pointer to the first byte of the V payload. */
} RAsn1BinTLV;

/** @name TLV parse helpers
 *
 * Interpret the @c value bytes of a TLV as a particular ASN.1 type.
 * Each helper returns @c R_ASN1_DECODER_OK on success, or a
 * @c R_ASN1_DECODER_WRONG_TYPE / @c R_ASN1_DECODER_PARSE_ERROR
 * variant if the tag or contents don't match.
 *  @{ */
/** @brief Parse a @c BOOLEAN value (@c R_ASN1_ID_BOOLEAN). */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_boolean (const RAsn1BinTLV * tlv, rboolean * value);
/**
 * @brief Inspect an @c INTEGER's bit width and signedness without
 * decoding the value.
 * @param tlv     TLV to inspect.
 * @param bits    Out-pointer: bit length of the integer.
 * @param unsign  Out-pointer: @c TRUE if the value is unsigned.
 */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_integer_bits (const RAsn1BinTLV * tlv, ruint * bits, rboolean * unsign);
/** @brief Parse an @c INTEGER into a signed 32-bit value. */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_integer_i32 (const RAsn1BinTLV * tlv, rint32 * value);
/** @brief Parse an @c INTEGER into an unsigned 32-bit value. */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_integer_u32 (const RAsn1BinTLV * tlv, ruint32 * value);
/** @brief Parse an @c INTEGER into a signed 64-bit value. */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_integer_i64 (const RAsn1BinTLV * tlv, rint64 * value);
/** @brief Parse an @c INTEGER into an unsigned 64-bit value. */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_integer_u64 (const RAsn1BinTLV * tlv, ruint64 * value);
/** @brief Parse an @c INTEGER into an @c rmpint (arbitrary width). */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_integer_mpint (const RAsn1BinTLV * tlv, rmpint * value);
/**
 * @brief Parse an @c OBJECT @c IDENTIFIER into a component array.
 * @param tlv    TLV to parse.
 * @param varray Caller-provided buffer for the OID components.
 * @param size   In/out: array capacity / actual component count.
 */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_oid (const RAsn1BinTLV * tlv, ruint32 * varray, rsize * size);
/**
 * @brief Render an @c OBJECT @c IDENTIFIER as a dotted-decimal
 * string ("1.2.840.113549.1.1.1") in a newly-allocated buffer.
 */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_oid_to_dot (const RAsn1BinTLV * tlv, rchar ** dot);
/** @brief Map an @c OBJECT @c IDENTIFIER for a hash algorithm to its @c RMsgDigestType. */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_oid_to_msg_digest_type (const RAsn1BinTLV * tlv, RMsgDigestType * mdtype);
/** @brief Parse a @c UTCTime / @c GeneralizedTime into a Unix timestamp. */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_time (const RAsn1BinTLV * tlv, ruint64 * time);
/** @brief Parse a @c BIT @c STRING into an @ref RBitset. */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_bit_string (const RAsn1BinTLV * tlv, RBitset ** bitset);
/** @brief Return the bit count of a @c BIT @c STRING (without copying the payload). */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_bit_string_bits (const RAsn1BinTLV * tlv, rsize * bits);
/** @brief Pointer to the first byte of a @c BIT @c STRING's payload (skipping the unused-bits prefix). */
#define r_asn1_bin_tlv_bit_string_value(tlv) (&(tlv)->value[1])

/**
 * @brief Copy any ASN.1 string-typed TLV into a fresh NUL-terminated
 * buffer.
 *
 * Accepts UTF8String, NumericString, PrintableString, T61String,
 * IA5String, VisibleString, GeneralString, GraphicString, BMPString
 * and UniversalString. Bytes are passed through verbatim — no
 * character-set validation, so callers that need to enforce e.g.
 * PrintableString rules must do so themselves.
 */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_string (const RAsn1BinTLV * tlv,
    rchar ** str);
/** @} */


/** @brief ASN.1 encoding rule variant used by the binary decoder / encoder. */
typedef enum {
  R_ASN1_BER,                       /**< Basic Encoding Rules (permissive). */
  R_ASN1_DER,                       /**< Distinguished Encoding Rules (canonical subset of BER). */
  R_ASN1_ENCODING_RULES_COUNT       /**< Sentinel. */
} RAsn1EncodingRules;

/** @brief Opaque, refcounted ASN.1 binary decoder. */
typedef struct RAsn1BinDecoder RAsn1BinDecoder;

/** @name Decoder construction
 *  @{ */
/** @brief Construct a decoder over a file (mapped on POSIX). */
R_API RAsn1BinDecoder * r_asn1_bin_decoder_new_file (RAsn1EncodingRules enc,
    const rchar * file);
/** @brief Construct a decoder taking ownership of @p data (freed on unref). */
R_API RAsn1BinDecoder * r_asn1_bin_decoder_new_with_data (RAsn1EncodingRules enc,
    ruint8 * data, rsize size);
/** @brief Construct a decoder over a borrowed memory buffer; @p data must outlive the decoder. */
R_API RAsn1BinDecoder * r_asn1_bin_decoder_new (RAsn1EncodingRules enc,
    const ruint8 * data, rsize size);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_asn1_bin_decoder_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_asn1_bin_decoder_unref r_ref_unref
/** @} */

/** @name Decoder navigation
 *
 * The decoder maintains a position cursor that the @c _next / @c _into /
 * @c _out trio walks through the TLV tree.
 *  @{ */
/**
 * @brief Advance to the next TLV at the current depth.
 * @param dec Decoder.
 * @param tlv Out-pointer: populated with the TLV at the new position.
 * @return @c R_ASN1_DECODER_EOC at end of a constructed value,
 *         @c R_ASN1_DECODER_EOS at end of stream.
 */
R_API RAsn1DecoderStatus r_asn1_bin_decoder_next (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);
/**
 * @brief Descend into the constructed TLV at @p tlv; subsequent
 * @ref r_asn1_bin_decoder_next calls walk its children.
 */
R_API RAsn1DecoderStatus r_asn1_bin_decoder_into (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);
/** @brief Ascend back to the enclosing constructed TLV. */
R_API RAsn1DecoderStatus r_asn1_bin_decoder_out (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);

/**
 * @brief Decode an X.500 distinguished name into a comma-separated
 * string (e.g. @c "CN=foo,O=Acme,C=US").
 */
R_API RAsn1DecoderStatus r_asn1_bin_tlv_parse_distinguished_name (RAsn1BinDecoder * dec,
    RAsn1BinTLV * tlv, rchar ** name);
/** @} */

/* TODO: Add callback/events based decoder/parser (like a SAX parser) */
/*R_API rboolean r_asn1_bin_decoder_decode_events (RAsn1BinDecoder * dec,*/
    /*RFunc primary, RFunc start, RFunc end);*/


/** @brief Opaque, refcounted ASN.1 binary encoder. */
typedef struct RAsn1BinEncoder RAsn1BinEncoder;

/** @name Encoder construction
 *  @{ */
/** @brief Construct a fresh encoder using @p enc encoding rules. */
R_API RAsn1BinEncoder * r_asn1_bin_encoder_new (RAsn1EncodingRules enc);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_asn1_bin_encoder_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_asn1_bin_encoder_unref r_ref_unref
/** @} */

/** @name Constructed encoding (SEQUENCE / SET / BIT STRING / OCTET STRING)
 *
 * @c begin / @c end calls bracket nested constructed values. The
 * @p sizehint preallocates the length-encoding region so DER's
 * known-length form can be used without retroactive shifts.
 *  @{ */
/** @brief Open a constructed value with arbitrary identifier @p id. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_begin_constructed (RAsn1BinEncoder * enc, ruint8 id, rsize sizehint);
/** @brief Open a @c BIT @c STRING value. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_begin_bit_string (RAsn1BinEncoder * enc, rsize sizehint);
/** @brief Open an @c OCTET @c STRING (delegates to @ref r_asn1_bin_encoder_begin_constructed). */
#define r_asn1_bin_encoder_begin_octet_string(enc, sizehint)                  \
  r_asn1_bin_encoder_begin_constructed (enc,                                  \
      R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OCTET_STRING), \
      sizehint)
/** @brief Close the most recently opened constructed / bit-string / octet-string. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_end_constructed (RAsn1BinEncoder * enc);
/** @brief Alias: close a @c BIT @c STRING. */
#define r_asn1_bin_encoder_end_bit_string  r_asn1_bin_encoder_end_constructed
/** @brief Alias: close an @c OCTET @c STRING. */
#define r_asn1_bin_encoder_end_octet_string  r_asn1_bin_encoder_end_constructed
/** @} */

/** @name Primitive value encoders
 *  @{ */
/** @brief Append a primitive TLV with arbitrary identifier @p id and raw payload @p data. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_raw (RAsn1BinEncoder * enc, ruint8 id, rconstpointer data, rsize size);
/** @brief Append a @c NULL value. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_null (RAsn1BinEncoder * enc);
/** @brief Append a @c BOOLEAN. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_boolean (RAsn1BinEncoder * enc, rboolean value);
/** @brief Append an @c INTEGER (signed 32-bit). */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_integer_i32 (RAsn1BinEncoder * enc, rint32 value);
/** @brief Append an @c INTEGER (unsigned 32-bit). */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_integer_u32 (RAsn1BinEncoder * enc, ruint32 value);
/** @brief Append an @c INTEGER (signed 64-bit). */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_integer_i64 (RAsn1BinEncoder * enc, rint64 value);
/** @brief Append an @c INTEGER (unsigned 64-bit). */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_integer_u64 (RAsn1BinEncoder * enc, ruint64 value);
/** @brief Append an @c INTEGER (arbitrary-width @c rmpint). */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_integer_mpint (RAsn1BinEncoder * enc, const rmpint * value);
/** @brief Append an @c OBJECT @c IDENTIFIER from a null-terminated raw OID byte string. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_oid_rawsz (RAsn1BinEncoder * enc, const rchar * rawsz);
/** @brief Append a @c BIT @c STRING from a raw bit array. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_bit_string_raw (RAsn1BinEncoder * enc, const ruint8 * bits, rsize size);
/** @brief Append a @c UTCTime from a Unix timestamp. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_utc_time (RAsn1BinEncoder * enc, ruint64 time);
/** @brief Append an @c IA5String; pass @c -1 for @p size to use @c strlen. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_ia5_string (RAsn1BinEncoder * enc, const rchar * dn, rssize size);
/** @brief Append a @c UTF8String. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_utf8_string (RAsn1BinEncoder * enc, const rchar * dn, rssize size);
/** @brief Append a @c PrintableString. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_printable_string (RAsn1BinEncoder * enc, const rchar * dn, rssize size);
/**
 * @brief Append an X.500 distinguished name parsed from a
 * comma-separated string (e.g. @c "CN=foo,O=Acme,C=US").
 */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_add_distinguished_name (RAsn1BinEncoder * enc, const rchar * dn);
/** @} */

/** @name Encoder output extraction
 *  @{ */
/**
 * @brief Return a freshly-allocated copy of the encoded bytes.
 *
 * Non-destructive: the encoder retains its contents, so a subsequent
 * encode appends to the existing buffer rather than starting fresh.
 */
R_API ruint8 * r_asn1_bin_encoder_get_data (RAsn1BinEncoder * enc, rsize * size) R_ATTR_MALLOC;
/** @brief Same as @ref r_asn1_bin_encoder_get_data but returns an @ref RBuffer. */
R_API RAsn1EncoderStatus r_asn1_bin_encoder_get_buffer (RAsn1BinEncoder * enc, RBuffer ** buf);
/** @} */



/** @brief Map an X.500 attribute OID to its short name (e.g. @c "CN", @c "O", @c "C"). */
const rchar * r_asn1_x500_name_from_oid (rconstpointer p, rsize size);
/** @brief Reverse of @ref r_asn1_x500_name_from_oid; short name -> OID bytes. */
const rchar * r_asn1_x500_name_to_oid (const rchar * name, rsize size);

R_END_DECLS

/** @} */

#endif /* __R_ASN1_ASN1_H__ */

