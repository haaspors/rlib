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

#include "config.h"
#include "rcrypto-private.h"
#include <rlib/crypto/rx509.h>

#include <rlib/format/roid.h>
#include <rlib/data/rlist.h>
#include <rlib/data/rmpint.h>
#include <rlib/data/rptrarray.h>
#include <rlib/net/rsocketaddress.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

typedef struct {
  ruint8 * value;
  rsize size;
} RX509Buf;

struct RX509GeneralName {
  ruint8 id;        /* original identifier octet (context tag) */
  ruint8 * raw;     /* content bytes of the chosen alternative */
  rsize rawsize;
  rchar * str;      /* IA5String (rfc822/dns/uri) or DN (directoryName); else NULL */
};

/* One PolicyMappings entry: a pair of dotted-OID strings. */
typedef struct {
  rchar * issuer;
  rchar * subject;
} RX509PolicyMapping;

typedef struct {
  RCryptoCert cert;

  RX509Version version;
  ruint8 serial[20];            /* raw magnitude, big-endian (RFC 5280: <= 20 octets) */
  ruint8 seriallen;
  rchar * issuer;
  rchar * subject;

  RX509Buf issuerUniqueID;
  RX509Buf subjectUniqueID;
  RX509Buf subjectKeyID;
  RX509Buf authorityKeyID;
  rchar * authority;
  RX509Buf authorityCertSerial;     /* AKI [2] raw INTEGER content */

  RX509KeyUsage keyUsage;
  RX509ExtKeyUsage extKeyUsage;
  RSList * policies;
  rboolean ca;
  rboolean haspathLen;              /* pathLenConstraint present in basicConstraints */
  rint32 pathLen;
  rint32 requireExplicitPolicy;
  rint32 inhibitPolicyMapping;

  RPtrArray * sans;                 /* RX509GeneralName *: subjectAltName */
  RPtrArray * authorityCertIssuer;  /* RX509GeneralName *: AKI [1] */
  RPtrArray * ncPermitted;          /* RX509GeneralName *: nameConstraints permitted */
  RPtrArray * ncExcluded;           /* RX509GeneralName *: nameConstraints excluded */
  RPtrArray * policyMappings;       /* RX509PolicyMapping * */
} RCryptoX509Cert;

typedef rboolean (*RCertX509ExtFunc) (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical);

static void
r_x509_general_name_free (RX509GeneralName * gn)
{
  r_free (gn->raw);
  r_free (gn->str);
  r_free (gn);
}

static void
r_x509_policy_mapping_free (RX509PolicyMapping * pm)
{
  r_free (pm->issuer);
  r_free (pm->subject);
  r_free (pm);
}

/* Build a GeneralName from a TLV positioned at one CHOICE element. */
static RX509GeneralName *
r_x509_general_name_new_from_tlv (const RAsn1BinTLV * tlv)
{
  RX509GeneralName * gn;

  if ((gn = r_mem_new0 (RX509GeneralName)) == NULL)
    return NULL;

  gn->id = *tlv->start;
  gn->rawsize = tlv->len;
  gn->raw = r_memdup (tlv->value, tlv->len);

  switch ((RX509GeneralNameType)(gn->id & R_ASN1_ID_TAG_MASK)) {
    case R_X509_GENERAL_NAME_RFC822:
    case R_X509_GENERAL_NAME_DNS:
    case R_X509_GENERAL_NAME_URI:
      gn->str = r_strndup ((const rchar *) tlv->value, tlv->len);
      break;
    case R_X509_GENERAL_NAME_DIRECTORY: {
      /* [4] is EXPLICIT, wrapping the RDNSequence; parse it with a
       * borrowed sub-decoder over the content bytes. */
      RAsn1BinDecoder * sub;
      if ((sub = r_asn1_bin_decoder_new (R_ASN1_DER, gn->raw, gn->rawsize)) != NULL) {
        RAsn1BinTLV stlv = R_ASN1_BIN_TLV_INIT;
        if (r_asn1_bin_decoder_next (sub, &stlv) == R_ASN1_DECODER_OK)
          r_asn1_bin_tlv_parse_distinguished_name (sub, &stlv, &gn->str);
        r_asn1_bin_decoder_unref (sub);
      }
      break;
    }
    default:
      break;
  }

  return gn;
}

RX509GeneralNameType
r_x509_general_name_type (const RX509GeneralName * gn)
{
  return (RX509GeneralNameType)(gn->id & R_ASN1_ID_TAG_MASK);
}

const rchar *
r_x509_general_name_as_string (const RX509GeneralName * gn)
{
  switch (r_x509_general_name_type (gn)) {
    case R_X509_GENERAL_NAME_RFC822:
    case R_X509_GENERAL_NAME_DNS:
    case R_X509_GENERAL_NAME_URI:
      return gn->str;
    default:
      return NULL;
  }
}

const ruint8 *
r_x509_general_name_as_ip (const RX509GeneralName * gn, rsize * size)
{
  if (r_x509_general_name_type (gn) != R_X509_GENERAL_NAME_IP)
    return NULL;
  if (size != NULL)
    *size = gn->rawsize;
  return gn->raw;
}

rchar *
r_x509_general_name_as_oid (const RX509GeneralName * gn)
{
  static const ruint8 oid_tag = R_ASN1_ID (R_ASN1_ID_UNIVERSAL,
      R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OBJECT_IDENTIFIER);
  RAsn1BinTLV tlv;
  rchar * dot = NULL;

  if (r_x509_general_name_type (gn) != R_X509_GENERAL_NAME_REGISTERED_ID)
    return NULL;

  /* Synthesise a TLV over the stored content: the parser checks the
   * tag via start[0] and reads the value from value/len. */
  tlv.start = &oid_tag;
  tlv.len = gn->rawsize;
  tlv.value = gn->raw;
  if (r_asn1_bin_tlv_parse_oid_to_dot (&tlv, &dot) != R_ASN1_DECODER_OK)
    return NULL;
  return dot;
}

const rchar *
r_x509_general_name_as_dn (const RX509GeneralName * gn)
{
  return r_x509_general_name_type (gn) == R_X509_GENERAL_NAME_DIRECTORY ?
      gn->str : NULL;
}

/* Iterate the GeneralName children of the constructed @p tlv points at
 * (a GeneralNames SEQUENCE, or the implicitly-tagged [1] of an AKI),
 * appending each to @p arr. Leaves the decoder stack balanced. */
static rboolean
r_x509_parse_general_names (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv,
    RPtrArray ** arr)
{
  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return FALSE;

  if (*arr == NULL && (*arr = r_ptr_array_new ()) == NULL) {
    r_asn1_bin_decoder_out (dec, tlv);
    return FALSE;
  }

  do {
    RX509GeneralName * gn;
    if (tlv->start != NULL &&
        (gn = r_x509_general_name_new_from_tlv (tlv)) != NULL)
      r_ptr_array_add (*arr, gn, (RDestroyNotify) r_x509_general_name_free);
  } while (r_asn1_bin_decoder_next (dec, tlv) == R_ASN1_DECODER_OK);

  r_asn1_bin_decoder_out (dec, tlv);
  return TRUE;
}

static rboolean
r_crypto_x509_authority_key_id (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  if (R_UNLIKELY (cert->authorityKeyID.value != NULL)) return FALSE;

  (void) critical; /* Warning if critical is TRUE! */

  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return FALSE;
  if (R_ASN1_BIN_TLV_IS_ID (tlv, R_ASN1_ID_CONTEXT | 0)) {
    cert->authorityKeyID.value = r_memdup (tlv->value, tlv->len);
    cert->authorityKeyID.size = tlv->len;
    r_asn1_bin_decoder_next (dec, tlv);
  }
  if (R_ASN1_BIN_TLV_IS_ID (tlv, R_ASN1_ID_CONTEXT | R_ASN1_ID_CONSTRUCTED | 1)) {
    /* authorityCertIssuer [1] GeneralNames (implicitly-tagged SEQUENCE OF).
     * parse_general_names descends and on return tlv already sits on the
     * following sibling, so no extra next() here. */
    r_x509_parse_general_names (dec, tlv, &cert->authorityCertIssuer);
  }
  if (R_ASN1_BIN_TLV_IS_ID (tlv, R_ASN1_ID_CONTEXT | 2)) {
    /* authorityCertSerialNumber [2]: keep the raw INTEGER content for
     * a byte-exact re-emit (it has no public accessor). */
    cert->authorityCertSerial.value = r_memdup (tlv->value, tlv->len);
    cert->authorityCertSerial.size = tlv->len;
    r_asn1_bin_decoder_next (dec, tlv);
  }
  r_asn1_bin_decoder_out (dec, tlv);
  return TRUE;
}

static rboolean
r_crypto_x509_subject_key_id (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  if (R_UNLIKELY (cert->subjectKeyID.value != NULL)) return FALSE;
  if (R_UNLIKELY (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OCTET_STRING)))
    return FALSE;

  (void) dec;
  (void) critical; /* Warning if critical is TRUE! */

  cert->subjectKeyID.value = r_memdup (tlv->value, tlv->len);
  cert->subjectKeyID.size = tlv->len;
  return TRUE;
}

static rboolean
r_crypto_x509_basic_constraints (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  (void) critical;

  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return FALSE;
  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BOOLEAN)) {
    r_asn1_bin_tlv_parse_boolean (tlv, &cert->ca);
    r_asn1_bin_decoder_next (dec, tlv);
  }

  if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_INTEGER)) {
    r_asn1_bin_tlv_parse_integer_i32 (tlv, &cert->pathLen);
    cert->haspathLen = TRUE;
    r_asn1_bin_decoder_next (dec, tlv);
  }
  r_asn1_bin_decoder_out (dec, tlv);

  return TRUE;
}

static rboolean
r_crypto_x509_policy_constraints (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  (void) critical;

  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return FALSE;
  if (R_ASN1_BIN_TLV_IS_ID (tlv, R_ASN1_ID_CONTEXT | 0)) {
    r_asn1_bin_tlv_parse_integer_i32 (tlv, &cert->requireExplicitPolicy);
    r_asn1_bin_decoder_next (dec, tlv);
  }
  if (R_ASN1_BIN_TLV_IS_ID (tlv, R_ASN1_ID_CONTEXT | 1)) {
    r_asn1_bin_tlv_parse_integer_i32 (tlv, &cert->inhibitPolicyMapping);
    r_asn1_bin_decoder_next (dec, tlv);
  }
  r_asn1_bin_decoder_out (dec, tlv);

  return TRUE;
}

static rboolean
r_crypto_x509_key_usage (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  rsize content_bytes, bits, n;
  RX509KeyUsage usage = 0;

  (void) dec;
  (void) critical;

  if (R_UNLIKELY (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BIT_STRING)))
    return FALSE;
  /* Need at least the unused-bits byte + one content byte, and the
   * unused-bits value must be 0..7 per the BIT STRING spec. */
  if (R_UNLIKELY (tlv->len < 2 || tlv->value[0] > 7))
    return FALSE;

  content_bytes = tlv->len - 1;
  bits = content_bytes * 8 - tlv->value[0];
  /* KeyUsage has nine named bits (0..8); reject obviously oversized
   * encodings before they could shift past the int width. */
  if (R_UNLIKELY (bits > sizeof (RX509KeyUsage) * 8))
    return FALSE;
  /* Only nine KeyUsage bits are defined (0..8); ignore any reserved
   * high bits so the shift below can't reach the int sign bit. */
  if (bits > 9)
    bits = 9;

  /* RFC 5280 / X.690: BIT STRING bit N is the (N % 8)th bit from
   * the MSB of content byte (N / 8). Map each set BIT STRING bit N
   * to bit N of the RX509KeyUsage flag set. */
  for (n = 0; n < bits; n++) {
    if (tlv->value[1 + (n / 8)] & ((ruint8)0x80 >> (n % 8)))
      usage |= (RX509KeyUsage)1 << n;
  }
  cert->keyUsage = usage;
  return TRUE;
}

static rboolean
r_crypto_x509_ext_key_usage (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  (void) critical;

  if (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SEQUENCE))
    return FALSE;
  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return FALSE;

  /* ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId; visit every OID. */
  do {
    if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER)) {
      if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_ID_CE_OID_EXT_KEY_USAGE"\x00"))
        cert->extKeyUsage |= R_X509_EXT_KEY_USAGE_ANY;
      else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_ID_KP_OID_SERVER_AUTH))
        cert->extKeyUsage |= R_X509_EXT_KEY_USAGE_SERVER_AUTH;
      else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_ID_KP_OID_CLIENT_AUTH))
        cert->extKeyUsage |= R_X509_EXT_KEY_USAGE_CLIENT_AUTH;
      else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_ID_KP_OID_CODE_SIGNING))
        cert->extKeyUsage |= R_X509_EXT_KEY_USAGE_CODE_SIGNING;
      else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_ID_KP_OID_EMAIL_PROTECTION))
        cert->extKeyUsage |= R_X509_EXT_KEY_USAGE_EMAIL_PROTECTION;
      else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_ID_KP_OID_TIME_STAMPING))
        cert->extKeyUsage |= R_X509_EXT_KEY_USAGE_TIME_STAMPING;
      else if (r_asn1_oid_bin_equals (tlv->value, tlv->len, R_ID_KP_OID_OCSP_SIGNING))
        cert->extKeyUsage |= R_X509_EXT_KEY_USAGE_OCSP_SIGNING;
    }
  } while (r_asn1_bin_decoder_next (dec, tlv) == R_ASN1_DECODER_OK);
  r_asn1_bin_decoder_out (dec, tlv);

  return TRUE;
}

static rboolean
r_crypto_x509_certificate_policies (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  (void) critical;

  if (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SEQUENCE))
    return FALSE;
  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return FALSE;

  /* certificatePolicies ::= SEQUENCE OF PolicyInformation, each a
   * SEQUENCE whose first element is the policyIdentifier OID. Descend
   * into every PolicyInformation; r_asn1_bin_decoder_out advances to
   * the next sibling. */
  do {
    if (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SEQUENCE))
      break;
    if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
      break;
    if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER)) {
      rchar * oid;
      if (r_asn1_bin_tlv_parse_oid_to_dot (tlv, &oid) == R_ASN1_DECODER_OK)
        cert->policies = r_slist_prepend (cert->policies, oid);
    }
  } while (r_asn1_bin_decoder_out (dec, tlv) == R_ASN1_DECODER_OK);
  r_asn1_bin_decoder_out (dec, tlv);

  return TRUE;
}

static rboolean
r_crypto_x509_subject_alt_name (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  (void) critical;

  if (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SEQUENCE))
    return FALSE;
  return r_x509_parse_general_names (dec, tlv, &cert->sans);
}

static rboolean
r_crypto_x509_name_constraints (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  (void) critical;

  /* NameConstraints ::= SEQUENCE { permittedSubtrees [0] OPTIONAL,
   * excludedSubtrees [1] OPTIONAL }, each GeneralSubtrees ::= SEQUENCE
   * OF GeneralSubtree ::= SEQUENCE { base GeneralName, ... }. */
  if (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SEQUENCE))
    return FALSE;
  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return FALSE;

  /* Walk the (at most two) children. A matched subtree set is descended
   * into, and r_asn1_bin_decoder_out advances to the following child;
   * an unmatched child is stepped over with next. Both yield the same
   * status, so a single check drives the loop. */
  for (;;) {
    RAsn1DecoderStatus st;
    RPtrArray ** arr;

    if (R_ASN1_BIN_TLV_IS_ID (tlv, R_ASN1_ID_CONTEXT | R_ASN1_ID_CONSTRUCTED | 0))
      arr = &cert->ncPermitted;
    else if (R_ASN1_BIN_TLV_IS_ID (tlv, R_ASN1_ID_CONTEXT | R_ASN1_ID_CONSTRUCTED | 1))
      arr = &cert->ncExcluded;
    else
      arr = NULL;

    if (arr == NULL) {
      st = r_asn1_bin_decoder_next (dec, tlv);
    } else if (*arr == NULL && (*arr = r_ptr_array_new ()) == NULL) {
      break;
    } else if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK) {
      break;
    } else {
      /* This [0]/[1] is the GeneralSubtrees SEQUENCE OF; descend into
       * each GeneralSubtree to reach its base GeneralName. */
      do {
        if (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SEQUENCE))
          break;
        if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
          break;
        if (tlv->start != NULL) {
          RX509GeneralName * gn = r_x509_general_name_new_from_tlv (tlv);
          if (gn != NULL)
            r_ptr_array_add (*arr, gn, (RDestroyNotify) r_x509_general_name_free);
        }
      } while (r_asn1_bin_decoder_out (dec, tlv) == R_ASN1_DECODER_OK);
      st = r_asn1_bin_decoder_out (dec, tlv);
    }

    if (st != R_ASN1_DECODER_OK)
      break;
  }

  r_asn1_bin_decoder_out (dec, tlv);
  return TRUE;
}

static rboolean
r_crypto_x509_policy_mappings (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv, rboolean critical)
{
  (void) critical;

  /* PolicyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy OID,
   * subjectDomainPolicy OID }. */
  if (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SEQUENCE))
    return FALSE;
  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
    return FALSE;

  if (cert->policyMappings == NULL &&
      (cert->policyMappings = r_ptr_array_new ()) == NULL) {
    r_asn1_bin_decoder_out (dec, tlv);
    return FALSE;
  }

  do {
    RX509PolicyMapping * pm;

    if (!R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_SEQUENCE))
      break;
    if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK)
      break;

    if ((pm = r_mem_new0 (RX509PolicyMapping)) != NULL) {
      if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER))
        r_asn1_bin_tlv_parse_oid_to_dot (tlv, &pm->issuer);
      if (r_asn1_bin_decoder_next (dec, tlv) == R_ASN1_DECODER_OK &&
          R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER))
        r_asn1_bin_tlv_parse_oid_to_dot (tlv, &pm->subject);
      r_ptr_array_add (cert->policyMappings, pm,
          (RDestroyNotify) r_x509_policy_mapping_free);
    }
  } while (r_asn1_bin_decoder_out (dec, tlv) == R_ASN1_DECODER_OK);

  r_asn1_bin_decoder_out (dec, tlv);
  return TRUE;
}

static rboolean
r_crypto_x509_cert_v3_parse_extensions (RCryptoX509Cert * cert,
    RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  RAsn1DecoderStatus res;
  static const struct {
    const rchar * oid;
    rsize oidsize;
    RCertX509ExtFunc func;
  } exttbl[] = {
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_AUTHORITY_KEY_ID), r_crypto_x509_authority_key_id },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_SUBJECT_KEY_ID), r_crypto_x509_subject_key_id },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_BASIC_CONSTRAINTS), r_crypto_x509_basic_constraints },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_NAME_CONSTRAINTS), r_crypto_x509_name_constraints },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_POLICY_CONSTRAINTS), r_crypto_x509_policy_constraints },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_KEY_USAGE), r_crypto_x509_key_usage },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_EXT_KEY_USAGE), r_crypto_x509_ext_key_usage },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_CERTIFICATE_POLICIES), r_crypto_x509_certificate_policies },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_SUBJECT_ALT_NAME), r_crypto_x509_subject_alt_name },
    { R_STR_WITH_SIZE_ARGS (R_ID_CE_OID_POLICY_MAPPINGS), r_crypto_x509_policy_mappings },
  };

  if (R_UNLIKELY (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK))
    return FALSE;

  do {
    if (R_UNLIKELY (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK))
      break;

    if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OBJECT_IDENTIFIER)) {
      const ruint8 * oidp = tlv->value;
      rsize oidsize = tlv->len;
      rboolean critical = FALSE;
      ruint i;

      r_asn1_bin_decoder_next (dec, tlv);

      if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_BOOLEAN)) {
        r_asn1_bin_tlv_parse_boolean (tlv, &critical);
        r_asn1_bin_decoder_next (dec, tlv);
      }

      if (R_ASN1_BIN_TLV_ID_IS_TAG (tlv, R_ASN1_ID_OCTET_STRING) &&
          r_asn1_bin_decoder_into (dec, tlv) == R_ASN1_DECODER_OK) {
        for (i = 0; i < R_N_ELEMENTS (exttbl); i++) {
          if (r_asn1_oid_bin_equals_full (oidp, oidsize,
                exttbl[i].oid, exttbl[i].oidsize)) {
            exttbl[i].func (cert, dec, tlv, critical);
            break;
          }
        }
        r_asn1_bin_decoder_out (dec, tlv);
      }
    }
  } while ((res = r_asn1_bin_decoder_out (dec, tlv)) == R_ASN1_DECODER_OK);

  r_asn1_bin_decoder_out (dec, tlv);
  return res == R_ASN1_DECODER_EOC;
}

/* Store a serialNumber INTEGER's raw magnitude (DER leading-zero sign byte
 * stripped), capped to the buffer; a serial can be up to 20 octets, too wide
 * for a 64-bit integer. */
static void
r_crypto_x509_cert_store_serial (RCryptoX509Cert * cert, const RAsn1BinTLV * tlv)
{
  const ruint8 * v = tlv->value;
  rsize n = tlv->len;

  while (n > 1 && v[0] == 0x00) { v++; n--; }
  if (n > sizeof (cert->serial)) { v += n - sizeof (cert->serial); n = sizeof (cert->serial); }
  r_memcpy (cert->serial, v, n);
  cert->seriallen = (ruint8) n;
}

static rboolean
r_crypto_x509_cert_init (RCryptoX509Cert * cert, RAsn1BinDecoder * dec)
{
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;

  if (R_UNLIKELY (r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK))
    return FALSE;

  /* X.509 Certificate */
  if (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) {
    const ruint8 * tbs = tlv.start;
    rsize tbssize = RPOINTER_TO_SIZE (tlv.value - tlv.start) + tlv.len;
    RMsgDigest * md;
    rboolean is_eddsa;

    /* TBSCertificate */
    if (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) {
      /* version - Optional */
      if (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) {
        rint32 ver;
        if (r_asn1_bin_tlv_parse_integer_i32 (&tlv, &ver) != R_ASN1_DECODER_OK ||
            ver < R_X509_VERSION_V1 || ver > R_X509_VERSION_SUPPORTED)
          goto beach;
        cert->version = ver;
        r_asn1_bin_decoder_out (dec, &tlv);
      } else {
        cert->version = R_X509_VERSION_V1; /* Default value*/
      }
      /* serialNumber */
      if (!R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER))
        goto beach;
      r_crypto_x509_cert_store_serial (cert, &tlv);
      if (r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK)
        goto beach;
      /* signature - Skip */
      if (r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK)
        goto beach;
      /* issuer */
      if (r_asn1_bin_tlv_parse_distinguished_name (dec, &tlv, &cert->issuer) != R_ASN1_DECODER_OK)
        goto beach;
      /* validity */
      if (r_asn1_bin_decoder_into (dec, &tlv) != R_ASN1_DECODER_OK ||
          r_asn1_bin_tlv_parse_time (&tlv, &cert->cert.valid_from) != R_ASN1_DECODER_OK ||
          r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK ||
          r_asn1_bin_tlv_parse_time (&tlv, &cert->cert.valid_to) != R_ASN1_DECODER_OK ||
          r_asn1_bin_decoder_out (dec, &tlv) != R_ASN1_DECODER_OK)
        goto beach;
      /* subject */
      if (r_asn1_bin_tlv_parse_distinguished_name (dec, &tlv, &cert->subject) != R_ASN1_DECODER_OK)
        goto beach;
      /* subjectPublicKeyInfo */
      if ((cert->cert.pk = r_crypto_key_from_asn1_public_key (dec, &tlv)) == NULL)
        goto beach;

      if (cert->version > R_X509_VERSION_V1) {
        if (R_ASN1_BIN_TLV_IS_ID (&tlv, R_ASN1_ID_CONTEXT | R_ASN1_ID_CONSTRUCTED | 1)) {
          if (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) {
            rsize bits;
            if (r_asn1_bin_tlv_parse_bit_string_bits (&tlv, &bits) == R_ASN1_DECODER_OK && (bits % 8) == 0) {
              cert->issuerUniqueID.value = r_memdup (r_asn1_bin_tlv_bit_string_value (&tlv), bits / 8);
              cert->issuerUniqueID.size = bits / 8;
            }
            r_asn1_bin_decoder_out (dec, &tlv);
          }
        }
        if (R_ASN1_BIN_TLV_IS_ID (&tlv, R_ASN1_ID_CONTEXT | R_ASN1_ID_CONSTRUCTED | 2)) {
          if (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) {
            rsize bits;
            if (r_asn1_bin_tlv_parse_bit_string_bits (&tlv, &bits) == R_ASN1_DECODER_OK && (bits % 8) == 0) {
              cert->subjectUniqueID.value = r_memdup (r_asn1_bin_tlv_bit_string_value (&tlv), bits / 8);
              cert->subjectUniqueID.size = bits / 8;
            }
            r_asn1_bin_decoder_out (dec, &tlv);
          }
        }
        if (cert->version > R_X509_VERSION_V2) {
          if (R_ASN1_BIN_TLV_IS_ID (&tlv, R_ASN1_ID_CONTEXT | R_ASN1_ID_CONSTRUCTED | 3)) {
            if (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) {
              /*rboolean ret = */r_crypto_x509_cert_v3_parse_extensions (cert, dec, &tlv);
              r_asn1_bin_decoder_out (dec, &tlv);
              /*if (!ret)*/
                /*goto beach;*/
            }
          }
        }
      }

      r_asn1_bin_decoder_out (dec, &tlv);
    } else goto beach;

    /* signatureAlgorithm */
    if (r_asn1_bin_decoder_into (dec, &tlv) != R_ASN1_DECODER_OK)
      goto beach;
    /* PureEdDSA (Ed25519) signs the TBSCertificate directly; there is no
     * digest OID and no pre-hash, so keep a copy of the raw TBS for
     * verification instead of the signhash the hashed schemes precompute. */
    is_eddsa = r_asn1_oid_bin_equals (tlv.value, tlv.len, R_RFC8410_OID_ED25519);
    if (r_asn1_bin_tlv_parse_oid_to_msg_digest_type (&tlv, &cert->cert.signalgo) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_out (dec, &tlv) != R_ASN1_DECODER_OK) {
      goto beach;
    }

    if (is_eddsa) {
      cert->cert.signalgo = R_MSG_DIGEST_TYPE_NONE;
      if ((cert->cert.tbs = r_memdup (tbs, tbssize)) == NULL)
        goto beach;
      cert->cert.tbssize = tbssize;
    } else if ((md = r_msg_digest_new (cert->cert.signalgo)) != NULL) {
      if (!r_msg_digest_update (md, tbs, tbssize) ||
          !r_msg_digest_get_data (md, cert->cert.signhash, sizeof (cert->cert.signhash), NULL)) {
        r_msg_digest_free (md);
        goto beach;
      }

      r_msg_digest_free (md);
    } else goto beach;

    /* signature */
    if (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_BIT_STRING) &&
        r_asn1_bin_tlv_parse_bit_string_bits (&tlv, &cert->cert.signbits) == R_ASN1_DECODER_OK &&
        cert->cert.signbits >= 8) {
      cert->cert.sign = r_memdup (r_asn1_bin_tlv_bit_string_value (&tlv), cert->cert.signbits / 8);
      if (R_UNLIKELY (cert->cert.sign == NULL)) goto beach;
    } else goto beach;

    return TRUE;
  }

beach:
  return FALSE;
}

static rboolean r_x509_write_oid_from_dot (RAsn1BinEncoder * enc, const rchar * dot);

/* Emit each GeneralName verbatim: its original context tag and the
 * stored content reproduce the CHOICE alternative byte-for-byte. */
static rboolean
r_crypto_x509_write_general_names (RAsn1BinEncoder * enc, const RPtrArray * arr)
{
  rsize i, n = (arr != NULL) ? r_ptr_array_size (arr) : 0;

  for (i = 0; i < n; i++) {
    const RX509GeneralName * gn = r_ptr_array_get_const (arr, i);
    if (r_asn1_bin_encoder_add_raw (enc, gn->id, gn->raw, gn->rawsize) != R_ASN1_ENCODER_OK)
      return FALSE;
  }

  return TRUE;
}

static rboolean
r_crypto_x509_write_ext_subject_alt_name (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;

  if (cert->sans == NULL || r_ptr_array_size (cert->sans) == 0)
    return TRUE;

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_SUBJECT_ALT_NAME) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
          ret = r_crypto_x509_write_general_names (enc, cert->sans);
          r_asn1_bin_encoder_end_constructed (enc);
        }
        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

/* Emit one GeneralSubtrees set ([0] permitted / [1] excluded), each
 * base GeneralName wrapped in a GeneralSubtree SEQUENCE. */
static rboolean
r_crypto_x509_write_name_constraint_subtrees (RAsn1BinEncoder * enc,
    const RPtrArray * arr, ruint tag)
{
  const ruint8 seqid = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;
  rsize i, n = r_ptr_array_size (arr);

  if (r_asn1_bin_encoder_begin_constructed (enc,
        R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_CONSTRUCTED, tag), 0) != R_ASN1_ENCODER_OK)
    return FALSE;

  ret = TRUE;
  for (i = 0; i < n && ret; i++) {
    const RX509GeneralName * gn = r_ptr_array_get_const (arr, i);
    ret = FALSE;
    if (r_asn1_bin_encoder_begin_constructed (enc, seqid, 0) == R_ASN1_ENCODER_OK) {
      ret = r_asn1_bin_encoder_add_raw (enc, gn->id, gn->raw, gn->rawsize) == R_ASN1_ENCODER_OK;
      r_asn1_bin_encoder_end_constructed (enc);
    }
  }

  r_asn1_bin_encoder_end_constructed (enc);
  return ret;
}

static rboolean
r_crypto_x509_write_ext_name_constraints (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;
  rboolean have_p = cert->ncPermitted != NULL && r_ptr_array_size (cert->ncPermitted) > 0;
  rboolean have_e = cert->ncExcluded != NULL && r_ptr_array_size (cert->ncExcluded) > 0;

  if (!have_p && !have_e)
    return TRUE;

  /* Mark critical (RFC 5280 §4.2.1.10: NameConstraints MUST be critical). */
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_NAME_CONSTRAINTS) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_boolean (enc, TRUE) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
          ret = TRUE;
          if (ret && have_p)
            ret = r_crypto_x509_write_name_constraint_subtrees (enc, cert->ncPermitted, 0);
          if (ret && have_e)
            ret = r_crypto_x509_write_name_constraint_subtrees (enc, cert->ncExcluded, 1);
          r_asn1_bin_encoder_end_constructed (enc);
        }
        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static rboolean
r_crypto_x509_write_ext_policy_mappings (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;
  rsize i, n = (cert->policyMappings != NULL) ? r_ptr_array_size (cert->policyMappings) : 0;

  if (n == 0)
    return TRUE;

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_POLICY_MAPPINGS) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
          ret = TRUE;
          for (i = 0; i < n && ret; i++) {
            const RX509PolicyMapping * pm = r_ptr_array_get_const (cert->policyMappings, i);
            ret = FALSE;
            if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
              ret = r_x509_write_oid_from_dot (enc, pm->issuer) &&
                    r_x509_write_oid_from_dot (enc, pm->subject);
              r_asn1_bin_encoder_end_constructed (enc);
            }
          }
          r_asn1_bin_encoder_end_constructed (enc);
        }
        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static rboolean
r_crypto_x509_write_ext_basic_constraints (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;

  if (cert->pathLen == 0 && cert->ca == FALSE)
    return TRUE;

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_BASIC_CONSTRAINTS) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
          r_asn1_bin_encoder_add_boolean (enc, cert->ca);
          if (cert->pathLen > 0)
            r_asn1_bin_encoder_add_integer_i32 (enc, cert->pathLen);

          ret = TRUE;
          r_asn1_bin_encoder_end_constructed (enc);
        }

        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }

    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static rboolean
r_crypto_x509_write_ext_key_usage (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;
  RX509KeyUsage usage = cert->keyUsage;
  ruint8 bsbuf[3] = { 0, };
  ruint used_bits = 0, n, nbytes;

  if (usage == R_X509_KEY_USAGE_NONE)
    return TRUE;

  /* RFC 5280 / X.690 minimal DER: bit N of KeyUsage lives at the
   * (N % 8)th position from the MSB of content byte (N / 8). Find
   * the highest set bit to size the encoding, then place each set
   * bit at its MSB-relative position. */
  for (n = 0; n < sizeof (RX509KeyUsage) * 8; n++) {
    if (usage & ((RX509KeyUsage)1 << n))
      used_bits = n + 1;
  }
  nbytes = (used_bits + 7) / 8;
  for (n = 0; n < used_bits; n++) {
    if (usage & ((RX509KeyUsage)1 << n))
      bsbuf[1 + (n / 8)] |= (ruint8)0x80 >> (n % 8);
  }
  bsbuf[0] = (ruint8)(nbytes * 8 - used_bits);

  /* Mark critical */
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_KEY_USAGE) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_boolean (enc, TRUE) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        /* add_bit_string_raw always emits unused-bits = 0 and the
         * raw bytes after, so use add_raw with an unused-bits byte
         * we control. */
        ret = r_asn1_bin_encoder_add_raw (enc,
            R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_BIT_STRING),
            bsbuf, 1 + nbytes) == R_ASN1_ENCODER_OK;
        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }

    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static rboolean
r_crypto_x509_write_ext_ext_key_usage (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;

  if (cert->extKeyUsage == R_X509_EXT_KEY_USAGE_NONE)
    return TRUE;

  /* ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId: all purpose OIDs are
   * direct children of one SEQUENCE inside the extnValue OCTET STRING. */
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_EXT_KEY_USAGE) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
          ret = TRUE;
          if (cert->extKeyUsage & R_X509_EXT_KEY_USAGE_ANY)
            r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_EXT_KEY_USAGE"\x00");
          if (cert->extKeyUsage & R_X509_EXT_KEY_USAGE_SERVER_AUTH)
            r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_KP_OID_SERVER_AUTH);
          if (cert->extKeyUsage & R_X509_EXT_KEY_USAGE_CLIENT_AUTH)
            r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_KP_OID_CLIENT_AUTH);
          if (cert->extKeyUsage & R_X509_EXT_KEY_USAGE_CODE_SIGNING)
            r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_KP_OID_CODE_SIGNING);
          if (cert->extKeyUsage & R_X509_EXT_KEY_USAGE_EMAIL_PROTECTION)
            r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_KP_OID_EMAIL_PROTECTION);
          if (cert->extKeyUsage & R_X509_EXT_KEY_USAGE_TIME_STAMPING)
            r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_KP_OID_TIME_STAMPING);
          if (cert->extKeyUsage & R_X509_EXT_KEY_USAGE_OCSP_SIGNING)
            r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_KP_OID_OCSP_SIGNING);
          r_asn1_bin_encoder_end_constructed (enc);
        }
        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }

    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static rboolean
r_crypto_x509_write_ext_subject_key_id (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;

  if (cert->subjectKeyID.value == NULL)
    return TRUE;

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_SUBJECT_KEY_ID) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_add_raw (enc,
              R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OCTET_STRING),
              cert->subjectKeyID.value, cert->subjectKeyID.size) == R_ASN1_ENCODER_OK)
          ret = TRUE;

        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }

    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static rboolean
r_crypto_x509_write_ext_authority_key_id (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;
  rboolean have_issuer = cert->authorityCertIssuer != NULL &&
      r_ptr_array_size (cert->authorityCertIssuer) > 0;

  if (cert->authorityKeyID.value == NULL && !have_issuer)
    return TRUE;

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_AUTHORITY_KEY_ID) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
          ret = TRUE;
          /* keyIdentifier [0] */
          if (ret && cert->authorityKeyID.value != NULL)
            ret = r_asn1_bin_encoder_add_raw (enc,
                R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_PRIMITIVE, 0),
                cert->authorityKeyID.value, cert->authorityKeyID.size) == R_ASN1_ENCODER_OK;
          /* authorityCertIssuer [1] and authorityCertSerialNumber [2]
           * are both-present-or-both-absent (RFC 5280 §4.2.1.1). */
          if (ret && have_issuer) {
            if (r_asn1_bin_encoder_begin_constructed (enc,
                  R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_CONSTRUCTED, 1), 0) == R_ASN1_ENCODER_OK) {
              ret = r_crypto_x509_write_general_names (enc, cert->authorityCertIssuer);
              r_asn1_bin_encoder_end_constructed (enc);
            } else {
              ret = FALSE;
            }
            if (ret && cert->authorityCertSerial.value != NULL)
              ret = r_asn1_bin_encoder_add_raw (enc,
                  R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_PRIMITIVE, 2),
                  cert->authorityCertSerial.value, cert->authorityCertSerial.size) == R_ASN1_ENCODER_OK;
          }
          r_asn1_bin_encoder_end_constructed (enc);
        }

        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }

    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static rboolean
r_crypto_x509_write_ext_policy_constraints (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;

  if (cert->requireExplicitPolicy == 0 && cert->inhibitPolicyMapping == 0)
    return TRUE;

  /* Mark critical */
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_POLICY_CONSTRAINTS) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_boolean (enc, TRUE) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_octet_string (enc, 0) == R_ASN1_ENCODER_OK) {
        if (cert->requireExplicitPolicy != 0) {
          if (r_asn1_bin_encoder_begin_constructed (enc,
                R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_CONSTRUCTED, 0),
                0) == R_ASN1_ENCODER_OK) {
            r_asn1_bin_encoder_add_integer_i32 (enc, cert->requireExplicitPolicy);
            r_asn1_bin_encoder_end_constructed (enc);
          }
        }

        if (cert->inhibitPolicyMapping != 0) {
          if (r_asn1_bin_encoder_begin_constructed (enc,
                R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_CONSTRUCTED, 1),
                0) == R_ASN1_ENCODER_OK) {
            r_asn1_bin_encoder_add_integer_i32 (enc, cert->inhibitPolicyMapping);
            r_asn1_bin_encoder_end_constructed (enc);
          }
        }

        ret = TRUE;
        r_asn1_bin_encoder_end_octet_string (enc);
      }
    }

    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

/* Encode a dot-notation OID and emit it as a primitive OBJECT IDENTIFIER
 * TLV. Cannot use r_asn1_bin_encoder_add_oid_rawsz here because the
 * encoded binary form may legitimately contain 0x00 bytes (arcs of
 * value zero), which would prematurely terminate r_strlen. */
static rboolean
r_x509_write_oid_from_dot (RAsn1BinEncoder * enc, const rchar * dot)
{
  ruint32 * arr;
  ruint8 * buf;
  rsize len, bufsize = 1, i, j, k;
  rboolean ret = FALSE;

  if ((arr = r_asn1_oid_from_dot (dot, -1, &len)) == NULL)
    return FALSE;
  if (len < 2)
    goto out_arr;

  for (i = 2; i < len; i++) {
    ruint32 v = arr[i];
    bufsize++;
    while ((v >>= 7) != 0)
      bufsize++;
  }

  if ((buf = r_malloc (bufsize)) == NULL)
    goto out_arr;

  buf[0] = (ruint8)(arr[0] * 40 + arr[1]);
  j = 1;
  for (i = 2; i < len; i++) {
    ruint32 v = arr[i];
    rsize nbytes = 1;
    ruint32 tmp = v >> 7;
    while (tmp != 0) {
      nbytes++;
      tmp >>= 7;
    }
    for (k = 0; k < nbytes; k++) {
      ruint8 b = (v >> ((nbytes - 1 - k) * 7)) & 0x7F;
      if (k + 1 < nbytes)
        b |= 0x80;
      buf[j + k] = b;
    }
    j += nbytes;
  }

  ret = r_asn1_bin_encoder_add_raw (enc,
      R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OBJECT_IDENTIFIER),
      buf, bufsize) == R_ASN1_ENCODER_OK;
  r_free (buf);

out_arr:
  r_free (arr);
  return ret;
}

static rboolean
r_crypto_x509_write_ext_certificate_policies (const RCryptoX509Cert * cert,
    RAsn1BinEncoder * enc)
{
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  rboolean ret = FALSE;
  RSList * cur;

  if (cert->policies == NULL)
    return TRUE;

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) != R_ASN1_ENCODER_OK)
    return FALSE;

  if (r_asn1_bin_encoder_add_oid_rawsz (enc, R_ID_CE_OID_CERTIFICATE_POLICIES) != R_ASN1_ENCODER_OK)
    goto end_outer;

  if (r_asn1_bin_encoder_begin_octet_string (enc, 0) != R_ASN1_ENCODER_OK)
    goto end_outer;

  /* certificatePolicies ::= SEQUENCE OF PolicyInformation: one outer
   * SEQUENCE holds a PolicyInformation SEQUENCE per policyIdentifier. */
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    ret = TRUE;
    for (cur = cert->policies; cur != NULL && ret; cur = cur->next) {
      ret = FALSE;
      if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
        ret = r_x509_write_oid_from_dot (enc, (const rchar *)cur->data);
        r_asn1_bin_encoder_end_constructed (enc);
      }
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  r_asn1_bin_encoder_end_octet_string (enc);

end_outer:
  r_asn1_bin_encoder_end_constructed (enc);
  return ret;
}

static const rchar *
r_rsa_signalgo_get_asn1_oid (RMsgDigestType signalgo)
{
  switch (signalgo) {
    case R_MSG_DIGEST_TYPE_MD2:
      return R_RSA_OID_MD2_WITH_RSA;
    case R_MSG_DIGEST_TYPE_MD5:
      return R_RSA_OID_MD5_WITH_RSA;
    case R_MSG_DIGEST_TYPE_SHA1:
      return R_RSA_OID_SHA1_WITH_RSA;
    case R_MSG_DIGEST_TYPE_SHA256:
      return R_RSA_OID_SHA256_WITH_RSA;
    case R_MSG_DIGEST_TYPE_SHA384:
      return R_RSA_OID_SHA384_WITH_RSA;
    case R_MSG_DIGEST_TYPE_SHA512:
      return R_RSA_OID_SHA512_WITH_RSA;
    case R_MSG_DIGEST_TYPE_SHA224:
      return R_RSA_OID_SHA224_WITH_RSA;
    default:
      break;
  }

  return NULL;
}

static const rchar *
r_crypto_cert_get_asn1_oid_signalgo (RCryptoAlgorithm cryptoalgo, RMsgDigestType signalgo)
{
  switch (cryptoalgo) {
    case R_CRYPTO_ALGO_RSA:
      return r_rsa_signalgo_get_asn1_oid (signalgo);
    default:
      break;
  }

  return NULL;
}

static RCryptoResult
r_crypto_x509_cert_export (const RCryptoCert * ccert, RAsn1BinEncoder * enc)
{
  RCryptoResult ret = R_CRYPTO_ERROR;
  const RCryptoX509Cert * cert = (const RCryptoX509Cert *)ccert;
  const ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  const rchar * algo = r_crypto_cert_get_asn1_oid_signalgo (
      r_crypto_key_get_algo (ccert->pk), ccert->signalgo);

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    /* TBSCertificate */
    if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
      /* version */
      if (cert->version > R_X509_VERSION_V1) {
        if (r_asn1_bin_encoder_begin_constructed (enc,
              R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_CONSTRUCTED, 0),
              0) == R_ASN1_ENCODER_OK) {
          if (r_asn1_bin_encoder_add_integer_i32 (enc, cert->version) == R_ASN1_ENCODER_OK)
            ret = R_CRYPTO_OK;
          r_asn1_bin_encoder_end_constructed (enc);
        }
        if (ret != R_CRYPTO_OK) goto beach;
        else ret = R_CRYPTO_ERROR;
      }

      /* serialNumber */
      {
        rmpint serial;
        RAsn1EncoderStatus es;
        r_mpint_init_binary (&serial, cert->serial, cert->seriallen);
        es = r_asn1_bin_encoder_add_integer_mpint (enc, &serial);
        r_mpint_clear (&serial);
        if (es != R_ASN1_ENCODER_OK)
          goto beach;
      }

      /* signature algo */
      if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_add_oid_rawsz (enc, algo) == R_ASN1_ENCODER_OK &&
            r_asn1_bin_encoder_add_null (enc) == R_ASN1_ENCODER_OK)
          ret = R_CRYPTO_OK;
        r_asn1_bin_encoder_end_constructed (enc);
      }
      if (ret != R_CRYPTO_OK) goto beach;
      else ret = R_CRYPTO_ERROR;

      /* issuer - distinguished name */
      if (r_asn1_bin_encoder_add_distinguished_name (enc, cert->issuer) != R_ASN1_ENCODER_OK)
        goto beach;

      /* validity */
      if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_add_utc_time (enc, ccert->valid_from) == R_ASN1_ENCODER_OK &&
            r_asn1_bin_encoder_add_utc_time (enc, ccert->valid_to) == R_ASN1_ENCODER_OK)
          ret = R_CRYPTO_OK;
        r_asn1_bin_encoder_end_constructed (enc);
      }
      if (ret != R_CRYPTO_OK) goto beach;
      else ret = R_CRYPTO_ERROR;

      /* subject - distinguished name */
      if (r_asn1_bin_encoder_add_distinguished_name (enc, cert->subject) != R_ASN1_ENCODER_OK)
        goto beach;

      /* subjectPublicKeyInfo */
      if ((ret = r_crypto_key_to_asn1 (ccert->pk, enc)) != R_CRYPTO_OK)
        goto beach;
      else
        ret = R_CRYPTO_ERROR;

      if (cert->version > R_X509_VERSION_V1) {
        if (cert->issuerUniqueID.value != NULL) {
          if (r_asn1_bin_encoder_begin_constructed (enc,
                R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_CONSTRUCTED, 1),
                0) == R_ASN1_ENCODER_OK) {
            if (r_asn1_bin_encoder_add_bit_string_raw (enc,
                cert->issuerUniqueID.value, cert->issuerUniqueID.size) == R_ASN1_ENCODER_OK)
              ret = R_CRYPTO_OK;
            r_asn1_bin_encoder_end_constructed (enc);
          }
          if (ret != R_CRYPTO_OK) goto beach;
          else ret = R_CRYPTO_ERROR;
        }
        if (cert->subjectUniqueID.value != NULL) {
          if (r_asn1_bin_encoder_begin_constructed (enc,
                R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_CONSTRUCTED, 2),
                0) == R_ASN1_ENCODER_OK) {
            if (r_asn1_bin_encoder_add_bit_string_raw (enc,
                cert->subjectUniqueID.value, cert->subjectUniqueID.size) == R_ASN1_ENCODER_OK)
              ret = R_CRYPTO_OK;
            r_asn1_bin_encoder_end_constructed (enc);
          }
          if (ret != R_CRYPTO_OK) goto beach;
          else ret = R_CRYPTO_ERROR;
        }
      }
      if (cert->version > R_X509_VERSION_V2) {
        /* extensions */
        if (r_asn1_bin_encoder_begin_constructed (enc,
              R_ASN1_ID (R_ASN1_ID_CONTEXT, R_ASN1_ID_CONSTRUCTED, 3),
              0) == R_ASN1_ENCODER_OK) {
          if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
            if (r_crypto_x509_write_ext_subject_key_id (cert, enc) &&
                r_crypto_x509_write_ext_authority_key_id (cert, enc) &&
                r_crypto_x509_write_ext_basic_constraints (cert, enc) &&
                r_crypto_x509_write_ext_key_usage (cert, enc) &&
                r_crypto_x509_write_ext_ext_key_usage (cert, enc) &&
                r_crypto_x509_write_ext_policy_constraints (cert, enc) &&
                r_crypto_x509_write_ext_certificate_policies (cert, enc) &&
                r_crypto_x509_write_ext_subject_alt_name (cert, enc) &&
                r_crypto_x509_write_ext_name_constraints (cert, enc) &&
                r_crypto_x509_write_ext_policy_mappings (cert, enc))
              ret = R_CRYPTO_OK;
            r_asn1_bin_encoder_end_constructed (enc);
          }
          r_asn1_bin_encoder_end_constructed (enc);
        }
        if (ret != R_CRYPTO_OK) goto beach;
        else ret = R_CRYPTO_ERROR;
      }

      ret = R_CRYPTO_OK;
beach:
      r_asn1_bin_encoder_end_constructed (enc);
    }

    if (ret == R_CRYPTO_OK) {
      /* signatureAlgorithm */
      if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
        if (r_asn1_bin_encoder_add_oid_rawsz (enc, algo) != R_ASN1_ENCODER_OK ||
            r_asn1_bin_encoder_add_null (enc) != R_ASN1_ENCODER_OK)
          ret = R_CRYPTO_ERROR;
        r_asn1_bin_encoder_end_constructed (enc);
      }
    }

    if (ret == R_CRYPTO_OK) {
      /* signature */
      if (r_asn1_bin_encoder_add_bit_string_raw (enc,
            ccert->sign, ccert->signbits / 8) != R_ASN1_ENCODER_OK)
        ret = R_CRYPTO_ERROR;
    }

    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static void
r_crypto_x509_cert_free (RCryptoX509Cert * cert)
{
  r_crypto_cert_destroy ((RCryptoCert *)cert);
  r_free (cert->issuer);
  r_free (cert->subject);
  r_free (cert->issuerUniqueID.value);
  r_free (cert->subjectUniqueID.value);
  r_free (cert->subjectKeyID.value);
  r_free (cert->authorityKeyID.value);
  r_free (cert->authorityCertSerial.value);
  r_free (cert->authority);
  r_slist_destroy_full (cert->policies, r_free);
  if (cert->sans != NULL) r_ptr_array_unref (cert->sans);
  if (cert->authorityCertIssuer != NULL) r_ptr_array_unref (cert->authorityCertIssuer);
  if (cert->ncPermitted != NULL) r_ptr_array_unref (cert->ncPermitted);
  if (cert->ncExcluded != NULL) r_ptr_array_unref (cert->ncExcluded);
  if (cert->policyMappings != NULL) r_ptr_array_unref (cert->policyMappings);
  r_free (cert);
}

RCryptoCert *
r_crypto_x509_cert_new (rconstpointer data, rsize size)
{
  RBuffer * buf;
  RCryptoCert * ret;

  if ((buf = r_buffer_new_dup (data, size)) != NULL) {
    ret = r_crypto_x509_cert_new_from_buffer (buf);
    r_buffer_unref (buf);
  } else {
    ret = NULL;
  }

  return ret;
}

RCryptoCert *
r_crypto_x509_cert_new_take (rpointer data, rsize size)
{
  RBuffer * buf;
  RCryptoCert * ret;

  if ((buf = r_buffer_new_take (data, size)) != NULL) {
    ret = r_crypto_x509_cert_new_from_buffer (buf);
    r_buffer_unref (buf);
  } else {
    ret = NULL;
  }

  return ret;
}

RCryptoCert *
r_crypto_x509_cert_new_from_buffer (RBuffer * buf)
{
  RAsn1BinDecoder * dec;
  RCryptoX509Cert * ret;

  if (R_UNLIKELY (buf == NULL))
    return NULL;

  if ((ret = r_mem_new0 (RCryptoX509Cert)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;
    r_ref_init (ret, r_crypto_x509_cert_free);
    ret->cert.export = r_crypto_x509_cert_export;

    if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
      if ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, info.data, info.size)) != NULL) {
        ret->cert.type = R_CRYPTO_CERT_X509;
        ret->cert.strtype = "X.509";
        ret->cert.certdata = r_buffer_ref (buf);

        if (!r_crypto_x509_cert_init (ret, dec)) {
          r_crypto_cert_unref (ret);
          ret = NULL;
        }
        r_asn1_bin_decoder_unref (dec);
      } else {
        r_crypto_cert_unref (ret);
        ret = NULL;
      }
      r_buffer_unmap (buf, &info);
    } else {
      r_crypto_cert_unref (ret);
      ret = NULL;
    }
  }

  return (RCryptoCert *)ret;
}

RX509Version
r_crypto_x509_cert_version (const RCryptoCert * cert)
{
  return ((const RCryptoX509Cert *)cert)->version;
}

ruint64
r_crypto_x509_cert_serial_number (const RCryptoCert * cert)
{
  const RCryptoX509Cert * c = (const RCryptoX509Cert *)cert;
  ruint64 v = 0;
  ruint8 i;

  /* Low 64 bits for serials wider than 8 bytes (the full value is available
   * via r_crypto_x509_cert_serial). */
  for (i = 0; i < c->seriallen; i++)
    v = (v << 8) | c->serial[i];

  return v;
}

const ruint8 *
r_crypto_x509_cert_serial (const RCryptoCert * cert, rsize * size)
{
  const RCryptoX509Cert * c = (const RCryptoX509Cert *)cert;

  if (size != NULL)
    *size = c->seriallen;
  return c->serial;
}

const rchar *
r_crypto_x509_cert_issuer (const RCryptoCert * cert)
{
  return ((const RCryptoX509Cert *)cert)->issuer;
}

const rchar *
r_crypto_x509_cert_subject (const RCryptoCert * cert)
{
  return ((const RCryptoX509Cert *)cert)->subject;
}

const ruint8 *
r_crypto_x509_cert_issuer_unique_id (const RCryptoCert * cert, rsize * size)
{
  if (size != NULL)
    *size = ((const RCryptoX509Cert *)cert)->issuerUniqueID.size;
  return ((const RCryptoX509Cert *)cert)->issuerUniqueID.value;
}

const ruint8 *
r_crypto_x509_cert_subject_unique_id (const RCryptoCert * cert, rsize * size)
{
  if (size != NULL)
    *size = ((const RCryptoX509Cert *)cert)->subjectUniqueID.size;
  return ((const RCryptoX509Cert *)cert)->subjectUniqueID.value;
}

const ruint8 *
r_crypto_x509_cert_subject_key_id (const RCryptoCert * cert, rsize * size)
{
  if (size != NULL)
    *size = ((const RCryptoX509Cert *)cert)->subjectKeyID.size;
  return ((const RCryptoX509Cert *)cert)->subjectKeyID.value;
}

const ruint8 *
r_crypto_x509_cert_authority_key_id (const RCryptoCert * cert, rsize * size)
{
  if (size != NULL)
    *size = ((const RCryptoX509Cert *)cert)->authorityKeyID.size;
  return ((const RCryptoX509Cert *)cert)->authorityKeyID.value;
}

RX509KeyUsage
r_crypto_x509_cert_key_usage (const RCryptoCert * cert)
{
  return ((const RCryptoX509Cert *)cert)->keyUsage;
}

RX509ExtKeyUsage
r_crypto_x509_cert_ext_key_usage (const RCryptoCert * cert)
{
  return ((const RCryptoX509Cert *)cert)->extKeyUsage;
}

rboolean
r_crypto_x509_cert_is_ca (const RCryptoCert * cert)
{
  return ((const RCryptoX509Cert *)cert)->ca;
}

rint32
r_crypto_x509_cert_path_len (const RCryptoCert * cert)
{
  const RCryptoX509Cert * x = (const RCryptoX509Cert *)cert;
  return x->haspathLen ? x->pathLen : -1;
}

rboolean
r_crypto_x509_cert_is_self_issued (const RCryptoCert * cert)
{
  return r_str_equals (((const RCryptoX509Cert *)cert)->issuer,
      ((const RCryptoX509Cert *)cert)->subject);
}

rboolean
r_crypto_x509_cert_is_self_signed (const RCryptoCert * cert)
{
  const RCryptoX509Cert * c = (const RCryptoX509Cert *)cert;

  return c->authorityKeyID.value == NULL || (c->subjectKeyID.value != NULL &&
      c->authorityKeyID.size == c->subjectKeyID.size &&
      r_memcmp (c->authorityKeyID.value, c->subjectKeyID.value, c->subjectKeyID.size) == 0);
}

rboolean
r_crypto_x509_cert_has_policy (const RCryptoCert * cert, const rchar * policy)
{
  const RCryptoX509Cert * x509 = (const RCryptoX509Cert *)cert;
  RSList * it;

  for (it = x509->policies; it != NULL; it = it->next) {
    if (r_str_equals (policy, it->data))
      return TRUE;
  }

  return FALSE;
}

/* Match a presented dNSName @pattern against @host (RFC 6125): exact and
 * case-insensitive, with a single leftmost-label '*' wildcard that matches
 * exactly one label and never spans a dot. */
static rboolean
r_x509_host_match_dns (const rchar * host, const rchar * pattern)
{
  if (r_strcasecmp (host, pattern) == 0)
    return TRUE;

  if (pattern[0] == '*' && pattern[1] == '.') {
    const rchar * hdot = r_strchr (host, '.');
    /* host's first label must be non-empty and the remainder must equal the
     * pattern's suffix (the part from the dot after '*'). */
    if (hdot != NULL && hdot != host && r_strcasecmp (hdot, pattern + 1) == 0)
      return TRUE;
  }

  return FALSE;
}

rboolean
r_crypto_x509_host_match_dns (const rchar * host, const rchar * pattern)
{
  if (R_UNLIKELY (host == NULL || pattern == NULL ||
        *host == '\0' || *pattern == '\0'))
    return FALSE;
  return r_x509_host_match_dns (host, pattern);
}

/* Render @host as raw IP octets if it is an IPv4/IPv6 literal; returns the
 * length (4 or 16) or 0 when @host is not an IP literal. */
static rsize
r_x509_host_ip_octets (const rchar * host, ruint8 out[16])
{
  RSocketAddress * a;

  if ((a = r_socket_address_ipv4_new_from_string (host, 0)) != NULL) {
    ruint32 v = r_socket_address_ipv4_get_ip (a);   /* host byte order */
    out[0] = (ruint8)(v >> 24); out[1] = (ruint8)(v >> 16);
    out[2] = (ruint8)(v >>  8); out[3] = (ruint8) v;
    r_socket_address_unref (a);
    return 4;
  }
  if ((a = r_socket_address_ipv6_new_from_string (host, 0)) != NULL) {
    rboolean ok = r_socket_address_ipv6_get_ip_bytes (a, out);
    r_socket_address_unref (a);
    return ok ? 16 : 0;
  }
  return 0;
}

rboolean
r_crypto_x509_cert_verify_host (const RCryptoCert * cert, const rchar * host)
{
  ruint8 wantip[16];
  rsize wantlen, i, n;

  if (R_UNLIKELY (cert == NULL || host == NULL || *host == '\0'))
    return FALSE;

  n = r_crypto_x509_cert_subject_alt_name_count (cert);
  wantlen = r_x509_host_ip_octets (host, wantip);

  for (i = 0; i < n; i++) {
    const RX509GeneralName * gn = r_crypto_x509_cert_subject_alt_name (cert, i);

    if (wantlen > 0) {
      /* IP literal: match an iPAddress SAN by octets only. */
      if (r_x509_general_name_type (gn) == R_X509_GENERAL_NAME_IP) {
        rsize iplen;
        const ruint8 * ip = r_x509_general_name_as_ip (gn, &iplen);
        if (ip != NULL && iplen == wantlen &&
            r_memcmp_ct (ip, wantip, wantlen) == 0)
          return TRUE;
      }
    } else {
      /* DNS name: match a dNSName SAN (with wildcard). CN is not consulted --
       * SAN-only matching matches modern TLS clients and is intentional. */
      if (r_x509_general_name_type (gn) == R_X509_GENERAL_NAME_DNS) {
        const rchar * dns = r_x509_general_name_as_string (gn);
        /* Reject a dNSName carrying an embedded NUL: its NUL-terminated form is
         * shorter than the attested bytes, so "good.example.com\0.evil" must
         * not be allowed to match "good.example.com". */
        if (dns != NULL && r_strlen (dns) == gn->rawsize &&
            r_x509_host_match_dns (host, dns))
          return TRUE;
      }
    }
  }

  return FALSE;
}

static rsize
r_x509_ptr_array_count (const RPtrArray * arr)
{
  return (arr != NULL) ? r_ptr_array_size (arr) : 0;
}

static const RX509GeneralName *
r_x509_ptr_array_gn (const RPtrArray * arr, rsize idx)
{
  if (arr == NULL || idx >= r_ptr_array_size (arr))
    return NULL;
  return r_ptr_array_get_const ((RPtrArray *)arr, idx);
}

rsize
r_crypto_x509_cert_subject_alt_name_count (const RCryptoCert * cert)
{
  return r_x509_ptr_array_count (((const RCryptoX509Cert *)cert)->sans);
}

const RX509GeneralName *
r_crypto_x509_cert_subject_alt_name (const RCryptoCert * cert, rsize idx)
{
  return r_x509_ptr_array_gn (((const RCryptoX509Cert *)cert)->sans, idx);
}

rsize
r_crypto_x509_cert_authority_cert_issuer_count (const RCryptoCert * cert)
{
  return r_x509_ptr_array_count (((const RCryptoX509Cert *)cert)->authorityCertIssuer);
}

const RX509GeneralName *
r_crypto_x509_cert_authority_cert_issuer (const RCryptoCert * cert, rsize idx)
{
  return r_x509_ptr_array_gn (((const RCryptoX509Cert *)cert)->authorityCertIssuer, idx);
}

rsize
r_crypto_x509_cert_name_constraint_permitted_count (const RCryptoCert * cert)
{
  return r_x509_ptr_array_count (((const RCryptoX509Cert *)cert)->ncPermitted);
}

const RX509GeneralName *
r_crypto_x509_cert_name_constraint_permitted (const RCryptoCert * cert, rsize idx)
{
  return r_x509_ptr_array_gn (((const RCryptoX509Cert *)cert)->ncPermitted, idx);
}

rsize
r_crypto_x509_cert_name_constraint_excluded_count (const RCryptoCert * cert)
{
  return r_x509_ptr_array_count (((const RCryptoX509Cert *)cert)->ncExcluded);
}

const RX509GeneralName *
r_crypto_x509_cert_name_constraint_excluded (const RCryptoCert * cert, rsize idx)
{
  return r_x509_ptr_array_gn (((const RCryptoX509Cert *)cert)->ncExcluded, idx);
}

rsize
r_crypto_x509_cert_policy_mapping_count (const RCryptoCert * cert)
{
  const RCryptoX509Cert * x509 = (const RCryptoX509Cert *)cert;
  return (x509->policyMappings != NULL) ? r_ptr_array_size (x509->policyMappings) : 0;
}

rboolean
r_crypto_x509_cert_policy_mapping (const RCryptoCert * cert, rsize idx,
    const rchar ** issuer_domain_policy, const rchar ** subject_domain_policy)
{
  const RCryptoX509Cert * x509 = (const RCryptoX509Cert *)cert;
  const RX509PolicyMapping * pm;

  if (x509->policyMappings == NULL || idx >= r_ptr_array_size (x509->policyMappings))
    return FALSE;

  pm = r_ptr_array_get_const (x509->policyMappings, idx);
  if (issuer_domain_policy != NULL)
    *issuer_domain_policy = pm->issuer;
  if (subject_domain_policy != NULL)
    *subject_domain_policy = pm->subject;
  return TRUE;
}

RCryptoResult
r_crypto_x509_cert_verify_signature (const RCryptoCert * cert, const RCryptoCert * parent)
{
  if (R_UNLIKELY (parent->pk == NULL)) return R_CRYPTO_NOT_AVAILABLE;

  /* PureEdDSA verifies over the raw TBSCertificate (kept at parse time),
   * not a pre-hash; signalgo is NONE for it. */
  if (cert->signalgo == R_MSG_DIGEST_TYPE_NONE) {
    if (R_UNLIKELY (cert->tbs == NULL)) return R_CRYPTO_NOT_AVAILABLE;
    return r_crypto_key_verify (parent->pk, R_MSG_DIGEST_TYPE_NONE,
        cert->tbs, cert->tbssize, cert->sign, cert->signbits / 8);
  }

  return r_crypto_key_verify (parent->pk, cert->signalgo, cert->signhash,
      r_msg_digest_type_size (cert->signalgo), cert->sign, cert->signbits / 8);
}

