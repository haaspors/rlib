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
#ifndef __R_CRYPTO_X509_H__
#define __R_CRYPTO_X509_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @defgroup r_crypto_x509 X.509 certificates (RFC 5280)
 * @ingroup r_crypto_cert
 *
 * @brief X.509 builders for @ref RCryptoCert plus the accessors and
 * predicates that only make sense for the X.509 certificate kind.
 *
 * Use @ref r_crypto_x509_cert_new to parse a DER-encoded
 * certificate; the result is an @ref RCryptoCert that the generic
 * @c r_crypto_cert_* accessors in @ref r_crypto_cert can introspect.
 * The X.509-specific accessors here expose fields that don't have a
 * cross-format meaning: version, issuer / subject DNs, serial
 * number, key-usage bitmasks, the CA flag, etc.
 *
 * Certificate validation is split between the X.509-specific
 * @ref r_crypto_x509_cert_verify_signature (single hop, given a
 * parent) and the chain-building logic that belongs in callers; no
 * built-in path-building or revocation checking is provided.
 *
 * @{
 */

/**
 * @file rlib/crypto/rx509.h
 * @brief X.509 certificate parsing, field accessors and
 * single-hop signature verification.
 */

#include <rlib/rtypes.h>

#include <rlib/format/rasn1.h>
#include <rlib/crypto/rcert.h>

R_BEGIN_DECLS

/** @brief X.509 version field. */
typedef enum {
  R_X509_VERSION_UNKNOWN  = -1,
  R_X509_VERSION_V1       = 0,  /**< RFC 5280 v1. */
  R_X509_VERSION_V2       = 1,  /**< RFC 5280 v2 (unique IDs). */
  R_X509_VERSION_V3       = 2,  /**< RFC 5280 v3 (extensions). */
} RX509Version;
/** @brief Highest X.509 version this implementation parses. */
#define R_X509_VERSION_SUPPORTED R_X509_VERSION_V3

/**
 * @brief X.509 @c KeyUsage bitmask (RFC 5280 §4.2.1.3).
 *
 * Bit positions match the on-wire BIT STRING. Multiple bits may be
 * set; the returned value is the union of the certificate's
 * declared usages.
 */
typedef enum {
  R_X509_KEY_USAGE_NONE                         = 0,
  R_X509_KEY_USAGE_DIGITAL_SIGNATURE            = (1 << 0), /**< bit 0 */
  R_X509_KEY_USAGE_NON_REPUDIATION              = (1 << 1), /**< bit 1 */
  R_X509_KEY_USAGE_KEY_ENCIPHERMENT             = (1 << 2), /**< bit 2 */
  R_X509_KEY_USAGE_DATA_ENCIPHERMENT            = (1 << 3), /**< bit 3 */
  R_X509_KEY_USAGE_KEY_AGREEMENT                = (1 << 4), /**< bit 4 */
  R_X509_KEY_USAGE_KEY_CERT_SIGN                = (1 << 5), /**< bit 5 */
  R_X509_KEY_USAGE_CRL_SIGN                     = (1 << 6), /**< bit 6 */
  R_X509_KEY_USAGE_ENCIPHER_ONLY                = (1 << 7), /**< bit 7 */
  R_X509_KEY_USAGE_DECIPHER_ONLY                = (1 << 8), /**< bit 8 */
} RX509KeyUsage;

/**
 * @brief X.509 @c ExtendedKeyUsage bitmask (RFC 5280 §4.2.1.12).
 *
 * Each bit maps to one of the well-known EKU OIDs.
 */
typedef enum {
  R_X509_EXT_KEY_USAGE_NONE                     = 0,
  R_X509_EXT_KEY_USAGE_ANY                      = (1 << 0), /**< @c anyExtendedKeyUsage. */
  R_X509_EXT_KEY_USAGE_SERVER_AUTH              = (1 << 1), /**< TLS server. */
  R_X509_EXT_KEY_USAGE_CLIENT_AUTH              = (1 << 2), /**< TLS client. */
  R_X509_EXT_KEY_USAGE_CODE_SIGNING             = (1 << 3), /**< Code signing. */
  R_X509_EXT_KEY_USAGE_EMAIL_PROTECTION         = (1 << 4), /**< S/MIME. */
  R_X509_EXT_KEY_USAGE_TIME_STAMPING            = (1 << 5), /**< RFC 3161. */
  R_X509_EXT_KEY_USAGE_OCSP_SIGNING             = (1 << 6), /**< OCSP responder. */
} RX509ExtKeyUsage;

/**
 * @brief X.509 @c GeneralName alternative (RFC 5280 §4.2.1.6).
 *
 * The enumerator value equals the on-wire context-tag number of the
 * CHOICE, so it can be read directly off the DER tag.
 */
typedef enum {
  R_X509_GENERAL_NAME_OTHER             = 0, /**< @c otherName [0]. */
  R_X509_GENERAL_NAME_RFC822            = 1, /**< @c rfc822Name [1] (e-mail, IA5String). */
  R_X509_GENERAL_NAME_DNS               = 2, /**< @c dNSName [2] (IA5String). */
  R_X509_GENERAL_NAME_X400              = 3, /**< @c x400Address [3]. */
  R_X509_GENERAL_NAME_DIRECTORY         = 4, /**< @c directoryName [4] (a @c Name). */
  R_X509_GENERAL_NAME_EDI_PARTY         = 5, /**< @c ediPartyName [5]. */
  R_X509_GENERAL_NAME_URI               = 6, /**< @c uniformResourceIdentifier [6] (IA5String). */
  R_X509_GENERAL_NAME_IP                = 7, /**< @c iPAddress [7] (OCTET STRING). */
  R_X509_GENERAL_NAME_REGISTERED_ID     = 8, /**< @c registeredID [8] (OBJECT IDENTIFIER). */
} RX509GeneralNameType;

/**
 * @brief One parsed @c GeneralName, as carried by Subject Alternative
 * Name, Name Constraints and the Authority Key Identifier's
 * @c authorityCertIssuer.
 *
 * Opaque; introspect with @ref r_x509_general_name_type and the
 * @c r_x509_general_name_as_* accessors. Owned by the @ref RCryptoCert
 * it was parsed from and valid for that certificate's lifetime.
 */
typedef struct RX509GeneralName RX509GeneralName;

/** @brief Return which CHOICE alternative @p gn holds. */
R_API RX509GeneralNameType r_x509_general_name_type (const RX509GeneralName * gn);
/**
 * @brief Return the textual value for the IA5String alternatives
 * (@c rfc822Name, @c dNSName, @c uniformResourceIdentifier).
 * @return NUL-terminated string owned by @p gn, or @c NULL for any
 *         other alternative.
 */
R_API const rchar * r_x509_general_name_as_string (const RX509GeneralName * gn);
/**
 * @brief Return the raw address octets for the @c iPAddress alternative
 * (4 bytes for IPv4, 16 for IPv6; or a CIDR pair in Name Constraints).
 * @param gn    The general name.
 * @param size  Out: length of the returned octets.
 * @return Octets owned by @p gn, or @c NULL for any other alternative.
 */
R_API const ruint8 * r_x509_general_name_as_ip (const RX509GeneralName * gn, rsize * size);
/**
 * @brief Return the @c registeredID alternative as a dotted OID string.
 * @return Newly allocated string the caller frees with @c r_free, or
 *         @c NULL for any other alternative.
 */
R_API rchar * r_x509_general_name_as_oid (const RX509GeneralName * gn);
/**
 * @brief Return the @c directoryName alternative as a Distinguished
 * Name string.
 * @return String owned by @p gn, or @c NULL for any other alternative.
 */
R_API const rchar * r_x509_general_name_as_dn (const RX509GeneralName * gn);

/**
 * @brief Parse a DER-encoded X.509 certificate, copying the bytes.
 *
 * @param data  Pointer to the certificate's DER bytes.
 * @param size  Length of @p data.
 * @return Parsed @ref RCryptoCert, or @c NULL on malformed input.
 */
R_API RCryptoCert * r_crypto_x509_cert_new (rconstpointer data, rsize size) R_ATTR_MALLOC;

/**
 * @brief Parse a DER-encoded X.509 certificate, taking ownership of
 * the buffer.
 *
 * @p data must have been allocated with @c r_malloc; on success the
 * certificate frees it with @c r_free when its refcount drops.
 */
R_API RCryptoCert * r_crypto_x509_cert_new_take (rpointer data, rsize size) R_ATTR_MALLOC;

/**
 * @brief Parse a DER-encoded X.509 certificate from an @c RBuffer.
 *
 * Shares the buffer's storage; the certificate keeps a reference on
 * @p buf for as long as it lives.
 */
R_API RCryptoCert * r_crypto_x509_cert_new_from_buffer (RBuffer * buf) R_ATTR_MALLOC;

/** @brief Return the @c version field (v1 / v2 / v3). */
R_API RX509Version r_crypto_x509_cert_version (const RCryptoCert * cert);
/** @brief Return the @c serialNumber as a 64-bit integer. */
R_API ruint64 r_crypto_x509_cert_serial_number (const RCryptoCert * cert);
/** @brief Return the issuer Distinguished Name as a string. */
R_API const rchar * r_crypto_x509_cert_issuer (const RCryptoCert * cert);
/** @brief Return the subject Distinguished Name as a string. */
R_API const rchar * r_crypto_x509_cert_subject (const RCryptoCert * cert);
/**
 * @brief Return the v2 @c issuerUniqueID, or @c NULL if absent.
 * @param cert  The certificate.
 * @param size  Out: length of the returned blob.
 */
R_API const ruint8 * r_crypto_x509_cert_issuer_unique_id (const RCryptoCert * cert, rsize * size);
/**
 * @brief Return the v2 @c subjectUniqueID, or @c NULL if absent.
 * @param cert  The certificate.
 * @param size  Out: length of the returned blob.
 */
R_API const ruint8 * r_crypto_x509_cert_subject_unique_id (const RCryptoCert * cert, rsize * size);
/**
 * @brief Return the v3 @c SubjectKeyIdentifier extension, or @c NULL
 * if absent.
 * @param cert  The certificate.
 * @param size  Out: length of the returned key identifier.
 */
R_API const ruint8 * r_crypto_x509_cert_subject_key_id (const RCryptoCert * cert, rsize * size);
/**
 * @brief Return the v3 @c AuthorityKeyIdentifier extension, or
 * @c NULL if absent.
 * @param cert  The certificate.
 * @param size  Out: length of the returned key identifier.
 */
R_API const ruint8 * r_crypto_x509_cert_authority_key_id (const RCryptoCert * cert, rsize * size);
/** @brief Return the @c KeyUsage bitmask. */
R_API RX509KeyUsage r_crypto_x509_cert_key_usage (const RCryptoCert * cert);
/** @brief Return the @c ExtendedKeyUsage bitmask. */
R_API RX509ExtKeyUsage r_crypto_x509_cert_ext_key_usage (const RCryptoCert * cert);
/**
 * @brief True iff @p cert's @c certificatePolicies extension contains
 * the OID dotted string @p policy.
 */
R_API rboolean r_crypto_x509_cert_has_policy (const RCryptoCert * cert, const rchar * policy);

/** @brief Number of @c SubjectAltName general names (0 if absent). */
R_API rsize r_crypto_x509_cert_subject_alt_name_count (const RCryptoCert * cert);
/**
 * @brief Return the @p idx'th @c SubjectAltName general name.
 * @return The general name, or @c NULL if @p idx is out of range.
 */
R_API const RX509GeneralName * r_crypto_x509_cert_subject_alt_name (const RCryptoCert * cert, rsize idx);

/** @brief Number of @c authorityCertIssuer general names in the AKI (0 if absent). */
R_API rsize r_crypto_x509_cert_authority_cert_issuer_count (const RCryptoCert * cert);
/**
 * @brief Return the @p idx'th @c authorityCertIssuer general name.
 * @return The general name, or @c NULL if @p idx is out of range.
 */
R_API const RX509GeneralName * r_crypto_x509_cert_authority_cert_issuer (const RCryptoCert * cert, rsize idx);

/** @brief Number of @c permittedSubtrees base names in @c NameConstraints. */
R_API rsize r_crypto_x509_cert_name_constraint_permitted_count (const RCryptoCert * cert);
/**
 * @brief Return the @p idx'th @c permittedSubtrees base general name.
 * @return The general name, or @c NULL if @p idx is out of range.
 */
R_API const RX509GeneralName * r_crypto_x509_cert_name_constraint_permitted (const RCryptoCert * cert, rsize idx);
/** @brief Number of @c excludedSubtrees base names in @c NameConstraints. */
R_API rsize r_crypto_x509_cert_name_constraint_excluded_count (const RCryptoCert * cert);
/**
 * @brief Return the @p idx'th @c excludedSubtrees base general name.
 * @return The general name, or @c NULL if @p idx is out of range.
 */
R_API const RX509GeneralName * r_crypto_x509_cert_name_constraint_excluded (const RCryptoCert * cert, rsize idx);

/** @brief Number of @c PolicyMappings entries (0 if absent). */
R_API rsize r_crypto_x509_cert_policy_mapping_count (const RCryptoCert * cert);
/**
 * @brief Return the @p idx'th @c PolicyMappings entry as a pair of
 * dotted OID strings.
 * @param cert                    The certificate.
 * @param idx                     Entry index.
 * @param issuer_domain_policy    Out (optional): issuer-domain policy OID,
 *                                owned by @p cert.
 * @param subject_domain_policy   Out (optional): subject-domain policy OID,
 *                                owned by @p cert.
 * @return @c TRUE if @p idx is in range and the out pointers were set.
 */
R_API rboolean r_crypto_x509_cert_policy_mapping (const RCryptoCert * cert, rsize idx,
    const rchar ** issuer_domain_policy, const rchar ** subject_domain_policy);

/**
 * @brief True iff @p cert is a CA: the @c BasicConstraints @c CA flag
 * is set.
 */
R_API rboolean r_crypto_x509_cert_is_ca (const RCryptoCert * cert);
/** @brief True iff issuer DN equals subject DN. */
R_API rboolean r_crypto_x509_cert_is_self_issued (const RCryptoCert * cert);
/**
 * @brief Heuristic self-signed check based on key identifiers: returns
 * @c TRUE when the AuthorityKeyIdentifier is absent, or when it matches
 * the SubjectKeyIdentifier.
 *
 * This does @b not verify the signature or compare issuer/subject DNs;
 * use @ref r_crypto_x509_cert_verify_signature and
 * @ref r_crypto_x509_cert_is_self_issued for those.
 */
R_API rboolean r_crypto_x509_cert_is_self_signed (const RCryptoCert * cert);

/**
 * @brief Verify @p cert's signature against @p parent's public key.
 *
 * Single-hop check only. Chain construction (path building, AIA
 * fetching, name constraints), validity-window checking and
 * revocation (CRL, OCSP) are the caller's responsibility.
 *
 * @return @c R_CRYPTO_OK iff the signature is valid.
 */
R_API RCryptoResult r_crypto_x509_cert_verify_signature (const RCryptoCert * cert,
    const RCryptoCert * parent);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_X509_H__ */

