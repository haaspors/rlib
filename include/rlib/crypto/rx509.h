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
#error "#include <rlib.h> only pelase."
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

#include <rlib/asn1/rasn1.h>
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

/**
 * @brief True iff @p cert is a CA: the @c BasicConstraints @c CA flag
 * is set.
 */
R_API rboolean r_crypto_x509_cert_is_ca (const RCryptoCert * cert);
/** @brief True iff issuer DN equals subject DN. */
R_API rboolean r_crypto_x509_cert_is_self_issued (const RCryptoCert * cert);
/**
 * @brief True iff @p cert is self-signed: self-issued AND the
 * signature verifies under @p cert's own public key.
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

