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
#ifndef __R_CRYPTO_CERT_H__
#define __R_CRYPTO_CERT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @addtogroup r_crypto_cert
 *
 * Generic certificate handle @c RCryptoCert and the polymorphic
 * operations (validity range, public-key extraction, fingerprint,
 * raw-data access) that work across any certificate type live in
 * @c rcert.h.
 *
 * @c RCryptoCert is the same kind of polymorphic handle that
 * @ref r_crypto_key is for keys: callers parse a certificate via a
 * concrete builder (typically @c r_crypto_x509_cert_new from
 * @ref r_crypto_x509, or @ref r_pem_block_get_cert for PEM input)
 * and then interact with it through the generic API.
 *
 * Concrete certificate kinds are tagged by @ref RCryptoCertType.
 * X.509 is fully supported; OpenPGP is reserved but not yet
 * implemented.
 */

/**
 * @file rlib/crypto/rcert.h
 * @brief Generic certificate handle and the operations that work
 * across any certificate type.
 * @ingroup r_crypto_cert
 */

#include <rlib/rtypes.h>

#include <rlib/crypto/rkey.h>

#include <rlib/rbuffer.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

/**
 * @ingroup r_crypto_cert
 * @brief Concrete certificate kind carried by an @ref RCryptoCert.
 */
typedef enum {
  R_CRYPTO_CERT_X509,    /**< X.509 certificate. */
  R_CRYPTO_CERT_OPENPGP, /**< OpenPGP certificate (reserved, not implemented). */
} RCryptoCertType;

/**
 * @ingroup r_crypto_cert
 * @brief Opaque, refcounted polymorphic certificate handle.
 */
typedef struct RCryptoCert RCryptoCert;

/**
 * @ingroup r_crypto_cert
 * @brief Increment the certificate's refcount.
 */
#define r_crypto_cert_ref r_ref_ref
/**
 * @ingroup r_crypto_cert
 * @brief Decrement the certificate's refcount; frees when it reaches zero.
 */
#define r_crypto_cert_unref r_ref_unref

/**
 * @ingroup r_crypto_cert
 * @brief Drop the cached raw byte representation, keeping just the
 * parsed fields.
 *
 * Use when memory is tight and the caller is done re-exporting the
 * certificate. Subsequent calls to @ref r_crypto_cert_get_data_buffer
 * / @ref r_crypto_cert_dup_data will return @c NULL.
 */
R_API void r_crypto_cert_clear_data (RCryptoCert * cert);

/**
 * @ingroup r_crypto_cert
 * @brief Return the concrete kind of @p cert (X.509, OpenPGP, ...).
 */
R_API RCryptoCertType r_crypto_cert_get_type (const RCryptoCert * cert);
/**
 * @ingroup r_crypto_cert
 * @brief Return @p cert's kind as a short ASCII string (e.g. @c "X.509").
 */
R_API const rchar * r_crypto_cert_get_strtype (const RCryptoCert * cert);
/**
 * @ingroup r_crypto_cert
 * @brief Return @p cert's signature bytes plus metadata.
 *
 * @param cert     The certificate.
 * @param signalgo Out: digest used inside the signature scheme.
 * @param signbits Out: signature length in bits.
 * @return Pointer to the signature bytes inside @p cert (not owned).
 */
R_API const ruint8 * r_crypto_cert_get_signature (const RCryptoCert * cert,
    RMsgDigestType * signalgo, rsize * signbits);
/**
 * @ingroup r_crypto_cert
 * @brief Return the start of @p cert's validity window as a Unix
 * timestamp (seconds since 1970-01-01 UTC).
 */
R_API ruint64 r_crypto_cert_get_valid_from (const RCryptoCert * cert);
/**
 * @ingroup r_crypto_cert
 * @brief Return the end of @p cert's validity window as a Unix
 * timestamp.
 */
R_API ruint64 r_crypto_cert_get_valid_to (const RCryptoCert * cert);
/**
 * @ingroup r_crypto_cert
 * @brief Return @p cert's subject public key as an @ref RCryptoKey.
 *
 * The returned key holds a reference; the caller releases it via
 * @c r_crypto_key_unref.
 */
R_API RCryptoKey * r_crypto_cert_get_public_key (const RCryptoCert * cert);

/**
 * @ingroup r_crypto_cert
 * @brief Re-emit @p cert into an ASN.1 BER/DER encoder.
 */
R_API RCryptoResult r_crypto_cert_export (const RCryptoCert * cert, RAsn1BinEncoder * enc);

/**
 * @ingroup r_crypto_cert
 * @brief Return the cached raw certificate bytes as an @c RBuffer.
 *
 * The @c RBuffer is borrowed; do not free it. Returns @c NULL if
 * @ref r_crypto_cert_clear_data has been called.
 */
R_API RBuffer * r_crypto_cert_get_data_buffer (const RCryptoCert * cert);
/**
 * @ingroup r_crypto_cert
 * @brief Return a freshly-allocated copy of the certificate's raw
 * bytes.
 *
 * @param cert  The certificate.
 * @param size  Out: length of the returned blob.
 */
R_API ruint8 * r_crypto_cert_dup_data (const RCryptoCert * cert, rsize * size);
/**
 * @ingroup r_crypto_cert
 * @brief Compute the certificate's fingerprint into a caller-supplied
 * buffer.
 *
 * The fingerprint is the digest @p type computed over the raw DER /
 * BER bytes of @p cert.
 *
 * @param cert  The certificate.
 * @param buf   Output buffer.
 * @param size  Capacity of @p buf.
 * @param type  Digest algorithm (SHA-1, SHA-256, ...).
 * @param out   Out: number of bytes written.
 */
R_API RCryptoResult r_crypto_cert_fingerprint (const RCryptoCert * cert,
    ruint8 * buf, rsize size, RMsgDigestType type, rsize * out);
/**
 * @ingroup r_crypto_cert
 * @brief Format the certificate's fingerprint as a string with
 * optional dividers (e.g. colon-separated hex).
 *
 * @param cert      The certificate.
 * @param type      Digest algorithm.
 * @param divider   Separator inserted between hex pairs (e.g. @c ":");
 *                  pass @c NULL or @c "" for no separator.
 * @param interval  Hex characters between dividers (typically 2).
 * @return Newly-allocated NUL-terminated string. Caller frees with
 *         @c r_free.
 */
R_API rchar * r_crypto_cert_fingerprint_str (const RCryptoCert * cert,
    RMsgDigestType type, const rchar * divider, rsize interval) R_ATTR_MALLOC;

R_END_DECLS

#endif /* __R_CRYPTO_CERT_H__ */

