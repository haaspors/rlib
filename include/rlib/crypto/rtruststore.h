/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_TRUST_STORE_H__
#define __R_CRYPTO_TRUST_STORE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/crypto/rtruststore.h
 * @brief Certificate trust store: decide whether a peer certificate chain is
 * trusted.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rx509.h>

/**
 * @defgroup r_trust_store Certificate trust store
 * @ingroup r_crypto
 *
 * @brief A refcounted, backend-pluggable decision point for "is this peer
 * certificate chain trusted?".
 *
 * The store is an abstraction over *where trust comes from*; callers hand it a
 * peer chain (leaf first, exactly as a TLS @c Certificate message carries it)
 * and get a single @ref RTrustResult back. Two backends ship here:
 *
 * - @ref r_trust_store_new_certs — a set of trust-anchor certificates. The
 *   chain is path-built to an anchor and each intermediate hop validated with
 *   rlib's own engine: signatures, validity window, @c BasicConstraints
 *   (intermediates must be CAs within their @c pathLenConstraint), @c keyUsage
 *   (CAs need @c keyCertSign) and an optional leaf @c extendedKeyUsage. The
 *   matched anchor is trusted by inclusion (only its validity and pathLen bound
 *   the path).
 * - @ref r_trust_store_new_pinned_spki — certificate pinning: trusted only when
 *   the leaf's SubjectPublicKeyInfo matches a registered SHA-256 pin.
 *
 * Hostname verification is intentionally *not* part of the store (it is an
 * application-protocol concern); use @ref r_crypto_x509_cert_verify_host on the
 * leaf separately.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Outcome of a trust evaluation. */
typedef enum {
  R_TRUST_OK = 0,       /**< The chain is trusted. */
  R_TRUST_UNTRUSTED,    /**< No path from the leaf to a trust anchor / pin. */
  R_TRUST_EXPIRED,      /**< A certificate in the path is expired or not yet valid. */
  R_TRUST_NOT_CA,       /**< A non-leaf certificate is not a CA. */
  R_TRUST_BAD_USAGE,    /**< keyUsage / extendedKeyUsage forbids the certificate's role. */
  R_TRUST_PATHLEN,      /**< A CA's pathLenConstraint is exceeded. */
  R_TRUST_INVALID,      /**< Bad arguments or an unusable certificate. */
} RTrustResult;

/** @brief Opaque, refcounted trust store. */
typedef struct RTrustStore RTrustStore;

/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_trust_store_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_trust_store_unref  r_ref_unref

/**
 * @brief Create an empty trust store whose anchors are a set of certificates.
 *
 * Add anchors with @ref r_trust_store_add_cert / @ref r_trust_store_add_pem /
 * @ref r_trust_store_add_pem_file; a chain is trusted when it path-builds to one
 * of them. Returns @c NULL on allocation failure.
 */
R_API RTrustStore * r_trust_store_new_certs (void) R_ATTR_MALLOC;

/** @brief Add a single trust-anchor certificate (referenced). */
R_API rboolean r_trust_store_add_cert (RTrustStore * store, RCryptoCert * cert);
/**
 * @brief Add every @c CERTIFICATE block found in a PEM buffer as an anchor.
 * @return The number of certificates added, or @c -1 on error.
 */
R_API rssize r_trust_store_add_pem (RTrustStore * store, const rchar * pem, rssize size);
/**
 * @brief Add every @c CERTIFICATE block in a PEM file (a CA bundle) as an anchor.
 * @return The number of certificates added, or @c -1 if the file can't be read.
 */
R_API rssize r_trust_store_add_pem_file (RTrustStore * store, const rchar * filename);

/** @brief Length of an SPKI pin: the SHA-256 of a SubjectPublicKeyInfo. */
#define R_TRUST_SPKI_PIN_SIZE  32

/**
 * @brief Create a trust store that pins SubjectPublicKeyInfo (SPKI) hashes.
 *
 * A chain is trusted when the leaf certificate's SPKI SHA-256 matches a
 * registered pin; no chain to a CA is required, and the leaf's validity window
 * is still enforced (an expired leaf yields @ref R_TRUST_EXPIRED). Only the
 * leaf is matched -- it is the certificate whose private key the peer proves it
 * holds -- so an attacker cannot pass by attaching the genuine pinned (public)
 * certificate to an unrelated leaf. Pinning the key (rather than the whole
 * certificate) keeps the pin valid across a reissue that reuses the key.
 * Returns @c NULL on allocation failure.
 */
R_API RTrustStore * r_trust_store_new_pinned_spki (void) R_ATTR_MALLOC;

/** @brief Add a SPKI pin: the SHA-256 (@ref R_TRUST_SPKI_PIN_SIZE bytes) of a
 *  SubjectPublicKeyInfo. */
R_API rboolean r_trust_store_add_spki_sha256 (RTrustStore * store,
    const ruint8 sha256[R_TRUST_SPKI_PIN_SIZE]);
/** @brief Convenience: pin @p cert's public key (computes its SPKI SHA-256). */
R_API rboolean r_trust_store_pin_cert_spki (RTrustStore * store,
    const RCryptoCert * cert);

/**
 * @brief Decide whether a peer certificate @p chain is trusted.
 *
 * @param store        The trust store.
 * @param chain        The peer chain, leaf first (as a TLS @c Certificate
 *                     message delivers it); intermediates may follow.
 * @param count        Number of certificates in @p chain (must be >= 1).
 * @param now          Current time as a Unix timestamp (seconds) for the
 *                     validity-window check (see @ref r_time_get_unix_time).
 * @param required_eku An @c extendedKeyUsage the leaf must carry (e.g.
 *                     @c R_X509_EXT_KEY_USAGE_SERVER_AUTH), or
 *                     @c R_X509_EXT_KEY_USAGE_NONE to skip the check.
 * @return @ref R_TRUST_OK if trusted, otherwise the reason it was rejected.
 */
R_API RTrustResult r_trust_store_verify (RTrustStore * store,
    RCryptoCert * const * chain, ruint count, ruint64 now,
    RX509ExtKeyUsage required_eku);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_TRUST_STORE_H__ */
