/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_SRTP_CIPHER_SUITE_H__
#define __R_CRYPTO_SRTP_CIPHER_SUITE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_crypto_srtp_ciphersuite SRTP ciphersuites
 * @ingroup r_crypto_ciphersuite
 *
 * @brief Lookup table mapping IANA SRTP / SDP-security-descriptions
 * ciphersuite identifiers to the concrete cipher / MAC / KDF
 * parameters needed to instantiate the protection profile.
 *
 * Each suite is named by its IANA identifier (`R_SRTP_CS_*`) and
 * carries an @ref RSRTPCipherSuiteInfo entry describing:
 *
 *   - the cipher to use on RTP / RTCP payload (`cipher`, `saltbits`),
 *   - the authentication MAC (`auth`, `authprefixlen`) and the SRTP /
 *     SRTCP tag lengths,
 *   - the key-derivation PRF.
 *
 * The full IANA list is at
 * <https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml>
 * (SRTP protection profiles) and
 * <https://www.iana.org/assignments/sdp-security-descriptions/sdp-security-descriptions.xhtml>
 * (SDP `crypto:` descriptions).
 *
 * @{
 */

/**
 * @file rlib/crypto/rsrtpciphersuite.h
 * @brief SRTP ciphersuite enumeration and parameter-table lookup.
 */

#include <rlib/rtypes.h>

#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rmsgdigest.h>

R_BEGIN_DECLS

/**
 * @brief IANA-registered SRTP ciphersuites.
 *
 * Values are the 16-bit IANA identifiers. @c R_SRTP_CS_NONE is the
 * sentinel returned by negotiation helpers when no suite matches.
 */
typedef enum {
  R_SRTP_CS_NONE                                      = -1,
  R_SRTP_CS_NULL_NULL                                 = 0x0000,
  R_SRTP_CS_AES_128_CM_HMAC_SHA1_80                   = 0x0001, /**< RFC 4568, RFC 5764. */
  R_SRTP_CS_AES_128_CM_HMAC_SHA1_32                   = 0x0002, /**< RFC 4568, RFC 5764. */
  R_SRTP_CS_F8_128_HMAC_SHA1_80                       = 0x0003, /**< RFC 4568. */

  R_SRTP_CS_NULL_HMAC_SHA1_80                         = 0x0005, /**< RFC 5764. */
  R_SRTP_CS_NULL_HMAC_SHA1_32                         = 0x0006, /**< RFC 5764. */
  R_SRTP_CS_AEAD_AES_128_GCM                          = 0x0007, /**< RFC 7714. */
  R_SRTP_CS_AEAD_AES_256_GCM                          = 0x0008, /**< RFC 7714. */

  R_SRTP_CS_SEED_CTR_128_HMAC_SHA1_80                 = 0x0011, /**< RFC 5669. */
  R_SRTP_CS_SEED_128_CCM_80                           = 0x0012, /**< RFC 5669. */
  R_SRTP_CS_SEED_128_GCM_96                           = 0x0013, /**< RFC 5669. */
  R_SRTP_CS_AES_192_CM_HMAC_SHA1_80                   = 0x0021, /**< RFC 6188. */
  R_SRTP_CS_AES_192_CM_HMAC_SHA1_32                   = 0x0022, /**< RFC 6188. */
  R_SRTP_CS_AES_256_CM_HMAC_SHA1_80                   = 0x0023, /**< RFC 6188. */
  R_SRTP_CS_AES_256_CM_HMAC_SHA1_32                   = 0x0024, /**< RFC 6188. */
} RSRTPCipherSuite;

/**
 * @brief Parameter table for one SRTP ciphersuite.
 *
 * Returned by @ref r_srtp_cipher_suite_get_info; describes how to
 * wire the protection profile into the SRTP / SRTCP framing.
 */
typedef struct {
  RSRTPCipherSuite suite;             /**< IANA identifier. */
  const rchar * str;                  /**< Short ASCII name (matches SDP). */

  const RCryptoCipherInfo * cipher;   /**< Payload cipher. */
  rsize saltbits;                     /**< Session-salt size in bits. */

  RMsgDigestType auth;                /**< Authentication MAC. */
  rsize authprefixlen;                /**< Length of authenticated prefix. */
  rsize srtp_tagbits;                 /**< Tag length on RTP packets, bits. */
  rsize srtcp_tagbits;                /**< Tag length on RTCP packets, bits. */

  const RCryptoCipherInfo * kdprf;    /**< Key-derivation pseudorandom function. */
} RSRTPCipherSuiteInfo;

/** @brief True iff rlib has an implementation for @p suite. */
R_API rboolean r_srtp_cipher_suite_is_supported (RSRTPCipherSuite suite);

/**
 * @brief Pick the most-preferred suite in @p preferred that also
 * appears in @p incoming.
 *
 * Used by SDP-style negotiation to select a common suite. Returns
 * @c R_SRTP_CS_NONE if the intersection is empty.
 *
 * @param incoming   Peer-offered suites in their order.
 * @param ilen       Length of @p incoming.
 * @param preferred  Local preference order (most preferred first).
 * @param plen       Length of @p preferred.
 */
R_API RSRTPCipherSuite r_srtp_cipher_suite_filter (
    const RSRTPCipherSuite * incoming, ruint ilen,
    const RSRTPCipherSuite * preferred, ruint plen);

/** @brief Look up the parameter table for @p suite, or @c NULL. */
R_API const RSRTPCipherSuiteInfo * r_srtp_cipher_suite_get_info (RSRTPCipherSuite suite);
/**
 * @brief Look up the parameter table by short ASCII name (e.g.
 * @c "AES_CM_128_HMAC_SHA1_80"), or @c NULL.
 */
R_API const RSRTPCipherSuiteInfo * r_srtp_cipher_suite_get_info_from_str (const rchar * str);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_SRTP_CIPHER_SUITE_H__ */

