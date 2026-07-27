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
#ifndef __R_NET_PROTO_TLS_PRIV_H__
#define __R_NET_PROTO_TLS_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rtls-private.h should only be used internally in rlib!"
#endif

#include <rlib/net/proto/rtls.h>
#include <rlib/net/proto/rtls12.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/rrand.h>
#include <rlib/rtypes.h>

R_BEGIN_DECLS

/* Default cipher-suite preference shared by the client and server, most
 * preferred first: AEAD (AES-GCM) over CBC, ECDHE (forward secrecy) over static
 * RSA, ECDSA over RSA authentication within a tier, AES-128 over AES-256,
 * SHA-256 MAC over SHA-1. The server keeps only the suites its certificate can
 * authenticate; the client offers all and lets the server choose. */
#define R_TLS_DEFAULT_CIPHER_SUITES                                            \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,                              \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,                             \
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                                \
    R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,                                \
    R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256,                                      \
    R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384,                                      \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,                             \
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,                               \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,                                \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,                                \
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA,                                   \
    R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA,                                   \
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256,                                      \
    R_TLS_CS_RSA_WITH_AES_256_CBC_SHA256,                                      \
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA,                                         \
    R_TLS_CS_RSA_WITH_AES_256_CBC_SHA

/* Map a TLS signature scheme to the message-digest its hash uses. This cut
 * only handles rsa_pkcs1_sha256 (SHA-256) - the scheme used for both the mTLS
 * CertificateVerify and the ECDHE ServerKeyExchange signature. Returns FALSE
 * for any other scheme. */
R_API_HIDDEN rboolean r_tls_sign_scheme_to_md (RTLSSignatureScheme scheme,
    RMsgDigestType * md);

/* Choose the TLS 1.2 signature scheme matching a signing key's algorithm:
 * ecdsa_secp256r1_sha256 for an ECDSA key, rsa_pkcs1_sha256 otherwise. Both
 * hash with SHA-256, so the caller's transcript/params hash is unchanged. */
R_API_HIDDEN RTLSSignatureScheme r_tls_sign_scheme_for_key (const RCryptoKey * key);

/* Select the TLS 1.2 PRF and a fresh handshake-transcript digest for a cipher
 * suite's hash (@ref RTLSCipherSuiteInfo.prf): SHA-256 or SHA-384. Writes the
 * PRF function to @prf and an owned digest (caller frees) to @hshash. Returns
 * FALSE on an unsupported hash or allocation failure. */
R_API_HIDDEN rboolean r_tls_prf_and_hash_for (RMsgDigestType hash,
    RTLSPrfFunc * prf, RMsgDigest ** hshash);

/* ECDHE curve abstraction shared by the TLS/DTLS client and server. The two
 * supported curves take different code paths: secp256r1 is short-Weierstrass
 * (SEC 1 uncompressed point 0x04||X||Y, the recc/ECDH primitives) and x25519
 * is Montgomery (raw little-endian u-coordinate, the rxdh primitives). These
 * helpers hide that split so both endpoints share one code path. */

/* Largest (EC)DHE shared secret and uncompressed ECPoint across the supported
 * groups: P-521 has 66-byte coordinates, so a 66-byte shared secret and a
 * 133-byte uncompressed point (0x04 || X || Y). Buffers on the key-exchange
 * paths are sized to these so any supported group fits (RFC 8446 7.4.2 / SEC 1). */
#define R_TLS_ECDHE_SECRET_MAX    66
#define R_TLS_ECDHE_POINT_MAX     133

/* Map a TLS supported_group to an REcurveID we can do ECDHE on, gating to the
 * curves this cut supports (secp256r1, secp384r1, secp521r1, x25519, x448).
 * Returns FALSE otherwise. */
R_API_HIDDEN rboolean r_tls_ecdhe_group_to_curve (RTLSSupportedGroup group,
    REcurveID * curve);

/* TRUE for Montgomery curves (x25519/x448) whose wire ECPoint is the raw
 * little-endian u-coordinate; FALSE for short-Weierstrass curves whose
 * ECPoint is the SEC 1 uncompressed encoding. */
R_API_HIDDEN rboolean r_tls_ecdhe_curve_is_montgomery (REcurveID curve);

/* Generate an ephemeral ECDH private key on @curve. NULL on failure. */
R_API_HIDDEN RCryptoKey * r_tls_ecdhe_keygen (REcurveID curve, RPrng * prng);

/* Serialize @key's public point into @out (capacity @cap) in TLS ECPoint wire
 * form for @curve, writing the byte length to @len. FALSE on bad key / small
 * buffer. */
R_API_HIDDEN rboolean r_tls_ecdhe_point_write (const RCryptoKey * key,
    REcurveID curve, ruint8 * out, rsize cap, ruint8 * len);

/* Parse a peer's TLS ECPoint (@point/@len) on @curve into a public key.
 * Weierstrass points are decoded and on-curve checked; Montgomery
 * u-coordinates are length checked (any 32 bytes form a valid input). NULL on
 * a malformed point. Identity / small-subgroup inputs are rejected later, by
 * r_tls_ecdhe_compute. */
R_API_HIDDEN RCryptoKey * r_tls_ecdhe_point_read (REcurveID curve,
    const ruint8 * point, rsize len);

/* Compute the ECDH shared secret between local private @priv and peer public
 * @peer into @out (capacity @cap), writing its length to @len. The TLS
 * pre-master secret is this raw, fixed-width coordinate. FALSE on failure or a
 * rejected (e.g. all-zero) secret. */
R_API_HIDDEN rboolean r_tls_ecdhe_compute (const RCryptoKey * priv,
    const RCryptoKey * peer, ruint8 * out, rsize cap, rsize * len);

R_END_DECLS

#endif /* __R_NET_PROTO_TLS_PRIV_H__ */
