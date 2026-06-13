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
#ifndef __R_NET_TLS_CLIENT_H__
#define __R_NET_TLS_CLIENT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/rtlsclient.h
 * @brief Client-side TLS / DTLS session: drives the handshake, verifies the
 * server certificate, and encrypts / decrypts record traffic via callbacks.
 */

#include <rlib/rtypes.h>

#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rtlsciphersuite.h>
#include <rlib/ev/revloop.h>
#include <rlib/net/proto/rtls.h>
#include <rlib/net/rtlsserver.h>   /* RTLSCallbacks (shared with the server) */

#include <rlib/rbuffer.h>
#include <rlib/rref.h>

/**
 * @defgroup r_tls_client TLS / DTLS client
 * @ingroup r_net
 *
 * @brief Client-side TLS / DTLS endpoint that initiates a handshake and
 * encrypts / decrypts record traffic via callbacks.
 *
 * Like @ref r_tls_server it is transport-agnostic: @ref r_tls_client_start
 * builds and emits the ClientHello through the @c out callback, received
 * bytes are fed in with @ref r_tls_client_incoming_data, and the
 * @ref RTLSCallbacks deliver outgoing records (@c out) and decrypted
 * application data (@c appdata). The server certificate is checked with the
 * @c verify_cert callback (or inspected afterwards via
 * @ref r_tls_client_get_peer_cert).
 *
 * Mirrors @ref r_tls_server with the roles reversed; the initial capability
 * matches it (TLS / DTLS 1.2, RSA key exchange).
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted TLS / DTLS client session. */
typedef struct RTLSClient RTLSClient;

/** @brief Create a TLS client with the given callbacks and user context. */
R_API RTLSClient * r_tls_client_new (const RTLSCallbacks * cb,
    rpointer userdata, RDestroyNotify notify) R_ATTR_MALLOC;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_tls_client_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_tls_client_unref  r_ref_unref

/**
 * @brief Set the client certificate and private key for mutual TLS.
 *
 * When the server sends a CertificateRequest the client presents @p cert and
 * proves possession of it with @p privkey; without this the client answers a
 * CertificateRequest with an empty certificate. RSA keys with
 * rsa_pkcs1_sha256 are supported.
 */
R_API RTLSError r_tls_client_set_cert (RTLSClient * client,
    RCryptoCert * cert, RCryptoKey * privkey);
/**
 * @brief Offer @p host in the ClientHello @c server_name (SNI) extension.
 *
 * Lets the server select a certificate (and policy) for the requested name --
 * see @ref r_tls_server_get_server_name. Pass @c NULL to clear. Must be called
 * before @ref r_tls_client_start. @p host is copied.
 */
R_API RTLSError r_tls_client_set_server_name (RTLSClient * client,
    const rchar * host);
/** @brief Override the client-random (testing / determinism). */
R_API RTLSError r_tls_client_set_random (RTLSClient * client,
    const ruint8 clirandom[R_TLS_HELLO_RANDOM_BYTES]);
/**
 * @brief Start the session on @p loop, drawing randomness from @p prng, and
 * emit the ClientHello offering @p version (@c R_TLS_VERSION_TLS_1_2 or
 * @c R_TLS_VERSION_DTLS_1_2).
 */
R_API RTLSError r_tls_client_start (RTLSClient * client, REvLoop * loop,
    RPrng * prng, RTLSVersion version) R_ATTR_WARN_UNUSED_RESULT;

/** @brief Feed received ciphertext bytes into the session. */
R_API rboolean r_tls_client_incoming_data (RTLSClient * client, RBuffer * buffer);
/** @brief Encrypt and send application data through the session. */
R_API rboolean r_tls_client_send_appdata (RTLSClient * client, RBuffer * buffer);
/**
 * @brief Cleanly close an established session.
 *
 * Emits a warning @c close_notify alert to the peer and moves the session to
 * its closed state; @ref r_tls_client_send_appdata refuses thereafter. Returns
 * @c TRUE if the alert was emitted, @c FALSE if the session was not in its
 * application-data state (so a second call is a no-op). This does not free the
 * session — drop the reference with @ref r_tls_client_unref.
 */
R_API rboolean r_tls_client_close (RTLSClient * client);

/** @brief Export RFC 5705 keying material for an application label / context. */
R_API RTLSError r_tls_client_export_keying_material (const RTLSClient * client,
    ruint8 * material, rsize size, const rchar * label, rsize len,
    const ruint8 * ctx, rsize ctxsize);

/** @brief Negotiated TLS / DTLS version. */
R_API RTLSVersion r_tls_client_get_version (const RTLSClient * client);
/** @brief Negotiated cipher suite, or @c NULL before the ServerHello. */
R_API const RTLSCipherSuiteInfo * r_tls_client_get_cipher_suite (const RTLSClient * client);
/** @brief The server's end-entity certificate (borrowed), or @c NULL. */
R_API RCryptoCert * r_tls_client_get_peer_cert (const RTLSClient * client);
/** @brief Negotiated DTLS-SRTP protection profile (for @ref r_srtp). */
R_API RSRTPCipherSuite r_tls_client_get_dtls_srtp_profile (const RTLSClient * client);

R_END_DECLS

/** @} */

#endif /* __R_NET_TLS_CLIENT_H__ */
