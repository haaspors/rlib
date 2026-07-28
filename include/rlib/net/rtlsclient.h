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

/**
 * @brief Opaque, refcounted TLS 1.3 resumption session (RFC 8446).
 *
 * Carries a NewSessionTicket the server issued and the pre-shared key derived
 * from it, so a later @ref RTLSClient can resume without a full handshake.
 * Obtain one with @ref r_tls_client_get_session after a 1.3 handshake, and
 * feed it to a new client with @ref r_tls_client_set_session before starting.
 */
typedef struct RTLSClientSession RTLSClientSession;
/** @brief Take a reference on a resumption session (alias for @ref r_ref_ref). */
#define r_tls_client_session_ref    r_ref_ref
/** @brief Drop a reference; scrubs the PSK at zero (alias for @ref r_ref_unref). */
#define r_tls_client_session_unref  r_ref_unref

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
 * @brief Offer post-handshake client authentication (RFC 8446, 4.6.2; TLS 1.3).
 *
 * When @p enable is @c TRUE the client advertises the @c post_handshake_auth
 * extension in its ClientHello, permitting the server to send a
 * @c CertificateRequest after the handshake. The client answers with the
 * certificate configured via @ref r_tls_client_set_cert (or an empty
 * Certificate when none is set). Off by default; must be set before
 * @ref r_tls_client_start and has no effect on TLS 1.2 / DTLS.
 */
R_API RTLSError r_tls_client_set_post_handshake_auth (RTLSClient * client,
    rboolean enable);
/**
 * @brief Offer @p host in the ClientHello @c server_name (SNI) extension.
 *
 * Lets the server select a certificate (and policy) for the requested name --
 * see @ref r_tls_server_get_server_name. Pass @c NULL to clear. Must be called
 * before @ref r_tls_client_start. @p host is copied.
 */
R_API RTLSError r_tls_client_set_server_name (RTLSClient * client,
    const rchar * host);
/**
 * @brief Configure the application protocols the client offers for ALPN
 * (RFC 7301), in descending order of preference.
 *
 * Each @p protocols entry is a NUL-terminated protocol name (e.g. @c "h2",
 * @c "http/1.1"); names are copied and offered in a ClientHello @c ALPN
 * extension. The server's selection is then available via
 * @ref r_tls_client_get_alpn_selected. With no protocols configured (the
 * default) the client does not offer ALPN. Must be called before
 * @ref r_tls_client_start. Returns @c R_TLS_ERROR_INVAL if any name is empty or
 * longer than 255 bytes. Call with @p count 0 to clear a previously configured
 * list.
 */
R_API RTLSError r_tls_client_set_alpn_protocols (RTLSClient * client,
    const rchar * const * protocols, rsize count);
/**
 * @brief Advertise a TLS 1.3 @c record_size_limit (RFC 8449).
 *
 * @p limit is the largest protected-record plaintext -- counting the inner
 * content-type byte -- the client is willing to @e receive, in the range
 * 64 .. @ref R_TLS_MAX_PLAINTEXT (16384); an inbound record whose plaintext
 * exceeds it aborts the session with a @c record_overflow alert. The value is
 * offered in the ClientHello, and the server's echoed limit is honoured,
 * capping the plaintext of each record the client emits. With @p limit 0 (the
 * default) the client neither offers the extension nor enforces an inbound cap.
 * The cap governs post-handshake traffic (application data and post-handshake
 * messages); the handshake flight itself is exempt. Applies to TLS 1.3 only;
 * must be called before @ref r_tls_client_start. Returns @c R_TLS_ERROR_INVAL
 * for a non-zero @p limit below 64 or above @ref R_TLS_MAX_PLAINTEXT.
 */
R_API RTLSError r_tls_client_set_record_size_limit (RTLSClient * client,
    ruint16 limit);
/**
 * @brief Offer the @c status_request extension to request a stapled OCSP
 * response (RFC 6066 / RFC 8446 4.4.2.1).
 *
 * With @p request @c TRUE the ClientHello asks the server to staple an OCSP
 * response for its certificate; if the server does, it is available after the
 * handshake via @ref r_tls_client_get_ocsp_response. The staple is delivered
 * as-is -- the library does not validate it. Off by default; must be called
 * before @ref r_tls_client_start. Applies to TLS 1.3 only.
 */
R_API RTLSError r_tls_client_request_ocsp (RTLSClient * client, rboolean request);
/**
 * @brief The OCSP response the server stapled to its certificate, or @c NULL.
 *
 * Valid once the handshake has completed when @ref r_tls_client_request_ocsp was
 * set and the server stapled one (RFC 6066). The bytes are the DER
 * @c OCSPResponse, borrowed (owned by the session); @p len, when non-@c NULL,
 * receives the length. The library does not validate the response.
 */
R_API const ruint8 * r_tls_client_get_ocsp_response (const RTLSClient * client,
    rsize * len);
/**
 * @brief Offer the @c signed_certificate_timestamp extension to request SCTs
 * (RFC 6962).
 *
 * With @p request @c TRUE the ClientHello asks the server for Signed Certificate
 * Timestamps evidencing certificate-transparency log inclusion; if the server
 * carries them, the serialized @c SignedCertificateTimestampList is available
 * after the handshake via @ref r_tls_client_get_sct_list. The list is delivered
 * as-is -- the library does not validate it. Off by default; must be called
 * before @ref r_tls_client_start. Applies to TLS 1.3 only.
 */
R_API RTLSError r_tls_client_request_sct (RTLSClient * client, rboolean request);
/**
 * @brief The Signed Certificate Timestamps the server sent, or @c NULL.
 *
 * Valid once the handshake has completed when @ref r_tls_client_request_sct was
 * set and the server carried them (RFC 6962). The bytes are the serialized
 * @c SignedCertificateTimestampList, borrowed (owned by the session); @p len,
 * when non-@c NULL, receives the length. The library does not validate them.
 */
R_API const ruint8 * r_tls_client_get_sct_list (const RTLSClient * client,
    rsize * len);
/**
 * @brief Constrain the TLS versions the client offers.
 *
 * Both bounds lie in the window @c R_TLS_VERSION_TLS_1_2 ..
 * @c R_TLS_VERSION_TLS_1_3; @p min must not exceed @p max. The ClientHello
 * offers every version in the range (a @c [1.2, 1.3] range sends a hybrid
 * ClientHello that a server may answer with either), and a ServerHello outside
 * the range is refused. Without this call the range defaults to @c [1.2, @p
 * version] from @ref r_tls_client_start, so starting at 1.3 offers both 1.3 and
 * 1.2 (the common modern default) and starting at 1.2 offers 1.2 only; setting
 * @c [1.3, 1.3] pins the client to 1.3 with no downgrade. When set, the version
 * passed to @ref r_tls_client_start only selects TLS versus DTLS. Must be called
 * before @ref r_tls_client_start; DTLS is fixed at 1.2 and unaffected.
 */
R_API RTLSError r_tls_client_set_version_range (RTLSClient * client,
    RTLSVersion min, RTLSVersion max);
/** @brief Override the client-random (testing / determinism). */
R_API RTLSError r_tls_client_set_random (RTLSClient * client,
    const ruint8 clirandom[R_TLS_HELLO_RANDOM_BYTES]);
/**
 * @brief Offer @p session for TLS 1.3 resumption in the next handshake.
 *
 * The ClientHello will carry the session's ticket in a @c pre_shared_key
 * extension (with @c psk_dhe_ke); if the server accepts, the handshake is
 * abbreviated and no server certificate is exchanged. Must be called before
 * @ref r_tls_client_start and only applies when starting with
 * @c R_TLS_VERSION_TLS_1_3. The client takes its own reference; pass @c NULL to
 * clear. A server that declines simply runs a full handshake.
 */
R_API RTLSError r_tls_client_set_session (RTLSClient * client,
    RTLSClientSession * session);
/**
 * @brief The resumption session from the server's NewSessionTicket, or @c NULL.
 *
 * Available once a 1.3 handshake has completed and the server has issued a
 * ticket. The caller owns the returned reference (release with
 * @ref r_tls_client_session_unref) and may feed it to a future client via
 * @ref r_tls_client_set_session.
 */
R_API RTLSClientSession * r_tls_client_get_session (const RTLSClient * client);
/**
 * @brief Queue @p buffer as TLS 1.3 0-RTT early data for the next handshake.
 *
 * When the offered @ref RTLSClient session (@ref r_tls_client_set_session)
 * permits early data, the client sends @p buffer encrypted under the client
 * early-traffic key immediately after the ClientHello, before the handshake
 * completes (RFC 8446 2.3). If the server accepts, the peer receives it through
 * its @c appdata callback during the handshake; if the server rejects 0-RTT (or
 * the session does not permit it, or @p buffer exceeds the ticket's
 * @c max_early_data_size), the client transparently resends @p buffer as
 * ordinary application data once the handshake completes, so the payload is
 * delivered either way. Must be called before @ref r_tls_client_start; the
 * client takes a reference on @p buffer. Pass @c NULL to clear.
 *
 * @warning 0-RTT data is not forward secret and may be replayed; only use it for
 * idempotent requests (see @ref r_tls_server_set_max_early_data_size).
 */
R_API RTLSError r_tls_client_set_early_data (RTLSClient * client,
    RBuffer * buffer);
/**
 * @brief Whether the server accepted the 0-RTT early data offered this handshake.
 *
 * @c TRUE once the server has echoed the @c early_data extension, i.e. the data
 * set with @ref r_tls_client_set_early_data was delivered as 0-RTT. When @c FALSE
 * after the handshake the data was (or will be) resent as ordinary application
 * data. Meaningful once the handshake has progressed past EncryptedExtensions.
 */
R_API rboolean r_tls_client_get_early_data_accepted (const RTLSClient * client);
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
 * @brief Rekey an established TLS 1.3 session (RFC 8446, section 4.6.3).
 *
 * Sends a post-handshake @c KeyUpdate and advances our sending key to its next
 * generation. When @p request_peer_update is @c TRUE the peer must reply with
 * its own @c KeyUpdate, advancing our receiving key too; the reply is processed
 * on the next @ref r_tls_client_incoming_data.
 *
 * @param client              An established TLS 1.3 client.
 * @param request_peer_update Ask the peer to rekey its sending direction.
 * @return @c TRUE if the @c KeyUpdate was emitted; @c FALSE if the session is
 *  not an established TLS 1.3 session (@c <=1.2 or not yet in its
 *  application-data state) or the record could not be produced.
 */
R_API rboolean r_tls_client_key_update (RTLSClient * client,
    rboolean request_peer_update);
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
/**
 * @brief Negotiated ALPN protocol, or @c NULL if none was negotiated.
 *
 * Returns the protocol the server selected from the offered list
 * (NUL-terminated); @p len, when non-@c NULL, receives its length. See
 * @ref r_tls_client_set_alpn_protocols.
 */
R_API const rchar * r_tls_client_get_alpn_selected (const RTLSClient * client, rsize * len);

R_END_DECLS

/** @} */

#endif /* __R_NET_TLS_CLIENT_H__ */
