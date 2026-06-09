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
#ifndef __R_NET_TLS_SERVER_H__
#define __R_NET_TLS_SERVER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/rtlsserver.h
 * @brief Server-side TLS / DTLS session: handshake, record I/O, key
 * export and DTLS-SRTP negotiation.
 */

#include <rlib/rtypes.h>

#include <rlib/crypto/rtlsciphersuite.h>
#include <rlib/crypto/rkey.h>
#include <rlib/ev/revloop.h>
#include <rlib/net/proto/rtls.h>
#include <rlib/net/rtlssessiontickets.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>

/**
 * @defgroup r_tls_server TLS / DTLS server
 * @ingroup r_net
 *
 * @brief Server-side TLS / DTLS endpoint driving a handshake and
 * encrypting / decrypting record traffic via callbacks.
 *
 * The transport is callback-based rather than owning a socket: feed
 * received bytes in with @ref r_tls_server_incoming_data, and the
 * @ref RTLSCallbacks deliver outgoing records (@c out) and decrypted
 * application data (@c appdata). Configure a certificate / key with
 * @ref r_tls_server_set_cert, then @ref r_tls_server_start.
 *
 * Also exposes DTLS-SRTP negotiation (@ref r_tls_server_get_dtls_srtp_profile)
 * for @ref r_srtp keying, and RFC 5705 keying-material export.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted TLS / DTLS server session. */
typedef struct RTLSServer RTLSServer;

/**
 * @brief Callback delivering a buffer (outgoing record or app data).
 *
 * @p session is the @ref RTLSServer or @ref RTLSClient the callback bundle
 * is attached to (the bundle is shared between both); cast to the type the
 * caller registered it with.
 */
typedef rboolean (*RTLSBufferCb) (rpointer ctx, RBuffer * buf, rpointer session);
/** @brief Callback fired when the handshake completes (@p session as above). */
typedef void (*RTLSHandshakeDoneCb) (rpointer ctx, rpointer session);
/** @brief Callback selecting the preferred cipher suites for a TLS version. */
typedef rboolean (*RTLSPreferredCipherSuitesCb) (rpointer ctx, RTLSVersion ver, RTLSCipherSuite * cs, rsize * count);
/**
 * @brief Callback fired when the session aborts with a fatal alert.
 *
 * @p alert is the alert description sent to the peer. The session has
 * moved to its error state; the callback may fire more than once for a
 * session, so it should be idempotent (e.g. tear the transport down
 * only once). May be @c NULL. @p session is the @ref RTLSServer or
 * @ref RTLSClient the bundle is attached to.
 */
typedef void (*RTLSErrorCb) (rpointer ctx, RTLSAlertType alert, rpointer session);
/**
 * @brief Callback verifying the peer's certificate chain (leaf first).
 *
 * Invoked during the handshake with the parsed certificate @p chain
 * (@p count entries, the peer's end-entity certificate first). Return
 * @c FALSE to reject and abort the handshake with a @c bad_certificate
 * alert. May be @c NULL, which accepts any chain — appropriate for tests
 * and for verifying out of band (e.g. SDP fingerprint) after the
 * handshake. The certificates are borrowed; do not unref them.
 *
 * Used by @ref RTLSClient to validate the server certificate, and by the
 * server to validate a client certificate under mutual TLS (see
 * @ref r_tls_server_set_client_cert_mode). This callback is the trust
 * decision: the library only checks proof-of-possession (the
 * CertificateVerify signature), so a @c NULL callback authenticates any
 * well-formed certificate.
 */
typedef rboolean (*RTLSCertVerifyCb) (rpointer ctx, RCryptoCert * const * chain, ruint count);

/** @brief Callback bundle wiring a session to its transport and policy. */
typedef struct {
  RTLSPreferredCipherSuitesCb   preferred_cipher_suites; /**< Choose cipher suites; may be @c NULL for defaults. */
  RTLSHandshakeDoneCb           handshake_done;          /**< Fired once the handshake finishes. */
  RTLSBufferCb                  out;                     /**< Sink for outgoing encrypted records. */
  RTLSBufferCb                  appdata;                 /**< Sink for decrypted application data. */
  RTLSErrorCb                   error;                   /**< Fired on a fatal alert; may be @c NULL. */
  RTLSCertVerifyCb              verify_cert;             /**< Verify the peer certificate chain; may be @c NULL. */
} RTLSCallbacks;

/** @brief Create a TLS server with the given callbacks and user context. */
R_API RTLSServer * r_tls_server_new (const RTLSCallbacks * cb,
    rpointer userdata, RDestroyNotify notify) R_ATTR_MALLOC;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_tls_server_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_tls_server_unref  r_ref_unref

/**
 * @brief Client-certificate (mutual-TLS) policy.
 *
 * Selects whether the server asks the client for a certificate and whether one
 * is mandatory. When a certificate is presented it is delivered to the
 * @ref RTLSCertVerifyCb for validation and its CertificateVerify signature is
 * checked; the verified leaf is then available via
 * @ref r_tls_server_get_peer_cert.
 */
typedef enum {
  R_TLS_CLIENT_CERT_MODE_NONE = 0,   /**< Do not request a client certificate (default). */
  R_TLS_CLIENT_CERT_MODE_REQUEST,    /**< Request one; an empty/absent certificate is accepted. */
  R_TLS_CLIENT_CERT_MODE_REQUIRE,    /**< Require one; an empty/absent certificate aborts the handshake. */
} RTLSClientCertMode;

/** @brief Set the server certificate and its private key. */
R_API RTLSError r_tls_server_set_cert (RTLSServer * server,
    RCryptoCert * cert, RCryptoKey * privkey);
/**
 * @brief Set the client-certificate (mutual-TLS) policy; defaults to
 * @ref R_TLS_CLIENT_CERT_MODE_NONE. Must be set before the handshake starts.
 */
R_API RTLSError r_tls_server_set_client_cert_mode (RTLSServer * server,
    RTLSClientCertMode mode);
/**
 * @brief The peer (client) leaf certificate presented during a mutual-TLS
 * handshake, or @c NULL if none was presented. The reference is borrowed
 * (owned by the session); ref it to outlive the session.
 */
R_API RCryptoCert * r_tls_server_get_peer_cert (const RTLSServer * server);
/**
 * @brief Attach the shared key store used to seal and open session tickets.
 *
 * The server takes a reference to @p keys, so one store can back many servers.
 * With no store configured the server neither offers nor issues session
 * tickets. See @ref r_tls_session_tickets.
 */
R_API RTLSError r_tls_server_set_session_ticket_keys (RTLSServer * server,
    RTLSSessionTicketKeys * keys);
/** @brief Override the server-random (testing / determinism). */
R_API RTLSError r_tls_server_set_random (RTLSServer * server,
    const ruint8 servrandom[R_TLS_HELLO_RANDOM_BYTES]);
/** @brief Start the session on @p loop, drawing randomness from @p prng. */
R_API RTLSError r_tls_server_start (RTLSServer * server, REvLoop * loop,
    RPrng * prng) R_ATTR_WARN_UNUSED_RESULT;

/** @brief Feed received ciphertext bytes into the session. */
R_API rboolean r_tls_server_incoming_data (RTLSServer * server, RBuffer * buffer);
/** @brief Encrypt and send application data through the session. */
R_API rboolean r_tls_server_send_appdata (RTLSServer * server, RBuffer * buffer);

/** @brief Export RFC 5705 keying material for an application label / context. */
R_API RTLSError r_tls_server_export_keying_material (const RTLSServer * server,
    ruint8 * material, rsize size, const rchar * label, rsize len,
    const ruint8 * ctx, rsize ctxsize);


/** @brief Negotiated TLS / DTLS version. */
R_API RTLSVersion r_tls_server_get_version (const RTLSServer * server);
/** @brief Negotiated cipher suite, or @c NULL before the handshake completes. */
R_API const RTLSCipherSuiteInfo * r_tls_server_get_cipher_suite (const RTLSServer * server);
/** @brief Negotiated DTLS-SRTP protection profile (for @ref r_srtp). */
R_API RSRTPCipherSuite r_tls_server_get_dtls_srtp_profile (const RTLSServer * server);
/** @brief Negotiated DTLS-SRTP MKI; @p size receives its byte length. */
R_API const ruint8 * r_tls_server_get_dtls_srtp_mki (const RTLSServer * server, ruint8 * size);

R_END_DECLS

/** @} */

#endif /* __R_NET_TLS_SERVER_H__ */

