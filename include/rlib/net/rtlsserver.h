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
/**
 * @brief Callback fired when the peer cleanly closes the session.
 *
 * Invoked once when an inbound @c close_notify is received: the session has
 * sent its own @c close_notify in reply and moved to its closed state, in
 * which it accepts no further application data. Distinct from
 * @ref RTLSErrorCb, which signals an aborted (fatal) session. May be @c NULL.
 * @p session is the @ref RTLSServer or @ref RTLSClient the bundle is attached
 * to.
 */
typedef void (*RTLSClosedCb) (rpointer ctx, rpointer session);
/**
 * @brief Callback selecting the certificate / policy for the requested SNI host
 * (server only).
 *
 * Fired during the handshake once the ClientHello has been parsed, with the
 * @c server_name (SNI) host the client requested (@c NULL if it sent none).
 * @p session is the @ref RTLSServer; the callback may call
 * @ref r_tls_server_set_cert and @ref r_tls_server_set_client_cert_mode on it to
 * configure this connection for the named host. Return @ref R_TLS_ERROR_OK to
 * proceed, or an error to abort the handshake. May be @c NULL.
 *
 * Runs before cipher negotiation, so the selected certificate (its key type) and
 * any per-connection cipher preference drive suite selection. Applies to full
 * handshakes only: a resumed (abbreviated) session reuses the original session's
 * certificate and verified peer, so a per-name policy is not re-applied on
 * resumption. If a per-name client-cert requirement must hold across resumption,
 * do not enable session tickets (@ref r_tls_server_set_session_ticket_keys).
 */
typedef RTLSError (*RTLSServerNameCb) (rpointer ctx, const rchar * name, rpointer session);

/** @brief Callback bundle wiring a session to its transport and policy. */
typedef struct {
  RTLSPreferredCipherSuitesCb   preferred_cipher_suites; /**< Choose cipher suites; may be @c NULL for defaults. */
  RTLSHandshakeDoneCb           handshake_done;          /**< Fired once the handshake finishes. */
  RTLSBufferCb                  out;                     /**< Sink for outgoing encrypted records. */
  RTLSBufferCb                  appdata;                 /**< Sink for decrypted application data. */
  RTLSErrorCb                   error;                   /**< Fired on a fatal alert; may be @c NULL. */
  RTLSCertVerifyCb              verify_cert;             /**< Verify the peer certificate chain; may be @c NULL. */
  RTLSClosedCb                  closed;                  /**< Fired on a peer close_notify; may be @c NULL. */
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
 * @brief Set a callback that selects the certificate / policy by SNI host name.
 *
 * Invoked during the handshake once the ClientHello is parsed (see
 * @ref RTLSServerNameCb), letting the server pick the certificate and
 * client-certificate policy for the requested name. Must be set before the
 * handshake starts; @c NULL clears it.
 */
R_API RTLSError r_tls_server_set_server_name_cb (RTLSServer * server,
    RTLSServerNameCb cb);
/**
 * @brief The peer (client) leaf certificate presented during a mutual-TLS
 * handshake, or @c NULL if none was presented. The reference is borrowed
 * (owned by the session); ref it to outlive the session.
 */
R_API RCryptoCert * r_tls_server_get_peer_cert (const RTLSServer * server);
/**
 * @brief The host requested in the ClientHello @c server_name (SNI) extension,
 * or @c NULL if the client sent none.
 *
 * Borrowed (owned by the session). Valid once the ClientHello has been
 * processed -- e.g. inside an @ref RTLSServerNameCb, or after the handshake.
 */
R_API const rchar * r_tls_server_get_server_name (const RTLSServer * server);
/**
 * @brief Attach the shared key store used to seal and open session tickets.
 *
 * The server takes a reference to @p keys, so one store can back many servers.
 * With no store configured the server neither offers nor issues session
 * tickets. See @ref r_tls_session_tickets.
 */
R_API RTLSError r_tls_server_set_session_ticket_keys (RTLSServer * server,
    RTLSSessionTicketKeys * keys);
/**
 * @brief Enable TLS 1.3 0-RTT early data, accepting up to @p size bytes.
 *
 * Opt in to 0-RTT (RFC 8446 2.3): the NewSessionTicket then advertises an
 * @c early_data extension with @p size as @c max_early_data_size, and a later
 * resumption that offers @c early_data is accepted -- the server decrypts the
 * client's 0-RTT records under the client early-traffic key and delivers them
 * through the @c appdata callback before the handshake completes. Requires a
 * session-ticket key store (@ref r_tls_server_set_session_ticket_keys); with
 * @p size 0 (the default) the server neither advertises nor accepts early data.
 *
 * @warning 0-RTT data carries no forward secrecy and, because the tickets are
 * stateless, this implementation provides no replay protection beyond the
 * ticket lifetime: an on-path attacker may replay the early-data records and the
 * server will accept them again. Enable this only when the 0-RTT-triggered
 * application actions are idempotent (RFC 8446 8, appendix E.5). The 1-RTT data
 * that follows the handshake is unaffected.
 */
R_API RTLSError r_tls_server_set_max_early_data_size (RTLSServer * server,
    ruint32 size);
/**
 * @brief Whether the current handshake accepted TLS 1.3 0-RTT early data.
 *
 * @c TRUE once a resumption offered early data and the server accepted it (see
 * @ref r_tls_server_set_max_early_data_size); the early-data bytes are delivered
 * via the @c appdata callback during the handshake.
 */
R_API rboolean r_tls_server_get_early_data_accepted (const RTLSServer * server);
/**
 * @brief Require a specific (EC)DHE group of TLS 1.3 clients (RFC 8446).
 *
 * When set, a TLS 1.3 ClientHello that does not carry a @c key_share for
 * @p group is answered with a HelloRetryRequest asking for it (provided the
 * client lists @p group in @c supported_groups); the client then retries with a
 * matching share. With @p group 0 (the default) the server accepts the client's
 * first offered key_share and never sends a HelloRetryRequest. Must be set
 * before the handshake starts.
 */
R_API RTLSError r_tls_server_set_key_share_group (RTLSServer * server,
    RTLSSupportedGroup group);
/**
 * @brief Configure the application protocols the server supports for ALPN
 * (RFC 7301), in descending order of preference.
 *
 * Each @p protocols entry is a NUL-terminated protocol name (e.g. @c "h2",
 * @c "http/1.1"); names are copied. When a client offers ALPN the server picks
 * the first configured protocol the client also lists (server preference) and
 * echoes it in the ServerHello; if none match the handshake aborts with a fatal
 * @c no_application_protocol alert. With no protocols configured (the default)
 * the server does not negotiate ALPN. Must be set before the handshake starts.
 * Returns @c R_TLS_ERROR_INVAL if any name is empty or longer than 255 bytes.
 * Call with @p count 0 to clear a previously configured list.
 */
R_API RTLSError r_tls_server_set_alpn_protocols (RTLSServer * server,
    const rchar * const * protocols, rsize count);
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
/**
 * @brief Cleanly close an established session.
 *
 * Emits a warning @c close_notify alert to the peer and moves the session to
 * its closed state; @ref r_tls_server_send_appdata refuses thereafter. Returns
 * @c TRUE if the alert was emitted, @c FALSE if the session was not in its
 * application-data state (so a second call is a no-op). This does not free the
 * session — drop the reference with @ref r_tls_server_unref.
 */
R_API rboolean r_tls_server_close (RTLSServer * server);

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
/**
 * @brief Negotiated ALPN protocol, or @c NULL if none was negotiated.
 *
 * Returns the protocol selected during the handshake (NUL-terminated); @p len,
 * when non-@c NULL, receives its length. See @ref r_tls_server_set_alpn_protocols.
 */
R_API const rchar * r_tls_server_get_alpn_selected (const RTLSServer * server, rsize * len);

R_END_DECLS

/** @} */

#endif /* __R_NET_TLS_SERVER_H__ */

