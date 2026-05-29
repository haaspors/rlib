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
#error "#include <rlib.h> only pelase."
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

/** @brief Callback delivering a buffer (outgoing record or app data). */
typedef rboolean (*RTLSServerBufferCb) (rpointer ctx, RBuffer * buf, RTLSServer * server);
/** @brief Callback fired when the handshake completes. */
typedef void (*RTLSServerHandshakeDoneCb) (rpointer ctx, RTLSServer * server);
/** @brief Callback selecting the preferred cipher suites for a TLS version. */
typedef rboolean (*RTLSPreferredCipherSuitesCb) (rpointer ctx, RTLSVersion ver, RTLSCipherSuite * cs, rsize * count);

/** @brief Callback bundle wiring a session to its transport and policy. */
typedef struct {
  RTLSPreferredCipherSuitesCb   preferred_cipher_suites; /**< Choose cipher suites; may be @c NULL for defaults. */
  RTLSServerHandshakeDoneCb     handshake_done;          /**< Fired once the handshake finishes. */
  RTLSServerBufferCb            out;                     /**< Sink for outgoing encrypted records. */
  RTLSServerBufferCb            appdata;                 /**< Sink for decrypted application data. */
} RTLSCallbacks;

/** @brief Create a TLS server with the given callbacks and user context. */
R_API RTLSServer * r_tls_server_new (const RTLSCallbacks * cb,
    rpointer userdata, RDestroyNotify notify) R_ATTR_MALLOC;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_tls_server_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_tls_server_unref  r_ref_unref

/** @brief Set the server certificate and its private key. */
R_API RTLSError r_tls_server_set_cert (RTLSServer * server,
    RCryptoCert * cert, RCryptoKey * privkey);
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
R_API RTLSError r_tls_server_export_keying_matierial (const RTLSServer * server,
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

