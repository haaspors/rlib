/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_NET_SRTP_H__
#define __R_NET_SRTP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/rsrtp.h
 * @brief SRTP / SRTCP encryption and decryption keyed per SSRC.
 */

#include <rlib/rtypes.h>
#include <rlib/rtime.h>

#include <rlib/crypto/rsrtpciphersuite.h>
#include <rlib/net/proto/rrtp.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>


/** @brief Wildcard SSRC filter matching any stream (see @ref r_srtp_add_crypto_context_with_filter). */
#define R_SRTP_FILTER_ANY         RUINT32_MAX

/** @brief Largest supported Master Key Identifier, in bytes (see @ref r_srtp_add_crypto_context_for_ssrc_with_mki). */
#define R_SRTP_MAX_MKI_SIZE       16

/**
 * @defgroup r_srtp SRTP / SRTCP
 * @ingroup r_net
 *
 * @brief Encrypt and authenticate RTP / RTCP packets (RFC 3711) using
 * per-SSRC crypto contexts.
 *
 * Create an @ref RSRTPCtx, register a cipher suite + key per SSRC
 * (@ref r_srtp_add_crypto_context_for_ssrc) or for a filter pattern
 * (@ref r_srtp_add_crypto_context_with_filter, e.g.
 * @ref R_SRTP_FILTER_ANY), then transform packets with the
 * encrypt / decrypt entry points. Keys typically come from a
 * DTLS-SRTP handshake (see @ref r_tls_server). Individual RTP header
 * extension IDs can be marked for encryption with
 * @ref r_srtp_set_encrypted_header_extension (RFC 6904).
 *
 * For key rollover, a crypto context can carry more than one master key, each
 * tagged with a Master Key Identifier (MKI) that is written into every
 * protected packet and read back to pick the decrypting key (RFC 3711 3.1,
 * 8.1). Create such a context with the @c _with_mki constructors, stage extra
 * keys with @ref r_srtp_add_master_key, and switch the sending key with
 * @ref r_srtp_set_send_master_key.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Result code from an SRTP operation. */
typedef enum {
  R_SRTP_ERROR_OK,                /**< Success. */
  R_SRTP_ERROR_OOM,               /**< Allocation failed. */
  R_SRTP_ERROR_INVAL,             /**< Invalid argument. */
  R_SRTP_ERROR_INTERNAL,          /**< Internal error. */
  R_SRTP_ERROR_NO_CRYPTO_CTX,     /**< No crypto context for the packet's SSRC. */
  R_SRTP_ERROR_CRYPTO_CTX_EXISTS, /**< A context already exists for that SSRC. */
  R_SRTP_ERROR_WRONG_DIRECTION,   /**< Context used for the wrong direction. */
  R_SRTP_ERROR_BAD_RTP_HDR,       /**< Malformed RTP header. */
  R_SRTP_ERROR_BAD_RTCP_HDR,      /**< Malformed RTCP header. */
  R_SRTP_ERROR_REPLAYED,          /**< Packet rejected as a replay. */
  R_SRTP_ERROR_REPLAY_TOO_OLD,    /**< Packet older than the replay window. */
  R_SRTP_ERROR_AUTH,              /**< Authentication-tag check failed. */
  R_SRTP_ERROR_E_BIT_MISMATCH,    /**< SRTCP E-bit / encryption-flag mismatch. */
} RSRTPError;

/** @brief Opaque, refcounted SRTP session context (a set of per-SSRC keys). */
typedef struct RSRTPCtx RSRTPCtx;

/** @brief Create an empty SRTP context. */
R_API RSRTPCtx * r_srtp_ctx_new (void) R_ATTR_MALLOC;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_srtp_ctx_ref      r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_srtp_ctx_unref    r_ref_unref

/** @brief Install a cipher suite + key for a specific @p ssrc. */
R_API RSRTPError r_srtp_add_crypto_context_for_ssrc (RSRTPCtx * ctx,
    ruint32 ssrc, RSRTPCipherSuite cs, const ruint8 * key);
/**
 * @brief Replace the master key of the per-SSRC crypto context for @p ssrc,
 * adding it if none exists.
 *
 * Rolls the key for an SSRC in place: the SRTP packet index continues (the
 * sequence does not restart) and, if EKT is announcing this SSRC, the new key
 * is advertised in a fresh Full-field burst at the next epoch
 * (@ref r_srtp_add_ekt_key). Use it to rotate an EKT sender's own key.
 *
 * @param ctx   The SRTP context.
 * @param ssrc  The synchronization source to rekey.
 * @param cs    The cipher suite.
 * @param key   The new master key + salt blob.
 * @return @ref R_SRTP_ERROR_OK, @ref R_SRTP_ERROR_INVAL or @ref R_SRTP_ERROR_OOM.
 */
R_API RSRTPError r_srtp_update_crypto_context_for_ssrc (RSRTPCtx * ctx,
    ruint32 ssrc, RSRTPCipherSuite cs, const ruint8 * key);

/** @brief Install a cipher suite + key for an SSRC @p filter (e.g. @ref R_SRTP_FILTER_ANY). */
R_API RSRTPError r_srtp_add_crypto_context_with_filter (RSRTPCtx * ctx,
    ruint32 filter, RSRTPCipherSuite cs, const ruint8 * key);
/**
 * @brief Install a cipher suite for an SSRC @p filter with distinct keys per
 * direction: @p recvkey decrypts inbound packets, @p sendkey encrypts outbound.
 *
 * DTLS-SRTP derives a separate write key for each side (RFC 5764 4.2); a
 * transport keys one @ref R_SRTP_FILTER_ANY context with the peer's write key
 * for receive and its own for send. @ref r_srtp_add_crypto_context_with_filter
 * is the single-key case where both directions share @p key.
 */
R_API RSRTPError r_srtp_add_crypto_context_with_filter_dual (RSRTPCtx * ctx,
    ruint32 filter, RSRTPCipherSuite cs,
    const ruint8 * recvkey, const ruint8 * sendkey);

/**
 * @brief Install an MKI-enabled crypto context for a specific @p ssrc, keyed
 * with its first master key (RFC 3711 8.1).
 *
 * Like @ref r_srtp_add_crypto_context_for_ssrc but reserves @p mkisize bytes
 * for a Master Key Identifier in every protected packet and tags this master
 * key with @p mki. @p recvkey decrypts inbound packets, @p sendkey encrypts
 * outbound (as in @ref r_srtp_add_crypto_context_with_filter_dual). Stage
 * additional keys for rollover with @ref r_srtp_add_master_key and select the
 * outbound one with @ref r_srtp_set_send_master_key; this first key is the
 * initial send key. @p mkisize is fixed for the lifetime of the context and
 * must be 1..@ref R_SRTP_MAX_MKI_SIZE.
 *
 * @param ctx      The SRTP context.
 * @param ssrc     The synchronization source this context keys.
 * @param cs       The cipher suite.
 * @param mkisize  MKI length in bytes (1..@ref R_SRTP_MAX_MKI_SIZE).
 * @param recvkey  Master key + salt used to decrypt inbound packets.
 * @param sendkey  Master key + salt used to encrypt outbound packets.
 * @param mki      The @p mkisize-byte identifier for this master key.
 * @return @ref R_SRTP_ERROR_OK, @ref R_SRTP_ERROR_INVAL,
 *   @ref R_SRTP_ERROR_CRYPTO_CTX_EXISTS or @ref R_SRTP_ERROR_OOM.
 */
R_API RSRTPError r_srtp_add_crypto_context_for_ssrc_with_mki (RSRTPCtx * ctx,
    ruint32 ssrc, RSRTPCipherSuite cs, ruint8 mkisize,
    const ruint8 * recvkey, const ruint8 * sendkey, const ruint8 * mki);

/**
 * @brief Install an MKI-enabled crypto context for an SSRC @p filter, keyed
 * with its first master key (RFC 3711 8.1).
 *
 * The @p filter counterpart of @ref r_srtp_add_crypto_context_for_ssrc_with_mki;
 * see it for the MKI and dual-key semantics.
 *
 * @param ctx      The SRTP context.
 * @param filter   The SSRC filter (e.g. @ref R_SRTP_FILTER_ANY); must be non-zero.
 * @param cs       The cipher suite.
 * @param mkisize  MKI length in bytes (1..@ref R_SRTP_MAX_MKI_SIZE).
 * @param recvkey  Master key + salt used to decrypt inbound packets.
 * @param sendkey  Master key + salt used to encrypt outbound packets.
 * @param mki      The @p mkisize-byte identifier for this master key.
 * @return @ref R_SRTP_ERROR_OK, @ref R_SRTP_ERROR_INVAL or @ref R_SRTP_ERROR_OOM.
 */
R_API RSRTPError r_srtp_add_crypto_context_with_filter_with_mki (RSRTPCtx * ctx,
    ruint32 filter, RSRTPCipherSuite cs, ruint8 mkisize,
    const ruint8 * recvkey, const ruint8 * sendkey, const ruint8 * mki);

/**
 * @brief Stage an additional master key on an MKI-enabled crypto context
 * (RFC 3711 8.1).
 *
 * Adds a master key, tagged with @p mki, to the context created for @p id — the
 * @c ssrc of a per-SSRC context or the @c filter value of a filter context. Its
 * MKI length must equal the context's @c mkisize. The key can then be received
 * immediately (the peer selects it by MKI); to start sending with it, call
 * @ref r_srtp_set_send_master_key. Adding a key does not change the send key.
 *
 * @param ctx      The SRTP context.
 * @param id       The @c ssrc or @c filter the context was created with.
 * @param recvkey  Master key + salt used to decrypt inbound packets.
 * @param sendkey  Master key + salt used to encrypt outbound packets.
 * @param mki      The identifier for this master key, @c mkisize bytes.
 * @return @ref R_SRTP_ERROR_OK, @ref R_SRTP_ERROR_INVAL,
 *   @ref R_SRTP_ERROR_NO_CRYPTO_CTX (no such context or it has no MKI),
 *   @ref R_SRTP_ERROR_CRYPTO_CTX_EXISTS (that MKI is already in use) or
 *   @ref R_SRTP_ERROR_OOM.
 */
R_API RSRTPError r_srtp_add_master_key (RSRTPCtx * ctx, ruint32 id,
    const ruint8 * recvkey, const ruint8 * sendkey, const ruint8 * mki);

/**
 * @brief Select which master key, by @p mki, the sender uses for outbound
 * packets (RFC 3711 8.1).
 *
 * Switches the active send key of the context created for @p id to the staged
 * master key tagged with @p mki. Inbound selection is unaffected: any staged
 * key can still decrypt. Use this to complete a rollover once both peers know
 * the new key.
 *
 * @param ctx  The SRTP context.
 * @param id   The @c ssrc or @c filter the context was created with.
 * @param mki  The identifier of the master key to send with, @c mkisize bytes.
 * @return @ref R_SRTP_ERROR_OK, @ref R_SRTP_ERROR_INVAL or
 *   @ref R_SRTP_ERROR_NO_CRYPTO_CTX (no such context, the context has no MKI,
 *   or no key with that MKI).
 */
R_API RSRTPError r_srtp_set_send_master_key (RSRTPCtx * ctx, ruint32 id,
    const ruint8 * mki);

/**
 * @brief Mark an RTP header-extension @p id as encrypted, or clear it (RFC 6904).
 *
 * Enables encryption of the bodies of RFC 8285 header-extension elements
 * carrying @p id, in both directions, for every stream of @p ctx. The 4-byte
 * extension header, the per-element ID/length bytes, padding and the bodies of
 * unmarked elements stay in the clear, so the extension remains parseable; the
 * SRTP auth tag covers the encrypted form. @p id is an RFC 8285 element
 * identifier (1..255), matching an SDP @c a=extmap that uses the
 * @c urn:ietf:params:rtp-hdrext:encrypt wrapper. Only extensions with the RFC
 * 8285 profiles are affected; note the one-byte form (@c 0xBEDE) carries only
 * IDs 1..14 on the wire, so marking an ID above 14 has no effect there, while
 * the two-byte form (@c 0x100x) carries 1..255.
 *
 * Call this during setup, before the first packet is processed: the extra
 * session keys are derived when a stream is first used, so IDs registered
 * afterwards do not apply to streams already in flight.
 *
 * @param ctx        The SRTP context.
 * @param id         The header-extension identifier (1..255; 0 is invalid).
 * @param encrypted  @c TRUE to encrypt this ID, @c FALSE to stop encrypting it.
 * @return @ref R_SRTP_ERROR_OK on success, @ref R_SRTP_ERROR_INVAL for a bad
 *   argument, or @ref R_SRTP_ERROR_OOM.
 */
R_API RSRTPError r_srtp_set_encrypted_header_extension (RSRTPCtx * ctx,
    ruint8 id, rboolean encrypted);

/** @brief EKT cipher used to wrap the SRTP master key (RFC 8870 4.4). */
typedef enum {
  R_SRTP_EKT_CIPHER_AESKW_128,      /**< AES-128 Key Wrap (mandatory to implement). */
  R_SRTP_EKT_CIPHER_AESKW_256,      /**< AES-256 Key Wrap. */
} RSRTPEktCipher;

/**
 * @brief Install an EKTKey for Encrypted Key Transport (RFC 8870).
 *
 * EKT carries a sender's SRTP master key in-band, in an EKT field appended
 * after the SRTP/SRTCP auth tag, so a peer (typically a conference focus) can
 * learn and rotate keys without separate signalling. Configuring at least one
 * EKTKey turns EKT on for @p ctx: protected packets gain an EKT field and, on
 * unprotect, a Full EKT field's wrapped key is ingested to key the sending
 * SSRC. Enable this before processing traffic.
 *
 * The @p spi selects this EKTKey in EKT fields. @p cipher and @p key are the
 * AES Key Wrap cipher and key-encryption key that wrap/unwrap the master key.
 * @p cs is the SRTP cipher suite the transported keys are used with, and
 * @p salt is the master salt paired with those keys (its length must match the
 * suite's salt size); both come from signalling alongside the EKTKey.
 *
 * @param ctx       The SRTP context.
 * @param spi       Security Parameter Index identifying this EKTKey (0..65535).
 * @param cipher    The EKT (AES Key Wrap) cipher.
 * @param key       The key-encryption key (16 bytes for AESKW-128, 32 for -256).
 * @param cs        SRTP cipher suite for keys carried under this EKTKey.
 * @param salt      SRTP master salt for those keys.
 * @param saltsize  Length of @p salt; must equal the suite's master-salt size.
 * @return @ref R_SRTP_ERROR_OK, @ref R_SRTP_ERROR_INVAL,
 *   @ref R_SRTP_ERROR_CRYPTO_CTX_EXISTS (that SPI is already configured) or
 *   @ref R_SRTP_ERROR_OOM.
 */
R_API RSRTPError r_srtp_add_ekt_key (RSRTPCtx * ctx, ruint16 spi,
    RSRTPEktCipher cipher, const ruint8 * key,
    RSRTPCipherSuite cs, const ruint8 * salt, rsize saltsize);

/**
 * @brief Select the EKTKey, by @p spi, used to build outbound Full EKT fields.
 *
 * Sending an SSRC's packets then appends an EKT field carrying that SSRC's
 * SRTP master key (wrapped under this EKTKey) and rollover counter: a Full
 * field in a short startup burst and periodically, a Short field otherwise.
 * Without a send key, protected packets still carry a Short field so the
 * stream remains EKT-framed. The master key wrapped is the one already
 * installed for the sending SSRC (see @ref r_srtp_add_crypto_context_for_ssrc).
 *
 * @param ctx  The SRTP context.
 * @param spi  SPI of a configured EKTKey (see @ref r_srtp_add_ekt_key).
 * @return @ref R_SRTP_ERROR_OK, @ref R_SRTP_ERROR_INVAL or
 *   @ref R_SRTP_ERROR_NO_CRYPTO_CTX (no EKTKey with that SPI).
 */
R_API RSRTPError r_srtp_set_ekt_send_key (RSRTPCtx * ctx, ruint16 spi);

/**
 * @brief Set how often a Full EKT field is re-sent for a keyed sending SSRC.
 *
 * Beyond the startup burst, sending a Full field periodically lets a receiver
 * that joins mid-stream (e.g. a new participant behind a conference focus)
 * learn the master key without waiting for a rekey (RFC 8870 4.6). @p interval
 * is a monotonic-clock duration (see @ref r_time_get_ts_monotonic); @c 0
 * disables periodic re-sends, leaving only the burst and rekey announcements.
 *
 * @param ctx       The SRTP context (EKT must be configured).
 * @param interval  Minimum time between Full fields, or @c 0 for burst-only.
 * @return @ref R_SRTP_ERROR_OK, @ref R_SRTP_ERROR_INVAL or
 *   @ref R_SRTP_ERROR_NO_CRYPTO_CTX (EKT not configured).
 */
R_API RSRTPError r_srtp_set_ekt_full_interval (RSRTPCtx * ctx, RClockTime interval);

/** @brief Encrypt an RTP packet into a new SRTP buffer. */
R_API RBuffer * r_srtp_encrypt_rtp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * err) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Decrypt and verify an SRTP packet into a new RTP buffer. */
R_API RBuffer * r_srtp_decrypt_rtp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * err) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Encrypt an RTCP packet into a new SRTCP buffer. */
R_API RBuffer * r_srtp_encrypt_rtcp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * err) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Decrypt and verify an SRTCP packet into a new RTCP buffer. */
R_API RBuffer * r_srtp_decrypt_rtcp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * err) R_ATTR_WARN_UNUSED_RESULT;

R_END_DECLS

/** @} */

#endif /* __R_NET_SRTP_H__ */


