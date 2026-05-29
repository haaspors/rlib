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
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/net/rsrtp.h
 * @brief SRTP / SRTCP encryption and decryption keyed per SSRC.
 */

#include <rlib/rtypes.h>

#include <rlib/crypto/rsrtpciphersuite.h>
#include <rlib/net/proto/rrtp.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>


/** @brief Wildcard SSRC filter matching any stream (see @ref r_srtp_add_crypto_context_with_filter). */
#define R_SRTP_FILTER_ANY         RUINT32_MAX

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
 * DTLS-SRTP handshake (see @ref r_tls_server).
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
/** @brief Install a cipher suite + key for an SSRC @p filter (e.g. @ref R_SRTP_FILTER_ANY). */
R_API RSRTPError r_srtp_add_crypto_context_with_filter (RSRTPCtx * ctx,
    ruint32 filter, RSRTPCipherSuite cs, const ruint8 * key);

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


