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
#ifndef __R_RTC_SESSION_H__
#define __R_RTC_SESSION_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtcsession.h
 * @brief WebRTC session: factory for ICE / DTLS transports and RTP
 * senders, receivers and transceivers.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/rrand.h>

#include <rlib/rtc/rrtcicetransport.h>
#include <rlib/rtc/rrtccryptotransport.h>
#include <rlib/rtc/rrtcrtpreceiver.h>
#include <rlib/rtc/rrtcrtpsender.h>
#include <rlib/rtc/rrtcrtptransceiver.h>

#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rkey.h>

#include <rlib/ev/revloop.h>

/**
 * @defgroup r_rtc_session WebRTC session
 * @ingroup r_rtc
 *
 * @brief A WebRTC session owns and creates the runtime objects for a
 * peer connection: @c RRtcIceTransport / @c RRtcCryptoTransport
 * transports and the @c RRtcRtpSender, @c RRtcRtpReceiver and
 * @c RRtcRtpTransceiver media endpoints layered on top of them.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque WebRTC session handle. */
typedef struct RRtcSession RRtcSession;
/** @brief Opaque controller coordinating a session's transports. */
typedef struct RRtcTransportController RRtcTransportController;

/**
 * @brief Create a session with explicit @p id (of @p size bytes) using
 * @p prng for random-value generation.
 */
R_API RRtcSession * r_rtc_session_new_full (const rchar * id, rssize size,
    RPrng * prng) R_ATTR_MALLOC;
/** @brief Create a session with an auto-generated id, using @p prng. */
#define r_rtc_session_new(prng) r_rtc_session_new_full (NULL, 0, prng)
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_session_ref       r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_session_unref     r_ref_unref

/** @brief Return the session's id string. */
R_API const rchar * r_rtc_session_get_id (const RRtcSession * s);
/** @brief Look up a transceiver by @p id (of @p size bytes); @c NULL if absent. */
R_API RRtcRtpTransceiver * r_rtc_session_lookup_rtp_transceiver (RRtcSession * s,
    const rchar * id, rssize size);

/**
 * @brief Create an ICE transport seeded with the local @p ufrag (of
 * @p usize bytes) and @p pwd (of @p psize bytes) credentials.
 */
R_API RRtcIceTransport * r_rtc_session_create_ice_transport (RRtcSession * s,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize);
/**
 * @brief Create a DTLS transport over @p ice with the given DTLS
 * @p role (see @ref RRtcRole), local certificate @p cert and private
 * key @p privkey.
 */
R_API RRtcCryptoTransport * r_rtc_session_create_dtls_transport (RRtcSession * s,
    RRtcIceTransport * ice,
    RRtcCryptoRole role, RCryptoCert * cert, RCryptoKey * privkey);
/** @brief Create an unencrypted transport over @p ice (no DTLS / SRTP). */
R_API RRtcCryptoTransport * r_rtc_session_create_raw_transport (RRtcSession * s,
    RRtcIceTransport * ice);
/**
 * @brief Create an RTP sender with @p id (of @p size bytes), the
 * callback set @p cbs, and the @p rtp / @p rtcp transports it sends on.
 */
R_API RRtcRtpSender * r_rtc_session_create_rtp_sender (RRtcSession * s,
    const rchar * id, rssize size,
    const RRtcRtpSenderCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp) R_ATTR_MALLOC;
/**
 * @brief Create an RTP receiver with @p id (of @p size bytes), the
 * callback set @p cbs, and the @p rtp / @p rtcp transports it receives on.
 */
R_API RRtcRtpReceiver * r_rtc_session_create_rtp_receiver (RRtcSession * s,
    const rchar * id, rssize size,
    const RRtcRtpReceiverCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp) R_ATTR_MALLOC;
/**
 * @brief Create an RTP transceiver (paired sender + receiver) with
 * @p id (of @p size bytes), the receiver callbacks @p rcbs and sender
 * callbacks @p scbs, over the @p rtp / @p rtcp transports.
 */
R_API RRtcRtpTransceiver * r_rtc_session_create_rtp_transceiver (RRtcSession * s,
    const rchar * id, rssize size,
    const RRtcRtpReceiverCallbacks * rcbs, const RRtcRtpSenderCallbacks * scbs,
    rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp) R_ATTR_MALLOC;


R_END_DECLS

/** @} */

#endif /* __R_RTC_SESSION_H__ */

