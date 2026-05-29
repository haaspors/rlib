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
#ifndef __R_RTC_RTP_SENDER_H__
#define __R_RTC_RTP_SENDER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtcrtpsender.h
 * @brief WebRTC RTP sender: sends an outgoing media stream over a transport.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/rtc/rrtcrtpparameters.h>

#include <rlib/ev/revloop.h>

/**
 * @defgroup r_rtc_rtpsender WebRTC RTP sender
 * @ingroup r_rtc
 *
 * @brief Sends a single outgoing RTP media stream.
 *
 * A sender encodes and packetizes one track's media according to its
 * @c RRtcRtpParameters and transmits the resulting RTP packets over the
 * negotiated transport. Configure it with @ref r_rtc_rtp_sender_start,
 * push prepared packets with @ref r_rtc_rtp_sender_send, and tear it
 * down with @ref r_rtc_rtp_sender_stop. A sender is paired with an
 * @ref RRtcRtpReceiver inside an @ref RRtcRtpTransceiver.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Lifecycle and feedback callbacks for an @ref RRtcRtpSender. */
typedef struct {
  RRtcEventCb       ready; /**< Handshake done; the sender is ready for data. */
  RRtcEventCb       close; /**< The sender has closed. */
  RRtcBufferCb      rtcp;  /**< Optional: incoming RTCP feedback about the sent stream. */
} RRtcRtpSenderCallbacks;

/** @brief Opaque WebRTC RTP sender handle. */
typedef struct RRtcRtpSender RRtcRtpSender;

/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_rtp_sender_ref        r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_rtp_sender_unref      r_ref_unref

/** @brief Return the sender's unique identifier. */
R_API const rchar * r_rtc_rtp_sender_get_id (RRtcRtpSender * s);
/** @brief Return the media-stream ID (m-line @c mid) the sender is bound to. */
R_API const rchar * r_rtc_rtp_sender_get_mid (RRtcRtpSender * s);
/**
 * @brief Configure and start the sender.
 * @param s The sender.
 * @param params RTP parameters (codecs, encodings, header extensions).
 * @param loop Event loop driving the sender's I/O.
 * @return @ref R_RTC_OK on success, otherwise an @ref RRtcError.
 */
R_API RRtcError r_rtc_rtp_sender_start (RRtcRtpSender * s,
    RRtcRtpParameters * params, REvLoop * loop);
/**
 * @brief Stop the sender.
 * @return @ref R_RTC_OK on success, otherwise an @ref RRtcError.
 */
R_API RRtcError r_rtc_rtp_sender_stop (RRtcRtpSender * s);
/**
 * @brief Transmit one prepared RTP @p packet.
 * @param s The sender.
 * @param packet The RTP packet to send.
 * @return @ref R_RTC_OK on success, otherwise an @ref RRtcError.
 */
R_API RRtcError r_rtc_rtp_sender_send (RRtcRtpSender * s, RBuffer * packet);

R_END_DECLS

/** @} */

#endif /* __R_RTC_RTP_SENDER_H__ */

