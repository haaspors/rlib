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
#ifndef __R_RTC_RTP_RECEIVER_H__
#define __R_RTC_RTP_RECEIVER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtcrtpreceiver.h
 * @brief WebRTC RTP receiver: receives an incoming media stream from a transport.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/rtc/rrtcrtpparameters.h>

#include <rlib/ev/revloop.h>

/**
 * @defgroup r_rtc_rtpreceiver WebRTC RTP receiver
 * @ingroup r_rtc
 *
 * @brief Receives a single incoming RTP media stream.
 *
 * A receiver accepts RTP packets for one track off the negotiated
 * transport according to its @c RRtcRtpParameters and delivers the
 * media (and RTCP) to the application through its callbacks. Configure
 * it with @ref r_rtc_rtp_receiver_start and tear it down with
 * @ref r_rtc_rtp_receiver_stop. A receiver is paired with an
 * @ref RRtcRtpSender inside an @ref RRtcRtpTransceiver.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Lifecycle and media callbacks for an @ref RRtcRtpReceiver. */
typedef struct {
  RRtcEventCb       ready; /**< Handshake done; the receiver is ready for data. */
  RRtcEventCb       close; /**< The receiver has closed. */
  RRtcBufferCb      rtp;   /**< Delivers an incoming RTP packet. */
  RRtcBufferCb      rtcp;  /**< Delivers incoming RTCP for the received stream. */
} RRtcRtpReceiverCallbacks;

/** @brief Opaque WebRTC RTP receiver handle. */
typedef struct RRtcRtpReceiver RRtcRtpReceiver;

/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_rtp_receiver_ref      r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_rtp_receiver_unref    r_ref_unref

/** @brief Return the receiver's unique identifier. */
R_API const rchar * r_rtc_rtp_receiver_get_id (RRtcRtpReceiver * r);
/** @brief Return the media-stream ID (m-line @c mid) the receiver is bound to. */
R_API const rchar * r_rtc_rtp_receiver_get_mid (RRtcRtpReceiver * r);
/**
 * @brief Configure and start the receiver.
 * @param r The receiver.
 * @param params RTP parameters (codecs, encodings, header extensions).
 * @param loop Event loop driving the receiver's I/O.
 * @return @ref R_RTC_OK on success, otherwise an @ref RRtcError.
 */
R_API RRtcError r_rtc_rtp_receiver_start (RRtcRtpReceiver * r,
    RRtcRtpParameters * params, REvLoop * loop);
/**
 * @brief Stop the receiver.
 * @return @ref R_RTC_OK on success, otherwise an @ref RRtcError.
 */
R_API RRtcError r_rtc_rtp_receiver_stop (RRtcRtpReceiver * r);

R_END_DECLS

/** @} */

#endif /* __R_RTC_RTP_RECEIVER_H__ */

