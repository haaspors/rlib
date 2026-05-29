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
#ifndef __R_RTC_RTP_TRANSCEIVER_H__
#define __R_RTC_RTP_TRANSCEIVER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtcrtptransceiver.h
 * @brief WebRTC RTP transceiver: pairs a sender and receiver for one m-line.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/rtc/rrtcrtpreceiver.h>
#include <rlib/rtc/rrtcrtpsender.h>

#include <rlib/ev/revloop.h>

/**
 * @defgroup r_rtc_rtptransceiver WebRTC RTP transceiver
 * @ingroup r_rtc
 *
 * @brief Bundles a sender and receiver sharing one m-line.
 *
 * A transceiver groups an @ref RRtcRtpSender and an
 * @ref RRtcRtpReceiver that share a single media section (m-line,
 * identified by its @c mid) and a transport. Its @ref RRtcDirection
 * determines which of the two are active. Transceivers belong to an
 * @c RRtcSession and are the unit of media negotiation in an
 * offer / answer exchange.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque WebRTC RTP transceiver handle. */
typedef struct RRtcRtpTransceiver RRtcRtpTransceiver;

/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_rtp_transceiver_ref     r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_rtp_transceiver_unref   r_ref_unref

/** @brief Return the transceiver's unique identifier. */
R_API const rchar * r_rtc_rtp_transceiver_get_id (RRtcRtpTransceiver * t);
/** @brief Return the media-stream ID (m-line @c mid) of the transceiver. */
R_API const rchar * r_rtc_rtp_transceiver_get_mid (RRtcRtpTransceiver * t);

/** @brief Return the transceiver's @ref RRtcRtpReceiver. */
R_API RRtcRtpReceiver * r_rtc_rtp_transceiver_get_receiver (RRtcRtpTransceiver * t);
/** @brief Return the transceiver's @ref RRtcRtpSender. */
R_API RRtcRtpSender * r_rtc_rtp_transceiver_get_sender (RRtcRtpTransceiver * t);
/**
 * @brief Set the transceiver's @ref RRtcRtpReceiver.
 * @param t The transceiver.
 * @param receiver The receiver to attach.
 * @return @ref R_RTC_OK on success, otherwise an @ref RRtcError.
 */
R_API RRtcError r_rtc_rtp_transceiver_set_receiver (RRtcRtpTransceiver * t,
    RRtcRtpReceiver * receiver);
/**
 * @brief Set the transceiver's @ref RRtcRtpSender.
 * @param t The transceiver.
 * @param sender The sender to attach.
 * @return @ref R_RTC_OK on success, otherwise an @ref RRtcError.
 */
R_API RRtcError r_rtc_rtp_transceiver_set_sender (RRtcRtpTransceiver * t,
    RRtcRtpSender * sender);


R_END_DECLS

/** @} */

#endif /* __R_RTC_RTP_TRANSCEIVER_H__ */


