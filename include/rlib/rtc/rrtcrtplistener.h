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
#ifndef __R_RTC_RTP_LISTENER_H__
#define __R_RTC_RTP_LISTENER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtcrtplistener.h
 * @brief WebRTC RTP listener: routes incoming RTP / RTCP to registered
 * receivers and senders.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/rtc/rrtcrtpparameters.h>
#include <rlib/rtc/rrtcrtpreceiver.h>
#include <rlib/rtc/rrtcrtpsender.h>

/**
 * @defgroup r_rtc_rtplistener WebRTC RTP listener
 * @ingroup r_rtc
 *
 * @brief Demultiplex incoming RTP / RTCP onto the @c RRtcRtpReceiver and
 * @c RRtcRtpSender objects registered on a transport.
 *
 * Receivers and senders are registered with their @ref RRtcRtpParameters
 * so the listener can match payload types and SSRCs to the right
 * handler; their parameters can be updated after a renegotiation.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque RTP demultiplexer routing RTP / RTCP to receivers and senders. */
typedef struct RRtcRtpListener RRtcRtpListener;

/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_rtp_listener_ref      r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_rtp_listener_unref    r_ref_unref

/** @brief Register receiver @p r with the listener @p l. */
R_API RRtcError r_rtc_rtp_listener_add_receiver (RRtcRtpListener * l, RRtcRtpReceiver * r);
/** @brief Register sender @p s with the listener @p l. */
R_API RRtcError r_rtc_rtp_listener_add_sender (RRtcRtpListener * l, RRtcRtpSender * s);
/** @brief Unregister receiver @p r from the listener @p l. */
R_API RRtcError r_rtc_rtp_listener_remove_receiver (RRtcRtpListener * l, RRtcRtpReceiver * r);
/** @brief Unregister sender @p s from the listener @p l. */
R_API RRtcError r_rtc_rtp_listener_remove_sender (RRtcRtpListener * l, RRtcRtpSender * s);

/** @brief Update the routing for receiver @p r on listener @p l with @p params. */
R_API RRtcError r_rtc_rtp_listener_update_receiver (RRtcRtpListener * l,
    RRtcRtpReceiver * r, RRtcRtpParameters * params);
/** @brief Update the routing for sender @p s on listener @p l with @p params. */
R_API RRtcError r_rtc_rtp_listener_update_sender (RRtcRtpListener * l,
    RRtcRtpSender * s, RRtcRtpParameters * params);

R_END_DECLS

/** @} */

#endif /* __R_RTC_RTP_LISTENER_H__ */


