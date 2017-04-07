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

#include <rlib/rtypes.h>

#include <rlib/rref.h>

#include <rlib/rtc/rrtc.h>
#include <rlib/rtc/rrtcrtpreceiver.h>
#include <rlib/rtc/rrtcrtpsender.h>

#include <rlib/ev/revloop.h>

R_BEGIN_DECLS

typedef struct _RRtcRtpTransceiver RRtcRtpTransceiver;

#define r_rtc_rtp_transceiver_ref     r_ref_ref
#define r_rtc_rtp_transceiver_unref   r_ref_unref

R_API const rchar * r_rtc_rtp_transceiver_get_id (RRtcRtpTransceiver * t);
R_API const rchar * r_rtc_rtp_transceiver_get_mid (RRtcRtpTransceiver * t);
R_API RRtcError r_rtc_rtp_transceiver_start (RRtcRtpTransceiver * t,
    REvLoop * loop);
R_API RRtcError r_rtc_rtp_transceiver_close (RRtcRtpTransceiver * t);
R_API RRtcRtpReceiver * r_rtc_rtp_transceiver_get_receiver (RRtcRtpTransceiver * t);
R_API RRtcRtpSender * r_rtc_rtp_transceiver_get_sender (RRtcRtpTransceiver * t);
R_API RRtcError r_rtc_rtp_transceiver_set_receiver (RRtcRtpTransceiver * t,
    RRtcRtpReceiver * receiver);
R_API RRtcError r_rtc_rtp_transceiver_set_sender (RRtcRtpTransceiver * t,
    RRtcRtpSender * sender);


R_END_DECLS

#endif /* __R_RTC_RTP_TRANSCEIVER_H__ */


