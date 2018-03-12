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

R_BEGIN_DECLS

typedef struct _RRtcSession RRtcSession;
typedef struct _RRtcTransportController RRtcTransportController;

R_API RRtcSession * r_rtc_session_new_full (const rchar * id, rssize size,
    RPrng * prng) R_ATTR_MALLOC;
#define r_rtc_session_new(prng) r_rtc_session_new_full (NULL, 0, prng)
#define r_rtc_session_ref       r_ref_ref
#define r_rtc_session_unref     r_ref_unref

R_API const rchar * r_rtc_session_get_id (const RRtcSession * s);
R_API RRtcRtpTransceiver * r_rtc_session_lookup_rtp_transceiver (RRtcSession * s,
    const rchar * id, rssize size);

R_API RRtcIceTransport * r_rtc_session_create_ice_transport (RRtcSession * s,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize);
R_API RRtcCryptoTransport * r_rtc_session_create_dtls_transport (RRtcSession * s,
    RRtcIceTransport * ice,
    RRtcCryptoRole role, RCryptoCert * cert, RCryptoKey * privkey);
R_API RRtcCryptoTransport * r_rtc_session_create_raw_transport (RRtcSession * s,
    RRtcIceTransport * ice);
R_API RRtcRtpSender * r_rtc_session_create_rtp_sender (RRtcSession * s,
    const rchar * id, rssize size,
    const RRtcRtpSenderCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp) R_ATTR_MALLOC;
R_API RRtcRtpReceiver * r_rtc_session_create_rtp_receiver (RRtcSession * s,
    const rchar * id, rssize size,
    const RRtcRtpReceiverCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp) R_ATTR_MALLOC;
R_API RRtcRtpTransceiver * r_rtc_session_create_rtp_transceiver (RRtcSession * s,
    const rchar * id, rssize size,
    const RRtcRtpReceiverCallbacks * rcbs, const RRtcRtpSenderCallbacks * scbs,
    rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp) R_ATTR_MALLOC;


R_END_DECLS

#endif /* __R_RTC_SESSION_H__ */

