/* RLIB - Convenience library for useful things
 * Copyright (C) 2017-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_RTC_H__
#define __R_RTC_H__

/**
 * @defgroup r_rtc Real-Time Communications (WebRTC)
 *
 * @brief WebRTC session, transport and media-routing primitives:
 * ICE candidate gathering / pairing, DTLS-over-UDP transports, RTP
 * sender / receiver / transceiver wiring, session description
 * exchange.
 *
 * Built on @c r_net for the underlying sockets and protocol
 * codecs (RTP / RTCP / SDP / STUN) and on @c r_crypto for the
 * DTLS + SRTP pieces. Use this layer when you need a WebRTC peer
 * connection or media-routing flow; the lower-level protocol code
 * lives in @c r_net.
 */

#include <rlib/rlib.h>

#include <rlib/rtc/rrtctypes.h>
#include <rlib/rtc/rrtccryptotransport.h>
#include <rlib/rtc/rrtcicecandidate.h>
#include <rlib/rtc/rrtcicetransport.h>
#include <rlib/rtc/rrtcrtplistener.h>
#include <rlib/rtc/rrtcrtpparameters.h>
#include <rlib/rtc/rrtcrtpreceiver.h>
#include <rlib/rtc/rrtcrtpsender.h>
#include <rlib/rtc/rrtcrtptransceiver.h>
#include <rlib/rtc/rrtcsession.h>
#include <rlib/rtc/rrtcsessiondescription.h>

#endif /* __R_RTC_H__ */

