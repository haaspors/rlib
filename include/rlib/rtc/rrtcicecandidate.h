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
#ifndef __R_RTC_ICE_CANDIDATE_H__
#define __R_RTC_ICE_CANDIDATE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rref.h>
#include <rlib/rsocketaddress.h>

#include <rlib/rtc/rrtc.h>

R_BEGIN_DECLS

typedef enum {
  R_RTC_ICE_CANDIDATE_HOST    = 0,
  R_RTC_ICE_CANDIDATE_SRFLX,
  R_RTC_ICE_CANDIDATE_PRFLX,
  R_RTC_ICE_CANDIDATE_RELAY,
  R_RTC_ICE_CANDIDATE_LAST = R_RTC_ICE_CANDIDATE_RELAY,
} RRtcIceCandidateType;

typedef enum {
  R_RTC_ICE_COMPONENT_UNKNOWN = 0,
  R_RTC_ICE_COMPONENT_RTP     = 1,
  R_RTC_ICE_COMPONENT_RTCP    = 2,
  R_RTC_ICE_COMPONENT_LAST    = R_RTC_ICE_COMPONENT_RTCP,
} RRtcIceComponent;

typedef enum {
  R_RTC_ICE_PROTO_UDP   = 0,
  R_RTC_ICE_PROTO_TCP   = 1,
  R_RTC_ICE_PROTO_LAST  = R_RTC_ICE_PROTO_TCP,
} RRtcIceProtocol;

typedef struct _RRtcIceCandidate RRtcIceCandidate;

R_API RRtcIceCandidate * r_rtc_ice_candidate_new_full (
    const rchar * foundation, rssize fsize, ruint64 pri, RRtcIceComponent component,
    RRtcIceProtocol proto, RSocketAddress * addr,
    RRtcIceCandidateType type) R_ATTR_MALLOC;
R_API RRtcIceCandidate * r_rtc_ice_candidate_new (
    const rchar * foundation, rssize fsize, ruint64 pri, RRtcIceComponent component,
    RRtcIceProtocol proto, const rchar * ip, ruint16 port,
    RRtcIceCandidateType type) R_ATTR_MALLOC;
R_API RRtcIceCandidate * r_rtc_ice_candidate_new_from_sdp_attrib_value (
    const rchar * value, rssize size) R_ATTR_MALLOC;

#define r_rtc_ice_candidate_ref       r_ref_ref
#define r_rtc_ice_candidate_unref     r_ref_unref

R_API const rchar * r_rtc_ice_candidate_get_foundation (const RRtcIceCandidate * candidate);
R_API RSocketAddress * r_rtc_ice_candidate_get_addr (RRtcIceCandidate * candidate) R_ATTR_WARN_UNUSED_RESULT;
R_API RRtcIceProtocol r_rtc_ice_candidate_get_protocol (const RRtcIceCandidate * candidate);
R_API RRtcIceComponent r_rtc_ice_candidate_get_component (const RRtcIceCandidate * candidate);
R_API RRtcIceCandidateType r_rtc_ice_candidate_get_type (const RRtcIceCandidate * candidate);
R_API ruint64 r_rtc_ice_candidate_get_pri (const RRtcIceCandidate * candidate);
R_API RSocketAddress * r_rtc_ice_candidate_get_raddr (RRtcIceCandidate * candidate) R_ATTR_WARN_UNUSED_RESULT;


typedef struct {
  RRtcIceCandidate * local;
  RRtcIceCandidate * remote;
} RRtcIceCandidatePair;

R_END_DECLS

#endif /* __R_RTC_ICE_CANDIDATE_H__ */

