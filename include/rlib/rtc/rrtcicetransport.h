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
#ifndef __R_RTC_ICE_TRANSPORT_H__
#define __R_RTC_ICE_TRANSPORT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/rtc/rrtcicecandidate.h>

#include <rlib/ev/revloop.h>

R_BEGIN_DECLS

typedef enum {
  R_RTC_ICE_ROLE_CONTROLLED     = 0,
  R_RTC_ICE_ROLE_CONTROLLING,
} RRtcIceRole;

typedef enum {
  R_RTC_ICE_STATE_NEW           = 0,
  R_RTC_ICE_STATE_CHECKING,
  R_RTC_ICE_STATE_CONNECTED,
  R_RTC_ICE_STATE_COMPLETED,
  R_RTC_ICE_STATE_DISCONNECTED,
  R_RTC_ICE_STATE_FAILED,
  R_RTC_ICE_STATE_CLOSED,
} RRtcIceState;

typedef struct _RRtcIceTransport RRtcIceTransport;

#define r_rtc_ice_transport_ref       r_ref_ref
#define r_rtc_ice_transport_unref     r_ref_unref

R_API RRtcError r_rtc_ice_transport_start (RRtcIceTransport * ice, REvLoop * loop);
R_API RRtcError r_rtc_ice_transport_close (RRtcIceTransport * ice);

/* FIXME: Change to proper ICE gathering API */
R_API RRtcError r_rtc_ice_transport_add_local_host_candidate (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate);

/* NOTE: this is used for unit-testing bypassing all sockets,
 * connecting alice and bob at the transport level */
R_API RRtcError r_rtc_ice_transport_create_fake_pair (RRtcIceTransport ** a,
    RRtcIceTransport ** b);

R_END_DECLS

#endif /* __R_RTC_ICE_TRANSPORT_H__ */


