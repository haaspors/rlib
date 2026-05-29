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

/**
 * @file rlib/rtc/rrtcicetransport.h
 * @brief ICE transport: runs connectivity checks over a set of ICE
 * candidates and carries the negotiated media path.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/rtc/rrtcicecandidate.h>

#include <rlib/ev/revloop.h>

/**
 * @defgroup r_rtc_icetransport WebRTC ICE transport
 * @ingroup r_rtc
 *
 * @brief An ICE transport (RFC 8445) that performs connectivity checks
 * between local and remote @ref RRtcIceCandidate sets and provides the
 * established path to the @ref r_rtc_cryptotransport layer.
 *
 * The transport is reference-counted
 * (@ref r_rtc_ice_transport_ref / @ref r_rtc_ice_transport_unref) and is
 * driven by an @c REvLoop: feed it candidates, then
 * @ref r_rtc_ice_transport_start / @ref r_rtc_ice_transport_close to run
 * it. Its lifecycle is reported via @ref RRtcIceState.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief ICE role governing the controlling / controlled agent rules. */
typedef enum {
  R_RTC_ICE_ROLE_CONTROLLED     = 0,  /**< Controlled agent. */
  R_RTC_ICE_ROLE_CONTROLLING,         /**< Controlling agent (nominates the pair). */
} RRtcIceRole;

/** @brief ICE connectivity state of the transport. */
typedef enum {
  R_RTC_ICE_STATE_NEW           = 0,  /**< Created; no checks started. */
  R_RTC_ICE_STATE_CHECKING,           /**< Running connectivity checks. */
  R_RTC_ICE_STATE_CONNECTED,          /**< A usable pair was found. */
  R_RTC_ICE_STATE_COMPLETED,          /**< Checks finished on all components. */
  R_RTC_ICE_STATE_DISCONNECTED,       /**< Connectivity lost; may recover. */
  R_RTC_ICE_STATE_FAILED,             /**< Checks failed; no usable pair. */
  R_RTC_ICE_STATE_CLOSED,             /**< Transport closed. */
} RRtcIceState;

/** @brief Opaque, reference-counted ICE transport. */
typedef struct RRtcIceTransport RRtcIceTransport;

/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_ice_transport_ref       r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_rtc_ice_transport_unref     r_ref_unref

/** @brief Start the ICE transport on event loop @p loop. */
R_API RRtcError r_rtc_ice_transport_start (RRtcIceTransport * ice, REvLoop * loop);
/** @brief Close the ICE transport and release its sockets. */
R_API RRtcError r_rtc_ice_transport_close (RRtcIceTransport * ice);

/**
 * @brief Add a local host @p candidate to the transport.
 * @note Provisional — intended to be replaced by a proper ICE
 * candidate-gathering API.
 */
R_API RRtcError r_rtc_ice_transport_add_local_host_candidate (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate);

/**
 * @brief Create a pair of transports @p a / @p b connected directly at the
 * transport level, bypassing sockets and connectivity checks (test helper).
 */
R_API RRtcError r_rtc_ice_transport_create_fake_pair (RRtcIceTransport ** a,
    RRtcIceTransport ** b);

R_END_DECLS

/** @} */

#endif /* __R_RTC_ICE_TRANSPORT_H__ */


