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
#error "#include <rlib.h> only please."
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
#include <rlib/net/rnetif.h>

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

/** @brief The transport's current ICE connectivity state (@ref RRtcIceState). */
R_API RRtcIceState r_rtc_ice_transport_get_state (const RRtcIceTransport * ice);

/**
 * @brief A copy of the address a bound local host socket is listening on,
 * or @c NULL if none is bound yet.
 *
 * After @ref r_rtc_ice_transport_start has bound the host candidates this
 * returns the actual (post-bind) address — including the OS-assigned port
 * when the candidate was added with port 0 — for the caller to signal as a
 * remote candidate to the peer. The caller owns the returned address.
 */
R_API RSocketAddress * r_rtc_ice_transport_get_local_address (
    const RRtcIceTransport * ice) R_ATTR_MALLOC;

/**
 * @brief Set the agent @p role (controlling / controlled).
 *
 * Determines the ICE-CONTROLLING / ICE-CONTROLLED attribute the transport
 * puts in its connectivity checks and which side nominates the pair. Must
 * be set before @ref r_rtc_ice_transport_start.
 */
R_API RRtcError r_rtc_ice_transport_set_role (RRtcIceTransport * ice,
    RRtcIceRole role);

/**
 * @brief Set the peer's ICE credentials, @p ufrag (of @p usize bytes) and
 * @p pwd (of @p psize bytes), taken from the remote SDP.
 *
 * The remote @p pwd keys the MESSAGE-INTEGRITY of the Binding requests this
 * transport sends; both are required before connectivity checks can run.
 */
R_API RRtcError r_rtc_ice_transport_set_remote_credentials (RRtcIceTransport * ice,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize);

/**
 * @brief Add a local host @p candidate to the transport explicitly.
 *
 * The address the transport binds and advertises is @p candidate's own
 * address. This is the right entry point when the reachable address is
 * already known — e.g. an SFU or other server that advertises a fixed
 * public address rather than enumerating interfaces — and the building
 * block @ref r_rtc_ice_transport_gather_host_candidates uses per address.
 */
R_API RRtcError r_rtc_ice_transport_add_local_host_candidate (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate);

/**
 * @brief Predicate selecting which interface addresses become host
 * candidates in @ref r_rtc_ice_transport_gather_host_candidates.
 *
 * Called once per address with its owning @p iface (for the name / flags)
 * and the specific @p addr; return @c TRUE to gather it, @c FALSE to skip.
 * @p user is the cookie passed to the gather call.
 */
typedef rboolean (*RRtcIceInterfaceFilter) (const RNetInterface * iface,
    const RSocketAddress * addr, rpointer user);

/**
 * @brief Gather host candidates by enumerating the local interfaces.
 *
 * Queries @ref r_net_query_interfaces and adds a host candidate for each
 * selected address (as @ref r_rtc_ice_transport_add_local_host_candidate).
 * With @p filter @c NULL the default policy keeps every interface that is
 * up and non-loopback; pass a @p filter for full control (e.g. an
 * allow-list of interfaces, or to include loopback). Servers that advertise
 * a fixed address should skip this and add candidates explicitly instead.
 */
R_API RRtcError r_rtc_ice_transport_gather_host_candidates (RRtcIceTransport * ice,
    RRtcIceInterfaceFilter filter, rpointer user);

/**
 * @brief Add a remote @p candidate learned from the peer's SDP.
 *
 * Each remote candidate is paired with every local socket; once the
 * transport is started (and credentials / role are set) a STUN Binding
 * connectivity check is issued for the new pairs.
 */
R_API RRtcError r_rtc_ice_transport_add_remote_candidate (RRtcIceTransport * ice,
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


