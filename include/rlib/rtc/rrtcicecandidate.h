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

/**
 * @file rlib/rtc/rrtcicecandidate.h
 * @brief ICE candidate object: construction, SDP parsing / serialisation
 * and field accessors.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/net/rsocketaddress.h>
#include <rlib/rstr.h>

/**
 * @defgroup r_rtc_icecandidate WebRTC ICE candidate
 * @ingroup r_rtc
 *
 * @brief An ICE candidate (RFC 8445) — a transport address with its
 * type, component, protocol, foundation and priority, used during ICE
 * connectivity checks.
 *
 * Candidates are reference-counted (@ref r_rtc_ice_candidate_ref /
 * @ref r_rtc_ice_candidate_unref). Build them from explicit fields with
 * @ref r_rtc_ice_candidate_new / @ref r_rtc_ice_candidate_new_full, or
 * parse an SDP @c candidate attribute value with
 * @ref r_rtc_ice_candidate_new_from_sdp_attrib_value; serialise back to
 * the SDP form with @ref r_rtc_ice_candidate_to_string.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief ICE candidate type, in order of decreasing local preference. */
typedef enum {
  R_RTC_ICE_CANDIDATE_HOST    = 0,    /**< Host (local interface) address. */
  R_RTC_ICE_CANDIDATE_SRFLX,          /**< Server-reflexive (STUN-derived) address. */
  R_RTC_ICE_CANDIDATE_PRFLX,          /**< Peer-reflexive address. */
  R_RTC_ICE_CANDIDATE_RELAY,          /**< Relayed (TURN) address. */
  R_RTC_ICE_CANDIDATE_LAST = R_RTC_ICE_CANDIDATE_RELAY, /**< Highest valid value. */
} RRtcIceCandidateType;

/** @brief ICE component the candidate belongs to. */
typedef enum {
  R_RTC_ICE_COMPONENT_UNKNOWN = 0,    /**< Unknown / unset. */
  R_RTC_ICE_COMPONENT_RTP     = 1,    /**< RTP component. */
  R_RTC_ICE_COMPONENT_RTCP    = 2,    /**< RTCP component. */
  R_RTC_ICE_COMPONENT_LAST    = R_RTC_ICE_COMPONENT_RTCP, /**< Highest valid value. */
} RRtcIceComponent;

/** @brief Transport protocol of an ICE candidate. */
typedef enum {
  R_RTC_ICE_PROTO_UDP   = 0,          /**< UDP. */
  R_RTC_ICE_PROTO_TCP   = 1,          /**< TCP. */
  R_RTC_ICE_PROTO_LAST  = R_RTC_ICE_PROTO_TCP, /**< Highest valid value. */
} RRtcIceProtocol;

/** @brief Opaque, reference-counted ICE candidate. */
typedef struct RRtcIceCandidate RRtcIceCandidate;

/**
 * @brief Create an ICE candidate from an existing @ref RSocketAddress.
 * @param foundation ICE foundation string.
 * @param fsize      Length of @p foundation in bytes, or -1 if NUL-terminated.
 * @param pri        Candidate priority.
 * @param component  ICE component (RTP / RTCP).
 * @param proto      Transport protocol.
 * @param addr       Transport address (a reference is taken).
 * @param type       Candidate type.
 * @return A new candidate, or @c NULL on failure.
 */
R_API RRtcIceCandidate * r_rtc_ice_candidate_new_full (
    const rchar * foundation, rssize fsize, ruint64 pri, RRtcIceComponent component,
    RRtcIceProtocol proto, RSocketAddress * addr,
    RRtcIceCandidateType type) R_ATTR_MALLOC;
/**
 * @brief Create an ICE candidate from a textual @p ip and @p port.
 * @param foundation ICE foundation string.
 * @param fsize      Length of @p foundation in bytes, or -1 if NUL-terminated.
 * @param pri        Candidate priority.
 * @param component  ICE component (RTP / RTCP).
 * @param proto      Transport protocol.
 * @param ip         Textual IP address.
 * @param port       Port number.
 * @param type       Candidate type.
 * @return A new candidate, or @c NULL on failure.
 */
R_API RRtcIceCandidate * r_rtc_ice_candidate_new (
    const rchar * foundation, rssize fsize, ruint64 pri, RRtcIceComponent component,
    RRtcIceProtocol proto, const rchar * ip, ruint16 port,
    RRtcIceCandidateType type) R_ATTR_MALLOC;
/** @brief Parse an SDP @c candidate attribute @p value into a new candidate. */
R_API RRtcIceCandidate * r_rtc_ice_candidate_new_from_sdp_attrib_value (
    const rchar * value, rssize size) R_ATTR_MALLOC;

/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_ice_candidate_ref       r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_rtc_ice_candidate_unref     r_ref_unref

/** @brief Return the candidate's ICE foundation string. */
R_API const rchar * r_rtc_ice_candidate_get_foundation (const RRtcIceCandidate * candidate);
/** @brief Return the candidate's transport address (a reference is taken). */
R_API RSocketAddress * r_rtc_ice_candidate_get_addr (RRtcIceCandidate * candidate) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Return the candidate's transport protocol. */
R_API RRtcIceProtocol r_rtc_ice_candidate_get_protocol (const RRtcIceCandidate * candidate);
/** @brief Return the candidate's ICE component. */
R_API RRtcIceComponent r_rtc_ice_candidate_get_component (const RRtcIceCandidate * candidate);
/** @brief Return the candidate type. */
R_API RRtcIceCandidateType r_rtc_ice_candidate_get_type (const RRtcIceCandidate * candidate);
/** @brief Return the candidate priority. */
R_API ruint64 r_rtc_ice_candidate_get_pri (const RRtcIceCandidate * candidate);
/** @brief Return the related address (for reflexive / relay candidates), or @c NULL (a reference is taken). */
R_API RSocketAddress * r_rtc_ice_candidate_get_raddr (RRtcIceCandidate * candidate) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Return the number of extension key-value pairs on the candidate. */
R_API rsize r_rtc_ice_candidate_ext_count (const RRtcIceCandidate * candidate);
/** @brief Return the extension pair at @p idx as an @ref RStrKV, or @c NULL if out of range. */
R_API const RStrKV * r_rtc_ice_candidate_get_ext (RRtcIceCandidate * candidate, rsize idx);

/**
 * @brief Append an extension key-value pair to the candidate.
 * @param candidate Candidate to modify.
 * @param key       Extension key.
 * @param ksize     Length of @p key in bytes, or -1 if NUL-terminated.
 * @param val       Extension value.
 * @param vsize     Length of @p val in bytes, or -1 if NUL-terminated.
 * @return @ref R_RTC_OK on success, or an @ref RRtcError code.
 */
R_API RRtcError r_rtc_ice_candidate_add_ext (RRtcIceCandidate * candidate,
    const rchar * key, rssize ksize, const rchar * val, rssize vsize);
/** @brief Append an extension pair from an @ref RStrKV (wraps @ref r_rtc_ice_candidate_add_ext). */
#define r_rtc_ice_candidate_add_ext_kv(canidate, kv) \
  r_rtc_ice_candidate_add_ext(candidate, kv->key.str, kv->key.size, kv->val.str, kv->val.size)

/** @brief Serialise the candidate to its SDP @c candidate attribute string. */
R_API rchar * r_rtc_ice_candidate_to_string (const RRtcIceCandidate * candidate) R_ATTR_MALLOC;


/** @brief A local / remote ICE candidate pair. */
typedef struct {
  RRtcIceCandidate * local;   /**< @brief Local candidate. */
  RRtcIceCandidate * remote;  /**< @brief Remote candidate. */
} RRtcIceCandidatePair;

R_END_DECLS

/** @} */

#endif /* __R_RTC_ICE_CANDIDATE_H__ */

