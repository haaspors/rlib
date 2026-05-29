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
#ifndef __R_RTC_SESSION_DESCRIPTION_H__
#define __R_RTC_SESSION_DESCRIPTION_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtcsessiondescription.h
 * @brief WebRTC session description: SDP offer / answer model with
 * transport, media-line and originator information.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/rbuffer.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/rrand.h>
#include <rlib/net/rsocketaddress.h>

#include <rlib/rtc/rrtcrtpparameters.h>

/**
 * @defgroup r_rtc_sessiondescription WebRTC session description
 * @ingroup r_rtc
 *
 * @brief The JSEP session-description model used to negotiate a peer
 * connection. An @ref RRtcSessionDescription is an offer or answer
 * (see @ref RRtcSignalType) holding a set of @ref RRtcTransportInfo
 * transports and @ref RRtcMediaLineInfo media lines; it parses from and
 * serialises to SDP carried in an @ref RBuffer.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief ICE transport parameters (local credentials). */
typedef struct {
  rchar * ufrag;        /**< @brief ICE username fragment. */
  rchar * pwd;          /**< @brief ICE password. */
  rboolean lite;        /**< @brief @c TRUE for an ICE-lite endpoint. */
} RRtcIceTransportParameters;

/** @brief DTLS transport parameters (role and certificate fingerprint). */
typedef struct {
  RRtcRole role;        /**< @brief Negotiated DTLS role (@ref RRtcRole). */
  RMsgDigestType md;    /**< @brief Digest algorithm of @c fingerprint. */
  rchar * fingerprint;  /**< @brief Certificate fingerprint. */
} RRtcDtlsTransportParameters;

/* FIXME: Add RRtcRtpSdesTransportParameters */
#if 0
typedef struct {
} RRtcRtpSdesTransportParameters;
#endif

/** @brief Combined transport parameters for a transport's RTP/RTCP path. */
typedef struct {
  RRtcIceTransportParameters ice;   /**< @brief ICE parameters. */
  RRtcDtlsTransportParameters dtls; /**< @brief DTLS parameters. */
  /* RRtcRtpSdesTransportParameters rtpsdes; */
} RRtcTransportParameters;

/** @brief A transport described in a session description. */
typedef struct {
  RRef ref;             /**< @brief Reference count. */

  rchar * id;           /**< @brief Transport identifier. */
  RSocketAddress * addr; /**< @brief Associated socket address. */

  rboolean rtcpmux;     /**< @brief @c TRUE if RTP and RTCP are multiplexed. */
  RRtcTransportParameters rtp;  /**< @brief Parameters for the RTP path. */
  RRtcTransportParameters rtcp; /**< @brief Parameters for the RTCP path (unused when multiplexed). */
} RRtcTransportInfo;

/**
 * @brief Create transport info with @p id (of @p size bytes), socket
 * @p addr and the @p rtcpmux flag.
 */
R_API RRtcTransportInfo * r_rtc_transport_info_new_full (const rchar * id,
    rssize size, RSocketAddress * addr, rboolean rtcpmux) R_ATTR_MALLOC;
/** @brief Create RTCP-multiplexed transport info with @p id (of @p size bytes) and no address. */
static inline RRtcTransportInfo * r_rtc_transport_info_new (const rchar * id,
    rssize size) { return r_rtc_transport_info_new_full (id, size, NULL, TRUE); }
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_transport_info_ref        r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_transport_info_unref      r_ref_unref

/**
 * @brief Set the ICE parameters of @p trans: @p ufrag (of @p usize
 * bytes), @p pwd (of @p psize bytes) and the ICE-@p lite flag.
 */
R_API RRtcError r_rtc_transport_set_ice_parameters (RRtcTransportInfo * trans,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize,
    rboolean lite);
/** @brief Set random ICE credentials on @p trans using @p prng, with the ICE-@p lite flag. */
R_API RRtcError r_rtc_transport_set_ice_parameters_random (RRtcTransportInfo * trans,
    RPrng * prng, rboolean lite);
/**
 * @brief Set the DTLS parameters of @p trans: @p role, fingerprint
 * digest @p md and @p fingerprint (of @p size bytes).
 */
R_API RRtcError r_rtc_transport_set_dtls_parameters (RRtcTransportInfo * trans,
    RRtcRole role, RMsgDigestType md, const rchar * fingerprint, rssize size);

/** @brief Transport protocol of a media line. */
typedef enum {
  R_RTC_PROTO_NONE = 0, /**< Unset. */
  R_RTC_PROTO_RTP,      /**< RTP-based media. */
  R_RTC_PROTO_SCTP,     /**< SCTP (data channel). */
} RRtcProtocol;

/** @brief Media-line protocol profile flags (combine into SAVP / AVPF / SAVPF). */
typedef enum {
  R_RTC_PROTO_FLAG_NONE       = 0,        /**< No flags. */
  R_RTC_PROTO_FLAG_AV_PROFILE = (1 << 0), /**< Audio/Video profile (AVP). */
  R_RTC_PROTO_FLAG_SECURE     = (1 << 1), /**< Secure (SRTP). */
  R_RTC_PROTO_FLAG_FEEDBACK   = (1 << 2), /**< RTCP feedback profile. */

  R_RTC_PROTO_FLAGS_SAVP      = R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE,   /**< Secure AVP. */
  R_RTC_PROTO_FLAGS_AVPF      = R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_FEEDBACK, /**< AVP with feedback. */
  R_RTC_PROTO_FLAGS_SAVPF     = R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE | R_RTC_PROTO_FLAG_FEEDBACK, /**< Secure AVP with feedback. */
} RRtcProtocolFlags;

/** @brief Parse an SDP protocol token @p proto (of @p size bytes), returning its profile @p flags. */
R_API RRtcProtocol r_rtc_protocol_from_string (const rchar * proto, rssize size, RRtcProtocolFlags * flags);
/** @brief Return the SDP protocol token for @p proto with profile @p flags. */
R_API const rchar * r_rtc_protocol_to_string (RRtcProtocol proto, RRtcProtocolFlags flags);

/** @brief A media line (m-line) within a session description. */
typedef struct {
  RRef ref;                     /**< @brief Reference count. */

  RRtcMediaType type;           /**< @brief Media kind (@ref RRtcMediaType). */
  RRtcDirection dir;            /**< @brief Flow direction (@ref RRtcDirection). */
  RRtcProtocol proto;           /**< @brief Transport protocol (@ref RRtcProtocol). */
  RRtcProtocolFlags protoflags; /**< @brief Protocol profile flags (@ref RRtcProtocolFlags). */
  rchar * mid;                  /**< @brief Media identification tag. */
  rchar * trans;                /**< @brief BUNDLE group tag / transport id. */
  rboolean bundled;             /**< @brief @c TRUE if bundled onto a shared transport. */

  /* Candidates should be unique per media line, not transport! */
  RPtrArray candidates;         /**< @brief @c RRtcIceCandidate entries for this line. */
  rboolean endofcandidates;     /**< @brief @c TRUE once all candidates have been gathered. */

  /*RDictionary * attrib;*/
  RRtcRtpParameters * params;   /**< @brief RTP parameters (@c RRtcRtpParameters). */
} RRtcMediaLineInfo;

/**
 * @brief Create a media line with @p mid (of @p size bytes), direction
 * @p dir, media @p type, transport @p proto and profile @p protoflags.
 */
R_API RRtcMediaLineInfo * r_rtc_media_line_info_new (
    const rchar * mid, rssize size, RRtcDirection dir,
    RRtcMediaType type, RRtcProtocol proto, RRtcProtocolFlags protoflags) R_ATTR_MALLOC;
/**
 * @brief Create a media line from string forms: @p mid (of @p size
 * bytes), direction @p dir, media @p type (of @p tsize bytes) and
 * transport @p proto (of @p psize bytes).
 */
R_API RRtcMediaLineInfo * r_rtc_media_line_info_new_from_str (
    const rchar * mid, rssize size, RRtcDirection dir,
    const rchar * type, rssize tsize, const rchar * proto, rssize psize) R_ATTR_MALLOC;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_media_line_info_ref       r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_media_line_info_unref     r_ref_unref

/** @brief Append @p candidate to @p mline, taking ownership of it. */
R_API RRtcError r_rtc_media_line_info_take_ice_candidate (RRtcMediaLineInfo * mline,
    RRtcIceCandidate * candidate);


/** @brief A WebRTC session description (an SDP offer or answer). */
typedef struct {
  RRef ref;             /**< @brief Reference count. */

  RRtcSignalType type;  /**< @brief Signalling type (@ref RRtcSignalType). */

  /* Details */
  RRtcDirection dir;    /**< @brief Default media direction (@ref RRtcDirection). */
  rchar * username;     /**< @brief Originator username (SDP @c o= line). */
  rchar * session_id;   /**< @brief Session identifier. */
  ruint64 session_ver;  /**< @brief Session version. */
  rchar * orig_nettype; /**< @brief Originator network type. */
  rchar * orig_addrtype; /**< @brief Originator address type. */
  rchar * orig_addr;    /**< @brief Originator unicast address. */
  rchar * session_name; /**< @brief Session name (SDP @c s= line). */
  rchar * conn_nettype; /**< @brief Connection network type. */
  rchar * conn_addrtype; /**< @brief Connection address type. */
  rchar * conn_addr;    /**< @brief Connection address. */
  ruint   conn_ttl;     /**< @brief Connection TTL (multicast). */
  ruint   conn_addrcount; /**< @brief Connection address count (multicast). */
  ruint64 tstart, tstop; /**< @brief Session start / stop times (SDP @c t= line). */

  RHashTable * transport; /**< @brief @ref RRtcTransportInfo entries keyed by id. */
  RPtrArray mline;      /**< @brief @ref RRtcMediaLineInfo media lines. */

  rpointer data;        /**< @brief User data pointer. */
  RDestroyNotify notify; /**< @brief Destructor for @c data. */
} RRtcSessionDescription;

/** @brief Create an empty session description of signalling @p type. */
R_API RRtcSessionDescription * r_rtc_session_description_new (RRtcSignalType type) R_ATTR_MALLOC;
/**
 * @brief Parse a session description of signalling @p type from the SDP
 * in @p buf, reporting failures via @p error.
 */
R_API RRtcSessionDescription * r_rtc_session_description_new_from_sdp (
    RRtcSignalType type, RBuffer * buf, RRtcError * error) R_ATTR_MALLOC;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_session_description_ref       r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_session_description_unref     r_ref_unref

/** @brief Number of media lines in @p sd. */
#define r_rtc_session_description_media_line_count(sd)    r_ptr_array_size (&(sd)->mline)
/** @brief Look up the media line of @p sd with media id @p mid (of @p size bytes); borrowed, no ref. */
R_API RRtcMediaLineInfo * r_rtc_session_description_get_media_line (RRtcSessionDescription * sd,
    const rchar * mid, rssize size);
/** @brief Return media line @p idx of @p sd; borrowed, no ref. */
#define r_rtc_session_description_get_media_line_by_idx(sd, idx) ((RRtcMediaLineInfo *) r_ptr_array_get (&(sd)->mline, idx))

/** @brief Number of transports in @p sd. */
#define r_rtc_session_description_transport_count(sd)     r_hash_table_size ((sd)->transport)
/** @brief Look up the transport of @p sd by @p id; borrowed, no ref. */
#define r_rtc_session_description_get_transport(sd, id)   ((RRtcTransportInfo *) r_hash_table_lookup ((sd)->transport, id))
/** @brief Look up the transport carrying media line @p mline within @p sd; borrowed, no ref. */
#define r_rtc_session_description_get_media_line_transport(sd, mline)         \
  r_rtc_session_description_get_transport (sd, (mline)->trans)

/**
 * @brief Set the originator (SDP @c o= line) of @p sd from string parts:
 * @p username (of @p usize bytes), session id @p sid (of @p sidsize
 * bytes), version @p sver, and address @p nettype / @p addrtype /
 * @p addr (of @p ntsize / @p atsize / @p asize bytes).
 */
R_API RRtcError r_rtc_session_description_set_originator_full (RRtcSessionDescription * sd,
    const rchar * username, rssize usize, const rchar * sid, rssize sidsize,
    ruint64 sver, const rchar * nettype, rssize ntsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize);
/**
 * @brief Set the originator of @p sd from @p username (of @p usize
 * bytes), session id @p sid (of @p sidsize bytes), version @p sver and
 * socket @p addr.
 */
R_API RRtcError r_rtc_session_description_set_originator_addr (RRtcSessionDescription * sd,
    const rchar * username, rssize usize, const rchar * sid, rssize sidsize,
    ruint64 sver, RSocketAddress * addr);
/** @brief Set the session name (SDP @c s= line) of @p sd to @p name (of @p size bytes). */
R_API RRtcError r_rtc_session_description_set_session_name (RRtcSessionDescription * sd,
    const rchar * name, rssize size);
/**
 * @brief Set the connection (SDP @c c= line) of @p sd from string parts
 * @p nettype / @p addrtype / @p addr (of @p ntsize / @p atsize /
 * @p asize bytes).
 */
R_API RRtcError r_rtc_session_description_set_connection_full (RRtcSessionDescription * sd,
    const rchar * nettype, rssize ntsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize);
/** @brief Set the connection of @p sd from socket @p addr. */
R_API RRtcError r_rtc_session_description_set_connection_addr (RRtcSessionDescription * sd,
    RSocketAddress * addr);

/** @brief Add @p transport to @p sd, taking ownership of it. */
R_API RRtcError r_rtc_session_description_take_transport (RRtcSessionDescription * sd,
    RRtcTransportInfo * transport);
/** @brief Add media line @p mline to @p sd, taking ownership of it. */
R_API RRtcError r_rtc_session_description_take_media_line (RRtcSessionDescription * sd,
    RRtcMediaLineInfo * mline);

/** @brief Serialise @p sd to SDP in a new @ref RBuffer, reporting failures via @p err. */
R_API RBuffer * r_rtc_session_description_to_sdp (RRtcSessionDescription * sd, RRtcError * err);

R_END_DECLS

/** @} */

#endif /* __R_RTC_SESSION_DESCRIPTION_H__ */

