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
#ifndef __R_NET_PROTO_SDP_H__
#define __R_NET_PROTO_SDP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/net/proto/rsdp.h
 * @brief Session Description Protocol (RFC 4566) message building and
 * zero-copy parsing.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/rbuffer.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/net/rsocketaddress.h>
#include <rlib/rstr.h>
#include <rlib/ruri.h>

#include <rlib/net/proto/rrtp.h>

/**
 * @defgroup r_sdp SDP
 * @ingroup r_net
 *
 * @brief Build and parse Session Description Protocol messages
 * (RFC 4566), including WebRTC / JSEP and ICE / DTLS conventions.
 *
 * Two complementary sides share the @ref RSdpResult status codes. The
 * builder grows a reference-counted @ref RSdpMsg (and its @ref RSdpMedia
 * sections) with the @c r_sdp_msg_* / @c r_sdp_media_* setters, then
 * serialises it with @ref r_sdp_msg_to_buffer. The parser maps an
 * @c RBuffer of received SDP onto an @ref RSdpBuf with
 * @ref r_sdp_buffer_map — every field stays in place as an @c RStrChunk
 * pointing into the mapped buffer, read through the @c r_sdp_buf_*
 * accessor macros, until released with @ref r_sdp_buffer_unmap.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Status code returned by the SDP build and parse API. */
typedef enum {
  R_SDP_EOB = -1,                   /**< End of buffer reached during iteration. */
  R_SDP_OK = 0,                     /**< Success. */
  R_SDP_INVAL,                      /**< Invalid argument. */
  R_SDP_OOM,                        /**< Out of memory. */
  R_SDP_MAP_FAILED,                 /**< Failed to map the source buffer. */
  R_SDP_MISSING_REQUIRED_LINE,      /**< A required SDP line is absent. */
  R_SDP_BAD_DATA,                   /**< Malformed SDP content. */
  R_SDP_NOT_FOUND,                  /**< Requested field or attribute not found. */
  R_SDP_MORE_DATA,                  /**< More data is needed to complete parsing. */
} RSdpResult;

/** @brief Media direction ("a=sendrecv" etc.); send / recv bits combine. */
typedef enum {
  R_SDP_MD_INACTIVE         = 0,
  R_SDP_MD_SENDONLY         = 1,
  R_SDP_MD_RECVONLY         = 2,
  R_SDP_MD_SENDRECV         = R_SDP_MD_SENDONLY | R_SDP_MD_RECVONLY,
} RSdpMediaDirection;

/** @brief DTLS connection role ("a=setup"); active / passive bits combine. */
typedef enum {
  R_SDP_CONN_ROLE_HOLDCONN  = 0,
  R_SDP_CONN_ROLE_ACTIVE    = 1,
  R_SDP_CONN_ROLE_PASSIVE   = 2,
  R_SDP_CONN_ROLE_ACTPASS   = R_SDP_CONN_ROLE_ACTIVE | R_SDP_CONN_ROLE_PASSIVE,
} RSdpConnRole;

/** @brief ICE candidate type ("a=candidate ... typ"). */
typedef enum {
  R_SDP_ICE_TYPE_HOST         = 0,  /**< Host candidate. */
  R_SDP_ICE_TYPE_SRFLX        = 1,  /**< Server-reflexive candidate. */
  R_SDP_ICE_TYPE_PRFLX        = 2,  /**< Peer-reflexive candidate. */
  R_SDP_ICE_TYPE_RELAY        = 3,  /**< Relayed (TURN) candidate. */
} RSdpICEType;

/**
 * @brief Bandwidth ("b=") modifier per RFC 4566 §5.8 and successors.
 *
 * Values defined in kbps: CT (RFC 4566), AS (RFC 4566), X-prefixed
 * extensions. Values defined in bps: TIAS (RFC 3890), RR / RS
 * (RFC 3556).
 */
typedef enum {
  R_SDP_BW_MODIFIER_UNKNOWN     = 0,
  R_SDP_BW_MODIFIER_CT          = 1,  /**< Conference total, kbps. */
  R_SDP_BW_MODIFIER_AS          = 2,  /**< Application specific, kbps. */
  R_SDP_BW_MODIFIER_TIAS        = 3,  /**< Transport-independent app spec, bps. */
  R_SDP_BW_MODIFIER_RR          = 4,  /**< RTCP receiver bandwidth, bps. */
  R_SDP_BW_MODIFIER_RS          = 5,  /**< RTCP sender bandwidth, bps. */
  R_SDP_BW_MODIFIER_X_PREFIXED  = 6,  /**< "X-..." vendor extension, kbps. */
} RSdpBandwidthModifier;


/** @brief Parsed (zero-copy) view of an SDP message; see @ref r_sdp_buffer_map. */
typedef struct RSdpBuf RSdpBuf; /* Fwd decl because of RSdpMsg API */

/* RSdpMsg API */
/** @brief Reference-counted, mutable SDP message being built. */
typedef struct RSdpMsg RSdpMsg;
/** @brief Reference-counted media ("m=") section of an @ref RSdpMsg. */
typedef struct RSdpMedia RSdpMedia;

/** @brief Allocate an empty SDP message. */
R_API RSdpMsg * r_sdp_msg_new (void) R_ATTR_MALLOC;
/** @brief Allocate an SDP message pre-filled for WebRTC / JSEP with the given session id / version. */
R_API RSdpMsg * r_sdp_msg_new_jsep (ruint64 sessid, ruint sessver) R_ATTR_MALLOC;
/** @brief Allocate a mutable SDP message copied from a parsed @ref RSdpBuf. */
R_API RSdpMsg * r_sdp_msg_new_from_sdp_buffer (const RSdpBuf * buf) R_ATTR_MALLOC;
/** @brief Increase the reference count of @p msg. */
#define r_sdp_msg_ref     r_ref_ref
/** @brief Decrease the reference count of @p msg, freeing it at zero. */
#define r_sdp_msg_unref   r_ref_unref

/** @brief Serialise @p msg into a newly allocated @c RBuffer. */
R_API RBuffer * r_sdp_msg_to_buffer (const RSdpMsg * msg);

/** @brief Set the protocol version ("v="). */
R_API RSdpResult r_sdp_msg_set_version (RSdpMsg * msg,
    const rchar * ver, rssize size);
/** @brief Set the originator ("o=") line from its component fields. */
R_API RSdpResult r_sdp_msg_set_originator (RSdpMsg * msg,
    const rchar * username, rssize usize,
    const rchar * sid, rssize sidsize, const rchar * sver, rssize sversize,
    const rchar * nettype, rssize nsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize);
/** @brief Set the session name ("s="). */
R_API RSdpResult r_sdp_msg_set_session_name (RSdpMsg * msg,
    const rchar * name, rssize size);
/** @brief Set the session information ("i="). */
R_API RSdpResult r_sdp_msg_set_session_info (RSdpMsg * msg,
    const rchar * info, rssize size);
/** @brief Set the session URI ("u="). */
R_API RSdpResult r_sdp_msg_set_uri (RSdpMsg * msg, RUri * uri);
/** @brief Append an email contact ("e="). */
R_API RSdpResult r_sdp_msg_add_email (RSdpMsg * msg,
    const rchar * email, rssize size);
/** @brief Append a phone contact ("p="). */
R_API RSdpResult r_sdp_msg_add_phone (RSdpMsg * msg,
    const rchar * phone, rssize size);
/**
 * @brief Clear the session-level connection ("c=").
 * @param msg Target SDP message.
 * @param def @c TRUE to reset to the default connection rather than removing it.
 */
R_API RSdpResult r_sdp_msg_clear_connection (RSdpMsg * msg, rboolean def);
/** @brief Set a session-level unicast connection ("c=") for @p addr. */
#define r_sdp_msg_set_connection_unicast(msg, addr)                           \
  r_sdp_msg_set_connection_full (msg, addr, 0, 1)
/** @brief Set the session-level connection ("c=") from its component fields. */
R_API RSdpResult r_sdp_msg_set_connection_full (RSdpMsg * msg,
    const rchar * nettype, rssize nsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize,
    ruint ttl, ruint addrcount);
/** @brief Append a session-level bandwidth line ("b=") of @p kbps for modifier @p type. */
R_API RSdpResult r_sdp_msg_add_bandwidth (RSdpMsg * msg,
    const rchar * type, rssize tsize, ruint kbps);
/** @brief Append a timing line ("t=") spanning @p start to @p stop. */
R_API RSdpResult r_sdp_msg_add_time (RSdpMsg * msg, ruint64 start, ruint64 stop);
/** @brief Append a repeat line ("r=") to the timing entry at @p timeidx. */
R_API RSdpResult r_sdp_msg_add_time_repeat (RSdpMsg * msg, rsize timeidx,
    const rchar * repeat, rssize size);
/** @brief Append a time-zone adjustment ("z=") at @p time with @p offset seconds. */
R_API RSdpResult r_sdp_msg_add_time_zone (RSdpMsg * msg, ruint64 time,
    rint64 offset);
/** @brief Set the encryption key ("k=") method and data. */
R_API RSdpResult r_sdp_msg_set_key (RSdpMsg * msg,
    const rchar * method, rssize msize, const rchar * data, rssize size);
/** @brief Append a session-level attribute ("a=key:value"). */
R_API RSdpResult r_sdp_msg_add_attribute (RSdpMsg * msg,
    const rchar * key, rssize ksize, const rchar * value, rssize vsize);
/** @brief Append a media ("m=") section; takes a reference on @p media. */
R_API RSdpResult r_sdp_msg_add_media (RSdpMsg * msg, RSdpMedia * media);


/** @brief Allocate an empty media section. */
R_API RSdpMedia * r_sdp_media_new (void) R_ATTR_MALLOC;
/** @brief Allocate a media section pre-filled for WebRTC / JSEP over DTLS with the given mid and direction. */
R_API RSdpMedia * r_sdp_media_new_jsep_dtls (
    const rchar * type, rssize tsize, const rchar * mid, rssize msize,
    RSdpMediaDirection md) R_ATTR_MALLOC;
/** @brief Allocate a media section from its "m=" component fields. */
R_API RSdpMedia * r_sdp_media_new_full (const rchar * type, rssize tsize,
    ruint port, ruint portcount, const rchar * proto, rssize psize) R_ATTR_MALLOC;
/** @brief Increase the reference count of @p media. */
#define r_sdp_media_ref     r_ref_ref
/** @brief Decrease the reference count of @p media, freeing it at zero. */
#define r_sdp_media_unref   r_ref_unref

/** @brief Add an RTP format ("a=rtpmap") with payload type, encoding, clock rate and params. */
R_API RSdpResult r_sdp_media_add_rtp_fmt (RSdpMedia * media,
    RRTPPayloadType pt, const rchar * enc, rssize esize,
    ruint rate, ruint params);
/** @brief Add a static RTP payload type @p pt without an "a=rtpmap" line. */
#define r_sdp_media_add_rtp_fmt_static(m, pt) r_sdp_media_add_rtp_fmt (m, pt, NULL, 0, 0, 0)
/** @brief Add a media-level unicast connection ("c=") for @p addr. */
#define r_sdp_media_add_connection_unicast(media, addr)                         \
  r_sdp_media_add_connection_addr (media, addr, 0, 1)
/** @brief Add a media-level connection ("c=") from a socket address. */
R_API RSdpResult r_sdp_media_add_connection_addr (RSdpMedia * media,
    RSocketAddress * addr, ruint ttl, ruint addrcount);
/** @brief Add a media-level connection ("c=") from its component fields. */
R_API RSdpResult r_sdp_media_add_connection_full (RSdpMedia * media,
    const rchar * nettype, rssize nsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize,
    ruint ttl, ruint addrcount);
/** @brief Set the media information ("i="). */
R_API RSdpResult r_sdp_media_set_media_info (RSdpMedia * media,
    const rchar * info, rssize size);
/** @brief Add a media-level bandwidth line ("b=") of @p kbps for modifier @p type. */
R_API RSdpResult r_sdp_media_add_bandwidth (RSdpMedia * media,
    const rchar * type, rssize tsize, ruint kbps);
/** @brief Set the media-level encryption key ("k=") method and data. */
R_API RSdpResult r_sdp_media_set_key (RSdpMedia * media,
    const rchar * method, rssize msize, const rchar * data, rssize size);
/** @brief Append a media-level attribute ("a=key:value"). */
R_API RSdpResult r_sdp_media_add_attribute (RSdpMedia * media,
    const rchar * key, rssize ksize, const rchar * value, rssize vsize);

/** @brief Append an attribute scoped to a single payload type @p pt. */
R_API RSdpResult r_sdp_media_add_pt_specific_attribute (RSdpMedia * media,
    RRTPPayloadType pt, const rchar * key, rssize ksize, const rchar * value, rssize vsize);
/** @brief Append a source-specific attribute ("a=ssrc:") for @p ssrc. */
R_API RSdpResult r_sdp_media_add_source_specific_attribute (RSdpMedia * media,
    ruint32 ssrc, const rchar * key, rssize ksize, const rchar * value, rssize vsize);
/** @brief Add an "a=ssrc:<ssrc> cname:<cname>" attribute. */
#define r_sdp_media_add_ssrc_cname(m, ssrc, cname, csize) \
  r_sdp_media_add_source_specific_attribute (m, ssrc, "cname", 5, cname, csize)
/** @brief Add a JSEP "a=ssrc:<ssrc> msid:" attribute with value and app data. */
R_API RSdpResult r_sdp_media_add_jsep_msid (RSdpMedia * media, ruint32 ssrc,
    const rchar * msidval, rssize vsize, const rchar * msidappdata, rssize asize);
/** @brief Add ICE credentials ("a=ice-ufrag" / "a=ice-pwd"). */
R_API RSdpResult r_sdp_media_add_ice_credentials (RSdpMedia * media,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize);
/** @brief Add an ICE candidate ("a=candidate") from raw string fields. */
R_API RSdpResult r_sdp_media_add_ice_candidate_raw (RSdpMedia * media,
    const rchar * foundation, rssize fsize, ruint componentid,
    const rchar * transport, rssize transize, ruint64 pri,
    const rchar * addr, rssize asize, ruint16 port,
    const rchar * type, rssize typesize,
    const rchar * raddr, rssize rasize, ruint16 rport,
    const rchar * extension, rssize esize);
/** @brief Add an ICE candidate ("a=candidate") from socket addresses and an @ref RSdpICEType. */
R_API RSdpResult r_sdp_media_add_ice_candidate (RSdpMedia * media,
    const rchar * foundation, rssize fsize, ruint componentid,
    const rchar * transport, rssize tsize, ruint64 pri,
    const RSocketAddress * addr, RSdpICEType type,
    const RSocketAddress * raddr, const rchar * extension, rssize esize);
/** @brief Add the DTLS setup role ("a=setup") and fingerprint ("a=fingerprint"). */
R_API RSdpResult r_sdp_media_add_dtls_setup (RSdpMedia * media,
    RSdpConnRole role, RMsgDigestType type, const rchar * fingerprint, rssize fsize);

/** @brief Duplicate the value of media attribute @p key, or @c NULL if absent. */
R_API rchar * r_sdp_media_get_attribute (const RSdpMedia * media,
    const rchar * key, rssize ksize) R_ATTR_MALLOC;
/** @brief Duplicate the media identification tag ("a=mid"). */
#define r_sdp_media_get_mid(m)  r_sdp_media_get_attribute (m, "mid", -1)


/* Parsing API */
/** @brief Parsed originator ("o=") line; fields point into the mapped buffer. */
typedef struct {
  RStrChunk username;       /**< @brief Originator user name. */
  RStrChunk sess_id;        /**< @brief Session identifier. */
  RStrChunk sess_version;   /**< @brief Session version. */
  RStrChunk nettype;        /**< @brief Network type (e.g. "IN"). */
  RStrChunk addrtype;       /**< @brief Address type (e.g. "IP4" / "IP6"). */
  RStrChunk addr;           /**< @brief Unicast address. */
} RSdpOriginatorBuf;
/** @brief Duplicate the originator user name as a string. */
#define r_sdp_originator_buf_username(orig)         r_str_chunk_dup (&(orig)->username)
/** @brief Duplicate the session id as a string. */
#define r_sdp_originator_buf_session_id(orig)       r_str_chunk_dup (&(orig)->sess_id)
/** @brief Parse the session id as a @c ruint64. */
#define r_sdp_originator_buf_session_id_u64(orig)   r_str_to_uint64 ((orig)->sess_id.str, NULL, 10, NULL)
/** @brief Duplicate the session version as a string. */
#define r_sdp_originator_buf_session_version(orig)  r_str_chunk_dup (&(orig)->sess_version)
/** @brief Parse the session version as a @c ruint64. */
#define r_sdp_originator_buf_session_version_u64(orig) r_str_to_uint64 ((orig)->sess_version.str, NULL, 10, NULL)
/** @brief Duplicate the network type as a string. */
#define r_sdp_originator_buf_nettype(orig)          r_str_chunk_dup (&(orig)->nettype)
/** @brief Duplicate the address type as a string. */
#define r_sdp_originator_buf_addrtype(orig)         r_str_chunk_dup (&(orig)->addrtype)
/** @brief Duplicate the originator address as a string. */
#define r_sdp_originator_buf_addr(orig)             r_str_chunk_dup (&(orig)->addr)

/** @brief Parsed connection ("c=") line; fields point into the mapped buffer. */
typedef struct {
  RStrChunk nettype;        /**< @brief Network type (e.g. "IN"). */
  RStrChunk addrtype;       /**< @brief Address type (e.g. "IP4" / "IP6"). */
  RStrChunk addr;           /**< @brief Connection address. */
  ruint ttl;                /**< @brief Multicast time-to-live, or 0. */
  ruint addrcount;          /**< @brief Number of contiguous addresses. */
} RSdpConnectionBuf;
/** @brief Duplicate the network type as a string. */
#define r_sdp_connection_buf_nettype(conn)          r_str_chunk_dup (&(conn)->nettype)
/** @brief Duplicate the address type as a string. */
#define r_sdp_connection_buf_addrtype(conn)         r_str_chunk_dup (&(conn)->addrtype)
/** @brief Duplicate the connection address as a string. */
#define r_sdp_connection_buf_addr(conn)             r_str_chunk_dup (&(conn)->addr)
/** @brief Multicast time-to-live of the connection. */
#define r_sdp_connection_buf_ttl(conn)              (conn)->ttl
/** @brief Number of contiguous addresses in the connection. */
#define r_sdp_connection_buf_addrcount(conn)        (conn)->addrcount
/** @brief Build an @c RSocketAddress from a parsed connection and @p port. */
R_API RSocketAddress * r_sdp_connection_buf_to_socket_address (const RSdpConnectionBuf * conn, ruint port);

/** @brief Parsed timing ("t=") line with its repeat ("r=") entries. */
typedef struct {
  RStrChunk start;          /**< @brief Session start time. */
  RStrChunk stop;           /**< @brief Session stop time. */
  rsize rcount;             /**< @brief Number of repeat entries. */
  RStrChunk * repeat;       /**< @brief Array of @c rcount repeat strings. */
} RSdpTimeBuf;
/** @brief Duplicate the start time as a string. */
#define r_sdp_time_buf_start(time)                  r_str_chunk_dup (&(time)->start)
/** @brief Duplicate the stop time as a string. */
#define r_sdp_time_buf_stop(time)                   r_str_chunk_dup (&(time)->stop)
/** @brief Number of repeat entries. */
#define r_sdp_time_buf_repeat_count(time)           (time)->rcount
/** @brief Duplicate repeat entry @p idx as a string. */
#define r_sdp_time_buf_repeat(time, idx)            r_str_chunk_dup (&(time)->repeat[idx])

/**
 * @brief Classify the modifier name of an SDP "b=<modifier>:<value>" line.
 *
 * Matches case-insensitively per RFC 4566 §5.8 and returns the matching
 * @ref RSdpBandwidthModifier. Anything beginning with "X-" / "x-" is
 * classified as @ref R_SDP_BW_MODIFIER_X_PREFIXED; anything else unknown
 * becomes @c R_SDP_BW_MODIFIER_UNKNOWN.
 */
R_API RSdpBandwidthModifier r_sdp_bandwidth_modifier_from_str (
    const rchar * type, rssize tsize);

/**
 * @brief Convert a raw "b=" value into bits per second by modifier unit.
 *
 * CT, AS and X-* are kbps and multiplied by 1000; TIAS, RR and RS are bps
 * and returned as-is; @c R_SDP_BW_MODIFIER_UNKNOWN returns 0 because the
 * unit is not interpretable.
 */
R_API ruint64 r_sdp_bandwidth_to_bps (RSdpBandwidthModifier modifier,
    ruint value);

/** @brief @ref R_SDP_OK if attribute @p field is present in @p attrib. */
R_API RSdpResult r_sdp_attrib_check (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize);
/**
 * @brief Find attribute @p field in @p attrib, searching from @p start.
 * @param attrib Attribute array to search.
 * @param acount Number of entries in @p attrib.
 * @param field Attribute field name to find.
 * @param fsize Size of @p field, or -1 if NUL-terminated.
 * @param start In/out search cursor (attribute index); may be @c NULL.
 * @return The matching value chunk, or @c NULL if not found.
 */
R_API const RStrChunk * r_sdp_attrib_find (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize, rsize * start);
/**
 * @brief Duplicate the value of attribute @p field, searching from @p start.
 * @param attrib Attribute array to search.
 * @param acount Number of entries in @p attrib.
 * @param field Attribute field name to find.
 * @param fsize Size of @p field, or -1 if NUL-terminated.
 * @param start In/out search cursor (attribute index); may be @c NULL.
 * @return Newly allocated value string, or @c NULL if not found.
 */
R_API rchar * r_sdp_attrib_dup_value (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize, rsize * start);

/** @brief Parsed media ("m=") section; fields point into the mapped buffer. */
typedef struct {
  RStrChunk type;           /**< @brief Media type (e.g. "audio" / "video"). */
  ruint port;               /**< @brief Transport port. */
  ruint portcount;          /**< @brief Number of contiguous ports. */
  RStrChunk proto;          /**< @brief Transport protocol (e.g. "UDP/TLS/RTP/SAVPF"). */
  rsize fmtcount;           /**< @brief Number of media formats. */
  RStrChunk * fmt;          /**< @brief Array of @c fmtcount format tokens. */
  RStrChunk info;           /**< @brief Media information ("i="). */
  rsize ccount;             /**< @brief Number of connection lines. */
  RSdpConnectionBuf * conn; /**< @brief Array of @c ccount connections. */
  rsize bcount;             /**< @brief Number of bandwidth lines. */
  RStrKV * bw;              /**< @brief Array of @c bcount bandwidth key/value pairs. */
  RStrKV key;               /**< @brief Encryption key ("k="). */
  rsize acount;             /**< @brief Number of attributes. */
  RStrKV * attrib;          /**< @brief Array of @c acount attribute key/value pairs. */
} RSdpMediaBuf;
/** @brief Duplicate the media type as a string. */
#define r_sdp_media_buf_type(media)                 r_str_chunk_dup (&(media)->type)
/** @brief Transport port of the media section. */
#define r_sdp_media_buf_port(media)                 (media)->port
/** @brief Number of contiguous ports. */
#define r_sdp_media_buf_portcount(media)            (media)->portcount
/** @brief Duplicate the transport protocol as a string. */
#define r_sdp_media_buf_proto(media)                r_str_chunk_dup (&(media)->proto)
/** @brief Number of media formats. */
#define r_sdp_media_buf_fmt_count(media)            (media)->fmtcount
/** @brief Duplicate media format @p idx as a string. */
#define r_sdp_media_buf_fmt(media, idx)             r_str_chunk_dup (&(media)->fmt[idx])
/** @brief Parse media format @p idx as an unsigned integer. */
#define r_sdp_media_buf_fmt_uint(media, idx)        r_str_to_uint ((media)->fmt[idx].str, NULL, 0, NULL)
/** @brief Index of media format @p fmt, or a negative value if absent. */
R_API rssize r_sdp_media_buf_find_fmt (const RSdpMediaBuf * media, const rchar * fmt, rssize size);
/** @brief Duplicate the media information as a string. */
#define r_sdp_media_buf_info(media)                 r_str_chunk_dup (&(media)->info)
/** @brief Number of connection lines. */
#define r_sdp_media_buf_conn_count(media)           (media)->ccount
/** @brief Duplicate the network type of connection @p idx. */
#define r_sdp_media_buf_conn_nettype(media, idx)    r_sdp_connection_buf_nettype (&(media)->conn[idx])
/** @brief Duplicate the address type of connection @p idx. */
#define r_sdp_media_buf_conn_addrtype(media, idx)   r_sdp_connection_buf_addrtype (&(media)->conn[idx])
/** @brief Duplicate the address of connection @p idx. */
#define r_sdp_media_buf_conn_addr(media, idx)       r_sdp_connection_buf_addr (&(media)->conn[idx])
/** @brief Multicast TTL of connection @p idx. */
#define r_sdp_media_buf_conn_ttl(media, idx)        r_sdp_connection_buf_ttl (&(media)->conn[idx])
/** @brief Address count of connection @p idx. */
#define r_sdp_media_buf_conn_addrcount(media, idx)  r_sdp_connection_buf_addrcount (&(media)->conn[idx])
/** @brief Build an @c RSocketAddress from connection @p idx using the media port. */
#define r_sdp_media_buf_conn_to_socket_address(media, idx) r_sdp_connection_buf_to_socket_address (&(media)->conn[idx], (media)->port)
/** @brief Number of bandwidth lines. */
#define r_sdp_media_buf_bandwidth_count(media)      (media)->bcount
/** @brief Duplicate the modifier name of bandwidth line @p idx. */
#define r_sdp_media_buf_bandwidth_type(media, idx)  r_str_kv_dup_key (&(media)->bw[idx])
/** @brief Classified @ref RSdpBandwidthModifier of bandwidth line @p idx. */
#define r_sdp_media_buf_bandwidth_modifier(media, idx) \
  r_sdp_bandwidth_modifier_from_str ((media)->bw[idx].key.str, (rssize) (media)->bw[idx].key.size)
/** @brief Raw integer value of bandwidth line @p idx. */
#define r_sdp_media_buf_bandwidth_raw(media, idx)  r_str_to_uint ((media)->bw[idx].val.str, NULL, 10, NULL)
/** @brief Bandwidth of line @p idx in bits per second. */
#define r_sdp_media_buf_bandwidth_bps(media, idx) \
  r_sdp_bandwidth_to_bps (r_sdp_media_buf_bandwidth_modifier (media, idx), \
      r_sdp_media_buf_bandwidth_raw (media, idx))
/** @brief Duplicate the media key method. */
#define r_sdp_media_buf_key_method(media)           r_str_kv_dup_key (&(media)->key)
/** @brief Duplicate the media key data. */
#define r_sdp_media_buf_key_data(media)             r_str_kv_dup_value (&(media)->key)
/** @brief Number of media attributes. */
#define r_sdp_media_buf_attrib_count(media)         (media)->acount
/** @brief @c TRUE if media attribute @p f is present. */
#define r_sdp_media_buf_has_attrib(media, f, fsize) (r_sdp_attrib_check ((media)->attrib, (media)->acount, f, fsize) == R_SDP_OK)
/** @brief Find media attribute @p f from cursor @p s; see @ref r_sdp_attrib_find. */
#define r_sdp_media_buf_attrib_find(media, f, fsize, s) r_sdp_attrib_find ((media)->attrib, (media)->acount, f, fsize, s)
/** @brief Duplicate the value of media attribute @p f from cursor @p s. */
#define r_sdp_media_buf_attrib_dup_value(media, f, fsize, s) r_sdp_attrib_dup_value ((media)->attrib, (media)->acount, f, fsize, s)
/**
 * @brief Find a format-specific attribute @p field for format @p fmt.
 * @param media Parsed media section.
 * @param fmt Format token to match.
 * @param fmtsize Size of @p fmt, or -1 if NUL-terminated.
 * @param field Attribute field name to find.
 * @param fsize Size of @p field, or -1 if NUL-terminated.
 * @param attrib Out chunk receiving the matched attribute.
 * @param start In/out search cursor; may be @c NULL.
 */
R_API RSdpResult r_sdp_media_buf_fmt_specific_attrib (const RSdpMediaBuf * media,
    const rchar * fmt, rssize fmtsize, const rchar * field, rssize fsize,
    RStrChunk * attrib, rsize * start);
/**
 * @brief Find a format-specific attribute @p field for format index @p fmtidx.
 * @param media Parsed media section.
 * @param fmtidx Format index to match.
 * @param field Attribute field name to find.
 * @param fsize Size of @p field, or -1 if NUL-terminated.
 * @param attrib Out chunk receiving the matched attribute.
 * @param start In/out search cursor; may be @c NULL.
 */
R_API RSdpResult r_sdp_media_buf_fmtidx_specific_attrib (const RSdpMediaBuf * media,
    rsize fmtidx, const rchar * field, rssize fsize, RStrChunk * attrib, rsize * start);
/** @brief Find the "rtpmap" attribute for format @p fmt. */
#define r_sdp_media_buf_rtpmap_for_fmt(media, fmt, fmtsize, attrib)           \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("rtpmap"), attrib, NULL)
/** @brief Find the "rtpmap" attribute for format index @p fmtidx. */
#define r_sdp_media_buf_rtpmap_for_fmt_idx(media, fmtidx, attrib)             \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("rtpmap"), attrib, NULL)
/** @brief Find an "rtcp-fb" attribute for format @p fmt from cursor @p start. */
#define r_sdp_media_buf_rtcpfb_for_fmt(media, fmt, fmtsize, attrib, start)    \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("rtcp-fb"), attrib, start)
/** @brief Find an "rtcp-fb" attribute for format index @p fmtidx from cursor @p start. */
#define r_sdp_media_buf_rtcpfb_for_fmt_idx(media, fmtidx, attrib, start)      \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("rtcp-fb"), attrib, start)
/** @brief Find the "fmtp" attribute for format @p fmt. */
#define r_sdp_media_buf_fmtp_for_fmt(media, fmt, fmtsize, attrib)             \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("fmtp"), attrib, NULL)
/** @brief Find the "fmtp" attribute for format index @p fmtidx. */
#define r_sdp_media_buf_fmtp_for_fmt_idx(media, fmtidx, attrib)               \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("fmtp"), attrib, NULL)
/** @brief Allocate an array of the distinct SSRCs referenced by "a=ssrc" attributes. */
R_API ruint32 * r_sdp_media_buf_source_specific_sources (
    const RSdpMediaBuf * media, rsize * size);
/** @brief Allocate an array of all "a=ssrc" attributes for @p ssrc. */
R_API RStrKV * r_sdp_media_buf_source_specific_all_media_attribs (
    const RSdpMediaBuf * media, ruint32 ssrc, rsize * size) R_ATTR_MALLOC;
/** @brief Find a single "a=ssrc" attribute @p field for @p ssrc into @p attrib. */
R_API RSdpResult r_sdp_media_buf_source_specific_media_attrib (const RSdpMediaBuf * media,
    ruint32 ssrc, const rchar * field, rssize fsize, RStrChunk * attrib);
/** @brief Find an "a=ssrc-group" attribute by @p semantics from cursor @p start into @p attrib. */
R_API RSdpResult r_sdp_media_buf_ssrc_group_attrib (const RSdpMediaBuf * media,
    const rchar * semantics, rssize size, RStrChunk * attrib, rsize * start);
/**
 * @brief Find an "a=extmap" attribute from cursor @p start.
 * @param media Parsed media section.
 * @param id Out receiving the extension id.
 * @param attrib Out chunk receiving the matched attribute.
 * @param start In/out search cursor; may be @c NULL.
 */
R_API RSdpResult r_sdp_media_buf_extmap_attrib (const RSdpMediaBuf * media,
    ruint16 * id, RStrChunk * attrib, rsize * start);

/** @brief Parsed (zero-copy) view of an SDP message; populated by @ref r_sdp_buffer_map. */
struct RSdpBuf {
  RMemMapInfo info;             /**< @brief Mapping holding the buffer the chunks point into. */

  RStrChunk ver;                /**< @brief Protocol version ("v="). */
  RSdpOriginatorBuf orig;       /**< @brief Originator ("o="). */
  RStrChunk session_name;       /**< @brief Session name ("s="). */
  RStrChunk session_info;       /**< @brief Session information ("i="). */
  RStrChunk uri;                /**< @brief Session URI ("u="). */
  rsize ecount;                 /**< @brief Number of email lines. */
  RStrChunk * email;            /**< @brief Array of @c ecount emails ("e="). */
  rsize pcount;                 /**< @brief Number of phone lines. */
  RStrChunk * phone;            /**< @brief Array of @c pcount phones ("p="). */
  RSdpConnectionBuf conn;       /**< @brief Session-level connection ("c="). */
  rsize bcount;                 /**< @brief Number of bandwidth lines. */
  RStrKV * bw;                  /**< @brief Array of @c bcount bandwidth pairs ("b="). */
  rsize tcount;                 /**< @brief Number of timing lines. */
  RSdpTimeBuf * time;           /**< @brief Array of @c tcount timing entries ("t="). */
  rsize zcount;                 /**< @brief Number of time-zone adjustments. */
  RStrKV * zone;                /**< @brief Array of @c zcount time-zone pairs ("z="). */
  RStrKV key;                   /**< @brief Encryption key ("k="). */
  rsize acount;                 /**< @brief Number of session attributes. */
  RStrKV * attrib;              /**< @brief Array of @c acount attribute pairs ("a="). */

  rsize mcount;                 /**< @brief Number of media sections. */
  RSdpMediaBuf * media;         /**< @brief Array of @c mcount media sections ("m="). */
};

/** @brief Parse @p buf into the zero-copy view @p sdp; release with @ref r_sdp_buffer_unmap. */
R_API RSdpResult r_sdp_buffer_map (RSdpBuf * sdp, RBuffer * buf);
/** @brief Release a view previously populated by @ref r_sdp_buffer_map. */
R_API RSdpResult r_sdp_buffer_unmap (RSdpBuf * sdp, RBuffer * buf);

/** @brief Duplicate the protocol version as a string. */
#define r_sdp_buf_version(buf)                      r_str_chunk_dup (&(buf)->ver)
/** @brief Duplicate the session name as a string. */
#define r_sdp_buf_session_name(buf)                 r_str_chunk_dup (&(buf)->session_name)
/** @brief Duplicate the session information as a string. */
#define r_sdp_buf_session_info(buf)                 r_str_chunk_dup (&(buf)->session_info)
/** @brief Duplicate the session URI as a string. */
#define r_sdp_buf_uri_str(buf)                      r_str_chunk_dup (&(buf)->uri)
/** @brief Parse the session URI into a new @c RUri. */
#define r_sdp_buf_uri(buf)                          r_uri_new_escaped ((buf)->uri.str, (buf)->uri.size)

/** @brief Duplicate the originator user name as a string. */
#define r_sdp_buf_orig_username(buf)                r_sdp_originator_buf_username (&(buf)->orig)
/** @brief Duplicate the originator session id as a string. */
#define r_sdp_buf_orig_session_id(buf)              r_sdp_originator_buf_session_id (&(buf)->orig)
/** @brief Parse the originator session id as a @c ruint64. */
#define r_sdp_buf_orig_session_id_u64(buf)          r_sdp_originator_buf_session_id_u64 (&(buf)->orig)
/** @brief Duplicate the originator session version as a string. */
#define r_sdp_buf_orig_session_version(buf)         r_sdp_originator_buf_session_version (&(buf)->orig)
/** @brief Parse the originator session version as a @c ruint64. */
#define r_sdp_buf_orig_session_version_u64(buf)     r_sdp_originator_buf_session_version_u64 (&(buf)->orig)
/** @brief Duplicate the originator network type as a string. */
#define r_sdp_buf_orig_nettype(buf)                 r_sdp_originator_buf_nettype (&(buf)->orig)
/** @brief Duplicate the originator address type as a string. */
#define r_sdp_buf_orig_addrtype(buf)                r_sdp_originator_buf_addrtype (&(buf)->orig)
/** @brief Duplicate the originator address as a string. */
#define r_sdp_buf_orig_addr(buf)                    r_sdp_originator_buf_addr (&(buf)->orig)

/** @brief Number of email lines. */
#define r_sdp_buf_email_count(buf)                  (buf)->ecount
/** @brief Number of phone lines. */
#define r_sdp_buf_phone_count(buf)                  (buf)->pcount
/** @brief Number of session-level bandwidth lines. */
#define r_sdp_buf_bandwidth_count(buf)              (buf)->bcount
/** @brief Number of timing lines. */
#define r_sdp_buf_time_count(buf)                   (buf)->tcount
/** @brief Number of time-zone adjustments. */
#define r_sdp_buf_time_zone_count(buf)              (buf)->zcount
/** @brief Number of session-level attributes. */
#define r_sdp_buf_attrib_count(buf)                 (buf)->acount
/** @brief Number of media sections. */
#define r_sdp_buf_media_count(buf)                  (buf)->mcount

/** @brief Duplicate email line @p idx as a string. */
#define r_sdp_buf_email(buf, idx)                   r_str_chunk_dup (&(buf)->email[idx])
/** @brief Duplicate phone line @p idx as a string. */
#define r_sdp_buf_phone(buf, idx)                   r_str_chunk_dup (&(buf)->phone[idx])

/** @brief Duplicate the session connection network type as a string. */
#define r_sdp_buf_conn_nettype(buf)                 r_sdp_connection_buf_nettype (&(buf)->conn)
/** @brief Duplicate the session connection address type as a string. */
#define r_sdp_buf_conn_addrtype(buf)                r_sdp_connection_buf_addrtype (&(buf)->conn)
/** @brief Duplicate the session connection address as a string. */
#define r_sdp_buf_conn_addr(buf)                    r_sdp_connection_buf_addr (&(buf)->conn)
/** @brief Multicast TTL of the session connection. */
#define r_sdp_buf_conn_ttl(buf)                     r_sdp_connection_buf_ttl (&(buf)->conn)
/** @brief Address count of the session connection. */
#define r_sdp_buf_conn_addrcount(buf)               r_sdp_connection_buf_addrcount (&(buf)->conn)
/** @brief Build an @c RSocketAddress from the session connection and @p port. */
#define r_sdp_buf_conn_to_socket_address(buf, port) r_sdp_connection_buf_to_socket_address (&(buf)->conn, port)

/** @brief Duplicate the modifier name of session bandwidth line @p idx. */
#define r_sdp_buf_bandwidth_type(buf, idx)          r_str_kv_dup_key (&(buf)->bw[idx])
/** @brief Classified @ref RSdpBandwidthModifier of session bandwidth line @p idx. */
#define r_sdp_buf_bandwidth_modifier(buf, idx) \
  r_sdp_bandwidth_modifier_from_str ((buf)->bw[idx].key.str, (rssize) (buf)->bw[idx].key.size)
/** @brief Raw integer value of session bandwidth line @p idx. */
#define r_sdp_buf_bandwidth_raw(buf, idx)           r_str_to_uint ((buf)->bw[idx].val.str, NULL, 10, NULL)
/** @brief Session bandwidth of line @p idx in bits per second. */
#define r_sdp_buf_bandwidth_bps(buf, idx) \
  r_sdp_bandwidth_to_bps (r_sdp_buf_bandwidth_modifier (buf, idx), \
      r_sdp_buf_bandwidth_raw (buf, idx))

/** @brief Duplicate the start time of timing line @p idx. */
#define r_sdp_buf_time_start(buf, idx)              r_sdp_time_buf_start (&(buf)->time[idx])
/** @brief Duplicate the stop time of timing line @p idx. */
#define r_sdp_buf_time_stop(buf, idx)               r_sdp_time_buf_stop (&(buf)->time[idx])
/** @brief Number of repeat entries on timing line @p idx. */
#define r_sdp_buf_time_repeat_count(buf, idx)       r_sdp_time_buf_repeat_count (&(buf)->time[idx])
/** @brief Duplicate repeat entry @p ridx of timing line @p idx. */
#define r_sdp_buf_time_repeat(buf, idx, ridx)       r_sdp_time_buf_repeat (&(buf)->time[idx], ridx)

/** @brief Duplicate the adjustment time of time-zone entry @p idx as a string. */
#define r_sdp_buf_zone_time_str(buf, idx)           r_str_kv_dup_key (&(buf)->zone[idx])
/** @brief Parse the adjustment time of time-zone entry @p idx as an unsigned integer. */
#define r_sdp_buf_zone_time_uint(buf, idx)          r_str_to_uint ((buf)->zone[idx].key.str, NULL, 10, NULL)
/** @brief Duplicate the offset of time-zone entry @p idx as a string. */
#define r_sdp_buf_zone_offset_str(buf, idx)         r_str_kv_dup_value (&(buf)->zone[idx])
/** @brief Parse the offset of time-zone entry @p idx as an unsigned integer. */
#define r_sdp_buf_zone_offset_uint(buf, idx)        r_str_to_uint ((buf)->zone[idx].val.str, NULL, 10, NULL)

/** @brief Duplicate the session key method. */
#define r_sdp_buf_key_method(buf)                   r_str_kv_dup_key (&(buf)->key)
/** @brief Duplicate the session key data. */
#define r_sdp_buf_key_data(buf)                     r_str_kv_dup_value (&(buf)->key)

/** @brief @c TRUE if session attribute @p f is present. */
#define r_sdp_buf_has_attrib(buf, f, fsize)         (r_sdp_attrib_check ((buf)->attrib, (buf)->acount, f, fsize) == R_SDP_OK)
/** @brief Find session attribute @p f from cursor @p s; see @ref r_sdp_attrib_find. */
#define r_sdp_buf_attrib_find(buf, f, fsize, s)     r_sdp_attrib_find ((buf)->attrib, (buf)->acount, f, fsize, s)
/** @brief Duplicate the value of session attribute @p f from cursor @p s. */
#define r_sdp_buf_attrib_dup_value(buf, f, fsize, s) r_sdp_attrib_dup_value ((buf)->attrib, (buf)->acount, f, fsize, s)

/* media lines */
/** @brief Duplicate the media type of media section @p idx. */
#define r_sdp_buf_media_type(buf, idx)                  r_sdp_media_buf_type (&(buf)->media[idx])
/** @brief Transport port of media section @p idx. */
#define r_sdp_buf_media_port(buf, idx)                  r_sdp_media_buf_port (&(buf)->media[idx])
/** @brief Port count of media section @p idx. */
#define r_sdp_buf_media_portcount(buf, idx)             r_sdp_media_buf_portcount (&(buf)->media[idx])
/** @brief Duplicate the transport protocol of media section @p idx. */
#define r_sdp_buf_media_proto(buf, idx)                 r_sdp_media_buf_proto (&(buf)->media[idx])
/** @brief Number of formats in media section @p idx. */
#define r_sdp_buf_media_fmt_count(buf, idx)             r_sdp_media_buf_fmt_count (&(buf)->media[idx])
/** @brief Duplicate format @p fidx of media section @p idx. */
#define r_sdp_buf_media_fmt(buf, idx, fidx)             r_sdp_media_buf_fmt (&(buf)->media[idx], fidx)
/** @brief Parse format @p fidx of media section @p idx as an unsigned integer. */
#define r_sdp_buf_media_fmt_uint(buf, idx, fidx)        r_sdp_media_buf_fmt_uint (&(buf)->media[idx], fidx)
/** @brief Duplicate the media information of media section @p idx. */
#define r_sdp_buf_media_info(buf, idx)                  r_sdp_media_buf_info (&(buf)->media[idx])
/** @brief Number of connection lines in media section @p idx. */
#define r_sdp_buf_media_conn_count(buf, idx)            r_sdp_media_buf_conn_count (&(buf)->media[idx])
/** @brief Duplicate the network type of connection @p cidx in media section @p idx. */
#define r_sdp_buf_media_conn_nettype(buf, idx, cidx)    r_sdp_media_buf_conn_nettype (&(buf)->media[idx], cidx)
/** @brief Duplicate the address type of connection @p cidx in media section @p idx. */
#define r_sdp_buf_media_conn_addrtype(buf, idx, cidx)   r_sdp_media_buf_conn_addrtype (&(buf)->media[idx], cidx)
/** @brief Duplicate the address of connection @p cidx in media section @p idx. */
#define r_sdp_buf_media_conn_addr(buf, idx, cidx)       r_sdp_media_buf_conn_addr (&(buf)->media[idx], cidx)
/** @brief Multicast TTL of connection @p cidx in media section @p idx. */
#define r_sdp_buf_media_conn_ttl(buf, idx, cidx)        r_sdp_media_buf_conn_ttl (&(buf)->media[idx], cidx)
/** @brief Address count of connection @p cidx in media section @p idx. */
#define r_sdp_buf_media_conn_addrcount(buf, idx, cidx)  r_sdp_media_buf_conn_addrcount (&(buf)->media[idx], cidx)
/** @brief Build an @c RSocketAddress from connection @p cidx in media section @p idx. */
#define r_sdp_buf_media_conn_to_socket_address(buf, idx, cidx) r_sdp_media_buf_conn_to_socket_address (&(buf)->media[idx], cidx)
/** @brief Number of bandwidth lines in media section @p idx. */
#define r_sdp_buf_media_bandwidth_count(buf, idx)       r_sdp_media_buf_bandwidth_count (&(buf)->media[idx])
/** @brief Duplicate the modifier name of bandwidth line @p bidx in media section @p idx. */
#define r_sdp_buf_media_bandwidth_type(buf, idx, bidx)  r_sdp_media_buf_bandwidth_type (&(buf)->media[idx], bidx)
/** @brief Classified @ref RSdpBandwidthModifier of bandwidth line @p bidx in media section @p idx. */
#define r_sdp_buf_media_bandwidth_modifier(buf, idx, bidx) \
  r_sdp_media_buf_bandwidth_modifier (&(buf)->media[idx], bidx)
/** @brief Raw integer value of bandwidth line @p bidx in media section @p idx. */
#define r_sdp_buf_media_bandwidth_raw(buf, idx, bidx)   r_sdp_media_buf_bandwidth_raw (&(buf)->media[idx], bidx)
/** @brief Bandwidth of line @p bidx in media section @p idx, in bits per second. */
#define r_sdp_buf_media_bandwidth_bps(buf, idx, bidx) \
  r_sdp_media_buf_bandwidth_bps (&(buf)->media[idx], bidx)
/** @brief Duplicate the key method of media section @p idx. */
#define r_sdp_buf_media_key_method(buf, idx)            r_sdp_media_buf_key_method (&(buf)->media[idx])
/** @brief Duplicate the key data of media section @p idx. */
#define r_sdp_buf_media_key_data(buf, idx)              r_sdp_media_buf_key_data (&(buf)->media[idx])
/** @brief Number of attributes in media section @p idx. */
#define r_sdp_buf_media_attrib_count(buf, idx)          r_sdp_media_buf_attrib_count (&(buf)->media[idx])
/** @brief @c TRUE if attribute @p f is present in media section @p idx. */
#define r_sdp_buf_media_has_attrib(buf, idx, f, fsize)  r_sdp_media_buf_has_attrib (&(buf)->media[idx], f, fsize)
/** @brief Duplicate the value of attribute @p f from cursor @p s in media section @p idx. */
#define r_sdp_buf_media_attrib_dup_value(buf, idx, s, f, fsize) \
  r_sdp_media_buf_attrib_dup_value (&(buf)->media[idx], s, f, fsize)
/** @brief Find the "rtpmap" attribute for format @p fmt in media section @p idx. */
#define r_sdp_buf_media_rtpmap_for_fmt(buf, idx, fmt, fsize, attrib) \
  r_sdp_media_buf_rtpmap_for_fmt (&(buf)->media[idx], fmt, fsize, attrib)
/** @brief Find the "rtpmap" attribute for format index @p fmtidx in media section @p idx. */
#define r_sdp_buf_media_rtpmap_for_fmt_idx(buf, idx, fmtidx, attrib) \
  r_sdp_media_buf_rtpmap_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib)
/** @brief Find an "rtcp-fb" attribute for format @p fmt in media section @p idx from cursor @p start. */
#define r_sdp_buf_media_rtcpfb_for_fmt(buf, idx, fmt, fsize, attrib, start) \
  r_sdp_media_buf_rtcpfb_for_fmt (&(buf)->media[idx], fmt, fsize, attrib, start)
/** @brief Find an "rtcp-fb" attribute for format index @p fmtidx in media section @p idx from cursor @p start. */
#define r_sdp_buf_media_rtcpfb_for_fmt_idx(buf, idx, fmtidx, attrib, start) \
  r_sdp_media_buf_rtcpfb_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib, start)
/** @brief Find the "fmtp" attribute for format @p fmt in media section @p idx. */
#define r_sdp_buf_media_fmtp_for_fmt(buf, idx, fmt, fsize, attrib) \
  r_sdp_media_buf_fmtp_for_fmt (&(buf)->media[idx], fmt, fsize, attrib)
/** @brief Find the "fmtp" attribute for format index @p fmtidx in media section @p idx. */
#define r_sdp_buf_media_fmtp_for_fmt_idx(buf, idx, fmtidx, attrib) \
  r_sdp_media_buf_fmtp_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib)

/**
 * @brief Find a grouping ("a=group") chunk by semantics and member mid.
 * @param sdp Parsed SDP view.
 * @param group Out chunk receiving the matched grouping.
 * @param semantics Grouping semantics (e.g. "BUNDLE").
 * @param ssize Size of @p semantics, or -1 if NUL-terminated.
 * @param mid Member media identification tag to match.
 * @param midsize Size of @p mid, or -1 if NUL-terminated.
 */
R_API RSdpResult r_sdp_buf_find_grouping (const RSdpBuf * sdp, RStrChunk * group,
    const rchar * semantics, rssize ssize, const rchar * mid, rssize midsize);

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_SDP_H__ */


