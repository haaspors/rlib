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

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rmsgdigest.h>
#include <rlib/rref.h>
#include <rlib/rsocketaddress.h>

#include <rlib/rtc/rrtc.h>
#include <rlib/rtc/rrtcrtpparameters.h>

R_BEGIN_DECLS

typedef struct {
  rchar * ufrag;
  rchar * pwd;
  rboolean lite;
} RRtcIceTransportParameters;

typedef struct {
  RRtcRole role;
  RMsgDigestType md;
  rchar * fingerprint;
} RRtcDtlsTransportParameters;

/* FIXME: Add RRtcRtpSdesTransportParameters */
#if 0
typedef struct {
} RRtcRtpSdesTransportParameters;
#endif

typedef struct {
  RRtcIceTransportParameters ice;
  RRtcDtlsTransportParameters dtls;
  /* RRtcRtpSdesTransportParameters rtpsdes; */
} RRtcTransportParameters;

typedef struct {
  RRef ref;

  rchar * id;
  RSocketAddress * addr;

  rboolean rtcpmux;
  RRtcTransportParameters rtp;
  RRtcTransportParameters rtcp;
} RRtcTransportInfo;

R_API RRtcTransportInfo * r_rtc_transport_info_new_full (const rchar * id,
    rssize size, RSocketAddress * addr, rboolean rtcpmux) R_ATTR_MALLOC;
static inline RRtcTransportInfo * r_rtc_transport_info_new (const rchar * id,
    rssize size) { return r_rtc_transport_info_new_full (id, size, NULL, TRUE); }
#define r_rtc_transport_info_ref        r_ref_ref
#define r_rtc_transport_info_unref      r_ref_unref

R_API RRtcError r_rtc_transport_set_ice_parameters (RRtcTransportInfo * trans,
  const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize,
  rboolean lite);
R_API RRtcError r_rtc_transport_set_dtls_parameters (RRtcTransportInfo * trans,
  RRtcRole role, RMsgDigestType md, const rchar * fingerprint, rssize size);

typedef enum {
  R_RTC_PROTO_NONE = 0,
  R_RTC_PROTO_RTP,
  R_RTC_PROTO_SCTP,
} RRtcProtocol;

typedef enum {
  R_RTC_PROTO_FLAG_NONE       = 0,
  R_RTC_PROTO_FLAG_AV_PROFILE = (1 << 0),
  R_RTC_PROTO_FLAG_SECURE     = (1 << 1),
  R_RTC_PROTO_FLAG_FEEDBACK   = (1 << 2),

  R_RTC_PROTO_FLAGS_SAVP      = R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE,
  R_RTC_PROTO_FLAGS_AVPF      = R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_FEEDBACK,
  R_RTC_PROTO_FLAGS_SAVPF     = R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE | R_RTC_PROTO_FLAG_FEEDBACK,
} RRtcProtocolFlags;

R_API RRtcProtocol r_rtc_protocol_from_string (const rchar * proto, rssize size, RRtcProtocolFlags * flags);
R_API const rchar * r_rtc_protocol_to_string (RRtcProtocol proto, RRtcProtocolFlags flags);

typedef struct {
  RRef ref;

  RRtcMediaType type;
  RRtcDirection dir;
  RRtcProtocol proto;
  RRtcProtocolFlags protoflags;
  rchar * mid;
  rchar * trans; /* BUNDLE-tag */
  rboolean bundled;

  /* Candidates should be unique per media line, not transport! */
  RPtrArray candidates;     /* RRtcIceCandidate */
  rboolean endofcandidates;

  /*RDictionary * attrib;*/
  RRtcRtpParameters * params;
} RRtcMediaLineInfo;

R_API RRtcMediaLineInfo * r_rtc_media_line_info_new (
    const rchar * mid, rssize size, RRtcDirection dir,
    RRtcMediaType type, RRtcProtocol proto, RRtcProtocolFlags protoflags) R_ATTR_MALLOC;
R_API RRtcMediaLineInfo * r_rtc_media_line_info_new_from_str (
    const rchar * mid, rssize size, RRtcDirection dir,
    const rchar * type, rssize tsize, const rchar * proto, rssize psize) R_ATTR_MALLOC;
#define r_rtc_media_line_info_ref       r_ref_ref
#define r_rtc_media_line_info_unref     r_ref_unref

R_API RRtcError r_rtc_media_line_info_take_ice_candidate (RRtcMediaLineInfo * mline,
    RRtcIceCandidate * candidate);


typedef struct {
  RRef ref;

  RRtcSignalType type;

  /* Details */
  RRtcDirection dir;
  rchar * username;
  rchar * session_id;
  ruint64 session_ver;
  rchar * orig_nettype;
  rchar * orig_addrtype;
  rchar * orig_addr;
  rchar * session_name;
  rchar * conn_nettype;
  rchar * conn_addrtype;
  rchar * conn_addr;
  ruint   conn_ttl;
  ruint   conn_addrcount;
  ruint64 tstart, tstop;

  RHashTable * transport; /* RRtcTransportInfo */
  RPtrArray mline;     /* RRtcMediaLineInfo */

  rpointer data;
  RDestroyNotify notify;
} RRtcSessionDescription;

R_API RRtcSessionDescription * r_rtc_session_description_new (RRtcSignalType type) R_ATTR_MALLOC;
R_API RRtcSessionDescription * r_rtc_session_description_new_from_sdp (
    RRtcSignalType type, RBuffer * buf, RRtcError * error) R_ATTR_MALLOC;
#define r_rtc_session_description_ref       r_ref_ref
#define r_rtc_session_description_unref     r_ref_unref

#define r_rtc_session_description_transport_count(sd)     r_hash_table_size ((sd)->transport)
#define r_rtc_session_description_get_transport(sd, id)   ((RRtcTransportInfo *) r_hash_table_lookup ((sd)->transport, id))
#define r_rtc_session_description_media_line_count(sd)    r_ptr_array_size (&(sd)->mline)
#define r_rtc_session_description_get_media_line_by_idx(sd, idx) ((RRtcMediaLineInfo *) r_ptr_array_get (&(sd)->mline, idx))
R_API RRtcMediaLineInfo * r_rtc_session_description_get_media_line (RRtcSessionDescription * sd,
    const rchar * mid, rssize size);

R_API RRtcError r_rtc_session_description_set_originator_full (RRtcSessionDescription * sd,
    const rchar * username, rssize usize, const rchar * sid, rssize sidsize,
    ruint64 sver, const rchar * nettype, rssize ntsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize);
R_API RRtcError r_rtc_session_description_set_originator_addr (RRtcSessionDescription * sd,
    const rchar * username, rssize usize, const rchar * sid, rssize sidsize,
    ruint64 sver, RSocketAddress * addr);
R_API RRtcError r_rtc_session_description_set_session_name (RRtcSessionDescription * sd,
    const rchar * name, rssize size);
R_API RRtcError r_rtc_session_description_set_connection_full (RRtcSessionDescription * sd,
    const rchar * nettype, rssize ntsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize);
R_API RRtcError r_rtc_session_description_set_connection_addr (RRtcSessionDescription * sd,
    RSocketAddress * addr);

R_API RRtcError r_rtc_session_description_take_transport (RRtcSessionDescription * sd,
    RRtcTransportInfo * transport);
R_API RRtcError r_rtc_session_description_take_media_line (RRtcSessionDescription * sd,
    RRtcMediaLineInfo * mline);

R_API RBuffer * r_rtc_session_description_to_sdp (RRtcSessionDescription * sd, RRtcError * err);

R_END_DECLS

#endif /* __R_RTC_SESSION_DESCRIPTION_H__ */

