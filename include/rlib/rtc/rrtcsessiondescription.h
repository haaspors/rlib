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

  RPtrArray candidates;     /* RRtcIceCandidate */
  rboolean endofcandidates;
} RRtcTransportParameters;

typedef struct {
  RRef ref;

  rchar * id;
  RSocketAddress * addr;

  rboolean rtcpmux;
  RRtcTransportParameters rtp;
  RRtcTransportParameters rtcp;
} RRtcTransportInfo;

R_API RRtcTransportInfo * r_rtc_transport_info_new (const rchar * id, rssize size,
    rboolean rtcpmux) R_ATTR_MALLOC;
#define r_rtc_transport_info_ref        r_ref_ref
#define r_rtc_transport_info_unref      r_ref_unref

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

typedef struct {
  RRef ref;

  RRtcMediaType type;
  RRtcDirection dir;
  RRtcProtocol proto;
  RRtcProtocolFlags protoflags;
  rchar * mid;
  rchar * trans; /* BUNDLE-tag */

  /*RDictionary * attrib;*/
  RRtcRtpParameters * params;
} RRtcMediaLineInfo;

R_API RRtcMediaLineInfo * r_rtc_media_line_info_new (const rchar * mid, rssize size,
    RRtcMediaType type, RRtcDirection dir, const rchar * proto, rssize psize) R_ATTR_MALLOC;
#define r_rtc_media_line_info_ref       r_ref_ref
#define r_rtc_media_line_info_unref     r_ref_unref


typedef struct {
  RRef ref;

  RRtcSignalType type;

  /* Details */
  RRtcDirection dir;
  rchar * username;
  rchar * session_name;
  rchar * session_id;
  ruint64 session_ver;
  rchar * orig_nettype;
  rchar * orig_addrtype;
  rchar * orig_addr;
  rchar * conn_nettype;
  rchar * conn_addrtype;
  rchar * conn_addr;
  ruint   conn_ttl;
  ruint   conn_addrcount;

  RHashTable * transport; /* RRtcTransportInfo */
  RHashTable * mline;     /* RRtcMediaLineInfo */

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
#define r_rtc_session_description_media_line_count(sd)    r_hash_table_size ((sd)->mline)
#define r_rtc_session_description_get_media_line(sd, mid) ((RRtcMediaLineInfo *) r_hash_table_lookup ((sd)->mline, mid))

R_API RRtcError r_rtc_session_description_take_transport (RRtcSessionDescription * sd,
    RRtcTransportInfo * transport);
R_API RRtcError r_rtc_session_description_take_media_line (RRtcSessionDescription * sd,
    RRtcMediaLineInfo * mline);

/* FIXME: Add r_rtc_session_description_to_sdp */
R_API RBuffer * r_rtc_session_description_to_sdp (const RRtcSessionDescription * sd);

R_END_DECLS

#endif /* __R_RTC_SESSION_DESCRIPTION_H__ */

