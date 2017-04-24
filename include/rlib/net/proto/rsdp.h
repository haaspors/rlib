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

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rmsgdigest.h>
#include <rlib/rref.h>
#include <rlib/rsocketaddress.h>
#include <rlib/rstr.h>
#include <rlib/ruri.h>

#include <rlib/net/proto/rrtp.h>

R_BEGIN_DECLS

typedef enum {
  R_SDP_EOB = -1,
  R_SDP_OK = 0,
  R_SDP_INVAL,
  R_SDP_OOM,
  R_SDP_MAP_FAILED,
  R_SDP_MISSING_REQUIRED_LINE,
  R_SDP_BAD_DATA,
  R_SDP_NOT_FOUND,
  R_SDP_MORE_DATA,
} RSdpResult;

typedef enum {
  R_SDP_MD_INACTIVE         = 0,
  R_SDP_MD_SENDONLY         = 1,
  R_SDP_MD_RECVONLY         = 2,
  R_SDP_MD_SENDRECV         = R_SDP_MD_SENDONLY | R_SDP_MD_RECVONLY,
} RSdpMediaDirection;

typedef enum {
  R_SDP_CONN_ROLE_HOLDCONN  = 0,
  R_SDP_CONN_ROLE_ACTIVE    = 1,
  R_SDP_CONN_ROLE_PASSIVE   = 2,
  R_SDP_CONN_ROLE_ACTPASS   = R_SDP_CONN_ROLE_ACTIVE | R_SDP_CONN_ROLE_PASSIVE,
} RSdpConnRole;

typedef enum {
  R_SDP_ICE_TYPE_HOST         = 0,
  R_SDP_ICE_TYPE_SRFLX        = 1,
  R_SDP_ICE_TYPE_PRFLX        = 2,
  R_SDP_ICE_TYPE_RELAY        = 3,
} RSdpICEType;


typedef struct _RSdpBuf RSdpBuf; /* Fwd decl because of RSdpMsg API */

/* RSdpMsg API */
typedef struct _RSdpMsg RSdpMsg;
typedef struct _RSdpMedia RSdpMedia;

R_API RSdpMsg * r_sdp_msg_new (void) R_ATTR_MALLOC;
R_API RSdpMsg * r_sdp_msg_new_jsep (ruint64 sessid, ruint sessver) R_ATTR_MALLOC;
R_API RSdpMsg * r_sdp_msg_new_from_sdp_buffer (const RSdpBuf * buf) R_ATTR_MALLOC;
#define r_sdp_msg_ref     r_ref_ref
#define r_sdp_msg_unref   r_ref_unref

R_API RBuffer * r_sdp_msg_to_buffer (const RSdpMsg * msg);

R_API RSdpResult r_sdp_msg_set_version (RSdpMsg * msg,
    const rchar * ver, rssize size);
R_API RSdpResult r_sdp_msg_set_originator (RSdpMsg * msg,
    const rchar * username, rssize usize,
    const rchar * sid, rssize sidsize, const rchar * sver, rssize sversize,
    const rchar * nettype, rssize nsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize);
R_API RSdpResult r_sdp_msg_set_session_name (RSdpMsg * msg,
    const rchar * name, rssize size);
R_API RSdpResult r_sdp_msg_set_session_info (RSdpMsg * msg,
    const rchar * info, rssize size);
R_API RSdpResult r_sdp_msg_set_uri (RSdpMsg * msg, RUri * uri);
R_API RSdpResult r_sdp_msg_add_email (RSdpMsg * msg,
    const rchar * email, rssize size);
R_API RSdpResult r_sdp_msg_add_phone (RSdpMsg * msg,
    const rchar * phone, rssize size);
R_API RSdpResult r_sdp_msg_clear_connection (RSdpMsg * msg, rboolean def);
#define r_sdp_msg_set_connection_unicast(msg, addr)                           \
  r_sdp_msg_set_connection_full (msg, addr, 0, 1)
R_API RSdpResult r_sdp_msg_set_connection_full (RSdpMsg * msg,
    const rchar * nettype, rssize nsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize,
    ruint ttl, ruint addrcount);
R_API RSdpResult r_sdp_msg_add_bandwidth (RSdpMsg * msg,
    const rchar * type, rssize tsize, ruint kbps);
R_API RSdpResult r_sdp_msg_add_time (RSdpMsg * msg, ruint64 start, ruint64 stop);
/* FIXME R_API RSdpResult r_sdp_msg_add_repeat (RSdpMsg * msg, rsize timeidx, ); */
/* FIXME R_API RSdpResult r_sdp_msg_add_time_zone (RSdpMsg * msg, ruint64 time, ruint64 offset); */
R_API RSdpResult r_sdp_msg_set_key (RSdpMsg * msg,
    const rchar * method, rssize msize, const rchar * data, rssize size);
R_API RSdpResult r_sdp_msg_add_attribute (RSdpMsg * msg,
    const rchar * key, rssize ksize, const rchar * value, rssize vsize);
R_API RSdpResult r_sdp_msg_add_media (RSdpMsg * msg, RSdpMedia * media);


R_API RSdpMedia * r_sdp_media_new (void) R_ATTR_MALLOC;
R_API RSdpMedia * r_sdp_media_new_jsep_dtls (
    const rchar * type, rssize tsize, const rchar * mid, rssize msize,
    RSdpMediaDirection md) R_ATTR_MALLOC;
R_API RSdpMedia * r_sdp_media_new_full (const rchar * type, rssize tsize,
    ruint port, ruint portcount, const rchar * proto, rssize psize) R_ATTR_MALLOC;
#define r_sdp_media_ref     r_ref_ref
#define r_sdp_media_unref   r_ref_unref

R_API RSdpResult r_sdp_media_add_rtp_fmt (RSdpMedia * media,
    RRTPPayloadType pt, const rchar * enc, rssize esize,
    ruint rate, ruint params);
#define r_sdp_media_add_rtp_fmt_static(m, pt) r_sdp_media_add_rtp_fmt (m, pt, NULL, 0, 0, 0)
#define r_sdp_medida_add_connection_unicast(media, addr)                      \
  r_sdp_media_add_connection_full (media, addr, 0, 1)
R_API RSdpResult r_sdp_media_add_connection_full (RSdpMedia * media,
    const rchar * nettype, rssize nsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize,
    ruint ttl, ruint addrcount);
R_API RSdpResult r_sdp_media_set_media_info (RSdpMedia * media,
    const rchar * info, rssize size);
R_API RSdpResult r_sdp_media_add_bandwidth (RSdpMedia * media,
    const rchar * type, rssize tsize, ruint kbps);
R_API RSdpResult r_sdp_media_set_key (RSdpMedia * media,
    const rchar * method, rssize msize, const rchar * data, rssize size);
R_API RSdpResult r_sdp_media_add_attribute (RSdpMedia * media,
    const rchar * key, rssize ksize, const rchar * value, rssize vsize);

R_API RSdpResult r_sdp_media_add_source_specific_attribute (RSdpMedia * media,
    ruint32 ssrc, const rchar * key, rssize ksize, const rchar * value, rssize vsize);
#define r_sdp_media_add_ssrc_cname(m, ssrc, cname, csize) \
  r_sdp_media_add_source_specific_attribute (m, ssrc, "cname", 5, cname, csize)
R_API RSdpResult r_sdp_media_add_jsep_msid (RSdpMedia * media, ruint32 ssrc,
    const rchar * msidval, rssize vsize, const rchar * msidappdata, rssize asize);
R_API RSdpResult r_sdp_media_add_ice_credentials (RSdpMedia * media,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize);
R_API RSdpResult r_sdp_media_add_ice_candidate_raw (RSdpMedia * media,
    const rchar * foundation, rssize fsize, ruint componentid,
    const rchar * transport, rssize transize, ruint64 pri,
    const rchar * addr, rssize asize, ruint16 port,
    const rchar * type, rssize typesize,
    const rchar * raddr, rssize rasize, ruint16 rport,
    const rchar * extension, rssize esize);
R_API RSdpResult r_sdp_media_add_ice_candidate (RSdpMedia * media,
    const rchar * foundation, rssize fsize, ruint componentid,
    const rchar * transport, rssize tsize, ruint64 pri,
    const RSocketAddress * addr, RSdpICEType type,
    const RSocketAddress * raddr, const rchar * extension, rssize esize);
R_API RSdpResult r_sdp_media_add_dtls_setup (RSdpMedia * media,
    RSdpConnRole role, RMsgDigestType type, const rchar * fingerprint, rssize fsize);

R_API rchar * r_sdp_media_get_attribute (const RSdpMedia * media,
    const rchar * key, rssize ksize) R_ATTR_MALLOC;
#define r_sdp_media_get_mid(m)  r_sdp_media_get_attribute (m, "mid", -1)


/* Parsing API */
typedef struct {
  RStrChunk username;
  RStrChunk sess_id;
  RStrChunk sess_version;
  RStrChunk nettype;
  RStrChunk addrtype;
  RStrChunk addr;
} RSdpOriginatorBuf;
#define r_sdp_originator_buf_username(orig)         r_str_chunk_dup (&(orig)->username)
#define r_sdp_originator_buf_session_id(orig)       r_str_chunk_dup (&(orig)->sess_id)
#define r_sdp_originator_buf_session_id_u64(orig)   r_str_to_uint64 ((orig)->sess_id.str, NULL, 10, NULL)
#define r_sdp_originator_buf_session_version(orig)  r_str_chunk_dup (&(orig)->sess_version)
#define r_sdp_originator_buf_session_version_u64(orig) r_str_to_uint64 ((orig)->sess_version.str, NULL, 10, NULL)
#define r_sdp_originator_buf_nettype(orig)          r_str_chunk_dup (&(orig)->nettype)
#define r_sdp_originator_buf_addrtype(orig)         r_str_chunk_dup (&(orig)->addrtype)
#define r_sdp_originator_buf_addr(orig)             r_str_chunk_dup (&(orig)->addr)

typedef struct {
  RStrChunk nettype;
  RStrChunk addrtype;
  RStrChunk addr;
  ruint ttl;
  ruint addrcount;
} RSdpConnectionBuf;
#define r_sdp_connection_buf_nettype(conn)          r_str_chunk_dup (&(conn)->nettype)
#define r_sdp_connection_buf_addrtype(conn)         r_str_chunk_dup (&(conn)->addrtype)
#define r_sdp_connection_buf_addr(conn)             r_str_chunk_dup (&(conn)->addr)
#define r_sdp_connection_buf_ttl(conn)              (conn)->ttl
#define r_sdp_connection_buf_addrcount(conn)        (conn)->addrcount
R_API RSocketAddress * r_sdp_connection_buf_to_socket_address (const RSdpConnectionBuf * conn, ruint port);

typedef struct {
  RStrChunk start;
  RStrChunk stop;
  rsize rcount;
  RStrChunk * repeat;
} RSdpTimeBuf;
#define r_sdp_time_buf_start(time)                  r_str_chunk_dup (&(time)->start)
#define r_sdp_time_buf_stop(time)                   r_str_chunk_dup (&(time)->stop)
#define r_sdp_time_buf_repeat_count(time)           (time)->rcount
#define r_sdp_time_buf_repeat(time, idx)            r_str_chunk_dup (&(time)->repeat[idx])

R_API RSdpResult r_sdp_attrib_check (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize);
R_API const RStrChunk * r_sdp_attrib_find (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize, rsize * start);
R_API rchar * r_sdp_attrib_dup_value (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize, rsize * start);

typedef struct {
  RStrChunk type;
  ruint port;
  ruint portcount;
  RStrChunk proto;
  rsize fmtcount;
  RStrChunk * fmt;
  RStrChunk info;
  rsize ccount;
  RSdpConnectionBuf * conn;
  rsize bcount;
  RStrKV * bw;
  RStrKV key;
  rsize acount;
  RStrKV * attrib;
} RSdpMediaBuf;
#define r_sdp_media_buf_type(media)                 r_str_chunk_dup (&(media)->type)
#define r_sdp_media_buf_port(media)                 (media)->port
#define r_sdp_media_buf_portcount(media)            (media)->portcount
#define r_sdp_media_buf_proto(media)                r_str_chunk_dup (&(media)->proto)
#define r_sdp_media_buf_fmt_count(media)            (media)->fmtcount
#define r_sdp_media_buf_fmt(media, idx)             r_str_chunk_dup (&(media)->fmt[idx])
#define r_sdp_media_buf_fmt_uint(media, idx)        r_str_to_uint ((media)->fmt[idx].str, NULL, 0, NULL)
R_API rssize r_sdp_media_buf_find_fmt (const RSdpMediaBuf * media, const rchar * fmt, rssize size);
#define r_sdp_media_buf_info(media)                 r_str_chunk_dup (&(media)->info)
#define r_sdp_media_buf_conn_count(media)           (media)->ccount
#define r_sdp_media_buf_conn_nettype(media, idx)    r_sdp_connection_buf_nettype (&(media)->conn[idx])
#define r_sdp_media_buf_conn_addrtype(media, idx)   r_sdp_connection_buf_addrtype (&(media)->conn[idx])
#define r_sdp_media_buf_conn_addr(media, idx)       r_sdp_connection_buf_addr (&(media)->conn[idx])
#define r_sdp_media_buf_conn_ttl(media, idx)        r_sdp_connection_buf_ttl (&(media)->conn[idx])
#define r_sdp_media_buf_conn_addrcount(media, idx)  r_sdp_connection_buf_addrcount (&(media)->conn[idx])
#define r_sdp_media_buf_conn_to_socket_address(media, idx) r_sdp_connection_buf_to_socket_address (&(media)->conn[idx], (media)->port)
#define r_sdp_media_buf_bandwidth_count(media)      (media)->bcount
#define r_sdp_media_buf_bandwidth_type(media, idx)  r_str_kv_dup_key (&(media)->bw[idx])
#define r_sdp_media_buf_bandwidth_kbps(media, idx)  r_str_to_uint ((media)->bw[idx].val.str, NULL, 10, NULL)
/* FIXME: bw based CT, AS, TIAS */
#define r_sdp_media_buf_key_method(media)           r_str_kv_dup_key (&(media)->key)
#define r_sdp_media_buf_key_data(media)             r_str_kv_dup_value (&(media)->key)
#define r_sdp_media_buf_attrib_count(media)         (media)->acount
#define r_sdp_media_buf_has_attrib(media, f, fsize) (r_sdp_attrib_check ((media)->attrib, (media)->acount, f, fsize) == R_SDP_OK)
#define r_sdp_media_buf_attrib_find(media, f, fsize, s) r_sdp_attrib_find ((media)->attrib, (media)->acount, f, fsize, s)
#define r_sdp_media_buf_attrib_dup_value(media, f, fsize, s) r_sdp_attrib_dup_value ((media)->attrib, (media)->acount, f, fsize, s)
R_API RSdpResult r_sdp_media_buf_fmt_specific_attrib (const RSdpMediaBuf * media,
    const rchar * fmt, rssize fmtsize, const rchar * field, rssize fsize,
    RStrChunk * attrib, rsize * start);
R_API RSdpResult r_sdp_media_buf_fmtidx_specific_attrib (const RSdpMediaBuf * media,
    rsize fmtidx, const rchar * field, rssize fsize, RStrChunk * attrib, rsize * start);
#define r_sdp_media_buf_rtpmap_for_fmt(media, fmt, fmtsize, attrib)           \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("rtpmap"), attrib, NULL)
#define r_sdp_media_buf_rtpmap_for_fmt_idx(media, fmtidx, attrib)             \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("rtpmap"), attrib, NULL)
#define r_sdp_media_buf_rtcpfb_for_fmt(media, fmt, fmtsize, attrib, start)    \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("rtcp-fb"), attrib, start)
#define r_sdp_media_buf_rtcpfb_for_fmt_idx(media, fmtidx, attrib, start)      \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("rtcp-fb"), attrib, start)
#define r_sdp_media_buf_fmtp_for_fmt(media, fmt, fmtsize, attrib)             \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("fmtp"), attrib, NULL)
#define r_sdp_media_buf_fmtp_for_fmt_idx(media, fmtidx, attrib)               \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("fmtp"), attrib, NULL)
R_API ruint32 * r_sdp_media_buf_source_specific_sources (
    const RSdpMediaBuf * media, rsize * size);
R_API RStrKV * r_sdp_media_buf_source_specific_all_media_attribs (
    const RSdpMediaBuf * media, ruint32 ssrc, rsize * size) R_ATTR_MALLOC;
R_API RSdpResult r_sdp_media_buf_source_specific_media_attrib (const RSdpMediaBuf * media,
    ruint32 ssrc, const rchar * field, rssize fsize, RStrChunk * attrib);
R_API RSdpResult r_sdp_media_buf_extmap_attrib (const RSdpMediaBuf * media,
    ruint16 * id, RStrChunk * attrib, rsize * start);

struct _RSdpBuf {
  RMemMapInfo info;

  RStrChunk ver;
  RSdpOriginatorBuf orig;
  RStrChunk session_name;
  RStrChunk session_info;
  RStrChunk uri;
  rsize ecount;
  RStrChunk * email;
  rsize pcount;
  RStrChunk * phone;
  RSdpConnectionBuf conn;
  rsize bcount;
  RStrKV * bw;
  rsize tcount;
  RSdpTimeBuf * time;
  rsize zcount;
  RStrKV * zone;
  RStrKV key;
  rsize acount;
  RStrKV * attrib;

  rsize mcount;
  RSdpMediaBuf * media;
};

R_API RSdpResult r_sdp_buffer_map (RSdpBuf * sdp, RBuffer * buf);
R_API RSdpResult r_sdp_buffer_unmap (RSdpBuf * sdp, RBuffer * buf);

#define r_sdp_buf_version(buf)                      r_str_chunk_dup (&(buf)->ver)
#define r_sdp_buf_session_name(buf)                 r_str_chunk_dup (&(buf)->session_name)
#define r_sdp_buf_session_info(buf)                 r_str_chunk_dup (&(buf)->session_info)
#define r_sdp_buf_uri_str(buf)                      r_str_chunk_dup (&(buf)->uri)
#define r_sdp_buf_uri(buf)                          r_uri_new_escaped ((buf)->uri.str, (buf)->uri.size)

#define r_sdp_buf_orig_username(buf)                r_sdp_originator_buf_username (&(buf)->orig)
#define r_sdp_buf_orig_session_id(buf)              r_sdp_originator_buf_session_id (&(buf)->orig)
#define r_sdp_buf_orig_session_id_u64(buf)          r_sdp_originator_buf_session_id_u64 (&(buf)->orig)
#define r_sdp_buf_orig_session_version(buf)         r_sdp_originator_buf_session_version (&(buf)->orig)
#define r_sdp_buf_orig_session_version_u64(buf)     r_sdp_originator_buf_session_version_u64 (&(buf)->orig)
#define r_sdp_buf_orig_nettype(buf)                 r_sdp_originator_buf_nettype (&(buf)->orig)
#define r_sdp_buf_orig_addrtype(buf)                r_sdp_originator_buf_addrtype (&(buf)->orig)
#define r_sdp_buf_orig_addr(buf)                    r_sdp_originator_buf_addr (&(buf)->orig)

#define r_sdp_buf_email_count(buf)                  (buf)->ecount
#define r_sdp_buf_phone_count(buf)                  (buf)->pcount
#define r_sdp_buf_bandwidth_count(buf)              (buf)->bcount
#define r_sdp_buf_time_count(buf)                   (buf)->tcount
#define r_sdp_buf_time_zone_count(buf)              (buf)->zcount
#define r_sdp_buf_attrib_count(buf)                 (buf)->acount
#define r_sdp_buf_media_count(buf)                  (buf)->mcount

#define r_sdp_buf_email(buf, idx)                   r_str_chunk_dup (&(buf)->email[idx])
#define r_sdp_buf_phone(buf, idx)                   r_str_chunk_dup (&(buf)->phone[idx])

#define r_sdp_buf_conn_nettype(buf)                 r_sdp_connection_buf_nettype (&(buf)->conn)
#define r_sdp_buf_conn_addrtype(buf)                r_sdp_connection_buf_addrtype (&(buf)->conn)
#define r_sdp_buf_conn_addr(buf)                    r_sdp_connection_buf_addr (&(buf)->conn)
#define r_sdp_buf_conn_ttl(buf)                     r_sdp_connection_buf_ttl (&(buf)->conn)
#define r_sdp_buf_conn_addrcount(buf)               r_sdp_connection_buf_addrcount (&(buf)->conn)
#define r_sdp_buf_conn_to_socket_address(buf, port) r_sdp_connection_buf_to_socket_address (&(buf)->conn, port)

#define r_sdp_buf_bandwidth_type(buf, idx)          r_str_kv_dup_key (&(buf)->bw[idx])
#define r_sdp_buf_bandwidth_kbps(buf, idx)          r_str_to_uint ((buf)->bw[idx].val.str, NULL, 10, NULL)
/* FIXME: bw based CT, AS, TIAS */

#define r_sdp_buf_time_start(buf, idx)              r_sdp_time_buf_start (&(buf)->time[idx])
#define r_sdp_buf_time_stop(buf, idx)               r_sdp_time_buf_stop (&(buf)->time[idx])
#define r_sdp_buf_time_repeat_count(buf, idx)       r_sdp_time_buf_repeat_count (&(buf)->time[idx])
#define r_sdp_buf_time_repeat(buf, idx, ridx)       r_sdp_time_buf_repeat (&(buf)->time[idx], ridx)

#define r_sdp_buf_zone_time_str(buf, idx)           r_str_kv_dup_key (&(buf)->zone[idx])
#define r_sdp_buf_zone_time_uint(buf, idx)          r_str_to_uint ((buf)->zone[idx].key.str, NULL, 10, NULL)
#define r_sdp_buf_zone_offset_str(buf, idx)         r_str_kv_dup_value (&(buf)->zone[idx])
#define r_sdp_buf_zone_offset_uint(buf, idx)        r_str_to_uint ((buf)->zone[idx].val.str, NULL, 10, NULL)

#define r_sdp_buf_key_method(buf)                   r_str_kv_dup_key (&(buf)->key)
#define r_sdp_buf_key_data(buf)                     r_str_kv_dup_value (&(buf)->key)

#define r_sdp_buf_has_attrib(buf, f, fsize)         (r_sdp_attrib_check ((buf)->attrib, (buf)->acount, f, fsize) == R_SDP_OK)
#define r_sdp_buf_attrib_find(buf, f, fsize, s)     r_sdp_attrib_find ((buf)->attrib, (buf)->acount, f, fsize, s)
#define r_sdp_buf_attrib_dup_value(buf, f, fsize, s) r_sdp_attrib_dup_value ((buf)->attrib, (buf)->acount, f, fsize, s)

/* media lines */
#define r_sdp_buf_media_type(buf, idx)                  r_sdp_media_buf_type (&(buf)->media[idx])
#define r_sdp_buf_media_port(buf, idx)                  r_sdp_media_buf_port (&(buf)->media[idx])
#define r_sdp_buf_media_portcount(buf, idx)             r_sdp_media_buf_portcount (&(buf)->media[idx])
#define r_sdp_buf_media_proto(buf, idx)                 r_sdp_media_buf_proto (&(buf)->media[idx])
#define r_sdp_buf_media_fmt_count(buf, idx)             r_sdp_media_buf_fmt_count (&(buf)->media[idx])
#define r_sdp_buf_media_fmt(buf, idx, fidx)             r_sdp_media_buf_fmt (&(buf)->media[idx], fidx)
#define r_sdp_buf_media_fmt_uint(buf, idx, fidx)        r_sdp_media_buf_fmt_uint (&(buf)->media[idx], fidx)
#define r_sdp_buf_media_info(buf, idx)                  r_sdp_media_buf_info (&(buf)->media[idx])
#define r_sdp_buf_media_conn_count(buf, idx)            r_sdp_media_buf_conn_count (&(buf)->media[idx])
#define r_sdp_buf_media_conn_nettype(buf, idx, cidx)    r_sdp_media_buf_conn_nettype (&(buf)->media[idx], cidx)
#define r_sdp_buf_media_conn_addrtype(buf, idx, cidx)   r_sdp_media_buf_conn_addrtype (&(buf)->media[idx], cidx)
#define r_sdp_buf_media_conn_addr(buf, idx, cidx)       r_sdp_media_buf_conn_addr (&(buf)->media[idx], cidx)
#define r_sdp_buf_media_conn_ttl(buf, idx, cidx)        r_sdp_media_buf_conn_ttl (&(buf)->media[idx], cidx)
#define r_sdp_buf_media_conn_addrcount(buf, idx, cidx)  r_sdp_media_buf_conn_addrcount (&(buf)->media[idx], cidx)
#define r_sdp_buf_media_conn_to_socket_address(buf, idx, cidx) r_sdp_media_buf_conn_to_socket_address (&(buf)->media[idx], cidx)
#define r_sdp_buf_media_bandwidth_count(buf, idx)       r_sdp_media_buf_bandwidth_count (&(buf)->media[idx])
#define r_sdp_buf_media_bandwidth_type(buf, idx, bidx)  r_sdp_media_buf_bandwidth_type (&(buf)->media[idx], bidx)
#define r_sdp_buf_media_bandwidth_kbps(buf, idx, bidx)  r_sdp_media_buf_bandwidth_kbps (&(buf)->media[idx], bidx)
/* FIXME: bw based CT, AS, TIAS */
#define r_sdp_buf_media_key_method(buf, idx)            r_sdp_media_buf_key_method (&(buf)->media[idx])
#define r_sdp_buf_media_key_data(buf, idx)              r_sdp_media_buf_key_data (&(buf)->media[idx])
#define r_sdp_buf_media_attrib_count(buf, idx)          r_sdp_media_buf_attrib_count (&(buf)->media[idx])
#define r_sdp_buf_media_has_attrib(buf, idx, f, fsize)  r_sdp_media_buf_has_attrib (&(buf)->media[idx], f, fsize)
#define r_sdp_buf_media_attrib_dup_value(buf, idx, s, f, fsize) \
  r_sdp_media_buf_attrib_dup_value (&(buf)->media[idx], s, f, fsize)
#define r_sdp_buf_media_rtpmap_for_fmt(buf, idx, fmt, fsize, attrib) \
  r_sdp_media_buf_rtpmap_for_fmt (&(buf)->media[idx], fmt, fsize, attrib)
#define r_sdp_buf_media_rtpmap_for_fmt_idx(buf, idx, fmtidx, attrib) \
  r_sdp_media_buf_rtpmap_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib)
#define r_sdp_buf_media_rtcpfb_for_fmt(buf, idx, fmt, fsize, attrib, start) \
  r_sdp_media_buf_rtcpfb_for_fmt (&(buf)->media[idx], fmt, fsize, attrib, start)
#define r_sdp_buf_media_rtcpfb_for_fmt_idx(buf, idx, fmtidx, attrib, start) \
  r_sdp_media_buf_rtcpfb_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib, start)
#define r_sdp_buf_media_fmtp_for_fmt(buf, idx, fmt, fsize, attrib) \
  r_sdp_media_buf_fmtp_for_fmt (&(buf)->media[idx], fmt, fsize, attrib)
#define r_sdp_buf_media_fmtp_for_fmt_idx(buf, idx, fmtidx, attrib) \
  r_sdp_media_buf_fmtp_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib)

R_API RSdpResult r_sdp_buf_find_grouping (const RSdpBuf * sdp, RStrChunk * group,
    const rchar * semantics, rssize ssize, const rchar * mid, rssize midsize);

R_END_DECLS

#endif /* __R_NET_PROTO_SDP_H__ */


