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
#include <rlib/rref.h>
#include <rlib/rstr.h>
#include <rlib/ruri.h>

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
#define r_sdp_originator_buf_session_version(orig)  r_str_chunk_dup (&(orig)->sess_version)
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

typedef struct {
  RStrChunk start;
  RStrChunk stop;
  rsize rcount;
  RStrChunk * repeat;
} RSdpTimingBuf;
#define r_sdp_timing_buf_start(time)                r_str_chunk_dup (&(time)->start)
#define r_sdp_timing_buf_stop(time)                 r_str_chunk_dup (&(time)->stop)
#define r_sdp_timing_buf_repeat_count(time)         (time)->rcount
#define r_sdp_timing_buf_repeat(time, idx)          r_str_chunk_dup (&(time)->repeat[idx])

R_API RSdpResult r_sdp_attrib_check (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize);
R_API rchar * r_sdp_attrib (const RStrKV * attrib, rsize acount, rsize start,
    const rchar * field, rssize fsize);

typedef struct {
  RStrChunk type;
  ruint port;
  ruint portcount;
  RStrChunk proto;
  rsize fmtcount;
  RStrChunk * fmt;
  RStrChunk info;
  rsize ccount;
  RSdpConnectionBuf * connection;
  rsize bcount;
  RStrKV * bandwidth;
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
#define r_sdp_media_buf_conn_nettype(media)         r_sdp_connection_buf_nettype (&(media)->connection)
#define r_sdp_media_buf_conn_addrtype(media)        r_sdp_connection_buf_addrtype (&(media)->connection)
#define r_sdp_media_buf_conn_addr(media)            r_sdp_connection_buf_addr (&(media)->connection)
#define r_sdp_media_buf_conn_ttl(media)             r_sdp_connection_buf_ttl (&(media)->connection)
#define r_sdp_media_buf_conn_addrcount(media)       r_sdp_connection_buf_addrcount (&(media)->connection)
#define r_sdp_media_buf_bandwidth_count(media)      (media)->bcount
#define r_sdp_media_buf_bandwidth_type(media)       r_str_kv_dup_key (&(media)->bandwidth[idx])
#define r_sdp_media_buf_bandwidth_kbps(media)       r_str_to_uint ((media)->bandwidth[idx].val.str, NULL, 10, NULL)
/* FIXME: bw based CT, AS, TIAS */
#define r_sdp_media_buf_key_method(media)           r_str_kv_dup_key (&(media)->key)
#define r_sdp_media_buf_key_data(media)             r_str_kv_dup_value (&(media)->key)
#define r_sdp_media_buf_attrib_count(media)         (media)->acount
#define r_sdp_media_buf_has_attrib(media, f, fsize) r_sdp_attrib_check ((media)->attrib, (media)->acount, f, fsize)
#define r_sdp_media_buf_attrib(media, s, f, fsize)  r_sdp_attrib ((media)->attrib, (media)->acount, s, f, fsize)
R_API RSdpResult r_sdp_media_buf_fmt_specific_attrib (const RSdpMediaBuf * media,
    const rchar * fmt, rssize fmtsize, const rchar * field, rssize fsize,
    RStrChunk * attrib);
R_API RSdpResult r_sdp_media_buf_fmtidx_specific_attrib (const RSdpMediaBuf * media,
    rsize fmtidx, const rchar * field, rssize fsize, RStrChunk * attrib);
#define r_sdp_media_buf_rtpmap_for_fmt(media, fmt, fmtsize, attrib)           \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("rtpmap"), attrib)
#define r_sdp_media_buf_rtpmap_for_fmt_idx(media, fmtidx, attrib)             \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("rtpmap"), attrib)
#define r_sdp_media_buf_rtcpfb_for_fmt(media, fmt, fmtsize, attrib)           \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("rtcp-fb"), attrib)
#define r_sdp_media_buf_rtcpfb_for_fmt_idx(media, fmtidx, attrib)             \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("rtcp-fb"), attrib)
#define r_sdp_media_buf_fmtp_for_fmt(media, fmt, fmtsize, attrib)             \
  r_sdp_media_buf_fmt_specific_attrib (media, fmt, fmtsize,                   \
      R_STR_WITH_SIZE_ARGS ("fmtp"), attrib)
#define r_sdp_media_buf_fmtp_for_fmt_idx(media, fmtidx, attrib)               \
  r_sdp_media_buf_fmtidx_specific_attrib (media, fmtidx,                      \
      R_STR_WITH_SIZE_ARGS ("fmtp"), attrib)

typedef struct {
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
  RSdpConnectionBuf connection;
  rsize bcount;
  RStrKV * bandwidth;
  rsize tcount;
  RSdpTimingBuf * timing;
  rsize zcount;
  RStrKV * zone;
  RStrKV key;
  rsize acount;
  RStrKV * attrib;

  rsize mcount;
  RSdpMediaBuf * media;
} RSdpBuf;

R_API RSdpResult r_sdp_buffer_map (RSdpBuf * sdp, RBuffer * buf);
R_API RSdpResult r_sdp_buffer_unmap (RSdpBuf * sdp, RBuffer * buf);

#define r_sdp_buf_version(buf)                      r_str_chunk_dup (&(buf)->ver)
#define r_sdp_buf_session_name(buf)                 r_str_chunk_dup (&(buf)->session_name)
#define r_sdp_buf_session_info(buf)                 r_str_chunk_dup (&(buf)->session_info)
#define r_sdp_buf_uri_str(buf)                      r_str_chunk_dup (&(buf)->uri)
#define r_sdp_buf_uri(buf)                          r_uri_new_escaped ((buf)->uri.str, (buf)->uri.size)

#define r_sdp_buf_orig_username(buf)                r_sdp_originator_buf_username (&(buf)->orig)
#define r_sdp_buf_orig_session_id(buf)              r_sdp_originator_buf_session_id (&(buf)->orig)
#define r_sdp_buf_orig_session_version(buf)         r_sdp_originator_buf_session_version (&(buf)->orig)
#define r_sdp_buf_orig_nettype(buf)                 r_sdp_originator_buf_nettype (&(buf)->orig)
#define r_sdp_buf_orig_addrtype(buf)                r_sdp_originator_buf_addrtype (&(buf)->orig)
#define r_sdp_buf_orig_addr(buf)                    r_sdp_originator_buf_addr (&(buf)->orig)

#define r_sdp_buf_email_count(buf)                  (buf)->ecount
#define r_sdp_buf_phone_count(buf)                  (buf)->pcount
#define r_sdp_buf_bandwidth_count(buf)              (buf)->bcount
#define r_sdp_buf_timing_count(buf)                 (buf)->tcount
#define r_sdp_buf_time_zone_count(buf)              (buf)->zcount
#define r_sdp_buf_attrib_count(buf)                 (buf)->acount
#define r_sdp_buf_media_count(buf)                  (buf)->mcount

#define r_sdp_buf_email(buf, idx)                   r_str_chunk_dup (&(buf)->email[idx])
#define r_sdp_buf_phone(buf, idx)                   r_str_chunk_dup (&(buf)->phone[idx])

#define r_sdp_buf_conn_nettype(buf)                 r_sdp_connection_buf_nettype (&(buf)->connection)
#define r_sdp_buf_conn_addrtype(buf)                r_sdp_connection_buf_addrtype (&(buf)->connection)
#define r_sdp_buf_conn_addr(buf)                    r_sdp_connection_buf_addr (&(buf)->connection)
#define r_sdp_buf_conn_ttl(buf)                     r_sdp_connection_buf_ttl (&(buf)->connection)
#define r_sdp_buf_conn_addrcount(buf)               r_sdp_connection_buf_addrcount (&(buf)->connection)

#define r_sdp_buf_bandwidth_type(buf, idx)          r_str_kv_dup_key (&(buf)->bandwidth[idx])
#define r_sdp_buf_bandwidth_kbps(buf, idx)          r_str_to_uint ((buf)->bandwidth[idx].val.str, NULL, 10, NULL)
/* FIXME: bw based CT, AS, TIAS */

#define r_sdp_buf_timing_start(buf, idx)            r_sdp_timing_buf_start (&(buf)->timing[idx])
#define r_sdp_buf_timing_stop(buf, idx)             r_sdp_timing_buf_stop (&(buf)->timing[idx])
#define r_sdp_buf_timing_repeat_count(buf, idx)     r_sdp_timing_buf_repeat_count (&(buf)->timing[idx])
#define r_sdp_buf_timing_repeat(buf, idx, ridx)     r_sdp_timing_buf_repeat (&(buf)->timing[idx], ridx)

#define r_sdp_buf_zone_time_str(buf, idx)           r_str_kv_dup_key (&(buf)->zone[idx])
#define r_sdp_buf_zone_time_uint(buf, idx)          r_str_to_uint ((buf)->zone[idx].key.str, NULL, 10, NULL)
#define r_sdp_buf_zone_offset_str(buf, idx)         r_str_kv_dup_value (&(buf)->zone[idx])
#define r_sdp_buf_zone_offset_uint(buf, idx)        r_str_to_uint ((buf)->zone[idx].val.str, NULL, 10, NULL)

#define r_sdp_buf_key_method(buf)                   r_str_kv_dup_key (&(buf)->key)
#define r_sdp_buf_key_data(buf)                     r_str_kv_dup_value (&(buf)->key)

#define r_sdp_buf_has_attrib(buf, f, fsize)         r_sdp_attrib_check ((buf)->attrib, (buf)->acount, f, fsize)
#define r_sdp_buf_attrib(buf, s, f, fsize)          r_sdp_attrib ((buf)->attrib, (buf)->acount, s, f, fsize)

/* media lines */
#define r_sdp_buf_media_type(buf, idx)              r_sdp_media_buf_type (&(buf)->media[idx])
#define r_sdp_buf_media_port(buf, idx)              r_sdp_media_buf_port (&(buf)->media[idx])
#define r_sdp_buf_media_portcount(buf, idx)         r_sdp_media_buf_portcount (&(buf)->media[idx])
#define r_sdp_buf_media_proto(buf, idx)             r_sdp_media_buf_proto (&(buf)->media[idx])
#define r_sdp_buf_media_fmt_count(buf, idx)         r_sdp_media_buf_fmt_count (&(buf)->media[idx])
#define r_sdp_buf_media_fmt(buf, idx, fidx)         r_sdp_media_buf_fmt (&(buf)->media[idx], fidx)
#define r_sdp_buf_media_fmt_uint(buf, idx, fidx)    r_sdp_media_buf_fmt_uint (&(buf)->media[idx], fidx)
#define r_sdp_buf_media_info(buf, idx)              r_sdp_media_buf_info (&(buf)->media[idx])
#define r_sdp_buf_media_conn_count(buf, idx)        r_sdp_media_buf_conn_count (&(buf)->media[idx])
#define r_sdp_buf_media_conn_nettype(buf, idx)      r_sdp_media_buf_conn_nettype (&(buf)->media[idx])
#define r_sdp_buf_media_conn_addrtype(buf, idx)     r_sdp_media_buf_conn_addrtype (&(buf)->media[idx])
#define r_sdp_buf_media_conn_addr(buf, idx)         r_sdp_media_buf_conn_addr (&(buf)->media[idx])
#define r_sdp_buf_media_conn_ttl(buf, idx)          r_sdp_media_buf_conn_ttl (&(buf)->media[idx])
#define r_sdp_buf_media_conn_addrcount(buf, idx)    r_sdp_media_buf_conn_addrcount (&(buf)->media[idx])
#define r_sdp_buf_media_bandwidth_count(buf, idx)   r_sdp_media_buf_bandwidth_count (&(buf)->media[idx])
#define r_sdp_buf_media_bandwidth_type(buf, idx)    r_sdp_media_buf_bandwidth_type (&(buf)->media[idx])
#define r_sdp_buf_media_bandwidth_kbps(buf, idx)    r_sdp_media_buf_bandwidth_kbps (&(buf)->media[idx])
/* FIXME: bw based CT, AS, TIAS */
#define r_sdp_buf_media_key_method(buf, idx)        r_sdp_media_buf_key_method (&(buf)->media[idx])
#define r_sdp_buf_media_key_data(buf, idx)          r_sdp_media_buf_key_data (&(buf)->media[idx])
#define r_sdp_buf_media_attrib_count(buf, idx)      r_sdp_media_buf_attrib_count (&(buf)->media[idx])
#define r_sdp_buf_media_has_attrib(buf, idx, f, fsize)  r_sdp_media_buf_has_attrib (&(buf)->media[idx], f, fsize)
#define r_sdp_buf_media_attrib(buf, idx, s, f, fsize)   r_sdp_media_buf_attrib (&(buf)->media[idx], s, f, fsize)
#define r_sdp_buf_media_rtpmap_for_fmt(buf, idx, fmt, fsize, attrib) \
  r_sdp_media_buf_rtpmap_for_fmt (&(buf)->media[idx], fmt, fsize, attrib)
#define r_sdp_buf_media_rtpmap_for_fmt_idx(buf, idx, fmtidx, attrib) \
  r_sdp_media_buf_rtpmap_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib)
#define r_sdp_buf_media_rtcpfb_for_fmt(buf, idx, fmt, fsize, attrib) \
  r_sdp_media_buf_rtcpfb_for_fmt (&(buf)->media[idx], fmt, fsize, attrib)
#define r_sdp_buf_media_rtcpfb_for_fmt_idx(buf, idx, fmtidx, attrib) \
  r_sdp_media_buf_rtcpfb_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib)
#define r_sdp_buf_media_fmtp_for_fmt(buf, idx, fmt, fsize, attrib) \
  r_sdp_media_buf_fmtp_for_fmt (&(buf)->media[idx], fmt, fsize, attrib)
#define r_sdp_buf_media_fmtp_for_fmt_idx(buf, idx, fmtidx, attrib) \
  r_sdp_media_buf_fmtp_for_fmt_idx (&(buf)->media[idx], fmtidx, attrib)

R_END_DECLS

#endif /* __R_NET_PROTO_SDP_H__ */


