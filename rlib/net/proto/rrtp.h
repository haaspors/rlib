/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_NET_PROTO_RTP_H__
#define __R_NET_PROTO_RTP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

#define R_RTP_VERSION                 0x02
#define R_RTP_HDR_SIZE                12

/* http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-1 */
typedef enum {
  R_RTP_PT_PCMU             =   0, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_GSM              =   3, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_G723             =   4, /*  8000 (mono)    [Vineet_Kumar][RFC3551] */
  R_RTP_PT_DVI4_8000        =   5, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_DVI4_16000       =   6, /* 16000 (mono)    [RFC3551] */
  R_RTP_PT_LPC              =   7, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_PCMA             =   8, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_G722             =   9, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_L16_STERO        =  10, /* 44100 (stereo)  [RFC3551] */
  R_RTP_PT_L16_MONO         =  11, /* 44100 (mono)    [RFC3551] */
  R_RTP_PT_QCELP            =  12, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_CN               =  13, /*  8000 (mono)    [RFC3389] */
  R_RTP_PT_MPA              =  14, /* 90000           [RFC3551][RFC2250] */
  R_RTP_PT_G728             =  15, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_DVI4_11025       =  16, /* 11025 (mono)    [Joseph_Di_Pol] */
  R_RTP_PT_DVI4_22050       =  17, /* 22050 (mono)    [Joseph_Di_Pol] */
  R_RTP_PT_G729             =  18, /*  8000 (mono)    [RFC3551] */
  R_RTP_PT_CelB             =  25, /* 90000           [RFC2029] */
  R_RTP_PT_JPEG             =  26, /* 90000           [RFC2435] */
  R_RTP_PT_nv               =  28, /* 90000           [RFC3551] */
  R_RTP_PT_H261             =  31, /* 90000           [RFC4587] */
  R_RTP_PT_MPV              =  32, /* 90000           [RFC2250] */
  R_RTP_PT_MP2T             =  33, /* 90000           [RFC2250] */
  R_RTP_PT_H263             =  34, /* 90000           [Chunrong_Zhu] */
  /* 72-76 Reserved for RTCP conflict avoidance       [RFC3551] */
  R_RTP_PT_DYNAMIC_FIRST    =  96, /*                 [RFC3551] */
  R_RTP_PT_DYNAMIC_LAST     = 127, /*                 [RFC3551] */
} RRTPPayloadType;

#define R_RTP_PT_IS_DYNAMIC(pt)  ((pt) >= R_RTP_PT_DYNAMIC_FIRST && (pt) <= R_RTP_PT_DYNAMIC_LAST)

/* http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-4 */
typedef enum {
  /* Reserved 192 (Historic-FIR)  [RFC2032] */
  /* Reserved 193 (Historic-NACK) [RFC2032] */
  R_RTCP_PT_SMPTETC         = 194, /* SMPTE time-code mapping       [RFC5484] */
  R_RTCP_PT_IJ              = 195, /* Extended inter-arrival jitter report [RFC5450] */
  R_RTCP_PT_SR              = 200, /* sender report                 [RFC3550] */
  R_RTCP_PT_RR              = 201, /* receiver report               [RFC3550] */
  R_RTCP_PT_SDES            = 202, /* source description            [RFC3550] */
  R_RTCP_PT_BYE             = 203, /* goodbye                       [RFC3550] */
  R_RTCP_PT_APP             = 204, /* application-defined           [RFC3550] */
  R_RTCP_PT_RTPFB           = 205, /* Generic RTP Feedback          [RFC4585] */
  R_RTCP_PT_PSFB            = 206, /* payload-specific              [RFC4585] */
  R_RTCP_PT_XR              = 207, /* extended report               [RFC3611] */
  R_RTCP_PT_AVB             = 208, /* AVB RTCP packet ["Standard for Layer 3 Transport Protocol for Time Sensitive Applications in Local Area Networks." Work in progress.] */
  R_RTCP_PT_RSI             = 209, /* Receiver Summary Information  [RFC5760] */
  R_RTCP_PT_TOKEN           = 210, /* Port Mapping                  [RFC6284] */
  R_RTCP_PT_IDMS            = 211, /* DMS Settings                  [RFC7272] */
  R_RTCP_PT_RGRS            = 212, /* eporting Group Reporting Sources [RFC-ietf-avtcore-rtp-multi-stream-optimisation-12] */
  R_RTCP_PT_SNM             = 213, /* Splicing Notification Message [RFC-ietf-ietf-avtext-splicing-notification-09] */
} RRTCPPacketType;

R_API rboolean r_rtp_is_valid_hdr (rconstpointer buf, rsize size);
R_API rboolean r_rtcp_is_valid_hdr (rconstpointer buf, rsize size);

typedef struct {
  RBuffer * buffer;

  RMemMapInfo hdr;
  RMemMapInfo ext;
  RMemMapInfo pay;
} RRTPBuffer;
#define R_RTP_BUFFER_INIT   { NULL, R_MEM_MAP_INFO_INIT, R_MEM_MAP_INFO_INIT, R_MEM_MAP_INFO_INIT }

typedef enum {
  R_RTP_BUFFER_MAP_FLAG_SKIP_PADDING  = (R_MEM_MAP_FLAG_LAST << 0),
  R_RTP_BUFFER_MAP_FLAG_LAST          = (R_MEM_MAP_FLAG_LAST << 8)
} RRTPBufferMapFlags;

R_API RBuffer * r_buffer_new_rtp_buffer (RBuffer * payload, ruint8 pad, ruint8 cc);
R_API RBuffer * r_buffer_new_rtp_buffer_take (rpointer payload, rsize size, ruint8 pad, ruint8 cc);
R_API RBuffer * r_buffer_new_rtp_buffer_alloc (rsize payload, ruint8 pad, ruint8 cc);

R_API rboolean r_rtp_buffer_map (RRTPBuffer * rtp, RBuffer * buf, RMemMapFlags flags);
R_API rboolean r_rtp_buffer_unmap (RRTPBuffer * rtp, RBuffer * buf);

/* READ / getters */
R_API rboolean r_rtp_buffer_has_padding (const RRTPBuffer * rtp);
R_API rboolean r_rtp_buffer_has_extension (const RRTPBuffer * rtp);
R_API rboolean r_rtp_buffer_has_marker (const RRTPBuffer * rtp);
R_API ruint32 r_rtp_buffer_get_ssrc (const RRTPBuffer * rtp);
R_API RRTPPayloadType r_rtp_buffer_get_pt (const RRTPBuffer * rtp);
R_API ruint16 r_rtp_buffer_get_seq (const RRTPBuffer * rtp);
R_API ruint32 r_rtp_buffer_get_timestamp (const RRTPBuffer * rtp);
R_API ruint8 r_rtp_buffer_get_csrc_count (const RRTPBuffer * rtp);
R_API ruint32 r_rtp_buffer_get_csrc (const RRTPBuffer * rtp, ruint8 n);

/* WRITE / setters */
R_API void r_rtp_buffer_set_marker (RRTPBuffer * rtp, rboolean marker);
R_API void r_rtp_buffer_set_ssrc (RRTPBuffer * rtp, ruint32 ssrc);
R_API void r_rtp_buffer_set_pt (RRTPBuffer * rtp, RRTPPayloadType pt);
R_API void r_rtp_buffer_set_seq (RRTPBuffer * rtp, ruint16 seq);
R_API void r_rtp_buffer_set_timestamp (RRTPBuffer * rtp, ruint32 ts);
/* TODO: padding */
/* TODO: extension */
/* TODO: csrc */

R_END_DECLS

#endif /* __R_NET_PROTO_RTP_H__ */


