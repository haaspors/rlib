/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

/**
 * @file rlib/net/proto/rrtp.h
 * @brief RTP / RTCP (RFC 3550) packet validation, header access and parsing.
 */

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>

/**
 * @defgroup r_rtp RTP
 * @ingroup r_net
 *
 * @brief Read and write RTP packets (RFC 3550) over an @ref RBuffer.
 *
 * An @ref RRTPBuffer maps an @ref RBuffer into its header, optional
 * extension and payload regions with @ref r_rtp_buffer_map; the
 * @c r_rtp_buffer_get_* / @c r_rtp_buffer_set_* accessors then read and
 * write header fields in place. New packets are allocated with the
 * @c r_buffer_new_rtp_buffer_* constructors.
 *
 * @{
 */

R_BEGIN_DECLS

#define R_RTP_VERSION                 0x02    /**< @brief RTP protocol version (RFC 3550). */
#define R_RTP_HDR_SIZE                12      /**< @brief Size of the fixed RTP header in bytes. */
#define R_RTP_SEQ_MEDIAN              0x8000  /**< @brief Sequence-number midpoint, used for wrap detection. */

#define R_RTP_PT_FMT                  RUINT8_FMT              /**< @brief printf format for an RTP payload type. */
#define R_RTP_SSRC_FMT                ".8"RINT32_MODIFIER"x"  /**< @brief printf format for an SSRC (8 hex digits). */
#define R_RTP_SEQ_FMT                 ".4"RINT16_MODIFIER"x"  /**< @brief printf format for a sequence number (4 hex digits). */
#define R_RTP_SEQIDX_FMT              ".12"RINT64_MODIFIER"x" /**< @brief printf format for an extended sequence index (12 hex digits). */


/** @brief @c TRUE if @p buf (@p size bytes) looks like a valid RTP header. */
R_API rboolean r_rtp_is_valid_hdr (rconstpointer buf, rsize size);
/** @brief @c TRUE if @p buf (@p size bytes) looks like a valid RTCP header. */
R_API rboolean r_rtcp_is_valid_hdr (rconstpointer buf, rsize size);


/******************************************************************************/
/* RTP                                                                        */
/******************************************************************************/
/* http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-1 */
/** @brief RTP payload type (IANA-registered static values; @c 96..127 are dynamic). */
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

/** @brief @c TRUE if payload type @p pt is in the dynamic range (@c 96..127). */
#define R_RTP_PT_IS_DYNAMIC(pt)  ((pt) >= R_RTP_PT_DYNAMIC_FIRST && (pt) <= R_RTP_PT_DYNAMIC_LAST)

/** @brief An RTP packet mapped from an @ref RBuffer into its sub-regions. */
typedef struct {
  RBuffer * buffer;   /**< @brief The mapped backing buffer. */

  RMemMapInfo hdr;    /**< @brief Mapping of the fixed header (and CSRC list). */
  RMemMapInfo ext;    /**< @brief Mapping of the header extension, if present. */
  RMemMapInfo pay;    /**< @brief Mapping of the payload. */
} RRTPBuffer;
/** @brief Static initialiser for an empty @ref RRTPBuffer. */
#define R_RTP_BUFFER_INIT   { NULL, R_MEM_MAP_INFO_INIT, R_MEM_MAP_INFO_INIT, R_MEM_MAP_INFO_INIT }

/** @brief Flags controlling how an @ref RRTPBuffer is mapped. */
typedef enum {
  R_RTP_BUFFER_MAP_FLAG_SKIP_PADDING  = (R_MEM_MAP_FLAG_LAST << 0), /**< Exclude trailing padding from the payload mapping. */
  R_RTP_BUFFER_MAP_FLAG_LAST          = (R_MEM_MAP_FLAG_LAST << 8)  /**< First flag bit free for derived use. */
} RRTPBufferMapFlags;


/** @brief Allocate a new RTP buffer wrapping @p payload, with @p pad bytes padding and @p cc CSRC entries. */
R_API RBuffer * r_buffer_new_rtp_buffer (RBuffer * payload, ruint8 pad, ruint8 cc);
/** @brief Allocate a new RTP buffer taking ownership of @p payload (@p size bytes), with @p pad padding and @p cc CSRC entries. */
R_API RBuffer * r_buffer_new_rtp_buffer_take (rpointer payload, rsize size, ruint8 pad, ruint8 cc);
/** @brief Allocate a new RTP buffer with a @p payload-byte payload, @p pad padding and @p cc CSRC entries. */
R_API RBuffer * r_buffer_new_rtp_buffer_alloc (rsize payload, ruint8 pad, ruint8 cc);

/** @brief Map @p buf into @p rtp for header/payload access. */
R_API rboolean r_rtp_buffer_map (RRTPBuffer * rtp, RBuffer * buf, RMemMapFlags flags);
/** @brief Unmap @p buf, releasing the regions mapped into @p rtp. */
R_API rboolean r_rtp_buffer_unmap (RRTPBuffer * rtp, RBuffer * buf);

/* READ / getters */
/** @brief @c TRUE if the padding bit is set. */
R_API rboolean r_rtp_buffer_has_padding (const RRTPBuffer * rtp);
/** @brief @c TRUE if the extension bit is set. */
R_API rboolean r_rtp_buffer_has_extension (const RRTPBuffer * rtp);
/** @brief @c TRUE if the marker bit is set. */
R_API rboolean r_rtp_buffer_has_marker (const RRTPBuffer * rtp);
/** @brief Return the synchronisation source (SSRC) identifier. */
R_API ruint32 r_rtp_buffer_get_ssrc (const RRTPBuffer * rtp);
/** @brief Return the payload type. */
R_API RRTPPayloadType r_rtp_buffer_get_pt (const RRTPBuffer * rtp);
/** @brief Return the sequence number. */
R_API ruint16 r_rtp_buffer_get_seq (const RRTPBuffer * rtp);
/** @brief Return the RTP timestamp. */
R_API ruint32 r_rtp_buffer_get_timestamp (const RRTPBuffer * rtp);
/** @brief Return the number of CSRC entries. */
R_API ruint8 r_rtp_buffer_get_csrc_count (const RRTPBuffer * rtp);
/** @brief Return the @p n-th contributing source (CSRC) identifier. */
R_API ruint32 r_rtp_buffer_get_csrc (const RRTPBuffer * rtp, ruint8 n);

/* WRITE / setters */
/** @brief Set the marker bit. */
R_API void r_rtp_buffer_set_marker (RRTPBuffer * rtp, rboolean marker);
/** @brief Set the synchronisation source (SSRC) identifier. */
R_API void r_rtp_buffer_set_ssrc (RRTPBuffer * rtp, ruint32 ssrc);
/** @brief Set the payload type. */
R_API void r_rtp_buffer_set_pt (RRTPBuffer * rtp, RRTPPayloadType pt);
/** @brief Set the sequence number. */
R_API void r_rtp_buffer_set_seq (RRTPBuffer * rtp, ruint16 seq);
/** @brief Set the RTP timestamp. */
R_API void r_rtp_buffer_set_timestamp (RRTPBuffer * rtp, ruint32 ts);
/** @brief Set the @p n-th contributing source (CSRC) identifier. */
R_API rboolean r_rtp_buffer_set_csrc (RRTPBuffer * rtp, ruint8 n, ruint32 csrc);
/* TODO: padding */
/* TODO: extension */


/** @brief Extend a 16-bit sequence number @p seq to a 48-bit index, given the current index @p curidx. */
R_API ruint64 r_rtp_estimate_seq_idx (ruint16 seq, ruint64 curidx);
/** @brief Extend @p rtp's sequence number to a 48-bit index, given the current index @p curidx. */
R_API ruint64 r_rtp_buffer_estimate_seq_idx (RRTPBuffer * rtp, ruint64 curidx);

/** @} */


/******************************************************************************/
/* RTCP                                                                       */
/******************************************************************************/
/**
 * @defgroup r_rtcp RTCP / SDES
 * @ingroup r_net
 *
 * @brief Parse RTCP compound packets (RFC 3550) over an @ref RBuffer.
 *
 * An @ref RRTCPBuffer maps an @ref RBuffer with @ref r_rtcp_buffer_map and
 * iterates its packets via @ref r_rtcp_buffer_get_next_packet. Per
 * packet type, accessors decode Sender/Receiver Reports, Source
 * Description (SDES) chunks and items, BYE and APP packets.
 *
 * @{
 */
/* http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-4 */
/** @brief RTCP packet type (IANA-registered values). */
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

/** @brief RTCP SDES item type (RFC 3550). */
typedef enum {
  R_RTCP_SDES_ZERO     = 0x00,
  R_RTCP_SDES_CNAME    = 0x01,
  R_RTCP_SDES_NAME     = 0x02,
  R_RTCP_SDES_EMAIL    = 0x03,
  R_RTCP_SDES_PHONE    = 0x04,
  R_RTCP_SDES_LOC      = 0x05,
  R_RTCP_SDES_TOOL     = 0x06,
  R_RTCP_SDES_NOTE     = 0x07,
  R_RTCP_SDES_PRIV     = 0x08,
  R_RTCP_SDES_MAX      = 0x09,
  R_RTCP_SDES_UNKNOWN  = 0xff
} RRTCPSDESType;

/** @brief Result of parsing an RTCP packet or field. */
typedef enum {
  R_RTCP_PARSE_ZERO = -1,         /**< Sentinel / uninitialised. */
  R_RTCP_PARSE_OK   =  0,         /**< Parsed successfully. */
  R_RTCP_PARSE_INVAL,             /**< Invalid argument or malformed data. */
  R_RTCP_PARSE_WRONG_PT,          /**< Packet is not of the expected type. */
  R_RTCP_PARSE_OVERFLOW,          /**< Field extends past the packet. */
  R_RTCP_PARSE_UNEXPECTED,        /**< Unexpected structure encountered. */
  R_RTCP_PARSE_BUF_TOO_SMALL,     /**< Caller buffer too small for the result. */
} RRTCPParseResult;


/** @brief An RTCP compound packet mapped from an @ref RBuffer. */
typedef struct {
  RBuffer * buffer;   /**< @brief The mapped backing buffer. */
  RMemMapInfo info;   /**< @brief Mapping covering the compound packet. */
} RRTCPBuffer;
/** @brief Static initialiser for an empty @ref RRTCPBuffer. */
#define R_RTCP_BUFFER_INIT   { NULL, R_MEM_MAP_INFO_INIT }

/** @brief Opaque cursor over a single packet within an @ref RRTCPBuffer. */
typedef struct RRTCPPacket RRTCPPacket;
/** @brief Opaque cursor over a single SDES chunk within an SDES packet. */
typedef struct RRTCPSDESChunk RRTCPSDESChunk;

/** @brief Decoded Sender Report (SR) sender info block. */
typedef struct {
  ruint32 ssrc;       /**< @brief Sender's synchronisation source identifier. */
  ruint32 rtptime;    /**< @brief RTP timestamp corresponding to @c ntptime. */
  ruint64 ntptime;    /**< @brief NTP wall-clock timestamp. */
  ruint32 packets;    /**< @brief Sender's cumulative packet count. */
  ruint32 bytes;      /**< @brief Sender's cumulative octet count. */
} RRTCPSenderInfo;

/** @brief Decoded reception report block (from an SR or RR). */
typedef struct {
  ruint32 ssrc;           /**< @brief Source this block reports on. */
  ruint8 fractionlost;    /**< @brief Fraction of packets lost since the last report. */
  rint32 packetslost;     /**< @brief Cumulative number of packets lost. */
  ruint32 exthighestseq;  /**< @brief Extended highest sequence number received. */
  ruint32 jitter;         /**< @brief Interarrival jitter estimate. */
  ruint32 lsr;            /**< @brief Last SR timestamp (middle 32 bits of NTP). */
  ruint32 dlsr;           /**< @brief Delay since the last SR. */
} RRTCPReportBlock;

/** @brief A single decoded SDES item, pointing into the packet buffer. */
typedef struct {
  RRTCPSDESType type;     /**< @brief Item type (@ref RRTCPSDESType). */
  ruint8 len;             /**< @brief Length of @c data in bytes. */
  ruint8 * data;          /**< @brief Pointer to the item value. */
} RRTCPSDESItem;
/** @brief Static initialiser for an empty @ref RRTCPSDESItem. */
#define R_RTCP_SDES_ITEM_INIT     { R_RTCP_SDES_UNKNOWN, 0, NULL }

/* TODO: Add construction/writing of RTCP buffers and packets */

/** @brief Map @p buf into @p rtcp for packet iteration. */
R_API rboolean r_rtcp_buffer_map (RRTCPBuffer * rtcp, RBuffer * buf, RMemMapFlags flags);
/** @brief Unmap @p buf, releasing the region mapped into @p rtcp. */
R_API rboolean r_rtcp_buffer_unmap (RRTCPBuffer * rtcp, RBuffer * buf);

/** @brief Number of packets in the RTCP compound buffer @p rtcp. */
R_API ruint r_rtcp_buffer_get_packet_count (const RRTCPBuffer * rtcp);
/** @brief Return the first packet in @p rtcp (or @c NULL if empty). */
#define r_rtcp_buffer_get_first_packet(rtcp) r_rtcp_buffer_get_next_packet (rtcp, NULL)
/** @brief Return the packet after @p packet (pass @c NULL for the first). */
R_API RRTCPPacket * r_rtcp_buffer_get_next_packet (RRTCPBuffer * rtcp, const RRTCPPacket * packet);

/* Packet header */
/** @brief @c TRUE if @p packet has the padding bit set. */
R_API rboolean r_rtcp_packet_has_padding (const RRTCPPacket * packet);
/** @brief Return the type-specific count/subtype field of @p packet. */
R_API ruint8 r_rtcp_packet_get_count (const RRTCPPacket * packet);
/** @brief Return the RTCP packet type of @p packet. */
R_API RRTCPPacketType r_rtcp_packet_get_type (const RRTCPPacket * packet);
/** @brief Return the length of @p packet in bytes. */
R_API ruint r_rtcp_packet_get_length (const RRTCPPacket * packet);
/** @brief Return the SSRC of @p packet. */
R_API ruint32 r_rtcp_packet_get_ssrc (const RRTCPPacket * packet);

/* Sender Report (SR) */
/** @brief Decode the sender info of an SR @p packet into @p srinfo. */
R_API rboolean r_rtcp_packet_sr_get_sender_info (const RRTCPPacket * packet,
    RRTCPSenderInfo * srinfo);
/** @brief Number of report blocks in an SR packet. */
#define r_rtcp_packet_sr_get_rb_count       r_rtcp_packet_get_count
/** @brief Decode report block @p idx of an SR @p packet into @p rb. */
R_API rboolean r_rtcp_packet_sr_get_report_block (const RRTCPPacket * packet,
    ruint8 idx, RRTCPReportBlock * rb);

/* Receiver Report (RR) */
/** @brief Return the reporter SSRC of an RR @p packet. */
R_API ruint32 r_rtcp_packet_rr_get_ssrc (const RRTCPPacket * packet);
/** @brief Number of report blocks in an RR packet. */
#define r_rtcp_packet_rr_get_rb_count       r_rtcp_packet_get_count
/** @brief Decode a report block of an RR packet. */
#define r_rtcp_packet_rr_get_report_block   r_rtcp_packet_sr_get_report_block

/* Source Description (SDES) */
/** @brief Number of chunks in an SDES packet. */
#define r_rtcp_packet_sdes_get_chunk_count  r_rtcp_packet_get_count
/** @brief Return the first SDES chunk of @p packet (or @c NULL if none). */
#define r_rtcp_packet_sdes_get_first_chunk(packet) r_rtcp_packet_sdes_get_next_chunk (packet, NULL)
/** @brief Return the chunk after @p chunk (pass @c NULL for the first). */
R_API RRTCPSDESChunk * r_rtcp_packet_sdes_get_next_chunk (RRTCPPacket * packet,
    RRTCPSDESChunk * chunk);
/** @brief Return the SSRC/CSRC of an SDES @p chunk. */
R_API ruint32 r_rtcp_packet_sdes_chunk_get_ssrc (const RRTCPPacket * packet,
    const RRTCPSDESChunk * chunk);
/** @brief Decode the next SDES item of @p chunk into @p item. */
R_API RRTCPParseResult r_rtcp_packet_sdes_chunk_get_next_item (const RRTCPPacket * packet,
    RRTCPSDESChunk * chunk, RRTCPSDESItem * item);

/* BYE */
/** @brief Number of SSRCs listed in a BYE packet. */
#define r_rtcp_packet_bye_get_ssrc_count  r_rtcp_packet_get_count
/** @brief Return SSRC @p idx of a BYE @p packet. */
R_API ruint32 r_rtcp_packet_bye_get_ssrc (const RRTCPPacket * packet, ruint8 idx);
/**
 * @brief Copy the optional reason-for-leaving string from a BYE @p packet.
 * @param packet The BYE packet.
 * @param reason Caller buffer receiving the reason string.
 * @param len Capacity of @p reason in bytes.
 * @param out Receives the number of bytes written.
 * @return Parse result.
 */
R_API RRTCPParseResult r_rtcp_packet_bye_get_reason (const RRTCPPacket * packet,
    rchar * reason, rsize len, ruint8 * out);

/* APP */
/** @brief Return the application-defined subtype of an APP packet. */
#define r_rtcp_packet_app_get_subtype     r_rtcp_packet_get_count
/** @brief Return the SSRC/CSRC of an APP @p packet. */
R_API ruint32 r_rtcp_packet_app_get_ssrc (const RRTCPPacket * packet);
/** @brief Return the 4-octet name of an APP @p packet. */
R_API const rchar * r_rtcp_packet_app_get_name (const RRTCPPacket * packet);
/** @brief Return the application-defined data of an APP @p packet; @p size receives its length. */
R_API const ruint8 * r_rtcp_packet_app_get_data (const RRTCPPacket * packet, ruint16 * size);

/* TODO: Feedback */

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_RTP_H__ */


