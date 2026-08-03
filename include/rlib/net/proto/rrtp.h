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
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/proto/rrtp.h
 * @brief RTP / RTCP (RFC 3550): packet validation, header access, parsing and
 * serialization.
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
  R_RTP_PT_L16_STEREO        =  10, /* 44100 (stereo)  [RFC3551] */
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
/**
 * @brief Allocate a new RTP buffer carrying a header extension.
 * @param payload  Payload buffer to wrap.
 * @param pad      Number of trailing padding octets (0 for none).
 * @param cc       Number of CSRC entries (0..15).
 * @param profile  The 16-bit profile-defined field of the extension.
 * @param extdata  Extension payload (@p extsize bytes), or @c NULL to zero-fill.
 * @param extsize  Extension payload size; must be a multiple of 4 (RFC 3550 5.3.1).
 * @return New buffer, or @c NULL on bad arguments / allocation failure.
 */
R_API RBuffer * r_buffer_new_rtp_buffer_ext (RBuffer * payload, ruint8 pad, ruint8 cc, ruint16 profile, rconstpointer extdata, rsize extsize);

/** @brief Map @p buf into @p rtp for header/payload access. */
R_API rboolean r_rtp_buffer_map (RRTPBuffer * rtp, RBuffer * buf, RMemMapFlags flags);
/** @brief Unmap @p buf, releasing the regions mapped into @p rtp. */
R_API rboolean r_rtp_buffer_unmap (RRTPBuffer * rtp, RBuffer * buf);

/* READ / getters */
/** @brief @c TRUE if the padding bit is set. */
R_API rboolean r_rtp_buffer_has_padding (const RRTPBuffer * rtp);
/**
 * @brief Number of trailing padding octets when the padding bit is set, else 0.
 *
 * The count is the packet's last octet (RFC 3550 §5.1, which counts itself),
 * taken verbatim; for malformed input it may exceed the payload, so treat it
 * as advisory (@ref r_rtp_buffer_map already clamps the payload mapping).
 */
R_API ruint8 r_rtp_buffer_get_padding (const RRTPBuffer * rtp);
/** @brief @c TRUE if the extension bit is set. */
R_API rboolean r_rtp_buffer_has_extension (const RRTPBuffer * rtp);
/**
 * @brief Read the header extension's profile field, data pointer and size.
 * @param rtp      The mapped RTP buffer.
 * @param profile  Out: the 16-bit profile-defined field. Pass @c NULL to skip.
 * @param data     Out: pointer to the extension data (past the 4-byte header).
 * @param size     Out: extension data size in bytes (a multiple of 4).
 * @return @c TRUE if an extension is present, else @c FALSE.
 */
R_API rboolean r_rtp_buffer_get_extension (const RRTPBuffer * rtp, ruint16 * profile, const ruint8 ** data, ruint16 * size);
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
 * @brief Parse and build RTCP compound packets (RFC 3550) over an @ref RBuffer.
 *
 * An @ref RRTCPBuffer maps an @ref RBuffer with @ref r_rtcp_buffer_map and
 * iterates its packets via @ref r_rtcp_buffer_get_next_packet. Per
 * packet type, accessors decode Sender/Receiver Reports, Source
 * Description (SDES) chunks and items, BYE and APP packets; the
 * @c r_rtcp_buffer_add_* helpers build the same packet types.
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
  R_RTCP_PT_RGRS            = 212, /* Reporting Group Reporting Sources [RFC-ietf-avtcore-rtp-multi-stream-optimisation-12] */
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

/** @brief RTCP Extended Report (XR) block type (RFC 3611). */
typedef enum {
  R_RTCP_XR_BT_LOSS_RLE   = 1,    /**< Loss RLE Report Block. */
  R_RTCP_XR_BT_DUP_RLE    = 2,    /**< Duplicate RLE Report Block. */
  R_RTCP_XR_BT_RCPT_TIMES = 3,    /**< Packet Receipt Times Report Block. */
  R_RTCP_XR_BT_RRT        = 4,    /**< Receiver Reference Time Report Block. */
  R_RTCP_XR_BT_DLRR       = 5,    /**< DLRR Report Block. */
  R_RTCP_XR_BT_STATS      = 6,    /**< Statistics Summary Report Block. */
  R_RTCP_XR_BT_VOIP       = 7,    /**< VoIP Metrics Report Block. */
} RRTCPXRBlockType;

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
/** @brief Opaque cursor over a single report block within an XR packet. */
typedef struct RRTCPXRBlock RRTCPXRBlock;

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

/* WRITE / construction
 *
 * RTCP packets are appended to a plain @ref RBuffer (start with
 * @ref r_buffer_new); each @c r_rtcp_buffer_add_* call appends one packet,
 * forming a compound buffer readable with @ref r_rtcp_buffer_map. */
/**
 * @brief Append a Sender Report (SR) packet.
 * @param buf     Compound RTCP buffer to append to.
 * @param srinfo  Sender info (its @c ssrc is the report sender).
 * @param rb      Array of @p nrb reception report blocks (may be @c NULL if 0).
 * @param nrb     Number of report blocks (0..31).
 * @return @c TRUE on success.
 */
R_API rboolean r_rtcp_buffer_add_sr (RBuffer * buf, const RRTCPSenderInfo * srinfo, const RRTCPReportBlock * rb, ruint8 nrb);
/**
 * @brief Append a Receiver Report (RR) packet.
 * @param buf   Compound RTCP buffer to append to.
 * @param ssrc  SSRC of the report sender.
 * @param rb    Array of @p nrb reception report blocks (may be @c NULL if 0).
 * @param nrb   Number of report blocks (0..31).
 * @return @c TRUE on success.
 */
R_API rboolean r_rtcp_buffer_add_rr (RBuffer * buf, ruint32 ssrc, const RRTCPReportBlock * rb, ruint8 nrb);
/**
 * @brief Append a Source Description (SDES) packet with a single chunk.
 * @param buf     Compound RTCP buffer to append to.
 * @param ssrc    The chunk's SSRC/CSRC.
 * @param items   Array of @p nitems SDES items (@c type / @c len / @c data).
 * @param nitems  Number of items (0 produces an empty chunk).
 * @return @c TRUE on success.
 *
 * Builds one chunk (source count 1); call again to describe further sources.
 */
R_API rboolean r_rtcp_buffer_add_sdes (RBuffer * buf, ruint32 ssrc, const RRTCPSDESItem * items, ruint8 nitems);
/**
 * @brief Append a BYE packet.
 * @param buf     Compound RTCP buffer to append to.
 * @param ssrcs   Array of @p nssrc leaving SSRCs.
 * @param nssrc   Number of SSRCs (0..31).
 * @param reason  Optional NUL-terminated reason-for-leaving (<= 255 bytes), or @c NULL.
 * @return @c TRUE on success.
 */
R_API rboolean r_rtcp_buffer_add_bye (RBuffer * buf, const ruint32 * ssrcs, ruint8 nssrc, const rchar * reason);
/**
 * @brief Append an APP (application-defined) packet.
 * @param buf      Compound RTCP buffer to append to.
 * @param subtype  Application subtype (0..31).
 * @param ssrc     SSRC/CSRC of the source.
 * @param name     4-octet application name.
 * @param data     Application data (@p size bytes), or @c NULL.
 * @param size     Application data size; must be a multiple of 4.
 * @return @c TRUE on success.
 */
R_API rboolean r_rtcp_buffer_add_app (RBuffer * buf, ruint8 subtype, ruint32 ssrc, const rchar name[4], const ruint8 * data, ruint16 size);
/**
 * @brief Append a feedback (RTPFB or PSFB) packet (RFC 4585).
 * @param buf      Compound RTCP buffer to append to.
 * @param pt       @c R_RTCP_PT_RTPFB or @c R_RTCP_PT_PSFB.
 * @param fmt      Feedback message type (0..31; see @ref RRTCPRTPFBType / @ref RRTCPPSFBType).
 * @param sender   SSRC of the feedback sender.
 * @param media    SSRC of the media source.
 * @param fci      Feedback Control Information (@p fcisize bytes), or @c NULL.
 * @param fcisize  FCI size; must be a multiple of 4.
 * @return @c TRUE on success.
 */
R_API rboolean r_rtcp_buffer_add_fb (RBuffer * buf, RRTCPPacketType pt, ruint8 fmt, ruint32 sender, ruint32 media, const ruint8 * fci, ruint16 fcisize);

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


/* RTCP feedback (RTPFB / PSFB) -- RFC 4585 / 5104.  The feedback message type
 * (FMT) is carried in the packet's count field; the body is the sender SSRC,
 * the media-source SSRC and type-specific Feedback Control Information (FCI). */
/** @brief Transport-layer (RTPFB) feedback message type. */
typedef enum {
  R_RTCP_RTPFB_FMT_NACK   = 1,    /**< Generic NACK (RFC 4585). */
  R_RTCP_RTPFB_FMT_TMMBR  = 3,    /**< Temporary Max Media Bitrate Request (RFC 5104). */
  R_RTCP_RTPFB_FMT_TMMBN  = 4,    /**< Temporary Max Media Bitrate Notification (RFC 5104). */
} RRTCPRTPFBType;

/** @brief Payload-specific (PSFB) feedback message type. */
typedef enum {
  R_RTCP_PSFB_FMT_PLI   = 1,      /**< Picture Loss Indication (RFC 4585). */
  R_RTCP_PSFB_FMT_SLI   = 2,      /**< Slice Loss Indication. */
  R_RTCP_PSFB_FMT_RPSI  = 3,      /**< Reference Picture Selection Indication. */
  R_RTCP_PSFB_FMT_FIR   = 4,      /**< Full Intra Request (RFC 5104). */
  R_RTCP_PSFB_FMT_TSTR  = 5,      /**< Temporal-Spatial Trade-off Request. */
  R_RTCP_PSFB_FMT_TSTN  = 6,      /**< Temporal-Spatial Trade-off Notification. */
  R_RTCP_PSFB_FMT_VBCM  = 7,      /**< Video Back Channel Message. */
  R_RTCP_PSFB_FMT_AFB   = 15,     /**< Application Layer Feedback. */
} RRTCPPSFBType;

/** @brief Feedback message type (FMT) of an RTPFB/PSFB @p packet, else 0. */
R_API ruint8 r_rtcp_packet_fb_get_fmt (const RRTCPPacket * packet);
/** @brief SSRC of the feedback packet sender. */
R_API ruint32 r_rtcp_packet_fb_get_sender_ssrc (const RRTCPPacket * packet);
/** @brief SSRC of the media source the feedback refers to. */
R_API ruint32 r_rtcp_packet_fb_get_media_ssrc (const RRTCPPacket * packet);
/** @brief Pointer to the Feedback Control Information; @p size receives its length. */
R_API const ruint8 * r_rtcp_packet_fb_get_fci (const RRTCPPacket * packet, ruint16 * size);


/* Extended Report (XR) -- RFC 3611.  The RTCP header is followed by the
 * reporter SSRC (@ref r_rtcp_packet_get_ssrc) and a sequence of report blocks,
 * each a 1-octet block type, a type-specific octet, a 16-bit block length and
 * the block content. */
/** @brief Return the first XR report block of @p packet (or @c NULL if none). */
#define r_rtcp_packet_xr_get_first_block(packet) r_rtcp_packet_xr_get_next_block (packet, NULL)
/** @brief Return the XR block after @p block (pass @c NULL for the first). */
R_API RRTCPXRBlock * r_rtcp_packet_xr_get_next_block (RRTCPPacket * packet,
    const RRTCPXRBlock * block);
/** @brief Return the block type (@ref RRTCPXRBlockType) of an XR @p block. */
R_API RRTCPXRBlockType r_rtcp_packet_xr_block_get_type (const RRTCPXRBlock * block);
/** @brief Length in bytes of an XR @p block's content (excluding the 4-octet block header). */
R_API ruint16 r_rtcp_packet_xr_block_get_length (const RRTCPXRBlock * block);
/** @brief Number of source SSRCs an XR @p block reports on (0 for RRT and unknown types, 1 for most, N for DLRR). */
R_API ruint r_rtcp_packet_xr_block_get_ssrc_count (const RRTCPPacket * packet,
    const RRTCPXRBlock * block);
/** @brief Return source SSRC @p idx that an XR @p block reports on, or 0 if out of range. */
R_API ruint32 r_rtcp_packet_xr_block_get_ssrc (const RRTCPPacket * packet,
    const RRTCPXRBlock * block, ruint idx);

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_RTP_H__ */


