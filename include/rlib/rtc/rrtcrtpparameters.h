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
#ifndef __R_RTC_RTP_PARAMETERS_H__
#define __R_RTC_RTP_PARAMETERS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtcrtpparameters.h
 * @brief WebRTC RTP send / receive parameters: codecs, header extensions
 * and encodings.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/data/rptrarray.h>

#include <rlib/net/proto/rrtp.h>

/**
 * @defgroup r_rtc_rtpparameters WebRTC RTP parameters
 * @ingroup r_rtc
 *
 * @brief Describe how an RTP stream is sent or received — the codec
 * payload-type table, RTP header extensions, per-stream encodings and
 * RTCP options.
 *
 * The leaf descriptors (@ref RRtcRtpCodecParameters,
 * @ref RRtcRtpHdrExtParameters, @ref RRtcRtpEncodingParameters) are plain
 * value structs with @c _init / @c _clear / @c _dup helpers, and are
 * aggregated by the reference-counted @ref RRtcRtpParameters. Use the
 * @c r_rtc_rtp_parameters_add_* helpers to populate the arrays.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief RTCP multiplexing / reduced-size options (bitmask). */
typedef enum {
  R_RTC_RTCP_NONE       = 0,         /**< No RTCP options. */
  R_RTC_RTCP_MUX        = (1 << 0),  /**< RTP and RTCP multiplexed on one transport. */
  R_RTC_RTCP_MUX_ONLY   = (1 << 1),  /**< Only multiplexed RTCP is supported. */
  R_RTC_RTCP_RSIZE      = (1 << 2),  /**< Reduced-size RTCP (RFC 5506). */
} RRtcRtcpFlags;

/** @brief Relative priority hint for an encoding. */
typedef enum {
  R_RTC_PRIORITY_NONE = 0,    /**< Unset. */
  R_RTC_PRIORITY_VERY_LOW,    /**< Very low priority. */
  R_RTC_PRIORITY_LOW,         /**< Low priority. */
  R_RTC_PRIORITY_MEDIUM,      /**< Medium priority. */
  R_RTC_PRIORITY_HIGH,        /**< High priority. */
} RRtcPriorityType;

/** @brief Parameters describing a single codec in the payload-type table. */
typedef struct {
  rchar *         name;      /**< @brief Codec name (e.g. @c "opus"). */
  RRtcMediaType   media;     /**< @brief Media kind (@ref RRtcMediaType). */
  RRtcCodecType   type;      /**< @brief Codec identifier (@ref RRtcCodecType). */
  RRtcCodecKind   kind;      /**< @brief Codec role (@ref RRtcCodecKind). */
  RRTPPayloadType pt;        /**< @brief RTP payload type. */
  ruint           rate;      /**< @brief Clock rate in Hz. */
  ruint           maxptime;  /**< @brief Maximum packetization time in ms. */
  ruint           ptime;     /**< @brief Preferred packetization time in ms. */
  ruint           channels;  /**< @brief Channel count (audio). */
  RPtrArray       rtcpfb;    /**< @brief RTCP feedback mechanisms (array of @c rchar *). */
  rchar *         fmtp;      /**< @brief Format-specific parameters (SDP @c fmtp line). */
} RRtcRtpCodecParameters;

/** @brief Allocate and initialise a codec descriptor for @p name with payload type @p pt, clock rate @p rate and @p ch channels. */
R_API RRtcRtpCodecParameters * r_rtc_rtp_codec_parameters_new (const rchar * name,
    rssize size, RRTPPayloadType pt, ruint rate, ruint ch) R_ATTR_MALLOC;
/** @brief Initialise a caller-allocated codec descriptor to empty defaults. */
R_API void r_rtc_rtp_codec_parameters_init (RRtcRtpCodecParameters * p);
/** @brief Release the contents of a codec descriptor (does not free @p p). */
R_API void r_rtc_rtp_codec_parameters_clear (RRtcRtpCodecParameters * p);
/** @brief Deep-copy a codec descriptor. */
R_API RRtcRtpCodecParameters * r_rtc_rtp_codec_parameters_dup (
    const RRtcRtpCodecParameters * p);

/** @brief Forward error correction parameters for an encoding. */
typedef struct {
  ruint32 ssrc;       /**< @brief SSRC carrying the FEC stream. */
  rchar * mechanism;  /**< @brief FEC mechanism name. */
} RRtcRtpFecParameters;

/** @brief Retransmission (RTX) parameters for an encoding. */
typedef struct {
  ruint32 ssrc;  /**< @brief SSRC carrying the RTX stream. */
} RRtcRtpRtxParameters;

/** @brief Parameters describing a single RTP encoding (one SSRC stream). */
typedef struct {
  ruint32 ssrc;             /**< @brief SSRC of the media stream. */
  RRTPPayloadType pt;       /**< @brief RTP payload type. */
  RRtcPriorityType pri;     /**< @brief Relative priority (@ref RRtcPriorityType). */

  RRtcRtpFecParameters fec; /**< @brief FEC parameters (@ref RRtcRtpFecParameters). */
  RRtcRtpRtxParameters rtx; /**< @brief RTX parameters (@ref RRtcRtpRtxParameters). */

  rboolean active;          /**< @brief Whether the encoding is currently active. */
  rchar id[16 + 1];         /**< @brief RID (restriction identifier) string. */
  ruint64 maxbr;            /**< @brief Maximum bitrate in bits per second. */

  ruint maxfr;              /**< @brief Maximum frame rate. */
  rdouble scaleres;         /**< @brief Resolution scale-down factor. */
  rdouble scalefr;          /**< @brief Frame-rate scale-down factor. */
} RRtcRtpEncodingParameters;

/** @brief Allocate and initialise an encoding descriptor for SSRC @p ssrc with payload type @p pt. */
R_API RRtcRtpEncodingParameters * r_rtc_rtp_encoding_parameters_new (ruint32 ssrc,
    RRTPPayloadType pt) R_ATTR_MALLOC;
/** @brief Initialise a caller-allocated encoding descriptor to empty defaults. */
R_API void r_rtc_rtp_encoding_parameters_init (RRtcRtpEncodingParameters * p);
/** @brief Release the contents of an encoding descriptor (does not free @p p). */
R_API void r_rtc_rtp_encoding_parameters_clear (RRtcRtpEncodingParameters * p);
/** @brief Deep-copy an encoding descriptor. */
R_API RRtcRtpEncodingParameters * r_rtc_rtp_encoding_parameters_dup (
    const RRtcRtpEncodingParameters * p);

/** @brief Parameters describing a negotiated RTP header extension. */
typedef struct {
  rchar * uri;          /**< @brief Header-extension URI. */
  ruint16 id;           /**< @brief Negotiated extension ID. */
  rboolean prefencrypt; /**< @brief Whether encryption of the extension is preferred. */
  RPtrArray params;     /**< @brief Extension-specific parameters. */
} RRtcRtpHdrExtParameters;

/** @brief Allocate and initialise a header-extension descriptor for @p uri with ID @p id. */
R_API RRtcRtpHdrExtParameters * r_rtc_rtp_hdrext_parameters_new (
    const rchar * uri, rssize size, ruint16 id) R_ATTR_MALLOC;
/** @brief Initialise a caller-allocated header-extension descriptor to empty defaults. */
R_API void r_rtc_rtp_hdrext_parameters_init (RRtcRtpHdrExtParameters * p);
/** @brief Release the contents of a header-extension descriptor (does not free @p p). */
R_API void r_rtc_rtp_hdrext_parameters_clear (RRtcRtpHdrExtParameters * p);
/** @brief Deep-copy a header-extension descriptor. */
R_API RRtcRtpHdrExtParameters * r_rtc_rtp_hdrext_parameters_dup (
    const RRtcRtpHdrExtParameters * p);


/** @brief Reference-counted aggregate of all RTP parameters for a media stream. */
typedef struct {
  RRef ref;                 /**< @brief Embedded reference count. */

  /* RRtcRtcpParameters */
  rchar * cname;            /**< @brief RTCP canonical name (CNAME). */
  ruint32 ssrc;             /**< @brief RTCP sender SSRC. */
  RRtcRtcpFlags flags;      /**< @brief RTCP options (@ref RRtcRtcpFlags). */

  rchar *     mid;          /**< @brief Media identification (MID) tag. */
  RPtrArray   codecs;       /**< @brief Codec table (array of @ref RRtcRtpCodecParameters). */
  RPtrArray   extensions;   /**< @brief Header extensions (array of @ref RRtcRtpHdrExtParameters). */
  RPtrArray   encodings;    /**< @brief Encodings (array of @ref RRtcRtpEncodingParameters). */
} RRtcRtpParameters;


/** @brief Allocate an empty, reference-counted parameter set with media id @p mid. */
R_API RRtcRtpParameters * r_rtc_rtp_parameters_new (const rchar * mid, rssize size) R_ATTR_MALLOC;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_rtp_parameters_ref                r_ref_ref
/** @brief Release a reference (alias for @ref r_ref_unref). */
#define r_rtc_rtp_parameters_unref              r_ref_unref

/** @brief Return the media identification (MID) tag. */
#define r_rtc_rtp_parameters_mid(p)             ((p)->mid)
/** @brief Return the RTCP canonical name (CNAME). */
#define r_rtc_rtp_parameters_rtcp_cname(p)      ((p)->cname)
/** @brief Return the RTCP sender SSRC. */
#define r_rtc_rtp_parameters_rtcp_ssrc(p)       ((p)->ssrc)
/** @brief Return the RTCP options (@ref RRtcRtcpFlags). */
#define r_rtc_rtp_parameters_rtcp_flags(p)      ((p)->flags)
/** @brief Return the number of codecs. */
#define r_rtc_rtp_parameters_codec_count(p)     r_ptr_array_size (&(p)->codecs)
/** @brief Return the number of header extensions. */
#define r_rtc_rtp_parameters_hdrext_count(p)    r_ptr_array_size (&(p)->extensions)
/** @brief Return the number of encodings. */
#define r_rtc_rtp_parameters_encoding_count(p)  r_ptr_array_size (&(p)->encodings)
/** @brief Return the codec at index @c i (@ref RRtcRtpCodecParameters). */
#define r_rtc_rtp_parameters_get_codec(p, i)    ((RRtcRtpCodecParameters *)r_ptr_array_get (&(p)->codecs, i))
/** @brief Return the header extension at index @c i (@ref RRtcRtpHdrExtParameters). */
#define r_rtc_rtp_parameters_get_hdrext(p, i)   ((RRtcRtpHdrExtParameters *)r_ptr_array_get (&(p)->extensions, i))
/** @brief Return the encoding at index @c i (@ref RRtcRtpEncodingParameters). */
#define r_rtc_rtp_parameters_get_encoding(p, i) ((RRtcRtpEncodingParameters *)r_ptr_array_get (&(p)->encodings, i))

/** @brief Set the RTCP @p cname, @p ssrc and @p flags on @p params. */
R_API RRtcError r_rtc_rtp_parameters_set_rtcp (RRtcRtpParameters * params,
    const rchar * cname, rssize size, ruint32 ssrc, RRtcRtcpFlags flags);
/** @brief Append @p codec to @p params, taking ownership. */
R_API RRtcError r_rtc_rtp_parameters_take_codec (RRtcRtpParameters * params,
    RRtcRtpCodecParameters * codec);
/** @brief Append a copy of @c codec to @c params. */
#define r_rtc_rtp_parameters_add_codec(params, codec)                         \
  r_rtc_rtp_parameters_take_codec (params, r_rtc_rtp_codec_parameters_dup (codec))
/** @brief Construct a codec from @c name / @c pt / @c rate / @c ch and append it to @c params. */
#define r_rtc_rtp_parameters_add_codec_simple(params, name, pt, rate, ch)     \
  r_rtc_rtp_parameters_take_codec (params,                                    \
      r_rtc_rtp_codec_parameters_new (name, -1, pt, rate, ch))
/** @brief Append @p encoding to @p params, taking ownership. */
R_API RRtcError r_rtc_rtp_parameters_take_encoding (RRtcRtpParameters * params,
    RRtcRtpEncodingParameters * encoding);
/** @brief Append a copy of @c encoding to @c params. */
#define r_rtc_rtp_parameters_add_encoding(params, encoding)                   \
  r_rtc_rtp_parameters_take_encoding (params, r_rtc_rtp_encoding_parameters_dup (encoding))
/** @brief Construct an encoding from @c ssrc / @c pt and append it to @c params. */
#define r_rtc_rtp_parameters_add_encoding_simple(params, ssrc, pt)            \
  r_rtc_rtp_parameters_take_encoding (params,                                 \
      r_rtc_rtp_encoding_parameters_new (ssrc, pt))
/** @brief Append @p extension to @p params, taking ownership. */
R_API RRtcError r_rtc_rtp_parameters_take_hdrext (RRtcRtpParameters * params,
    RRtcRtpHdrExtParameters * extension);
/** @brief Append a copy of @c hdrext to @c params. */
#define r_rtc_rtp_parameters_add_hdrext(params, hdrext)                       \
  r_rtc_rtp_parameters_take_hdrext (params, r_rtc_rtp_hdrext_parameters_dup (hdrext))
/** @brief Construct a header extension from @c uri / @c id and append it to @c params. */
#define r_rtc_rtp_parameters_add_hdrext_simple(params, uri, id)               \
  r_rtc_rtp_parameters_take_hdrext (params,                                   \
      r_rtc_rtp_hdrext_parameters_new (uri, -1, id))


R_END_DECLS

/** @} */

#endif /* __R_RTC_RTP_PARAMETERS_H__ */

