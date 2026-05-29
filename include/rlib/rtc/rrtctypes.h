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
#ifndef __R_RTC_TYPES_H__
#define __R_RTC_TYPES_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtctypes.h
 * @brief Common enums and callback types shared across the WebRTC
 * (@ref r_rtc) headers: result codes, direction, DTLS role, signalling
 * type, media kind and codec identifiers.
 */

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>

/**
 * @defgroup r_rtc_types WebRTC common types
 * @ingroup r_rtc
 *
 * @brief Shared enums and callback signatures used throughout the
 * WebRTC layer — error codes, transceiver direction, DTLS role,
 * session-description signalling type, media kind, and the codec
 * registry.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Result code returned across the WebRTC API. */
typedef enum {
  R_RTC_OK      = 0,        /**< Success. */
  R_RTC_INVAL,              /**< Invalid argument. */
  R_RTC_OOM,                /**< Allocation failed. */
  R_RTC_WRONG_STATE,        /**< Operation not valid in the current state. */
  R_RTC_INCOMPLETE,         /**< Required information is missing. */
  R_RTC_INVALID_MEDIA,      /**< Media description is invalid. */
  R_RTC_INVALID_TYPE,       /**< Object / signalling type is invalid. */
  R_RTC_ALREADY_FOUND,      /**< Entry already exists. */
  R_RTC_MAP_ERROR,          /**< Buffer map failure. */
  R_RTC_DECRYPT_ERROR,      /**< SRTP / DTLS decrypt failure. */
  R_RTC_ENCRYPT_ERROR,      /**< SRTP / DTLS encrypt failure. */
  R_RTC_NO_HANDLER,         /**< No handler registered for the input. */
} RRtcError;

/** @brief Media flow direction of a transceiver (bitmask of send / recv). */
typedef enum {
  R_RTC_DIR_NONE      = 0,                                     /**< Inactive. */
  R_RTC_DIR_SEND_ONLY = (1 << 0),                              /**< Send only. */
  R_RTC_DIR_RECV_ONLY = (1 << 1),                              /**< Receive only. */
  R_RTC_DIR_SEND_RECV = R_RTC_DIR_SEND_ONLY | R_RTC_DIR_RECV_ONLY, /**< Bidirectional. */
} RRtcDirection;

/** @brief DTLS role for a transport (bitmask; @c AUTO defers the choice). */
typedef enum {
  R_RTC_ROLE_NONE     = 0,                                 /**< Unset. */
  R_RTC_ROLE_SERVER   = (1 << 0),                          /**< DTLS server (passive). */
  R_RTC_ROLE_CLIENT   = (1 << 1),                          /**< DTLS client (active). */
  R_RTC_ROLE_AUTO     = R_RTC_ROLE_SERVER | R_RTC_ROLE_CLIENT, /**< Negotiate the role. */
} RRtcRole;

/** @brief Session-description signalling type (JSEP offer / answer). */
typedef enum {
  R_RTC_SIGNAL_OFFER,     /**< SDP offer. */
  R_RTC_SIGNAL_ANSWER,    /**< SDP answer. */
  R_RTC_SIGNAL_PRANSWER,  /**< Provisional answer. */
  R_RTC_SIGNAL_ROLLBACK,  /**< Roll back to the previous stable state. */
} RRtcSignalType;

/** @brief Media kind of an m-line / track. */
typedef enum {
  R_RTC_MEDIA_UNKNOWN = 0,     /**< Unknown / unset. */
  R_RTC_MEDIA_AUDIO,           /**< Audio. */
  R_RTC_MEDIA_VIDEO,           /**< Video. */
  R_RTC_MEDIA_TEXT,            /**< Text. */
  R_RTC_MEDIA_APPLICATION,     /**< Application (e.g. data channel). */
} RRtcMediaType;
/** @brief Parse a media-kind string (e.g. @c "audio") into an @ref RRtcMediaType. */
R_API RRtcMediaType r_rtc_media_type_from_string (const rchar * type, rssize size);
/** @brief Return the SDP string for @p type (e.g. @c "video"). */
R_API const rchar * r_rtc_media_type_to_string (RRtcMediaType type);

/** @brief Role a codec plays in a media stream. */
typedef enum {
  R_RTC_CODEC_KIND_UNKNOWN = 0,      /**< Unknown. */
  R_RTC_CODEC_KIND_MEDIA,            /**< Primary media codec. */
  R_RTC_CODEC_KIND_RTX,              /**< Retransmission. */
  R_RTC_CODEC_KIND_FEC,              /**< Forward error correction. */
  R_RTC_CODEC_KIND_SUPPLEMENTAL,     /**< Supplemental (e.g. telephone-event). */
} RRtcCodecKind;

/** @brief Known codec identifiers (standard audio / video / RTX / FEC names). */
typedef enum {
  R_RTC_CODEC_UNKNOWN = 0,
  /* Audio */
  R_RTC_CODEC_PCMU,
  R_RTC_CODEC_PCMA,
  R_RTC_CODEC_G722,
  /*R_RTC_CODEC_G7221,*/
  R_RTC_CODEC_OPUS,
  R_RTC_CODEC_ISAC,
  R_RTC_CODEC_ILBC,
  R_RTC_CODEC_CN,
  R_RTC_CODEC_TELEPHONE_EVENT,
  /* Video */
  R_RTC_CODEC_VP8,
  R_RTC_CODEC_VP9,
  R_RTC_CODEC_H261,
  R_RTC_CODEC_H263,
  R_RTC_CODEC_H263_1998,
  R_RTC_CODEC_H263_2000,
  R_RTC_CODEC_H264,
  R_RTC_CODEC_H265,
  /* RTX */
  R_RTC_CODEC_RTX,
  /* FEC */
  R_RTC_CODEC_RED,
  R_RTC_CODEC_ULP_FEC,
  R_RTC_CODEC_FLEX_FEC,
} RRtcCodecType;


/** @brief Generic WebRTC event callback (alias for @ref RFunc). */
typedef RFunc RRtcEventCb;
/** @brief Buffer callback: receives a media / data @ref RBuffer plus a context pointer. */
typedef void (*RRtcBufferCb) (rpointer data, RBuffer * buf, rpointer ctx);

R_END_DECLS

/** @} */

#endif /* __R_RTC_TYPES_H__ */

