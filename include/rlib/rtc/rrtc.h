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
#ifndef __R_RTC_H__
#define __R_RTC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>

R_BEGIN_DECLS

typedef enum {
  R_RTC_OK      = 0,
  R_RTC_INVAL,
  R_RTC_OOM,
  R_RTC_WRONG_STATE,
  R_RTC_INVALID_MEDIA,
  R_RTC_INVALID_TYPE,
  R_RTC_ALREADY_FOUND,
  R_RTC_MAP_ERROR,
  R_RTC_DECRYPT_ERROR,
  R_RTC_ENCRYPT_ERROR,
  R_RTC_NO_HANDLER,
} RRtcError;

typedef enum {
  R_RTC_MEDIA_UNKNOWN = 0,
  R_RTC_MEDIA_AUDIO,
  R_RTC_MEDIA_VIDEO,
  R_RTC_MEDIA_TEXT,
  R_RTC_MEDIA_APPLICATION,
} RRtcMediaType;

typedef enum {
  R_RTC_CODEC_KIND_UNKNOWN = 0,
  R_RTC_CODEC_KIND_MEDIA,
  R_RTC_CODEC_KIND_RTX,
  R_RTC_CODEC_KIND_FEC,
  R_RTC_CODEC_KIND_SUPPLEMENTAL,
} RRtcCodecKind;

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


typedef RFunc RRtcEventCb;
typedef void (*RRtcBufferCb) (rpointer data, RBuffer * buf, rpointer ctx);

R_END_DECLS

#endif /* __R_RTC_H__ */

