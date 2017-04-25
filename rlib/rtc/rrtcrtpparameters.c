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

#include "config.h"
#include "rrtc-private.h"

#include <rlib/rtc/rrtcrtpparameters.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

static const struct _RRtcCodecInfo {
  const rchar *   name;
  RRTPPayloadType pt;
  RRtcMediaType   media;
  RRtcCodecType   type;
  RRtcCodecKind   kind;
} _r_rtc_rtp_codec_tbl[] = {
  { "Unknown", 0, R_RTC_MEDIA_UNKNOWN, R_RTC_CODEC_UNKNOWN, R_RTC_CODEC_KIND_UNKNOWN },
  /* Audio */
  { "PCMU", R_RTP_PT_PCMU, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_PCMU, R_RTC_CODEC_KIND_MEDIA },
  { "PCMA", R_RTP_PT_PCMA, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_PCMA, R_RTC_CODEC_KIND_MEDIA },
  { "G722", R_RTP_PT_G722, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_G722, R_RTC_CODEC_KIND_MEDIA },
  /*{ "G7221", 0, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_G7221, R_RTC_CODEC_KIND_MEDIA },*/
  { "opus", 0, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_OPUS, R_RTC_CODEC_KIND_MEDIA },
  { "isac", 0, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_ISAC, R_RTC_CODEC_KIND_MEDIA },
  { "ilbc", 0, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_ILBC, R_RTC_CODEC_KIND_MEDIA },
  { "CN", R_RTP_PT_CN, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_CN, R_RTC_CODEC_KIND_SUPPLEMENTAL },
  { "telephone-event", 0, R_RTC_MEDIA_AUDIO, R_RTC_CODEC_TELEPHONE_EVENT, R_RTC_CODEC_KIND_SUPPLEMENTAL },

  /* Vidoe */
  { "VP8", 0, R_RTC_MEDIA_VIDEO, R_RTC_CODEC_VP8, R_RTC_CODEC_KIND_MEDIA },
  { "VP9", 0, R_RTC_MEDIA_VIDEO, R_RTC_CODEC_VP9, R_RTC_CODEC_KIND_MEDIA },
  { "H261", R_RTP_PT_H261, R_RTC_MEDIA_VIDEO, R_RTC_CODEC_H261, R_RTC_CODEC_KIND_MEDIA },
  { "H263", 0, R_RTC_MEDIA_VIDEO, R_RTC_CODEC_H263, R_RTC_CODEC_KIND_MEDIA },
  { "H263-1998", 0, R_RTC_MEDIA_VIDEO, R_RTC_CODEC_H263_1998, R_RTC_CODEC_KIND_MEDIA },
  { "H263-2000", 0, R_RTC_MEDIA_VIDEO, R_RTC_CODEC_H263_2000, R_RTC_CODEC_KIND_MEDIA },
  { "H264", 0, R_RTC_MEDIA_VIDEO, R_RTC_CODEC_H264, R_RTC_CODEC_KIND_MEDIA },
  { "H265", 0, R_RTC_MEDIA_VIDEO, R_RTC_CODEC_H265, R_RTC_CODEC_KIND_MEDIA },

  { "rtx", 0, R_RTC_MEDIA_UNKNOWN, R_RTC_CODEC_RTX, R_RTC_CODEC_KIND_RTX },
  { "red", 0, R_RTC_MEDIA_UNKNOWN, R_RTC_CODEC_RED, R_RTC_CODEC_KIND_FEC },
  { "ulpfec", 0, R_RTC_MEDIA_UNKNOWN, R_RTC_CODEC_ULP_FEC, R_RTC_CODEC_KIND_FEC },
  { "flexfec", 0, R_RTC_MEDIA_UNKNOWN, R_RTC_CODEC_FLEX_FEC, R_RTC_CODEC_KIND_FEC },
};

static void
r_rtc_rtp_codec_parse_type_from_name (RRtcRtpCodecParameters * p)
{
  rsize i;

  for (i = 0; i < R_N_ELEMENTS (_r_rtc_rtp_codec_tbl); i++) {
    if (r_strcasecmp (p->name, _r_rtc_rtp_codec_tbl[i].name) == 0) {
      p->media = _r_rtc_rtp_codec_tbl[i].media;
      p->type = _r_rtc_rtp_codec_tbl[i].type;
      p->kind = _r_rtc_rtp_codec_tbl[i].kind;
      return;
    }
  }

  p->media = R_RTC_MEDIA_UNKNOWN;
  p->type = R_RTC_CODEC_UNKNOWN;
  p->kind = R_RTC_CODEC_KIND_UNKNOWN;
}

RRtcRtpCodecParameters *
r_rtc_rtp_codec_parameters_new (const rchar * name, rssize size,
    RRTPPayloadType pt, ruint rate, ruint ch)
{
  RRtcRtpCodecParameters * ret;

  if ((ret = r_mem_new (RRtcRtpCodecParameters)) != NULL) {
    ret->name = r_strdup_size (name, size);
    r_rtc_rtp_codec_parse_type_from_name (ret);
    ret->pt = pt;
    ret->rate = rate;
    ret->maxptime = 0;
    ret->ptime = 0;
    ret->channels = ch;
    r_ptr_array_init (&ret->rtcpfb);
    ret->fmtp = NULL;
  }

  return ret;
}

void
r_rtc_rtp_codec_parameters_init (RRtcRtpCodecParameters * p)
{
  p->name = NULL;
  p->media = R_RTC_MEDIA_UNKNOWN;
  p->type = R_RTC_CODEC_UNKNOWN;
  p->kind = R_RTC_CODEC_KIND_UNKNOWN;
  p->pt = (RRTPPayloadType) 1;
  p->rate = 0;
  p->maxptime = 0;
  p->ptime = 0;
  p->channels = 0;
  r_ptr_array_init (&p->rtcpfb);
  p->fmtp = NULL;
}

void
r_rtc_rtp_codec_parameters_clear (RRtcRtpCodecParameters * p)
{
  r_free (p->fmtp); p->fmtp = NULL;
  r_ptr_array_clear (&p->rtcpfb);

  r_free (p->name); p->name = NULL;
}

static void
_copy_str_array_cb (rpointer data, rpointer user)
{
  r_ptr_array_add (user, r_strdup (data), r_free);
}

RRtcRtpCodecParameters *
r_rtc_rtp_codec_parameters_dup (const RRtcRtpCodecParameters * p)
{
  RRtcRtpCodecParameters * ret;

  if ((ret = r_rtc_rtp_codec_parameters_new (p->name, -1,
          p->pt, p->rate, p->channels)) != NULL) {
    ret->maxptime = p->maxptime;
    ret->ptime = p->ptime;
    r_ptr_array_foreach ((RPtrArray *)&p->rtcpfb,
        _copy_str_array_cb, &ret->rtcpfb);
    ret->fmtp = r_strdup (p->fmtp);
  }

  return ret;
}

static void
r_rtc_rtp_codec_parameters_free (rpointer data)
{
  RRtcRtpCodecParameters * p = data;
  r_rtc_rtp_codec_parameters_clear (p);
  r_free (p);
}


RRtcRtpHdrExtParameters *
r_rtc_rtp_hdrext_parameters_new (const rchar * uri, rssize size, ruint16 id)
{
  RRtcRtpHdrExtParameters * ret;

  if ((ret = r_mem_new (RRtcRtpHdrExtParameters)) != NULL) {
    ret->uri = r_strdup_size (uri, size);
    ret->id = id;
    ret->prefencrypt = FALSE;
    r_ptr_array_init (&ret->params);
  }

  return ret;
}

void
r_rtc_rtp_hdrext_parameters_init (RRtcRtpHdrExtParameters * p)
{
  p->uri = NULL;
  p->id = 0;
  p->prefencrypt = FALSE;
  r_ptr_array_init (&p->params);
}

void
r_rtc_rtp_hdrext_parameters_clear (RRtcRtpHdrExtParameters * p)
{
  r_free (p->uri); p->uri = NULL;
  r_ptr_array_clear (&p->params);
}

RRtcRtpHdrExtParameters *
r_rtc_rtp_hdrext_parameters_dup (const RRtcRtpHdrExtParameters * p)
{
  RRtcRtpHdrExtParameters * ret;

  if ((ret = r_rtc_rtp_hdrext_parameters_new (p->uri, -1, p->id)) != NULL) {
    ret->prefencrypt = p->prefencrypt;
    /* TODO: Coypy params */
  }

  return ret;
}

static void
r_rtc_rtp_hdrext_parameters_free (rpointer data)
{
  RRtcRtpHdrExtParameters * p = data;
  r_rtc_rtp_hdrext_parameters_clear (p);
  r_free (p);
}


RRtcRtpEncodingParameters *
r_rtc_rtp_encoding_parameters_new (ruint32 ssrc, RRTPPayloadType pt)
{
  RRtcRtpEncodingParameters * ret;

  if ((ret = r_mem_new0 (RRtcRtpEncodingParameters)) != NULL) {
    ret->ssrc = ssrc;
    ret->pt = pt;
    ret->active = TRUE;
  }

  return ret;
}

void
r_rtc_rtp_encoding_parameters_init (RRtcRtpEncodingParameters * p)
{
  r_memclear (p, sizeof (RRtcRtpEncodingParameters));
  p->pt = (RRTPPayloadType)1;
  p->active = TRUE;
}

void
r_rtc_rtp_encoding_parameters_clear (RRtcRtpEncodingParameters * p)
{
  r_free (p->fec.mechanism); p->fec.mechanism = NULL;
}

RRtcRtpEncodingParameters *
r_rtc_rtp_encoding_parameters_dup (const RRtcRtpEncodingParameters * p)
{
  RRtcRtpEncodingParameters * ret;

  if ((ret = r_memdup (p, sizeof (RRtcRtpEncodingParameters))) != NULL) {
    ret->fec.mechanism = r_strdup (p->fec.mechanism);
  }

  return ret;
}


static void
r_rtc_rtp_encoding_parameters_free (rpointer data)
{
  RRtcRtpEncodingParameters * p = data;
  r_rtc_rtp_encoding_parameters_clear (p);
  r_free (p);
}


static void
r_rtc_rtp_parameters_free (RRtcRtpParameters * p)
{
  r_free (p->mid);
  r_free (p->cname);

  r_ptr_array_clear (&p->encodings);
  r_ptr_array_clear (&p->extensions);
  r_ptr_array_clear (&p->codecs);

  r_free (p);
}

RRtcRtpParameters *
r_rtc_rtp_parameters_new (const rchar * mid, rssize size)
{
  RRtcRtpParameters * ret;

  if ((ret = r_mem_new (RRtcRtpParameters)) != NULL) {
    r_ref_init (ret, r_rtc_rtp_parameters_free);

    r_ptr_array_init (&ret->codecs);
    r_ptr_array_init (&ret->extensions);
    r_ptr_array_init (&ret->encodings);

    ret->cname = NULL;
    ret->ssrc = 0;
    ret->flags = R_RTC_RTCP_NONE;

    ret->mid = r_strdup_size (mid, size);
  }

  return ret;
}

RRtcError
r_rtc_rtp_parameters_set_rtcp (RRtcRtpParameters * params,
    const rchar * cname, rssize size, ruint32 ssrc, RRtcRtcpFlags flags)
{
  if (R_UNLIKELY (cname == NULL && ssrc != 0)) return R_RTC_INVAL;
  if (R_UNLIKELY (cname != NULL && ssrc == 0)) return R_RTC_INVAL;

  r_free (params->cname);
  params->cname = r_strdup_size (cname, size);
  params->ssrc = ssrc;
  params->flags = flags;
  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_parameters_take_codec (RRtcRtpParameters * params,
    RRtcRtpCodecParameters * codec)
{
  if (R_UNLIKELY (codec == NULL)) return R_RTC_INVAL;

  r_ptr_array_add (&params->codecs, codec, r_rtc_rtp_codec_parameters_free);
  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_parameters_take_encoding (RRtcRtpParameters * params,
    RRtcRtpEncodingParameters * encoding)
{
  if (R_UNLIKELY (encoding == NULL)) return R_RTC_INVAL;

  r_ptr_array_add (&params->encodings, encoding, r_rtc_rtp_encoding_parameters_free);
  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_parameters_take_hdrext (RRtcRtpParameters * params,
    RRtcRtpHdrExtParameters * extension)
{
  if (R_UNLIKELY (extension == NULL)) return R_RTC_INVAL;

  r_ptr_array_add (&params->extensions, extension,
      r_rtc_rtp_hdrext_parameters_free);
  return R_RTC_OK;
}

