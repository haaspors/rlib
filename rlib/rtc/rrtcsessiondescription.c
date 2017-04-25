/* RLIB - Convenience library for useful things
 * Copyright (C) 2017  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include <rlib/rtc/rrtcsessiondescription.h>

#include <rlib/rbase64.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#include <rlib/net/proto/rsdp.h>

static void
r_rtc_transport_info_free (RRtcTransportInfo * trans)
{
  r_free (trans->id);

  r_free (trans->rtcp.ice.ufrag);
  r_free (trans->rtcp.ice.pwd);
  r_free (trans->rtcp.dtls.fingerprint);
  r_ptr_array_clear (&trans->rtcp.candidates);

  r_free (trans->rtp.ice.ufrag);
  r_free (trans->rtp.ice.pwd);
  r_free (trans->rtp.dtls.fingerprint);
  r_ptr_array_clear (&trans->rtp.candidates);

  r_free (trans);
}

RRtcTransportInfo *
r_rtc_transport_info_new (const rchar * id, rssize size, rboolean rtcpmux)
{
  RRtcTransportInfo * ret;

  if ((ret = r_mem_new0 (RRtcTransportInfo)) != NULL) {
    r_ref_init (ret, r_rtc_transport_info_free);
    ret->id = r_strdup_size (id, size);
    ret->rtcpmux = rtcpmux;

    r_ptr_array_init (&ret->rtp.candidates);
    r_ptr_array_init (&ret->rtcp.candidates);
  }

  return ret;
}

static void
r_rtc_media_line_info_free (RRtcMediaLineInfo * mline)
{
  r_free (mline->mid);
  r_free (mline->trans);
  if (mline->params != NULL)
    r_rtc_rtp_parameters_unref (mline->params);
  r_free (mline);
}

static RRtcProtocolFlags
r_rtc_protocol_parse_rtp_profile (const RStrChunk * profile)
{
  if (r_str_chunk_casecmp (profile, R_STR_WITH_SIZE_ARGS ("AVP")) == 0)
    return R_RTC_PROTO_FLAG_AV_PROFILE;
  else if (r_str_chunk_casecmp (profile, R_STR_WITH_SIZE_ARGS ("SAVP")) == 0)
    return R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE;
  else if (r_str_chunk_casecmp (profile, R_STR_WITH_SIZE_ARGS ("AVPF")) == 0)
    return R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_FEEDBACK;
  else if (r_str_chunk_casecmp (profile, R_STR_WITH_SIZE_ARGS ("SAVPF")) == 0)
    return R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE | R_RTC_PROTO_FLAG_FEEDBACK;

  return R_RTC_PROTO_FLAG_NONE;
}

static RRtcProtocol
r_rtc_protocol_parse (const rchar * proto, rssize size, RRtcProtocolFlags * flags)
{
  RStrChunk in = { (rchar *)proto, (size < 0) ? r_strlen (proto) : (rsize)size }, f[5];
  ruint c = r_str_chunk_split (&in, "/", &f[0], &f[1], &f[2], &f[3], &f[4], NULL);

  *flags = R_RTC_PROTO_FLAG_NONE;

  if (c < 2) return R_RTC_PROTO_NONE;

  if (r_str_chunk_casecmp (&f[0], R_STR_WITH_SIZE_ARGS ("RTP")) == 0) {
    if ((*flags = r_rtc_protocol_parse_rtp_profile (&f[1])) == R_RTC_PROTO_FLAG_NONE)
      return R_RTC_PROTO_NONE;
    return R_RTC_PROTO_RTP;
  }

  if (r_str_chunk_casecmp (&f[0], R_STR_WITH_SIZE_ARGS ("DTLS")) == 0) {
    return (r_str_chunk_casecmp (&f[1], R_STR_WITH_SIZE_ARGS ("SCTP")) == 0) ?
      R_RTC_PROTO_SCTP : R_RTC_PROTO_NONE;
  }

  if (c < 3) return R_RTC_PROTO_NONE;

  if (r_str_chunk_casecmp (&f[0], R_STR_WITH_SIZE_ARGS ("UDP")) != 0 &&
      r_str_chunk_casecmp (&f[0], R_STR_WITH_SIZE_ARGS ("TCP")) != 0) {
    return R_RTC_PROTO_NONE;
  }

  if (r_str_chunk_casecmp (&f[1], R_STR_WITH_SIZE_ARGS ("DTLS")) == 0) {
    return (r_str_chunk_casecmp (&f[2], R_STR_WITH_SIZE_ARGS ("SCTP")) == 0) ?
      R_RTC_PROTO_SCTP : R_RTC_PROTO_NONE;
  } else if (r_str_chunk_casecmp (&f[1], R_STR_WITH_SIZE_ARGS ("RTP")) == 0) {
    if ((*flags = r_rtc_protocol_parse_rtp_profile (&f[2])) == R_RTC_PROTO_FLAG_NONE)
      return R_RTC_PROTO_NONE;
    return R_RTC_PROTO_RTP;
  }

  if (c != 4) return R_RTC_PROTO_NONE;

  if (r_str_chunk_casecmp (&f[2], R_STR_WITH_SIZE_ARGS ("RTP")) == 0) {
    if ((*flags = r_rtc_protocol_parse_rtp_profile (&f[3])) == R_RTC_PROTO_FLAG_NONE)
      return R_RTC_PROTO_NONE;
    return R_RTC_PROTO_RTP;
  }

  return R_RTC_PROTO_NONE;
}

RRtcMediaLineInfo *
r_rtc_media_line_info_new (const rchar * mid, rssize size,
    RRtcMediaType type, RRtcDirection dir, const rchar * proto, rssize psize)
{
  RRtcMediaLineInfo * ret;

  if ((ret = r_mem_new (RRtcMediaLineInfo)) != NULL) {
    r_ref_init (ret, r_rtc_media_line_info_free);
    ret->type = type;
    ret->dir = dir;
    ret->mid = r_strdup_size (mid, size);
    ret->proto = r_rtc_protocol_parse (proto, psize, &ret->protoflags);
    ret->params = NULL;
    ret->trans = NULL;
  }

  return ret;
}

static void
r_rtc_session_description_free (RRtcSessionDescription * sd)
{
  r_free (sd->conn_addr);
  r_free (sd->conn_addrtype);
  r_free (sd->conn_nettype);
  r_free (sd->orig_addr);
  r_free (sd->orig_addrtype);
  r_free (sd->orig_nettype);
  r_free (sd->session_id);
  r_free (sd->session_name);
  r_free (sd->username);

  r_hash_table_unref (sd->transport);
  r_hash_table_unref (sd->mline);

  if (sd->notify != NULL)
    sd->notify (sd->data);
  r_free (sd);
}

RRtcSessionDescription *
r_rtc_session_description_new (RRtcSignalType type)
{
  RRtcSessionDescription * ret;

  if ((ret = r_mem_new0 (RRtcSessionDescription)) != NULL) {
    r_ref_init (ret, r_rtc_session_description_free);
    ret->type = type;

    ret->transport = r_hash_table_new_full (r_str_hash, r_str_equal,
        NULL, r_rtc_transport_info_unref);
    ret->mline = r_hash_table_new_full (r_str_hash, r_str_equal,
        NULL, r_rtc_media_line_info_unref);
  }

  return ret;
}

static RRtcRtpParameters *
r_rtc_session_description_create_sdp_rtp_params (const rchar * mid,
    RSdpMediaBuf * media, RSdpBuf * sdp)
{
  RRtcRtpParameters * ret;

  if ((ret = r_rtc_rtp_parameters_new (mid, -1)) != NULL) {
    ruint32 * ssrcs;
    ruint16 extmapid;
    rsize start, i, j, ssrccount;
    RRtcRtcpFlags rtcpflags = R_RTC_RTCP_NONE;
    RRtcRtpCodecParameters * codec;
    RRtcRtpEncodingParameters * encoding;
    RStrChunk chunk;

    for (i = 0; i < r_sdp_media_buf_fmt_count (media); i++) {
      RStrChunk rtpmap = R_STR_CHUNK_INIT, name = R_STR_CHUNK_INIT;
      RRTPPayloadType pt;
      ruint rate = 0, ch = 1;

      pt = (RRTPPayloadType)r_sdp_media_buf_fmt_uint (media, i);
      if (r_sdp_media_buf_rtpmap_for_fmt (media,
          media->fmt[i].str, media->fmt[i].size, &rtpmap) == R_SDP_OK) {
        RStrChunk r[2] = { R_STR_CHUNK_INIT, R_STR_CHUNK_INIT };
        rsize len = r_str_chunk_split (&rtpmap, "/", &name, &r[0], &r[1], NULL);

        if (len > 1)
          rate = r_str_to_uint (r[0].str, NULL, 10, NULL);
        if (len > 2)
          ch = r_str_to_uint (r[1].str, NULL, 10, NULL);
      }

      if ((codec = r_rtc_rtp_codec_parameters_new (name.str, name.size,
              pt, rate, ch)) != NULL) {
        r_rtc_rtp_parameters_take_codec (ret, codec);

        if (r_sdp_media_buf_fmtp_for_fmt (media,
            media->fmt[i].str, media->fmt[i].size, &chunk) == R_SDP_OK) {
          codec->fmtp = r_str_chunk_dup (&chunk);
        }

        start = 0;
        while (r_sdp_media_buf_rtcpfb_for_fmt (media,
            media->fmt[i].str, media->fmt[i].size, &chunk, &start) == R_SDP_OK) {
          r_ptr_array_add (&codec->rtcpfb, r_str_chunk_dup (&chunk), r_free);
          start++;
        }
      }
    }

    /* RTCP ssrc and cname */
    if (r_sdp_media_buf_has_attrib (media, "rtcp-mux", -1) ||
        r_sdp_buf_has_attrib (sdp, "rtcp-mux", -1)) /* remove session-level check?*/
      rtcpflags |= R_RTC_RTCP_MUX;
    if (r_sdp_media_buf_has_attrib (media, "rtcp-mux-only", -1))
      rtcpflags |= R_RTC_RTCP_MUX | R_RTC_RTCP_MUX_ONLY;
    if (r_sdp_media_buf_has_attrib (media, "rtcp-rsize", -1))
      rtcpflags |= R_RTC_RTCP_RSIZE;

    if ((ssrcs = r_sdp_media_buf_source_specific_sources (media,
            &ssrccount)) != NULL) {
      RStrChunk cname = R_STR_CHUNK_INIT;
      RHashTable * fidmap = r_hash_table_new (NULL, NULL);
      RHashTable * revmap = r_hash_table_new (NULL, NULL);
      rchar * fecmechanism = NULL;

      /* Prepare FID SSRCs map encodings */
      start = 0;
      while (r_sdp_media_buf_ssrc_group_attrib (media,
            R_STR_WITH_SIZE_ARGS ("FID"), &chunk, &start) == R_SDP_OK) {
        const rchar * end;
        ruint32 ssrc[2];

        if ((ssrc[0] = r_str_to_int32 (chunk.str, &end, 10, NULL)) > 0) {
          while (end < chunk.str + chunk.size &&
              (ssrc[1] = r_str_to_int32 (end+1, &end, 10, NULL)) > 0) {
            r_hash_table_insert (fidmap, RUINT_TO_POINTER (ssrc[1]),
                RUINT_TO_POINTER (ssrc[0]));
            r_hash_table_insert (revmap, RUINT_TO_POINTER (ssrc[0]),
                RUINT_TO_POINTER (ssrc[1]));
          }
        }

        start++;
      }

      /* RTCP */
      r_sdp_media_buf_source_specific_media_attrib (media, ssrcs[0],
          R_STR_WITH_SIZE_ARGS ("cname"), &cname);
      r_rtc_rtp_parameters_set_rtcp (ret, cname.str, cname.size,
          ssrcs[0], rtcpflags);

      /* encodings */
      for (j = 0; j < r_rtc_rtp_parameters_codec_count (ret); j++) {
        codec = r_rtc_rtp_parameters_get_codec (ret, j);

        if (codec->kind == R_RTC_CODEC_KIND_FEC) {
          if (fecmechanism == NULL) {
            fecmechanism = r_strdup (codec->name);
          } else {
            rchar * newfecm = r_strprintf ("%s+%s", fecmechanism, codec->name);
            r_free (fecmechanism);
            fecmechanism = newfecm;
          }
          continue;
        }

        if (codec->kind == R_RTC_CODEC_KIND_RTX ||
            codec->kind == R_RTC_CODEC_KIND_SUPPLEMENTAL)
          continue;

        for (i = 0; i < ssrccount; i++) {
          if (r_hash_table_contains (fidmap, RUINT_TO_POINTER (ssrcs[i])) == R_HASH_TABLE_OK)
            continue;

          if ((encoding = r_rtc_rtp_encoding_parameters_new (ssrcs[i], codec->pt)) != NULL)
            r_rtc_rtp_parameters_take_encoding (ret, encoding);
        }
      }

      /* FEC for encodings */
      if (fecmechanism != NULL) {
        for (i = 0; i < r_rtc_rtp_parameters_encoding_count (ret); i++) {
          encoding = r_rtc_rtp_parameters_get_encoding (ret, i);

          encoding->fec.ssrc = (ruint32)RPOINTER_TO_SIZE (
              r_hash_table_lookup (revmap, RUINT_TO_POINTER (encoding->ssrc)));
          encoding->fec.mechanism = r_strdup (fecmechanism);
        }
      }

      /* RTX for encodings */
      for (j = 0; j < r_rtc_rtp_parameters_codec_count (ret); j++) {
        codec = r_rtc_rtp_parameters_get_codec (ret, j);

        if (codec->kind == R_RTC_CODEC_KIND_RTX) {
          rchar * apt;
          RRTPPayloadType pt;

          /* Find associated pt */
          if ((apt = r_str_ptr_of_str_case (codec->fmtp, -1, R_STR_WITH_SIZE_ARGS ("apt="))) == NULL)
            continue;
          if ((pt = r_str_to_uint8 (apt + 4, NULL, 10, NULL)) == 0)
            continue;

          for (i = 0; i < r_rtc_rtp_parameters_encoding_count (ret); i++) {
            encoding = r_rtc_rtp_parameters_get_encoding (ret, i);

            if (encoding->pt == pt)
              encoding->rtx.ssrc = (ruint32)RPOINTER_TO_SIZE (
                  r_hash_table_lookup (revmap, RUINT_TO_POINTER (encoding->ssrc)));
          }
        }
      }

      r_free (fecmechanism);
      r_hash_table_unref (fidmap);
      r_hash_table_unref (revmap);
      r_free (ssrcs);
    } else {
      r_rtc_rtp_parameters_set_rtcp (ret, NULL, 0, 0, rtcpflags);
    }

    /* header extensions */
    start = 0;
    while (r_sdp_media_buf_extmap_attrib (media, &extmapid, &chunk, &start) == R_SDP_OK) {
      RRtcRtpHdrExtParameters * hdrext;

      if ((hdrext = r_rtc_rtp_hdrext_parameters_new (chunk.str, chunk.size, extmapid)) != NULL)
        r_rtc_rtp_parameters_take_hdrext (ret, hdrext);
      start++;
    }
  }

  return ret;
}

static void
r_rtc_session_description_parse_sdp_transport (RRtcTransportInfo * trans,
    RSdpMediaBuf * media, RSdpBuf * sdp)
{
  const RStrChunk * cur;
  rsize i;

  /* FIXME: Support multiple c= lines */
  if (r_sdp_media_buf_port (media) != 0 && r_sdp_media_buf_port (media) != 9 &&
      r_sdp_media_buf_conn_count (media) == 1 && r_sdp_media_buf_conn_addrcount (media, 0) == 1) {
    trans->addr = r_sdp_media_buf_conn_to_socket_address (media, 0);
  }

  /* ICE */
  if ((trans->rtp.ice.ufrag = r_sdp_media_buf_attrib_dup_value (media, "ice-ufrag", -1, NULL)) == NULL)
    trans->rtp.ice.ufrag = r_sdp_buf_attrib_dup_value (sdp, "ice-ufrag", -1, NULL);
  if ((trans->rtp.ice.pwd = r_sdp_media_buf_attrib_dup_value (media, "ice-pwd", -1, NULL)) == NULL)
    trans->rtp.ice.pwd = r_sdp_buf_attrib_dup_value (sdp, "ice-pwd", -1, NULL);
  trans->rtp.ice.lite = r_sdp_media_buf_has_attrib (media, "ice-lite", -1) ||
    r_sdp_buf_has_attrib (sdp, "ice-lite", -1);

  /* DTLS */
  if ((cur = r_sdp_media_buf_attrib_find (media, "setup", -1, NULL)) != NULL ||
      (cur = r_sdp_buf_attrib_find (sdp, "setup", -1, NULL)) != NULL) {
    if (r_str_chunk_casecmp (cur, R_STR_WITH_SIZE_ARGS ("passive")) == 0)
      trans->rtp.dtls.role = R_RTC_ROLE_SERVER;
    else if (r_str_chunk_casecmp (cur, R_STR_WITH_SIZE_ARGS ("active")) == 0)
      trans->rtp.dtls.role = R_RTC_ROLE_CLIENT;
    else
      trans->rtp.dtls.role = R_RTC_ROLE_AUTO;

    if ((cur = r_sdp_media_buf_attrib_find (media, "fingerprint", -1, NULL)) != NULL ||
        (cur = r_sdp_buf_attrib_find (sdp, "fingerprint", -1, NULL)) != NULL) {
      RStrChunk md, f;
      if (r_str_chunk_split ((RStrChunk *)cur, " ", &md, &f, NULL) == 2) {
        if ((trans->rtp.dtls.md = r_msg_digest_type_from_str (md.str, md.size)) != R_MSG_DIGEST_TYPE_NONE)
          trans->rtp.dtls.fingerprint = r_str_chunk_dup (&f);
      }
    }
  }

  for (i = 0; (cur = r_sdp_media_buf_attrib_find (media, "candidate", -1, &i)) != NULL; i++) {
    RRtcIceCandidate * cand;

    if ((cand = r_rtc_ice_candidate_new_from_sdp_attrib_value (cur->str, cur->size)) != NULL) {
      switch (r_rtc_ice_candidate_get_component (cand)) {
        case R_RTC_ICE_COMPONENT_RTP:
          r_ptr_array_add (&trans->rtp.candidates, cand, r_rtc_ice_candidate_unref);
          break;
        case R_RTC_ICE_COMPONENT_RTCP:
          r_ptr_array_add (&trans->rtcp.candidates, cand, r_rtc_ice_candidate_unref);
          break;
        default:
          r_rtc_ice_candidate_unref (cand);
          break;
      }
    }
  }
  trans->rtp.endofcandidates = r_sdp_media_buf_has_attrib (media, "end-of-candidates", -1);
  trans->rtcp.endofcandidates = trans->rtp.endofcandidates;

  if (!trans->rtcpmux) {
    trans->rtcp.ice.ufrag = r_strdup (trans->rtp.ice.ufrag);
    trans->rtcp.ice.pwd   = r_strdup (trans->rtp.ice.pwd);
    trans->rtcp.ice.lite  = trans->rtp.ice.lite;

    trans->rtcp.dtls.role = trans->rtp.dtls.role;
    trans->rtcp.dtls.md   = trans->rtp.dtls.md;
    trans->rtcp.dtls.fingerprint = r_strdup (trans->rtp.dtls.fingerprint);
  }
}

static void
r_rtc_session_description_parse_sdp_mline (RRtcSessionDescription * sd,
    RSdpMediaBuf * media, RSdpBuf * sdp)
{
  const RStrChunk * mid;
  RStrChunk trans = R_STR_CHUNK_INIT;
  RStrChunk midchunk = R_STR_CHUNK_INIT;
  RRtcTransportInfo * tinfo;
  RRtcMediaLineInfo * mline;
  rboolean rtcpmux;
  RRtcMediaType mtype;
  RRtcDirection dir;

  if ((mid = r_sdp_media_buf_attrib_find (media, "mid", 3, NULL)) != NULL) {
    RStrChunk bundlegroup = R_STR_CHUNK_INIT;
    if (r_sdp_buf_find_grouping (sdp, &bundlegroup, R_STR_WITH_SIZE_ARGS ("BUNDLE"), mid->str, mid->size) != R_SDP_OK ||
        r_str_chunk_split (&bundlegroup, " ", &trans, NULL) < 1) {
      r_memcpy (&trans, mid, sizeof (RStrChunk));
    }
  } else {
    /* FIXME: Better way of generating some form of random??? */
    rsize hash, hashsize;
    if (r_sdp_media_buf_attrib_count (media) > 0)
      hashsize = media->attrib[media->acount - 1].val.str - media->type.str;
    else
      hashsize = r_str_idx_of_c (media->type.str, -1, '\n');
    hash = r_str_hash_sized (media->type.str, hashsize);
    midchunk.str = r_base64_encode_dup (RSIZE_TO_POINTER (hash), sizeof (rsize), &midchunk.size);
    mid = &midchunk;
    r_memcpy (&trans, mid, sizeof (RStrChunk));
  }

  rtcpmux = r_sdp_media_buf_has_attrib (media, "rtcp-mux", -1) ||
    r_sdp_buf_has_attrib (sdp, "rtcp-mux", -1);

  if (r_str_chunk_cmp (&media->type, R_STR_WITH_SIZE_ARGS ("audio")) == 0)
    mtype = R_RTC_MEDIA_AUDIO;
  else if (r_str_chunk_cmp (&media->type, R_STR_WITH_SIZE_ARGS ("video")) == 0)
    mtype = R_RTC_MEDIA_VIDEO;
  else if (r_str_chunk_cmp (&media->type, R_STR_WITH_SIZE_ARGS ("application")) == 0)
    mtype = R_RTC_MEDIA_APPLICATION;
  else
    mtype = R_RTC_MEDIA_UNKNOWN;

  if (r_sdp_media_buf_has_attrib (media, "sendrecv", -1))
    dir = R_RTC_DIR_SEND_RECV;
  else if (r_sdp_media_buf_has_attrib (media, "sendonly", -1))
    dir = R_RTC_DIR_SEND_ONLY;
  else if (r_sdp_media_buf_has_attrib (media, "recvonly", -1))
    dir = R_RTC_DIR_RECV_ONLY;
  else
    dir = R_RTC_DIR_NONE;

  /* TRANSPORT */
  if ((tinfo = r_rtc_transport_info_new (mid->str, mid->size, rtcpmux)) != NULL) {
    r_rtc_session_description_parse_sdp_transport (tinfo, media, sdp);
    r_rtc_session_description_take_transport (sd, tinfo);
  }

  /* MEDIA LINE */
  if ((mline = r_rtc_media_line_info_new (mid->str, mid->size, mtype, dir,
          media->proto.str, media->proto.size)) != NULL) {
    mline->params = r_rtc_session_description_create_sdp_rtp_params (mline->mid, media, sdp);
    mline->trans = r_str_chunk_dup (&trans);
    r_rtc_session_description_take_media_line (sd, mline);
  }

  r_free (midchunk.str);
}

static void
r_rtc_session_description_parse_sdp (RRtcSessionDescription * sd, RSdpBuf * sdp)
{
  rsize i;

  sd->username = r_sdp_buf_orig_username (sdp);
  sd->session_name = r_sdp_buf_session_name (sdp);
  sd->session_id = r_sdp_buf_orig_session_id (sdp);
  sd->session_ver = r_sdp_buf_orig_session_version_u64 (sdp);
  sd->orig_nettype = r_sdp_buf_orig_nettype (sdp);
  sd->orig_addrtype = r_sdp_buf_orig_addrtype (sdp);
  sd->orig_addr = r_sdp_buf_orig_addr (sdp);
  sd->conn_nettype = r_sdp_buf_conn_nettype (sdp);
  sd->conn_addrtype = r_sdp_buf_conn_addrtype (sdp);
  sd->conn_addr = r_sdp_buf_conn_addr (sdp);

  for (i = 0; i < r_sdp_buf_media_count (sdp); i++)
    r_rtc_session_description_parse_sdp_mline (sd, &sdp->media[i], sdp);
}

RRtcSessionDescription *
r_rtc_session_description_new_from_sdp (RRtcSignalType type,
    RBuffer * buf, RRtcError * error)
{
  RRtcSessionDescription * ret;
  RSdpBuf sdp;

  if (R_UNLIKELY (buf == NULL)) {
    if (error != NULL) *error = R_RTC_INVAL;
    return NULL;
  }

  if ((ret = r_rtc_session_description_new (type)) != NULL) {
    if (r_sdp_buffer_map (&sdp, buf) == R_SDP_OK) {
      ret->data = r_buffer_ref (buf);
      ret->notify = r_buffer_unref;
      r_rtc_session_description_parse_sdp (ret, &sdp);
      if (error != NULL) *error = R_RTC_OK;
    } else {
      r_rtc_session_description_unref (ret);
      ret = NULL;
      if (error != NULL) *error = R_RTC_MAP_ERROR;
    }
    r_sdp_buffer_unmap (&sdp, buf);
  } else {
    if (error != NULL) *error = R_RTC_OOM;
  }

  return ret;
}

RRtcError
r_rtc_session_description_take_transport (RRtcSessionDescription * sd,
    RRtcTransportInfo * transport)
{
  if (R_UNLIKELY (transport == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (transport->id == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (r_hash_table_contains (sd->transport, transport->id) == R_HASH_TABLE_OK))
    return R_RTC_ALREADY_FOUND;

  r_hash_table_insert (sd->transport, transport->id, transport);
  return R_RTC_OK;
}

RRtcError
r_rtc_session_description_take_media_line (RRtcSessionDescription * sd,
    RRtcMediaLineInfo * mline)
{
  if (R_UNLIKELY (mline == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (mline->mid == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (r_hash_table_contains (sd->mline, mline->mid) == R_HASH_TABLE_OK))
    return R_RTC_ALREADY_FOUND;

  r_hash_table_insert (sd->mline, mline->mid, mline);
  return R_RTC_OK;
}

