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
#include <rlib/rtc/rrtcrtplistener.h>

#include <rlib/data/rhashfuncs.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

/* RFC 8843 signals a bundled stream's MID in an RFC 8285 header
 * extension carrying this URI. */
#define R_RTC_RTP_HDREXT_MID  "urn:ietf:params:rtp-hdrext:sdes:mid"

static void
r_rtc_rtp_listener_free (RRtcRtpListener * l)
{
  r_hash_table_unref (l->send_ssrcmap);
  r_hash_table_unref (l->recv_ptmap);
  r_hash_table_unref (l->recv_extmap);
  r_hash_table_unref (l->recv_ssrcmap);
  r_ptr_array_unref (l->send);
  r_ptr_array_unref (l->recv);
  r_free (l);
}

RRtcRtpListener *
r_rtc_rtp_listener_new (void)
{
  RRtcRtpListener * ret;

  if ((ret = r_mem_new0 (RRtcRtpListener)) != NULL) {
    r_ref_init (ret, r_rtc_rtp_listener_free);

    ret->recv = r_ptr_array_new ();
    ret->send = r_ptr_array_new ();
    ret->recv_ssrcmap = r_hash_table_new (NULL, NULL);
    ret->recv_extmap = r_hash_table_new (r_str_hash, r_str_equal);
    ret->recv_ptmap = r_hash_table_new (NULL, NULL);
    ret->send_ssrcmap = r_hash_table_new (NULL, NULL);
  }

  return ret;
}

/* Locate the RFC 8285 header-extension element with id @id and return
 * its value pointer / length. Handles both the one-byte (0xBEDE) and
 * two-byte (0x100n) profiles. */
static rboolean
r_rtc_rtp_ext_element (const RRTPBuffer * rtp, ruint16 id,
    const ruint8 ** out, rsize * outsize)
{
  ruint16 profile, size;
  const ruint8 * data;
  rsize p = 0;

  if (id == 0 || !r_rtp_buffer_get_extension (rtp, &profile, &data, &size))
    return FALSE;

  if (profile == 0xBEDE) {
    while (p < size) {
      ruint8 eid = data[p] >> 4;
      ruint8 elen = (data[p] & 0x0F) + 1;
      p++;
      if (eid == 0)             /* padding */
        continue;
      if (eid == 15)            /* reserved: stop parsing (RFC 8285 4.2) */
        break;
      if (p + elen > size)
        break;
      if (eid == id) {
        *out = data + p;
        *outsize = elen;
        return TRUE;
      }
      p += elen;
    }
  } else if ((profile & 0xFFF0) == 0x1000) {
    while (p < size) {
      ruint8 eid = data[p++];
      ruint8 elen;
      if (eid == 0)             /* padding */
        continue;
      if (p >= size)            /* truncated: missing length octet */
        break;
      elen = data[p++];
      if (p + elen > size)
        break;
      if (eid == id) {
        *out = data + p;
        *outsize = elen;
        return TRUE;
      }
      p += elen;
    }
  }

  return FALSE;
}

RRtcError
r_rtc_rtp_listener_handle_rtp (RRtcRtpListener * l,
    RBuffer * buf, RRtcCryptoTransport * t)
{
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;
  RRtcRtpReceiver * r;

  (void) t;

  /* FIXME: Only enable this if flag set?  */
  if (r_hash_table_size (l->recv_ssrcmap) == 0 &&
      r_hash_table_size (l->recv_extmap) == 0 &&
      r_hash_table_size (l->recv_ptmap) == 0) {
    rsize i, c;
    if ((c = r_ptr_array_size (l->recv)) > 0) {
      for (i = 0; i < c; i++) {
        r = r_ptr_array_get (l->recv, i);
        r->cbs.rtp (r->data, buf, r);
      }
      return R_RTC_OK;
    }
  }

  if (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ)) {
    if ((r = r_hash_table_lookup (l->recv_ssrcmap,
            RSIZE_TO_POINTER (r_rtp_buffer_get_ssrc (&rtp)))) != NULL) {
      r_rtp_buffer_unmap (&rtp, buf);
      r->cbs.rtp (r->data, buf, r);
      return R_RTC_OK;
    }

    /* Bundled streams (RFC 8843) carry their MID in an RFC 8285 header
     * extension until their SSRC is observed. Route on the MID, then
     * remember the SSRC so subsequent packets take the fast path above. */
    if (l->recv_mid_ext_id != 0 && r_hash_table_size (l->recv_extmap) > 0) {
      const ruint8 * mid;
      rsize midsize;

      if (r_rtc_rtp_ext_element (&rtp, l->recv_mid_ext_id, &mid, &midsize) &&
          midsize < 256) {
        rchar key[256];

        r_memcpy (key, mid, midsize);
        key[midsize] = 0;
        if ((r = r_hash_table_lookup (l->recv_extmap, key)) != NULL) {
          r_hash_table_insert (l->recv_ssrcmap,
              RSIZE_TO_POINTER (r_rtp_buffer_get_ssrc (&rtp)), r);
          r_rtp_buffer_unmap (&rtp, buf);
          r->cbs.rtp (r->data, buf, r);
          return R_RTC_OK;
        }
      }
    }

    if ((r = r_hash_table_lookup (l->recv_ptmap,
            RSIZE_TO_POINTER (r_rtp_buffer_get_pt (&rtp)))) != NULL) {
      r_rtp_buffer_unmap (&rtp, buf);
      r->cbs.rtp (r->data, buf, r);
      return R_RTC_OK;
    }

    r_rtp_buffer_unmap (&rtp, buf);
  } else {
    return R_RTC_MAP_ERROR;
  }

  return R_RTC_NO_HANDLER;
}

RRtcError
r_rtc_rtp_listener_handle_rtcp (RRtcRtpListener * l,
    RBuffer * buf, RRtcCryptoTransport * t)
{
  RRtcRtpReceiver * r;
  rsize i, c;

  (void) t;

  for (i = 0, c = r_ptr_array_size (l->recv); i < c; i++) {
    r = r_ptr_array_get (l->recv, i);
    r->cbs.rtcp (r->data, buf, r);
  }

  /* Also fan out to senders -- receiver reports / NACK / PLI for our
   * outbound streams ride on incoming RTCP and senders need a way to
   * see them.  The rtcp callback is optional. */
  for (i = 0, c = r_ptr_array_size (l->send); i < c; i++) {
    RRtcRtpSender * s = r_ptr_array_get (l->send, i);
    if (s->cbs.rtcp != NULL)
      s->cbs.rtcp (s->data, buf, s);
  }

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_notify_ready (RRtcRtpListener * l, RRtcCryptoTransport * t)
{
  rsize i, c;

  (void) t;

  for (i = 0, c = r_ptr_array_size (l->recv); i < c; i++) {
    RRtcRtpReceiver * r = r_ptr_array_get (l->recv, i);
    r->cbs.ready (r->data, r);
  }

  for (i = 0, c = r_ptr_array_size (l->send); i < c; i++) {
    RRtcRtpSender * s = r_ptr_array_get (l->send, i);
    s->cbs.ready (s->data, s);
  }

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_notify_close (RRtcRtpListener * l, RRtcCryptoTransport * t)
{
  rsize i, c;

  (void) t;

  for (i = 0, c = r_ptr_array_size (l->recv); i < c; i++) {
    RRtcRtpReceiver * r = r_ptr_array_get (l->recv, i);
    r->cbs.close (r->data, r);
  }

  for (i = 0, c = r_ptr_array_size (l->send); i < c; i++) {
    RRtcRtpSender * s = r_ptr_array_get (l->send, i);
    s->cbs.close (s->data, s);
  }

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_add_receiver (RRtcRtpListener * l, RRtcRtpReceiver * r)
{
  if (R_UNLIKELY (r_ptr_array_find (l->recv, r) != R_PTR_ARRAY_INVALID_IDX))
    return R_RTC_ALREADY_FOUND;
  r_ptr_array_add (l->recv, r, NULL);

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_add_sender (RRtcRtpListener * l, RRtcRtpSender * s)
{
  if (R_UNLIKELY (r_ptr_array_find (l->send, s) != R_PTR_ARRAY_INVALID_IDX))
    return R_RTC_ALREADY_FOUND;
  r_ptr_array_add (l->send, s, NULL);

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_remove_receiver (RRtcRtpListener * l, RRtcRtpReceiver * r)
{
  /* Drop any ssrc/pt/extension demux mappings that pointed at this
   * receiver before forgetting it -- otherwise the next packet matching
   * one of those keys would dispatch to a now-stale pointer. */
  r_hash_table_remove_all_values (l->recv_ssrcmap, r);
  r_hash_table_remove_all_values (l->recv_extmap, r);
  r_hash_table_remove_all_values (l->recv_ptmap, r);
  r_ptr_array_remove_first_fast (l->recv, r);
  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_remove_sender (RRtcRtpListener * l, RRtcRtpSender * s)
{
  r_hash_table_remove_all_values (l->send_ssrcmap, s);
  r_ptr_array_remove_first_fast (l->send, s);
  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_update_receiver (RRtcRtpListener * l,
    RRtcRtpReceiver * r, RRtcRtpParameters * params)
{
  rsize i, c;

  if (R_UNLIKELY (r == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (params == NULL)) return R_RTC_INVAL;

  r_hash_table_remove_all_values (l->recv_ssrcmap, r);
  r_hash_table_remove_all_values (l->recv_extmap, r);
  r_hash_table_remove_all_values (l->recv_ptmap, r);

  for (i = 0, c = r_ptr_array_size (&params->encodings); i < c; i++) {
    RRtcRtpEncodingParameters * encp = r_ptr_array_get (&params->encodings, i);
    if (encp->ssrc != 0)
      r_hash_table_insert (l->recv_ssrcmap, RSIZE_TO_POINTER (encp->ssrc), r);
    if (encp->rtx.ssrc != 0)
      r_hash_table_insert (l->recv_ssrcmap, RSIZE_TO_POINTER (encp->rtx.ssrc), r);
    if (encp->fec.ssrc != 0)
      r_hash_table_insert (l->recv_ssrcmap, RSIZE_TO_POINTER (encp->fec.ssrc), r);
  }
  /* A negotiated MID header extension lets us demux this receiver's
   * bundled stream before its SSRC is learned (see handle_rtp). The id
   * is consistent across a BUNDLE group (RFC 8843), so the last one
   * wins for the listener. */
  for (i = 0, c = r_ptr_array_size (&params->extensions); i < c; i++) {
    RRtcRtpHdrExtParameters * extp = r_ptr_array_get (&params->extensions, i);
    if (extp->uri != NULL && r_str_equals (extp->uri, R_RTC_RTP_HDREXT_MID)) {
      l->recv_mid_ext_id = extp->id;
      if (r->mid != NULL)
        r_hash_table_insert (l->recv_extmap, r->mid, r);
    }
  }

  for (i = 0, c = r_ptr_array_size (&params->codecs); i < c; i++) {
    RRtcRtpCodecParameters * codecp = r_ptr_array_get (&params->codecs, i);
    r_hash_table_insert (l->recv_ptmap, RSIZE_TO_POINTER (codecp->pt), r);
  }

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_update_sender (RRtcRtpListener * l,
    RRtcRtpSender * s, RRtcRtpParameters * params)
{
  if (R_UNLIKELY (s == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (params == NULL)) return R_RTC_INVAL;

  r_hash_table_remove_all_values (l->send_ssrcmap, s);

  /* TODO */
  /*r_hash_table_insert (l->send_ssrcmap, RSIZE_TO_POINTER (0), s);*/
  return R_RTC_OK;
}

