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

#include <rlib/rmem.h>

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
    ret->recv_extmap = r_hash_table_new (NULL, NULL);
    ret->recv_ptmap = r_hash_table_new (NULL, NULL);
    ret->send_ssrcmap = r_hash_table_new (NULL, NULL);
  }

  return ret;
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

    /* FIXME: recv_extmap */

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

  /* FIXME send receiver reports to senders? */

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
  r_ptr_array_remove_first_fast (l->recv, r);
  /* FIXME: Remove from recv_* hash tables as well! */
  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_remove_sender (RRtcRtpListener * l, RRtcRtpSender * s)
{
  r_ptr_array_remove_first_fast (l->send, s);
  /* FIXME: Remove from send_* hash tables as well! */
  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_update_receiver (RRtcRtpListener * l,
    RRtcRtpReceiver * r, RRtcRtpParameters * params)
{
  rsize i, c, ssrcs = 0;

  if (R_UNLIKELY (r == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (params == NULL)) return R_RTC_INVAL;

  r_hash_table_remove_all_values (l->recv_ssrcmap, r);
  r_hash_table_remove_all_values (l->recv_extmap, r);
  r_hash_table_remove_all_values (l->recv_ptmap, r);

  for (i = 0, c = r_ptr_array_size (&params->encodings); i < c; i++) {
    RRtcRtpEncodingParameters * encp = r_ptr_array_get (&params->encodings, i);
    if (encp->ssrc != 0)
      r_hash_table_insert (l->recv_ssrcmap, RSIZE_TO_POINTER (encp->ssrc), r), ssrcs++;
    if (encp->rtx.ssrc != 0)
      r_hash_table_insert (l->recv_ssrcmap, RSIZE_TO_POINTER (encp->rtx.ssrc), r), ssrcs++;
    if (encp->fec.ssrc != 0)
      r_hash_table_insert (l->recv_ssrcmap, RSIZE_TO_POINTER (encp->fec.ssrc), r), ssrcs++;
  }
  /* FIXME: update mid against mux table */
  for (i = 0, c = r_ptr_array_size (&params->codecs); i < c; i++) {
    RRtcRtpCodecParameters * codecp = r_ptr_array_get (&params->encodings, i);
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

