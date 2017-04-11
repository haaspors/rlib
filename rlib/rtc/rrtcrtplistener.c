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

  /* TODO: Temporary filter. which will only work with one receiver obviously */
  if ((r = r_hash_table_lookup (l->recv_ssrcmap, RSIZE_TO_POINTER (0))) != NULL)
    goto process;

  if (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ)) {
    ruint32 ssrc = r_rtp_buffer_get_ssrc (&rtp);
    if ((r = r_hash_table_lookup (l->recv_ssrcmap, RSIZE_TO_POINTER (ssrc))) != NULL) {
      r_rtp_buffer_unmap (&rtp, buf);
      goto process;
    }

    /* FIXME: extmap */

    r_rtp_buffer_unmap (&rtp, buf);
  } else {
    return R_RTC_MAP_ERROR;
  }

  return R_RTC_NO_HANDLER;
process:
  r->cbs.rtp (r->data, buf, r);
  return R_RTC_OK;
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
  r_ptr_array_add (l->recv, r, NULL);
  r_hash_table_insert (l->recv_ssrcmap, RSIZE_TO_POINTER (0), r);

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_listener_add_sender (RRtcRtpListener * l, RRtcRtpSender * s)
{
  r_ptr_array_add (l->send, s, NULL);
  r_hash_table_insert (l->send_ssrcmap, RSIZE_TO_POINTER (0), s);

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

