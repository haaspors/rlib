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
#include <rlib/rtc/rrtcrtptransceiver.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

static void
r_rtc_rtp_transceiver_free (RRtcRtpTransceiver * t)
{
  if (t->recv != NULL)
    r_rtc_rtp_receiver_unref (t->recv);
  if (t->send != NULL)
    r_rtc_rtp_sender_unref (t->send);

  if (t->loop != NULL)
    r_ev_loop_unref (t->loop);

  r_free (t->id);
  r_free (t);
}

RRtcRtpTransceiver *
r_rtc_rtp_transceiver_new (const rchar * id, rssize size)
{
  RRtcRtpTransceiver * ret;

  if ((ret = r_mem_new0 (RRtcRtpTransceiver)) != NULL) {
    r_ref_init (ret, r_rtc_rtp_transceiver_free);

    ret->id = r_strdup_size (id, size);
  }

  return ret;
}

const rchar *
r_rtc_rtp_transceiver_get_id (RRtcRtpTransceiver * t)
{
  return t->id;
}

RRtcError
r_rtc_rtp_transceiver_start (RRtcRtpTransceiver * t, REvLoop * loop)
{
  if (R_UNLIKELY (loop == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (t->loop != NULL)) return R_RTC_WRONG_STATE;

  t->loop = r_ev_loop_ref (loop);
  if (t->recv != NULL)
    r_rtc_rtp_receiver_start (t->recv, loop);
  if (t->send != NULL)
    r_rtc_rtp_sender_start (t->send, loop);

  return R_RTC_OK;
}

#if 0
RRtcError
r_rtc_rtp_transceiver_close (RRtcRtpTransceiver * t)
{
}
#endif

RRtcRtpReceiver *
r_rtc_rtp_transceiver_get_receiver (RRtcRtpTransceiver * t)
{
  if (t->recv != NULL)
    r_rtc_rtp_receiver_ref (t->recv);

  return t->recv;
}

RRtcRtpSender *
r_rtc_rtp_transceiver_get_sender (RRtcRtpTransceiver * t)
{
  if (t->send != NULL)
    r_rtc_rtp_sender_ref (t->send);

  return t->send;
}

RRtcError
r_rtc_rtp_transceiver_set_receiver (RRtcRtpTransceiver * t, RRtcRtpReceiver * receiver)
{
  if (R_UNLIKELY (receiver == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (t->recv != NULL)) return R_RTC_WRONG_STATE;

  t->recv = r_rtc_rtp_receiver_ref (receiver);

  if (t->loop != NULL)
    r_rtc_rtp_receiver_start (t->recv, t->loop);

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_transceiver_set_sender (RRtcRtpTransceiver * t, RRtcRtpSender * sender)
{
  if (R_UNLIKELY (sender == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (t->send != NULL)) return R_RTC_WRONG_STATE;

  t->send = r_rtc_rtp_receiver_ref (sender);

  if (t->loop != NULL)
    r_rtc_rtp_sender_start (t->send, t->loop);

  return R_RTC_OK;
}

