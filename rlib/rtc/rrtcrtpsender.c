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
#include <rlib/rtc/rrtcrtpsender.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

static void
r_rtc_rtp_sender_free (RRtcRtpSender * s)
{
  r_rtc_crypto_transport_unref (s->rtp);
  r_rtc_crypto_transport_unref (s->rtcp);

  if (s->loop != NULL)
    r_ev_loop_unref (s->loop);

  r_free (s->id);
  r_free (s);
}

RRtcRtpSender *
r_rtc_rtp_sender_new (const rchar * id, rssize size, RPrng * prng,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp)
{
  RRtcRtpSender * ret;

  if (R_UNLIKELY (prng == NULL)) return NULL;
  if (R_UNLIKELY (rtp == NULL)) return NULL;
  if (R_UNLIKELY (rtcp == NULL)) rtcp = rtp;

  if ((ret = r_mem_new0 (RRtcRtpSender)) != NULL) {
    r_ref_init (ret, r_rtc_rtp_sender_free);

    if (size < 0) size = r_strlen (id);
    if ((ret->id = r_strdup_size (id, size)) == NULL) {
      ret->id = r_malloc (24 + 1);
      r_prng_fill_base64 (prng, ret->id, 24);
      ret->id[24] = 0;
    }
    ret->rtp = r_rtc_crypto_transport_ref (rtp);
    ret->rtcp = r_rtc_crypto_transport_ref (rtcp);
  }

  return ret;
}

const rchar *
r_rtc_rtp_sender_get_id (RRtcRtpSender * s)
{
  return s->id;
}

RRtcError
r_rtc_rtp_sender_start (RRtcRtpSender * s, REvLoop * loop)
{
  if (R_UNLIKELY (loop == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (s->loop != NULL)) return R_RTC_WRONG_STATE;

  s->loop = r_ev_loop_ref (loop);
  r_rtc_crypto_transport_start (s->rtp, loop);
  r_rtc_crypto_transport_start (s->rtcp, loop);

  return R_RTC_OK;
}

#if 0
RRtcError
r_rtc_rtp_sender_close (RRtcRtpSender * s)
{
}
#endif

RRtcError
r_rtc_rtp_sender_send (RRtcRtpSender * s, RBuffer * packet)
{
  if (R_UNLIKELY (packet == NULL)) return R_RTC_INVAL;

  /* FIXME: rtcp? */
  return r_rtc_crypto_transport_send (s->rtp, packet);
}

