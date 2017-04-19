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

  if (s->params != NULL)
    r_rtc_rtp_parameters_unref (s->params);
  if (s->notify != NULL)
    s->notify (s->data);

  r_free (s->mid);
  r_free (s);
}

RRtcRtpSender *
r_rtc_rtp_sender_new (RPrng * prng, const rchar * mid, rssize size,
    const RRtcRtpSenderCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp)
{
  RRtcRtpSender * ret;

  if (R_UNLIKELY (prng == NULL)) return NULL;
  if (R_UNLIKELY (cbs == NULL)) return NULL;
  if (R_UNLIKELY (cbs->ready == NULL || cbs->close == NULL)) return NULL;
  if (R_UNLIKELY (rtp == NULL)) return NULL;
  if (R_UNLIKELY (rtcp == NULL)) rtcp = rtp;

  if ((ret = r_mem_new0 (RRtcRtpSender)) != NULL) {
    r_ref_init (ret, r_rtc_rtp_sender_free);

    ret->mid = r_strdup_size (mid, size);
    r_memcpy (&ret->cbs, cbs, sizeof (RRtcRtpSenderCallbacks));
    ret->data = data;
    ret->notify = notify;
    ret->rtp = r_rtc_crypto_transport_ref (rtp);
    ret->rtcp = r_rtc_crypto_transport_ref (rtcp);

    r_prng_fill_base64 (prng, ret->id, 24);
    ret->id[24] = 0;
  }

  return ret;
}

const rchar *
r_rtc_rtp_sender_get_id (RRtcRtpSender * s)
{
  return s->id;
}

const rchar *
r_rtc_rtp_sender_get_mid (RRtcRtpSender * s)
{
  return s->mid;
}

RRtcError
r_rtc_rtp_sender_start (RRtcRtpSender * s,
    RRtcRtpParameters * params, REvLoop * loop)
{
  if (R_UNLIKELY (params == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (loop == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (s->params != NULL)) return R_RTC_WRONG_STATE;

  s->params = r_rtc_rtp_parameters_ref (params);

  r_rtc_crypto_transport_add_sender (s->rtp, s);
  r_rtc_crypto_transport_update_sender (s->rtp, s, params);
  if (s->rtp != s->rtcp) {
    r_rtc_crypto_transport_add_sender (s->rtcp, s);
    r_rtc_crypto_transport_update_sender (s->rtcp, s, params);
  }

  r_rtc_crypto_transport_start (s->rtp, loop);
  r_rtc_crypto_transport_start (s->rtcp, loop);

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_sender_stop (RRtcRtpSender * s)
{
  if (R_UNLIKELY (s->params == NULL)) return R_RTC_WRONG_STATE;

  r_rtc_rtp_parameters_unref (s->params);
  s->params = NULL;

  if (s->rtp != s->rtcp)
    r_rtc_crypto_transport_remove_sender (s->rtcp, s);
  return r_rtc_crypto_transport_remove_sender (s->rtp, s);
}

RRtcError
r_rtc_rtp_sender_send (RRtcRtpSender * s, RBuffer * packet)
{
  if (R_UNLIKELY (packet == NULL)) return R_RTC_INVAL;

  /* FIXME: rtcp? */
  return r_rtc_crypto_transport_send (s->rtp, packet);
}

