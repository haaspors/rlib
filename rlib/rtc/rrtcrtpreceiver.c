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
#include <rlib/rtc/rrtcrtpreceiver.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

static void
r_rtc_rtp_receiver_free (RRtcRtpReceiver * r)
{
  r_rtc_crypto_transport_unref (r->rtp);
  r_rtc_crypto_transport_unref (r->rtcp);

  if (r->params != NULL)
    r_rtc_rtp_parameters_unref (r->params);
  if (r->notify != NULL)
    r->notify (r->data);

  r_free (r->mid);
  r_free (r);
}


RRtcRtpReceiver *
r_rtc_rtp_receiver_new (RPrng * prng, const rchar * mid, rssize size,
    const RRtcRtpReceiverCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp)
{
  RRtcRtpReceiver * ret;

  if (R_UNLIKELY (prng == NULL)) return NULL;
  if (R_UNLIKELY (cbs == NULL)) return NULL;
  if (R_UNLIKELY (cbs->ready == NULL || cbs->close == NULL)) return NULL;
  if (R_UNLIKELY (cbs->rtp == NULL || cbs->rtcp == NULL)) return NULL;
  if (R_UNLIKELY (rtp == NULL)) return NULL;
  if (R_UNLIKELY (rtcp == NULL)) rtcp = rtp;

  if ((ret = r_mem_new0 (RRtcRtpReceiver)) != NULL) {
    r_ref_init (ret, r_rtc_rtp_receiver_free);

    ret->mid = r_strdup_size (mid, size);
    r_memcpy (&ret->cbs, cbs, sizeof (RRtcRtpReceiverCallbacks));
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
r_rtc_rtp_receiver_get_id (RRtcRtpReceiver * r)
{
  return r->id;
}

const rchar *
r_rtc_rtp_receiver_get_mid (RRtcRtpReceiver * r)
{
  return r->mid;
}

RRtcError
r_rtc_rtp_receiver_start (RRtcRtpReceiver * r,
    RRtcRtpParameters * params, REvLoop * loop)
{
  if (R_UNLIKELY (params == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (loop == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (r->params != NULL)) return R_RTC_WRONG_STATE;

  r->params = r_rtc_rtp_parameters_ref (params);

  r_rtc_crypto_transport_add_receiver (r->rtp, r);
  r_rtc_crypto_transport_update_receiver (r->rtp, r, params);
  if (r->rtp != r->rtcp) {
    r_rtc_crypto_transport_add_receiver (r->rtcp, r);
    r_rtc_crypto_transport_update_receiver (r->rtcp, r, params);
  }

  r_rtc_crypto_transport_start (r->rtp, loop);
  r_rtc_crypto_transport_start (r->rtcp, loop);

  return R_RTC_OK;
}

RRtcError
r_rtc_rtp_receiver_stop (RRtcRtpReceiver * r)
{
  if (R_UNLIKELY (r->params == NULL)) return R_RTC_WRONG_STATE;

  r_rtc_rtp_parameters_unref (r->params);
  r->params = NULL;

  if (r->rtp != r->rtcp)
    r_rtc_crypto_transport_remove_receiver (r->rtcp, r);
  return r_rtc_crypto_transport_remove_receiver (r->rtp, r);
}

