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

  if (r->loop != NULL)
    r_ev_loop_unref (r->loop);
  if (r->notify != NULL)
    r->notify (r->data);

  r_free (r->id);
  r_free (r);
}

static void
r_rtc_rtp_receiver_crypto_ready (rpointer data, rpointer ctx)
{
  RRtcRtpReceiver * s = data;
  RRtcCryptoTransport * crypto = ctx;

  (void) s;
  (void) crypto;
}

static void
r_rtc_rtp_receiver_crypto_close (rpointer data, rpointer ctx)
{
  RRtcRtpReceiver * s = data;
  RRtcCryptoTransport * crypto = ctx;

  (void) s;
  (void) crypto;
}

static void
r_rtc_rtp_receiver_crypto_null_packet (rpointer data, RBuffer * buf, rpointer ctx)
{
  RRtcRtpReceiver * s = data;
  RRtcCryptoTransport * crypto = ctx;

  (void) buf;

  R_LOG_WARNING ("RTP packet on RTCP only transport? "
      "(RRtcRtpReceiver: %p RRtcCryptoTransport: %p)", s, crypto);
}

static void
r_rtc_rtp_receiver_crypto_rtp_packet (rpointer data, RBuffer * buf, rpointer ctx)
{
  RRtcRtpReceiver * s = data;
  RRtcCryptoTransport * crypto = ctx;

  (void) crypto;

  s->cbs.rtp (s->data, buf, s);
}

static void
r_rtc_rtp_receiver_crypto_rtcp_packet (rpointer data, RBuffer * buf, rpointer ctx)
{
  RRtcRtpReceiver * s = data;
  RRtcCryptoTransport * crypto = ctx;

  (void) crypto;

  s->cbs.rtcp (s->data, buf, s);
}


RRtcRtpReceiver *
r_rtc_rtp_receiver_new (const rchar * id, rssize size, RPrng * prng,
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

    if (size < 0) size = r_strlen (id);
    if ((ret->id = r_strdup_size (id, size)) == NULL) {
      ret->id = r_malloc (24 + 1);
      r_prng_fill_base64 (prng, ret->id, 24);
      ret->id[24] = 0;
    }
    r_memcpy (&ret->cbs, cbs, sizeof (RRtcRtpReceiverCallbacks));
    ret->data = data;
    ret->notify = notify;
    ret->rtp = r_rtc_crypto_transport_ref (rtp);
    ret->rtcp = r_rtc_crypto_transport_ref (rtcp);

    /* FIXME: For now, set_cb,
     * this should relly be add_cb which is handled by internal RRtcRtpListener
     */
    r_rtc_crypto_transport_set_cb (ret->rtp,
        r_rtc_rtp_receiver_crypto_ready, r_rtc_rtp_receiver_crypto_close,
        r_rtc_rtp_receiver_crypto_rtp_packet, r_rtc_rtp_receiver_crypto_rtcp_packet,
        ret, NULL);
    if (ret->rtp != ret->rtcp) {
      r_rtc_crypto_transport_set_cb (ret->rtcp,
          r_rtc_rtp_receiver_crypto_ready, r_rtc_rtp_receiver_crypto_close,
          r_rtc_rtp_receiver_crypto_null_packet, r_rtc_rtp_receiver_crypto_rtcp_packet,
          ret, NULL);
    }
  }

  return ret;
}

const rchar *
r_rtc_rtp_receiver_get_id (RRtcRtpReceiver * r)
{
  return r->id;
}

RRtcError
r_rtc_rtp_receiver_start (RRtcRtpReceiver * r, REvLoop * loop)
{
  if (R_UNLIKELY (loop == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (r->loop != NULL)) return R_RTC_WRONG_STATE;

  r->loop = r_ev_loop_ref (loop);
  r_rtc_crypto_transport_start (r->rtp, r->loop);
  r_rtc_crypto_transport_start (r->rtcp, r->loop);

  return R_RTC_OK;
}

#if 0
RRtcError
r_rtc_rtp_receiver_close (RRtcRtpReceiver * r)
{
}
#endif

