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
#include <rlib/rtc/rrtccryptotransport.h>

#include <rlib/rassert.h>
#include <rlib/rstr.h>

static void
r_rtc_crypto_transport_ice_ready (rpointer data, rpointer ctx)
{
  RRtcCryptoTransport * crypto = data;
  RRtcIceTransport * ice = ctx;

  r_assert_cmpptr (ice, ==, crypto->ice);

  R_LOG_TRACE ("RtcCryptoTransport %p ice ready %p", crypto, ice);
  /* FIXME: Do something? */
}

static void
r_rtc_crypto_transport_ice_close (rpointer data, rpointer ctx)
{
  RRtcCryptoTransport * crypto = data;
  RRtcIceTransport * ice = ctx;

  r_assert_cmpptr (ice, ==, crypto->ice);

  /* FIXME: State change? */
  r_rtc_ice_transport_clear_cb (crypto->ice);
  r_rtc_rtp_listener_notify_close (crypto->listener, crypto);
}

void
r_rtc_crypto_transport_init (rpointer rtc, RRtcIceTransport * ice,
    RDestroyNotify destroy, RRtcStart start,
    RRtcBufferCb recv, RRtcBufferSend send)
{
  RRtcCryptoTransport * crypto = rtc;

  R_LOG_TRACE ("Init RtcCryptoTransport %p", crypto);
  r_ref_init (crypto, destroy);
  crypto->listener = r_rtc_rtp_listener_new ();
  crypto->loop = NULL;
  crypto->ice = r_rtc_ice_transport_ref (ice);
  crypto->send = send;
  crypto->start = start;

  r_rtc_ice_transport_set_cb (crypto->ice,
      r_rtc_crypto_transport_ice_ready, r_rtc_crypto_transport_ice_close,
      recv, crypto, NULL);
}

void
r_rtc_crypto_transport_clear (RRtcCryptoTransport * crypto)
{
  if (crypto->ice != NULL) {
    r_rtc_ice_transport_close (crypto->ice);
    r_rtc_ice_transport_clear_cb (crypto->ice);
    r_rtc_ice_transport_unref (crypto->ice);
  }

  r_rtc_rtp_listener_unref (crypto->listener);

  if (crypto->loop != NULL)
    r_ev_loop_unref (crypto->loop);
}

RRtcError
r_rtc_crypto_transport_send (RRtcCryptoTransport * crypto, RBuffer * buf)
{
  if (R_UNLIKELY (crypto == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_RTC_INVAL;
  return crypto->send (crypto, buf);
}

RRtcError
r_rtc_crypto_transport_start (RRtcCryptoTransport * crypto, REvLoop * loop)
{
  RRtcError ret;

  if (R_UNLIKELY (loop == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (crypto->loop != NULL)) return R_RTC_WRONG_STATE;

  crypto->loop = r_ev_loop_ref (loop);
  ret = crypto->start (crypto, loop);
  r_rtc_ice_transport_start (crypto->ice, loop);

  R_LOG_TRACE ("RtcCryptoTransport %p start %d", crypto, (int)ret);

  return ret;
}

#if 0
RRtcError
r_rtc_crypto_transport_close (RRtcCryptoTransport * crypto)
{
}
#endif

