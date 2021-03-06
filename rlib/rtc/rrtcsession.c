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
#include "../rlib-private.h"
#include "rrtc-private.h"
#include <rlib/rtc/rrtcsession.h>

#include <rlib/rassert.h>
#include <rlib/rstr.h>

R_LOG_CATEGORY_DEFINE (rtccat, "rtc", "RLib RTC stack",
    R_CLR_FG_CYAN | R_CLR_BG_YELLOW | R_CLR_FMT_BOLD);

void
r_rtc_init (void)
{
  r_log_category_register (&rtccat);
}

static void
r_rtc_session_free (RRtcSession * session)
{
  if (session->ice != NULL)
    r_ptr_array_unref (session->ice);
  if (session->crypto != NULL)
    r_ptr_array_unref (session->crypto);
  if (session->transceivers != NULL)
    r_ptr_array_unref (session->transceivers);

  if (session->prng != NULL)
    r_prng_unref (session->prng);
  if (session->notify != NULL)
    session->notify (session->data);

  r_free (session->id);
  r_free (session);
}

RRtcSession *
r_rtc_session_new_full (const rchar * id, rssize size, RPrng * prng)
{
  RRtcSession * ret;

  if (R_UNLIKELY (prng == NULL)) return NULL;

  if ((ret = r_mem_new0 (RRtcSession)) != NULL) {
    r_ref_init (ret, r_rtc_session_free);

    ret->prng = r_prng_ref (prng);
    if (id == NULL || size == 0 || (ret->id = r_strdup_size (id, size)) == NULL) {
      ret->id = r_malloc (64 + 1);
      r_prng_fill_base64 (prng, ret->id, 64);
      ret->id[64] = 0;
    }

    ret->transceivers = r_ptr_array_new_sized (16);
    ret->crypto = r_ptr_array_new_sized (16);
    ret->ice = r_ptr_array_new_sized (16);
  }

  return ret;
}

const rchar *
r_rtc_session_get_id (const RRtcSession * s)
{
  return s->id;
}

RRtcIceTransport *
r_rtc_session_create_ice_transport (RRtcSession * s,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize)
{
  RRtcIceTransport * ice;

  if (R_UNLIKELY (ufrag == NULL)) return NULL;
  if (usize < 0) usize = r_strlen (ufrag);
  if (R_UNLIKELY (usize == 0)) return NULL;

  if (R_UNLIKELY (pwd == NULL)) return NULL;
  if (psize < 0) psize = r_strlen (pwd);
  if (R_UNLIKELY (psize == 0)) return NULL;

  if ((ice = r_rtc_ice_transport_new (ufrag, usize, pwd, psize)) != NULL) {
    r_ptr_array_add (s->ice, ice, r_rtc_ice_transport_unref);
    r_rtc_ice_transport_ref (ice);
  }

  return ice;
}

RRtcCryptoTransport *
r_rtc_session_create_dtls_transport (RRtcSession * s, RRtcIceTransport * ice,
    RRtcCryptoRole role, RCryptoCert * cert, RCryptoKey * privkey)
{
  RRtcCryptoTransport * crypto;

  if ((crypto = r_rtc_crypto_transport_new_dtls (ice, s->prng, role, cert, privkey)) != NULL) {
    r_ptr_array_add (s->crypto, crypto, r_rtc_crypto_transport_unref);
    r_rtc_crypto_transport_ref (crypto);
  }

  return crypto;
}

RRtcCryptoTransport *
r_rtc_session_create_raw_transport (RRtcSession * s, RRtcIceTransport * ice)
{
  RRtcCryptoTransport * crypto;

  if ((crypto = r_rtc_crypto_transport_new_raw (ice)) != NULL) {
    r_ptr_array_add (s->crypto, r_rtc_crypto_transport_ref (crypto),
        r_rtc_crypto_transport_unref);
  }

  return crypto;
}

static RRtcRtpTransceiver *
r_rtc_session_get_rtp_transceiver (RRtcSession * s,
    const rchar * mid, rssize size)
{
  RRtcRtpTransceiver * t;

  if ((t = r_rtc_session_lookup_rtp_transceiver (s, mid, size)) != NULL)
    return t;

  if ((t = r_rtc_rtp_transceiver_new (s->prng)) != NULL) {
    r_ptr_array_add (s->transceivers, r_rtc_rtp_transceiver_ref (t),
        r_rtc_rtp_transceiver_unref);
  }

  return t;
}

RRtcRtpSender *
r_rtc_session_create_rtp_sender (RRtcSession * s, const rchar * mid, rssize size,
    const RRtcRtpSenderCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp)
{
  RRtcRtpSender * ret;

  if (R_UNLIKELY (mid == NULL)) return NULL;
  if (size < 0) size = r_strlen (mid);
  if (R_UNLIKELY (size == 0)) return NULL;


  if ((ret = r_rtc_rtp_sender_new (s->prng, mid, size, cbs, data, notify, rtp, rtcp)) != NULL) {
    RRtcRtpTransceiver * t;

    if ((t = r_rtc_session_get_rtp_transceiver (s, mid, size)) != NULL) {
      if (R_UNLIKELY (r_rtc_rtp_transceiver_set_sender (t, ret) != R_RTC_OK)) {
        r_rtc_rtp_sender_unref (ret);
        ret = NULL;
      }
      r_rtc_rtp_transceiver_unref (t);
    } else {
      r_rtc_rtp_sender_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

RRtcRtpReceiver *
r_rtc_session_create_rtp_receiver (RRtcSession * s,
    const rchar * mid, rssize size,
    const RRtcRtpReceiverCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp)
{
  RRtcRtpReceiver * ret;

  if (R_UNLIKELY (mid == NULL)) return NULL;
  if (size < 0) size = r_strlen (mid);
  if (R_UNLIKELY (size == 0)) return NULL;

  if ((ret = r_rtc_rtp_receiver_new (s->prng, mid, size, cbs, data, notify, rtp, rtcp)) != NULL) {
    RRtcRtpTransceiver * t;

    if ((t = r_rtc_session_get_rtp_transceiver (s, mid, size)) != NULL) {
      if (R_UNLIKELY (r_rtc_rtp_transceiver_set_receiver (t, ret) != R_RTC_OK)) {
        r_rtc_rtp_receiver_unref (ret);
        ret = NULL;
      }
      r_rtc_rtp_transceiver_unref (t);
    } else {
      r_rtc_rtp_receiver_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

RRtcRtpTransceiver *
r_rtc_session_lookup_rtp_transceiver (RRtcSession * s,
    const rchar * mid, rssize size)
{
  rsize i, c;

  if (R_UNLIKELY (mid == NULL)) return NULL;
  if (size < 0) size = r_strlen (mid);
  if (R_UNLIKELY (size == 0)) return NULL;

  for (i = 0, c = r_ptr_array_size (s->transceivers); i < c; i++) {
    RRtcRtpTransceiver * t = r_ptr_array_get (s->transceivers, i);
    if (r_strncasecmp (r_rtc_rtp_transceiver_get_mid (t), mid, size) == 0)
      return r_rtc_rtp_transceiver_ref (t);
  }

  return NULL;
}

RRtcRtpTransceiver *
r_rtc_session_create_rtp_transceiver (RRtcSession * s,
    const rchar * mid, rssize size,
    const RRtcRtpReceiverCallbacks * rcbs, const RRtcRtpSenderCallbacks * scbs,
    rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp)
{
  RRtcRtpTransceiver * t;

  if (R_UNLIKELY (mid == NULL)) return NULL;
  if (size < 0) size = r_strlen (mid);
  if (R_UNLIKELY (size == 0)) return NULL;

  if ((t = r_rtc_session_lookup_rtp_transceiver (s, mid, size)) == NULL) {
    if ((t = r_rtc_rtp_transceiver_new (s->prng)) != NULL) {
      if ((t->recv = r_rtc_rtp_receiver_new (s->prng, mid, size, rcbs, data, notify, rtp, rtcp)) != NULL &&
          (t->send = r_rtc_rtp_sender_new (s->prng, mid, size, scbs, data, notify, rtp, rtcp)) != NULL) {
        r_ptr_array_add (s->transceivers, r_rtc_rtp_transceiver_ref (t),
            r_rtc_rtp_transceiver_unref);
      } else {
        r_rtc_rtp_transceiver_unref (t);
        t = NULL;
      }
    }
  } else {
    r_rtc_rtp_transceiver_unref (t);
    t = NULL;
  }

  return t;
}

