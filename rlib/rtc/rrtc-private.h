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
#ifndef __R_RTC_PRIV_H__
#define __R_RTC_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rrtc-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtc/rrtctypes.h>
#include <rlib/rtc/rrtcicecandidate.h>
#include <rlib/rtc/rrtcicetransport.h>
#include <rlib/rtc/rrtccryptotransport.h>
#include <rlib/rtc/rrtcrtplistener.h>
#include <rlib/rtc/rrtcrtpreceiver.h>
#include <rlib/rtc/rrtcrtpsender.h>
#include <rlib/rtc/rrtcrtptransceiver.h>
#include <rlib/rtc/rrtcsession.h>

#include <rlib/ev/revudp.h>
#include <rlib/net/rtlsserver.h>
#include <rlib/net/rsrtp.h>

#include <rlib/data/rhashtable.h>
#include <rlib/data/rptrarray.h>

#include <rlib/rlog.h>

R_BEGIN_DECLS


R_LOG_CATEGORY_DEFINE_EXTERN (rtccat);
#define R_LOG_CAT_DEFAULT &rtccat


typedef RRtcError (*RRtcBufferSend) (rpointer rtc, RBuffer * buf);
typedef RRtcError (*RRtcStart) (rpointer rtc, REvLoop * loop);

struct _RRtcSession {
  RRef ref;
  rchar * id;

  rpointer data;
  RDestroyNotify notify;

  RPrng * prng;

  RPtrArray * transceivers;
  /* FIXME: Move to TransportController */
  RPtrArray * crypto;
  RPtrArray * ice;
};


struct _RRtcRtpTransceiver {
  RRef ref;

  RRtcRtpReceiver * recv;
  RRtcRtpSender * send;

  rchar id[24 + 1];
};

R_API_HIDDEN RRtcRtpTransceiver * r_rtc_rtp_transceiver_new (RPrng * prng) R_ATTR_MALLOC;


struct _RRtcRtpReceiver {
  RRef ref;
  rchar * mid;

  RRtcRtpReceiverCallbacks cbs;
  rpointer data;
  RDestroyNotify notify;

  RRtcRtpParameters * params;
  RRtcCryptoTransport * rtp;
  RRtcCryptoTransport * rtcp;

  /*REvLoop * loop;*/
  rchar id[24 + 1];
};

R_API_HIDDEN RRtcRtpReceiver * r_rtc_rtp_receiver_new (RPrng * prng,
    const rchar * mid, rssize size,
    const RRtcRtpReceiverCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp) R_ATTR_MALLOC;


struct _RRtcRtpSender {
  RRef ref;
  rchar * mid;

  RRtcRtpSenderCallbacks cbs;
  rpointer data;
  RDestroyNotify notify;

  RRtcRtpParameters * params;
  RRtcCryptoTransport * rtp;
  RRtcCryptoTransport * rtcp;

  /*REvLoop * loop;*/
  rchar id[24 + 1];
};

R_API_HIDDEN RRtcRtpSender * r_rtc_rtp_sender_new (RPrng * prng,
    const rchar * mid, rssize size,
    const RRtcRtpSenderCallbacks * cbs, rpointer data, RDestroyNotify notify,
    RRtcCryptoTransport * rtp, RRtcCryptoTransport * rtcp) R_ATTR_MALLOC;

struct _RRtcRtpListener {
  RRef ref;

  RPtrArray * recv;
  RPtrArray * send;

  RHashTable * recv_ssrcmap;
  RHashTable * recv_extmap;
  RHashTable * recv_ptmap;
  RHashTable * send_ssrcmap;
};

R_API_HIDDEN RRtcRtpListener * r_rtc_rtp_listener_new (void) R_ATTR_MALLOC;
R_API_HIDDEN RRtcError r_rtc_rtp_listener_handle_rtp (RRtcRtpListener * l,
    RBuffer * buf, RRtcCryptoTransport * t);
R_API_HIDDEN RRtcError r_rtc_rtp_listener_handle_rtcp (RRtcRtpListener * l,
    RBuffer * buf, RRtcCryptoTransport * t);
R_API_HIDDEN RRtcError r_rtc_rtp_listener_notify_ready (RRtcRtpListener * l,
    RRtcCryptoTransport * t);
R_API_HIDDEN RRtcError r_rtc_rtp_listener_notify_close (RRtcRtpListener * l,
    RRtcCryptoTransport * t);


struct _RRtcCryptoTransport {
  RRef ref;

  RRtcRtpListener * listener;
  REvLoop * loop;
  RRtcIceTransport * ice;
  RRtcBufferSend send;
  RRtcStart start;
};

typedef struct  {
  RRtcCryptoTransport crypto;

  RSRTPCtx * srtp;
  union {
    RTLSServer * srv;
    /*RTLSClient * cli;*/
  } dtls;
  RPrng * prng;
} RRtcDtlsTransport;

R_API_HIDDEN void r_rtc_crypto_transport_init (rpointer rtc, RRtcIceTransport * ice,
    RRtcStart start, RRtcBufferCb recv, RRtcBufferSend send);
R_API_HIDDEN void r_rtc_crypto_transport_clear (RRtcCryptoTransport * crypto);
R_API_HIDDEN RRtcCryptoTransport * r_rtc_crypto_transport_new_raw (
    RRtcIceTransport * ice);
R_API_HIDDEN RRtcCryptoTransport * r_rtc_crypto_transport_new_dtls (
    RRtcIceTransport * ice, RPrng * prng,
    RRtcCryptoRole role, RCryptoCert * cert, RCryptoKey * privkey) R_ATTR_MALLOC;
R_API_HIDDEN RRtcError r_rtc_crypto_transport_send (RRtcCryptoTransport * crypto,
    RBuffer * buf);
#define r_rtc_crypto_transport_add_receiver(t, r) \
  r_rtc_rtp_listener_add_receiver ((t)->listener, r)
#define r_rtc_crypto_transport_add_sender(t, s) \
  r_rtc_rtp_listener_add_sender ((t)->listener, s)
#define r_rtc_crypto_transport_remove_receiver(t, r) \
  r_rtc_rtp_listener_remove_receiver ((t)->listener, r)
#define r_rtc_crypto_transport_remove_sender(t, s) \
  r_rtc_rtp_listener_remove_sender ((t)->listener, s)
#define r_rtc_crypto_transport_update_receiver(t, r, p) \
  r_rtc_rtp_listener_update_receiver ((t)->listener, r, p)
#define r_rtc_crypto_transport_update_sender(t, s, p) \
  r_rtc_rtp_listener_update_sender ((t)->listener, s, p)


struct _RRtcIceCandidate {
  RRef ref;

  rchar * foundation;

  RRtcIceComponent component;
  RRtcIceProtocol proto;
  ruint64 pri;
  RSocketAddress * addr;
  RRtcIceCandidateType type;

  RSocketAddress * raddr;

  RPtrArray extensions;
};


struct _RRtcIceTransport {
  RRef ref;

  RRtcEventCb     ready;
  RRtcEventCb     close;
  RRtcBufferCb    packet;
  RRtcBufferSend  send;

  rpointer data;
  RDestroyNotify notify;

  REvLoop * loop;

  rchar * ufrag;
  rchar * pwd;

  RRtcIceComponent component;
  RRtcIceRole role;
  RRtcIceState state;
  RRtcIceCandidatePair selected;
  RHashTable * candidateSockets;
  RRtcIceTransport * related; /* FIXME: Make weak? */
};

R_API_HIDDEN RRtcIceTransport * r_rtc_ice_transport_new (
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize) R_ATTR_MALLOC;

R_API_HIDDEN RRtcError r_rtc_ice_transport_send (RRtcIceTransport * ice, RBuffer * buf);
#define r_rtc_ice_transport_clear_cb(ice) r_rtc_ice_transport_set_cb (ice, NULL, NULL, NULL, NULL, NULL)
static inline void
r_rtc_ice_transport_set_cb (RRtcIceTransport * ice,
    RRtcEventCb ready, RRtcEventCb close, RRtcBufferCb packet,
    rpointer data, RDestroyNotify notify)
{
  if (ice->notify != NULL)
    ice->notify (ice->data);
  ice->ready = ready;
  ice->close = close;
  ice->packet = packet;
  ice->data = data;
  ice->notify = notify;
}

R_END_DECLS

#endif /* __R_PRNG_PRIV_H__ */


