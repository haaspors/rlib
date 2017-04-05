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
#include <rlib/rtc/rrtcsession.h>

#include <rlib/rassert.h>
#include <rlib/rstr.h>

#include <rlib/net/proto/rstun.h>

static void
r_rtc_ice_transport_free (RRtcIceTransport * ice)
{
  if (ice->udp != NULL)
    r_ev_udp_unref (ice->udp);
  if (ice->local != NULL)
    r_socket_address_unref (ice->local);
  if (ice->remote != NULL)
    r_socket_address_unref (ice->remote);

  r_free (ice->pwd);
  r_free (ice->ufrag);

  if (ice->loop != NULL)
    r_ev_loop_unref (ice->loop);

  if (ice->notify != NULL)
    ice->notify (ice->data);

  r_free (ice);
}

RRtcIceTransport *
r_rtc_ice_transport_new (
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize)
{
  RRtcIceTransport * ret;

  if ((ret = r_mem_new0 (RRtcIceTransport)) != NULL) {
    r_ref_init (ret, r_rtc_ice_transport_free);

    ret->ufrag = r_strdup_size (ufrag, usize);
    ret->pwd = r_strdup_size (pwd, psize);
    R_LOG_TRACE ("RtcIceTransport %p new %s - %s", ret, ret->ufrag, ret->pwd);
  }

  return ret;
}

RRtcError
r_rtc_ice_transport_send (RRtcIceTransport * ice, RBuffer * buf)
{
  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_RTC_INVAL;

  r_assert_cmpptr (ice->udp, !=, NULL);

  R_LOG_TRACE ("RtcIceTransport %p: %p:%"RSIZE_FMT, ice, buf, r_buffer_get_size (buf));
  /* FIXME: Error checking */
  /* FIXME: Send on nominated socket! */
  r_ev_udp_send (ice->udp, buf, ice->remote, NULL, NULL, NULL);

  return R_RTC_OK;
}

static RBuffer *
r_rtc_ice_transport_create_stun_response_binding (RRtcIceTransport * ice,
    RSocketAddress * addr, const ruint8 transaction_id[R_STUN_TRANSACTION_ID_SIZE])
{
  RBuffer * ret;

  if ((ret = r_buffer_new_alloc (NULL, 1024, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      rsize size;

      r_stun_msg_begin (&ctx, info.data, info.size,
            R_STUN_CLASS_SUCCESS_RESPONSE, R_STUN_METHOD_BINDING, transaction_id);
      r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, addr);
      r_stun_msg_add_message_integrity_short_cred (&ctx, ice->pwd, r_strlen (ice->pwd));
      size = r_stun_msg_end (&ctx, TRUE);
      r_buffer_unmap (ret, &info);
      r_buffer_set_size (ret, size);
    } else {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

static void
r_rtc_ice_transport_udp_packet_cb (rpointer data,
    RBuffer * buf, RSocketAddress * addr, REvUDP * evudp)
{
  RRtcIceTransport * ice = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  R_LOG_TRACE ("RtcIceTransport %p packet", ice);
  r_assert_cmpptr (ice->udp, ==, evudp);

  /* FIXME: use candidate mapping */
  if (!r_socket_address_is_equal (addr, ice->remote))
    ice->remote = r_socket_address_ref (addr);

  r_buffer_map (buf, &info, R_MEM_MAP_READ);
  if (r_stun_is_valid_msg (info.data, info.size)) {
    if (r_stun_msg_is_request (info.data) && r_stun_msg_method_is_binding (info.data)) {
      RBuffer * outbuf;

      if ((outbuf = r_rtc_ice_transport_create_stun_response_binding (ice,
              addr, r_stun_msg_transaction_id (info.data))) != NULL) {
        r_ev_udp_send (ice->udp, outbuf, addr, NULL, NULL, NULL);
        r_buffer_unref (outbuf);
      }
    } else {
      R_LOG_WARNING ("RtcIceTransport %p unknown packet", ice);
    }

    r_buffer_unmap (buf, &info);
  } else {
    r_buffer_unmap (buf, &info);
    ice->packet (ice->data, buf, ice);
  }
}

static RRtcError
r_rtc_ice_transport_setup_udp (RRtcIceTransport * ice)
{
  rchar * tmp;
  ice->udp = r_ev_udp_new (r_socket_address_get_family (ice->local), ice->loop);

  tmp = r_socket_address_to_str (ice->local);
  R_LOG_TRACE ("RtcIceTransport %p setup UDP: %s", ice, tmp);
  r_free (tmp);

  if (r_ev_udp_bind (ice->udp, ice->local, TRUE)) {
    r_ev_udp_recv_start (ice->udp, NULL, r_rtc_ice_transport_udp_packet_cb, ice, NULL);
    ice->ready (ice->data, ice);
  } else {
    return R_RTC_WRONG_STATE;
  }

  return R_RTC_OK;
}

RRtcError
r_rtc_ice_transport_start (RRtcIceTransport * ice, REvLoop * loop)
{
  if (R_UNLIKELY (loop == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->loop != NULL)) return R_RTC_WRONG_STATE;

  ice->loop = r_ev_loop_ref (loop);
  /* FIXME: Start gathering! */

  R_LOG_TRACE ("RtcIceTransport %p start", ice);
  return (ice->local != NULL) ? r_rtc_ice_transport_setup_udp (ice) : R_RTC_OK;
}

RRtcError
r_rtc_ice_transport_close (RRtcIceTransport * ice)
{
  if (ice->udp != NULL)
    r_ev_udp_recv_stop (ice->udp);

  return R_RTC_OK;
}

RRtcError
r_rtc_ice_transport_add_udp_candidate (RRtcIceTransport * ice,
    RSocketAddress * local)
{
  rchar * tmp;

  if (R_UNLIKELY (local == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->local != NULL)) return R_RTC_WRONG_STATE;

  ice->local = r_socket_address_ref (local);

  tmp = r_socket_address_to_str (ice->local);
  R_LOG_TRACE ("RtcIceTransport %p add UDP: %s", ice, tmp);
  r_free (tmp);


  return (ice->loop != NULL) ? r_rtc_ice_transport_setup_udp (ice) : R_RTC_OK;
}

