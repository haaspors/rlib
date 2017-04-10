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
#include <rlib/rtc/rrtcicetransport.h>

#include <rlib/rassert.h>
#include <rlib/rstr.h>

#include <rlib/net/proto/rstun.h>

static void
r_rtc_ice_transport_free (RRtcIceTransport * ice)
{
  if (ice->selected.local != NULL)
    r_rtc_ice_candidate_unref (ice->selected.local);
  if (ice->selected.remote != NULL)
    r_rtc_ice_candidate_unref (ice->selected.remote);
  r_hash_table_unref (ice->candidateSockets);

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
    ret->candidateSockets = r_hash_table_new_full (NULL, NULL,
        r_rtc_ice_candidate_unref, r_ref_unref);
    R_LOG_TRACE ("RtcIceTransport %p new %s - %s", ret, ret->ufrag, ret->pwd);
  }

  return ret;
}

RRtcError
r_rtc_ice_transport_send_udp (RRtcIceTransport * ice, RBuffer * buf)
{
  REvUDP * udp;

  R_LOG_TRACE ("RtcIceTransport %p: %p:%"RSIZE_FMT, ice, buf, r_buffer_get_size (buf));

  if ((udp = r_hash_table_lookup (ice->candidateSockets, ice->selected.local)) != NULL) {
    /* FIXME: Error checking */
    r_ev_udp_send (udp, buf, ice->selected.remote->addr, NULL, NULL, NULL);
    return R_RTC_OK;
  }

  return R_RTC_WRONG_STATE;
}

RRtcError
r_rtc_ice_transport_send (RRtcIceTransport * ice, RBuffer * buf)
{
  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_RTC_INVAL;
  return ice->send (ice, buf);
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

  /* FIXME: use candidate mapping */
  if (ice->selected.remote != NULL) {
    if (!r_socket_address_is_equal (addr, ice->selected.remote->addr)) {
      r_rtc_ice_candidate_unref (ice->selected.remote);
      ice->selected.remote = NULL;
    }
  }
  if (ice->selected.remote == NULL) {
    ice->selected.remote = r_rtc_ice_candidate_new_full (addr,
        R_RTC_ICE_PROTO_UDP, R_RTC_ICE_CANDIDATE_HOST, 0);
  }

  r_buffer_map (buf, &info, R_MEM_MAP_READ);
  if (r_stun_is_valid_msg (info.data, info.size)) {
    if (r_stun_msg_is_request (info.data) && r_stun_msg_method_is_binding (info.data)) {
      RBuffer * outbuf;

      if ((outbuf = r_rtc_ice_transport_create_stun_response_binding (ice,
              addr, r_stun_msg_transaction_id (info.data))) != NULL) {
        r_ev_udp_send (evudp, outbuf, addr, NULL, NULL, NULL);
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
r_rtc_ice_transport_setup_udp (RRtcIceTransport * ice, RRtcIceCandidate * candidate)
{
  REvUDP * udp;

  if ((udp = r_ev_udp_new (r_socket_address_get_family (candidate->addr), ice->loop)) != NULL) {
    rchar * tmp = r_socket_address_to_str (candidate->addr);
    R_LOG_TRACE ("RtcIceTransport %p setup UDP: %s", ice, tmp);
    r_free (tmp);

    if (r_ev_udp_bind (udp, candidate->addr, TRUE)) {
      r_ev_udp_recv_start (udp, NULL, r_rtc_ice_transport_udp_packet_cb, ice, NULL);
      r_hash_table_insert (ice->candidateSockets, r_rtc_ice_candidate_ref (candidate), udp);

      /* FIXME: Wait for actual gathering and ICE stuff to happen! */
      if (ice->selected.local == NULL)
        ice->selected.local = r_rtc_ice_candidate_ref (candidate);
      ice->send = r_rtc_ice_transport_send_udp;
      ice->ready (ice->data, ice);
    } else {
      r_ev_udp_unref (udp);
      return R_RTC_WRONG_STATE;
    }
  } else {
    return R_RTC_OOM;
  }

  return R_RTC_OK;
}

static void
_candidate_socket_start (rpointer key, rpointer value, rpointer user)
{
  RRtcIceCandidate * candidate = key;
  RRtcIceTransport * ice = user;

  if (value == NULL) {
    if (candidate->proto == R_RTC_ICE_PROTO_UDP) {
      r_rtc_ice_transport_setup_udp (ice, candidate);
    } else {
      r_assert_not_reached (); /* FIXME */
    }
  }
}

RRtcError
r_rtc_ice_transport_start (RRtcIceTransport * ice, REvLoop * loop)
{
  if (R_UNLIKELY (loop == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->loop != NULL)) return R_RTC_WRONG_STATE;

  ice->loop = r_ev_loop_ref (loop);

  /* FIXME: Start gathering! */
  R_LOG_TRACE ("RtcIceTransport %p start", ice);
  r_hash_table_foreach (ice->candidateSockets, _candidate_socket_start, ice);
  return R_RTC_OK;
}

static void
_candidate_socket_close (rpointer key, rpointer value, rpointer user)
{
  RRtcIceCandidate * candidate = key;
  RRtcIceTransport * ice = user;

  if (candidate->proto == R_RTC_ICE_PROTO_UDP) {
    REvUDP * udp = value;

    r_ev_udp_recv_stop (udp);
    r_hash_table_insert (ice->candidateSockets, r_rtc_ice_candidate_ref (candidate), NULL);
  } else {
    r_assert_not_reached (); /* FIXME */
  }
}

RRtcError
r_rtc_ice_transport_close (RRtcIceTransport * ice)
{
  r_hash_table_foreach (ice->candidateSockets, _candidate_socket_close, ice);

  return R_RTC_OK;
}

RRtcError
r_rtc_ice_transport_send_fake (RRtcIceTransport * ice, RBuffer * buf)
{
  if (ice->related != NULL) {
    ice->related->packet (ice->related->data, buf, ice->related);
    return R_RTC_OK;
  }
  return R_RTC_WRONG_STATE;
}

RRtcError
r_rtc_ice_transport_add_local_host_candidate (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate)
{
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;
  if (R_UNLIKELY (candidate == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (candidate->type != R_RTC_ICE_CANDIDATE_HOST))
    return R_RTC_INVALID_TYPE;
  if (R_UNLIKELY (candidate->proto != R_RTC_ICE_PROTO_UDP))
    return R_RTC_INVALID_TYPE; /* FIXME: Support TCP */
  if (R_UNLIKELY (r_hash_table_contains (ice->candidateSockets, candidate) == R_HASH_TABLE_OK))
    return R_RTC_ALREADY_FOUND;

  if (ice->loop != NULL)
    return r_rtc_ice_transport_setup_udp (ice, candidate);

  r_hash_table_insert (ice->candidateSockets, r_rtc_ice_candidate_ref (candidate), NULL);
  return R_RTC_OK;
}

RRtcError
r_rtc_ice_transport_create_fake_pair (RRtcIceTransport ** a, RRtcIceTransport ** b)
{
  if (R_UNLIKELY (a == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (b == NULL)) return R_RTC_INVAL;

  *a = r_rtc_ice_transport_new (NULL, 0, NULL, 0);
  *b = r_rtc_ice_transport_new (NULL, 0, NULL, 0);
  (*a)->related = *b;
  (*b)->related = *a;
  (*a)->send = r_rtc_ice_transport_send_fake;
  (*b)->send = r_rtc_ice_transport_send_fake;

  return R_RTC_OK;
}

