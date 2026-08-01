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
#include <rlib/rmem.h>
#include <rlib/rrand.h>
#include <rlib/rstr.h>

#include <rlib/net/proto/rstun.h>
#include <rlib/types/rendianness.h>

/* Connectivity-check retransmission: RFC 8445 uses an RTO with backoff;
 * we keep a fixed interval and a bounded retry count, enough to ride out
 * loss without a full timer state machine. */
#define R_RTC_ICE_CHECK_RTO       (500 * R_MSECOND)
#define R_RTC_ICE_CHECK_MAX_SENDS 7

typedef enum {
  R_RTC_ICE_CHECK_FROZEN = 0,
  R_RTC_ICE_CHECK_WAITING,
  R_RTC_ICE_CHECK_IN_PROGRESS,
  R_RTC_ICE_CHECK_SUCCEEDED,
  R_RTC_ICE_CHECK_FAILED,
} RRtcIceCheckState;

typedef struct {
  RRtcIceCandidate * local;   /* owned; keys the socket in candidateSockets */
  RRtcIceCandidate * remote;  /* owned */
  REvUDP * udp;               /* borrowed: the local socket to check on */
  ruint64 priority;           /* pair priority (RFC 8445 6.1.2.3) */

  RRtcIceCheckState state;
  rboolean nominating;        /* our in-flight check carries USE-CANDIDATE */
  rboolean peer_use_candidate;/* controlled: peer nominated this pair */
  ruint8 tid[R_STUN_TRANSACTION_ID_SIZE];
  ruint nsent;

  RRtcIceTransport * ice;     /* borrowed back-pointer for the timer cb */
  RClockEntry * timer;        /* retransmission timer, or NULL */
} RRtcIceCheckPair;

/* candidateSockets keeps a NULL value for candidates that are added but
 * not yet bound, and close() resets bound sockets back to NULL -- so the
 * value destructor has to tolerate NULL. */
static void
r_rtc_ice_udp_destroy (rpointer udp)
{
  if (udp != NULL)
    r_ev_udp_unref (udp);
}

static void
r_rtc_ice_check_pair_free (rpointer data)
{
  RRtcIceCheckPair * pair = data;

  if (pair->timer != NULL && pair->ice->loop != NULL)
    r_ev_loop_cancel_timer (pair->ice->loop, pair->timer);
  r_rtc_ice_candidate_unref (pair->local);
  r_rtc_ice_candidate_unref (pair->remote);
  r_free (pair);
}

static void
r_rtc_ice_transport_free (RRtcIceTransport * ice)
{
  /* Drop the checks first: cancelling their timers needs ice->loop. */
  r_ptr_array_unref (ice->checks);
  r_ptr_array_unref (ice->remote);

  if (ice->selected.local != NULL)
    r_rtc_ice_candidate_unref (ice->selected.local);
  if (ice->selected.remote != NULL)
    r_rtc_ice_candidate_unref (ice->selected.remote);
  r_hash_table_unref (ice->candidateSockets);

  r_free (ice->rpwd);
  r_free (ice->rufrag);
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
    ret->tiebreaker = r_rand_entropy_u64 ();
    ret->candidateSockets = r_hash_table_new_full (NULL, NULL,
        r_rtc_ice_candidate_unref, r_rtc_ice_udp_destroy);
    ret->remote = r_ptr_array_new ();
    ret->checks = r_ptr_array_new ();
    R_LOG_TRACE ("RtcIceTransport %p new %s - %s", ret, ret->ufrag, ret->pwd);
  }

  return ret;
}

RRtcError
r_rtc_ice_transport_send_udp (rpointer rtc, RBuffer * buf)
{
  RRtcIceTransport * ice = rtc;
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
  if (R_UNLIKELY (ice->send == NULL)) return R_RTC_WRONG_STATE;
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

/* Pair priority, RFC 8445 6.1.2.3: G is the controlling agent's candidate
 * priority, D the controlled agent's. */
static ruint64
r_rtc_ice_pair_priority (RRtcIceRole role, ruint64 local, ruint64 remote)
{
  ruint64 g = (role == R_RTC_ICE_ROLE_CONTROLLING) ? local : remote;
  ruint64 d = (role == R_RTC_ICE_ROLE_CONTROLLING) ? remote : local;
  ruint64 lo = g < d ? g : d;
  ruint64 hi = g < d ? d : g;

  return (lo << 32) + (hi << 1) + (g > d ? 1 : 0);
}

typedef struct {
  REvUDP * udp;
  RRtcIceCandidate * local;
} RRtcIceLocalLookup;

static void
r_rtc_ice_local_for_udp_cb (rpointer key, rpointer value, rpointer user)
{
  RRtcIceLocalLookup * lookup = user;

  if (value == lookup->udp)
    lookup->local = key;
}

/* Reverse the candidate -> socket table to find the local candidate a
 * socket was bound for. */
static RRtcIceCandidate *
r_rtc_ice_local_for_udp (RRtcIceTransport * ice, REvUDP * udp)
{
  RRtcIceLocalLookup lookup = { udp, NULL };

  r_hash_table_foreach (ice->candidateSockets, r_rtc_ice_local_for_udp_cb, &lookup);
  return lookup.local;
}

static RRtcIceCheckPair *
r_rtc_ice_find_pair (RRtcIceTransport * ice, RRtcIceCandidate * local,
    RSocketAddress * remote_addr)
{
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->checks); i < c; i++) {
    RRtcIceCheckPair * pair = r_ptr_array_get (ice->checks, i);
    if (pair->local == local &&
        r_socket_address_is_equal (pair->remote->addr, remote_addr))
      return pair;
  }
  return NULL;
}

static RRtcIceCheckPair *
r_rtc_ice_add_pair (RRtcIceTransport * ice, RRtcIceCandidate * local,
    REvUDP * udp, RRtcIceCandidate * remote)
{
  RRtcIceCheckPair * pair;

  if ((pair = r_mem_new0 (RRtcIceCheckPair)) == NULL)
    return NULL;

  pair->local = r_rtc_ice_candidate_ref (local);
  pair->remote = r_rtc_ice_candidate_ref (remote);
  pair->udp = udp;
  pair->priority = r_rtc_ice_pair_priority (ice->role, local->pri, remote->pri);
  pair->state = R_RTC_ICE_CHECK_WAITING;
  pair->ice = ice;

  r_ptr_array_add (ice->checks, pair, r_rtc_ice_check_pair_free);
  return pair;
}

static RBuffer *
r_rtc_ice_build_check (RRtcIceTransport * ice, RRtcIceCheckPair * pair)
{
  RBuffer * ret;

  if ((ret = r_buffer_new_alloc (NULL, 512, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
      rchar * user = r_strprintf ("%s:%s", ice->rufrag, ice->ufrag);
      ruint8 prio[4], tb[8];
      rsize size;

      r_store_be32 (prio, (ruint32) pair->local->pri);
      r_store_be64 (tb, ice->tiebreaker);

      r_stun_msg_begin (&ctx, info.data, info.size,
          R_STUN_CLASS_REQUEST, R_STUN_METHOD_BINDING, pair->tid);

      tlv.type = R_STUN_ATTR_TYPE_USERNAME;
      tlv.len = (ruint16) r_strlen (user);
      tlv.value = (const ruint8 *) user;
      r_stun_msg_add_attribute (&ctx, &tlv);

      tlv.type = R_STUN_ATTR_TYPE_PRIORITY;
      tlv.len = sizeof (prio);
      tlv.value = prio;
      r_stun_msg_add_attribute (&ctx, &tlv);

      tlv.type = ice->role == R_RTC_ICE_ROLE_CONTROLLING ?
          R_STUN_ATTR_TYPE_ICE_CONTROLLING : R_STUN_ATTR_TYPE_ICE_CONTROLLED;
      tlv.len = sizeof (tb);
      tlv.value = tb;
      r_stun_msg_add_attribute (&ctx, &tlv);

      if (pair->nominating) {
        tlv.type = R_STUN_ATTR_TYPE_USE_CANDIDATE;
        tlv.len = 0;
        tlv.value = NULL;
        r_stun_msg_add_attribute (&ctx, &tlv);
      }

      r_stun_msg_add_message_integrity_short_cred (&ctx, ice->rpwd, r_strlen (ice->rpwd));
      size = r_stun_msg_end (&ctx, TRUE);
      r_buffer_unmap (ret, &info);
      r_buffer_set_size (ret, size);
      r_free (user);
    } else {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

static void r_rtc_ice_check_timeout (rpointer data, REvLoop * loop);

/* (Re)transmit the check for @pair. When @fresh a new transaction is
 * started; otherwise the previous transaction id is retransmitted. */
static void
r_rtc_ice_transmit_check (RRtcIceTransport * ice, RRtcIceCheckPair * pair,
    rboolean fresh)
{
  RBuffer * buf;

  if (fresh) {
    r_rand_entropy_fill (pair->tid, sizeof (pair->tid));
    pair->nsent = 0;
  }

  if ((buf = r_rtc_ice_build_check (ice, pair)) != NULL) {
    r_ev_udp_send (pair->udp, buf, pair->remote->addr, NULL, NULL, NULL);
    r_buffer_unref (buf);
    pair->state = R_RTC_ICE_CHECK_IN_PROGRESS;
    pair->nsent++;
  }

  pair->timer = NULL;
  r_ev_loop_add_callback_later (ice->loop, &pair->timer,
      R_RTC_ICE_CHECK_RTO, r_rtc_ice_check_timeout, pair, NULL);
}

static void
r_rtc_ice_check_timeout (rpointer data, REvLoop * loop)
{
  RRtcIceCheckPair * pair = data;
  (void) loop;

  pair->timer = NULL;   /* one-shot entry just fired */
  if (pair->state != R_RTC_ICE_CHECK_IN_PROGRESS || pair->ice->nominated)
    return;

  if (pair->nsent >= R_RTC_ICE_CHECK_MAX_SENDS) {
    R_LOG_INFO ("RtcIceTransport %p check pair timed out", pair->ice);
    pair->state = R_RTC_ICE_CHECK_FAILED;
    return;
  }

  r_rtc_ice_transmit_check (pair->ice, pair, FALSE);
}

static void
r_rtc_ice_select_pair (RRtcIceTransport * ice, RRtcIceCheckPair * pair)
{
  if (ice->nominated)
    return;

  ice->nominated = TRUE;
  ice->state = R_RTC_ICE_STATE_CONNECTED;
  if (ice->selected.local != NULL)
    r_rtc_ice_candidate_unref (ice->selected.local);
  if (ice->selected.remote != NULL)
    r_rtc_ice_candidate_unref (ice->selected.remote);
  ice->selected.local = r_rtc_ice_candidate_ref (pair->local);
  ice->selected.remote = r_rtc_ice_candidate_ref (pair->remote);
  ice->send = r_rtc_ice_transport_send_udp;

  R_LOG_INFO ("RtcIceTransport %p pair nominated, connected", ice);
  if (ice->ready != NULL)
    ice->ready (ice->data, ice);
}

/* Verify a message's short-term-credential MESSAGE-INTEGRITY against @pwd
 * (our local password for inbound requests, the remote password for the
 * responses to our checks). */
static rboolean
r_rtc_ice_check_integrity (rconstpointer msg, const rchar * pwd)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;

  if (pwd == NULL || !r_stun_attr_tlv_first (msg, &tlv))
    return FALSE;
  do {
    if (tlv.type == R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY)
      return r_stun_msg_check_integrity_short_cred (msg, &tlv, pwd, r_strlen (pwd));
  } while (r_stun_attr_tlv_next (msg, &tlv));

  return FALSE;
}

/* Controlled agents nominate once the peer's request carried USE-CANDIDATE
 * and our own check on the pair has succeeded (RFC 8445 7.3.1.5). */
static void
r_rtc_ice_maybe_select_controlled (RRtcIceTransport * ice, RRtcIceCheckPair * pair)
{
  if (ice->role == R_RTC_ICE_ROLE_CONTROLLING)
    return;
  if (pair->peer_use_candidate && pair->state == R_RTC_ICE_CHECK_SUCCEEDED)
    r_rtc_ice_select_pair (ice, pair);
}

static void
r_rtc_ice_handle_binding_request (RRtcIceTransport * ice, rconstpointer msg,
    RSocketAddress * addr, REvUDP * evudp)
{
  RRtcIceCandidate * local, * remote;
  RRtcIceCheckPair * pair;
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  rboolean use_candidate = FALSE;
  RBuffer * outbuf;

  /* The peer keys its requests with our local password. */
  if (!r_rtc_ice_check_integrity (msg, ice->pwd)) {
    R_LOG_WARNING ("RtcIceTransport %p check request failed integrity", ice);
    return;
  }

  /* Respond, keyed with our own (local) password. */
  if ((outbuf = r_rtc_ice_transport_create_stun_response_binding (ice,
          addr, r_stun_msg_transaction_id (msg))) != NULL) {
    r_ev_udp_send (evudp, outbuf, addr, NULL, NULL, NULL);
    r_buffer_unref (outbuf);
  }

  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_USE_CANDIDATE)
        use_candidate = TRUE;
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }

  if ((local = r_rtc_ice_local_for_udp (ice, evudp)) == NULL)
    return;

  /* Learn a peer-reflexive remote candidate when the source is unknown. */
  if ((pair = r_rtc_ice_find_pair (ice, local, addr)) == NULL) {
    remote = r_rtc_ice_candidate_new_full (R_STR_WITH_SIZE_ARGS ("prflx"), 0,
        ice->component, R_RTC_ICE_PROTO_UDP, addr, R_RTC_ICE_CANDIDATE_PRFLX);
    if (remote == NULL)
      return;
    r_ptr_array_add (ice->remote, remote, r_rtc_ice_candidate_unref);
    pair = r_rtc_ice_add_pair (ice, local, evudp, remote);
    if (pair == NULL)
      return;
  }

  /* A request is also a triggered check: probe back if we have not yet. */
  if (pair->state == R_RTC_ICE_CHECK_WAITING && ice->rpwd != NULL)
    r_rtc_ice_transmit_check (ice, pair, TRUE);

  if (use_candidate) {
    pair->peer_use_candidate = TRUE;
    r_rtc_ice_maybe_select_controlled (ice, pair);
  }
}

static void
r_rtc_ice_handle_binding_response (RRtcIceTransport * ice, rconstpointer msg)
{
  const ruint8 * tid = r_stun_msg_transaction_id (msg);
  rsize i, c;

  /* The response is keyed with the peer's password (our remote pwd). */
  if (!r_rtc_ice_check_integrity (msg, ice->rpwd)) {
    R_LOG_WARNING ("RtcIceTransport %p check response failed integrity", ice);
    return;
  }

  for (i = 0, c = r_ptr_array_size (ice->checks); i < c; i++) {
    RRtcIceCheckPair * pair = r_ptr_array_get (ice->checks, i);

    if (pair->state != R_RTC_ICE_CHECK_IN_PROGRESS ||
        r_memcmp_ct (pair->tid, tid, R_STUN_TRANSACTION_ID_SIZE) != 0)
      continue;

    if (pair->timer != NULL) {
      r_ev_loop_cancel_timer (ice->loop, pair->timer);
      pair->timer = NULL;
    }
    pair->state = R_RTC_ICE_CHECK_SUCCEEDED;
    R_LOG_TRACE ("RtcIceTransport %p check succeeded", ice);

    if (ice->role == R_RTC_ICE_ROLE_CONTROLLING) {
      if (pair->nominating) {
        r_rtc_ice_select_pair (ice, pair);
      } else if (!ice->nominated) {
        /* Regular nomination: re-check this valid pair with USE-CANDIDATE. */
        pair->nominating = TRUE;
        r_rtc_ice_transmit_check (ice, pair, TRUE);
      }
    } else {
      r_rtc_ice_maybe_select_controlled (ice, pair);
    }
    return;
  }
}

static void
r_rtc_ice_transport_udp_packet_cb (rpointer data,
    RBuffer * buf, RSocketAddress * addr, REvUDP * evudp)
{
  RRtcIceTransport * ice = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  R_LOG_TRACE ("RtcIceTransport %p packet", ice);

  r_buffer_map (buf, &info, R_MEM_MAP_READ);
  if (r_stun_is_valid_msg (info.data, info.size)) {
    if (r_stun_msg_method_is_binding (info.data)) {
      if (r_stun_msg_is_request (info.data))
        r_rtc_ice_handle_binding_request (ice, info.data, addr, evudp);
      else if (r_stun_msg_is_success_resp (info.data))
        r_rtc_ice_handle_binding_response (ice, info.data);
      else
        R_LOG_TRACE ("RtcIceTransport %p binding %s", ice,
            r_stun_msg_is_err_resp (info.data) ? "error" : "indication");
    } else {
      R_LOG_WARNING ("RtcIceTransport %p unknown STUN method", ice);
    }
    r_buffer_unmap (buf, &info);
  } else {
    r_buffer_unmap (buf, &info);
    ice->packet (ice->data, buf, ice);
  }
}

/* Pair each remote candidate with @local (its socket @udp) and, once the
 * transport is running with credentials, launch a check. */
static void
r_rtc_ice_pair_local_with_remotes (RRtcIceTransport * ice,
    RRtcIceCandidate * local, REvUDP * udp)
{
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->remote); i < c; i++) {
    RRtcIceCandidate * remote = r_ptr_array_get (ice->remote, i);
    RRtcIceCheckPair * pair;

    if (r_rtc_ice_find_pair (ice, local, remote->addr) != NULL)
      continue;
    if ((pair = r_rtc_ice_add_pair (ice, local, udp, remote)) == NULL)
      continue;
    if (ice->loop != NULL && ice->rpwd != NULL && ice->rufrag != NULL)
      r_rtc_ice_transmit_check (ice, pair, TRUE);
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
      if (ice->state == R_RTC_ICE_STATE_NEW)
        ice->state = R_RTC_ICE_STATE_CHECKING;
      r_rtc_ice_pair_local_with_remotes (ice, candidate, udp);
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

  if (value == NULL)
    return;

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
r_rtc_ice_transport_send_fake (rpointer rtc, RBuffer * buf)
{
  RRtcIceTransport * ice = rtc;

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

RRtcIceState
r_rtc_ice_transport_get_state (const RRtcIceTransport * ice)
{
  return ice->state;
}

static void
r_rtc_ice_first_socket_cb (rpointer key, rpointer value, rpointer user)
{
  REvUDP ** out = user;
  (void) key;

  if (*out == NULL && value != NULL)
    *out = value;
}

RSocketAddress *
r_rtc_ice_transport_get_local_address (const RRtcIceTransport * ice)
{
  REvUDP * udp = NULL;
  RSocketAddress * addr;

  if (R_UNLIKELY (ice == NULL)) return NULL;

  r_hash_table_foreach (ice->candidateSockets, r_rtc_ice_first_socket_cb, &udp);
  if (udp == NULL || (addr = r_ev_udp_get_local_address (udp)) == NULL)
    return NULL;

  return r_socket_address_copy (addr);
}

RRtcError
r_rtc_ice_transport_set_role (RRtcIceTransport * ice, RRtcIceRole role)
{
  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;

  ice->role = role;
  return R_RTC_OK;
}

RRtcError
r_rtc_ice_transport_set_remote_credentials (RRtcIceTransport * ice,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize)
{
  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ufrag == NULL || pwd == NULL)) return R_RTC_INVAL;

  r_free (ice->rufrag);
  r_free (ice->rpwd);
  ice->rufrag = r_strdup_size (ufrag, usize);
  ice->rpwd = r_strdup_size (pwd, psize);
  return R_RTC_OK;
}

typedef struct {
  RRtcIceTransport * ice;
  RRtcIceCandidate * remote;
} RRtcIcePairRemote;

static void
r_rtc_ice_pair_new_remote_cb (rpointer key, rpointer value, rpointer user)
{
  RRtcIceCandidate * local = key;
  REvUDP * udp = value;
  RRtcIcePairRemote * ctx = user;
  RRtcIceCheckPair * pair;

  if (udp == NULL)
    return;
  if (r_rtc_ice_find_pair (ctx->ice, local, ctx->remote->addr) != NULL)
    return;
  if ((pair = r_rtc_ice_add_pair (ctx->ice, local, udp, ctx->remote)) == NULL)
    return;
  if (ctx->ice->loop != NULL && ctx->ice->rpwd != NULL && ctx->ice->rufrag != NULL)
    r_rtc_ice_transmit_check (ctx->ice, pair, TRUE);
}

RRtcError
r_rtc_ice_transport_add_remote_candidate (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate)
{
  RRtcIcePairRemote ctx;

  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (candidate == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;
  if (R_UNLIKELY (candidate->proto != R_RTC_ICE_PROTO_UDP))
    return R_RTC_INVALID_TYPE; /* FIXME: Support TCP */

  r_ptr_array_add (ice->remote, r_rtc_ice_candidate_ref (candidate),
      r_rtc_ice_candidate_unref);

  /* Pair the new remote with every already-bound local socket and, once
   * running with credentials, check it. */
  ctx.ice = ice;
  ctx.remote = candidate;
  r_hash_table_foreach (ice->candidateSockets, r_rtc_ice_pair_new_remote_cb, &ctx);

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

