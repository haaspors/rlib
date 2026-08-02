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

#include <rlib/crypto/rmsgdigest.h>
#include <rlib/ev/revtcp.h>
#include <rlib/net/proto/rstun.h>
#include <rlib/types/rendianness.h>

/* Connectivity-check retransmission: RFC 8445 uses an RTO with backoff;
 * we keep a fixed interval and a bounded retry count, enough to ride out
 * loss without a full timer state machine. */
#define R_RTC_ICE_CHECK_RTO       (500 * R_MSECOND)
#define R_RTC_ICE_CHECK_MAX_SENDS 7

/* Ta: minimum spacing between ordinary connectivity checks (RFC 8445 14.2),
 * so a large check list is paced instead of blasted at once. */
#define R_RTC_ICE_TA              (50 * R_MSECOND)

/* A STUN message / media packet over TCP is framed with a 2-byte
 * big-endian length prefix (RFC 4571, as ICE-TCP mandates in RFC 6544). */
#define R_RTC_ICE_TCP_FRAME_HDR   2
/* Bound the passive side against accept floods and reassembly-buffer growth
 * from an unauthenticated peer. */
#define R_RTC_ICE_TCP_MAX_CONNS   64
#define R_RTC_ICE_TCP_RX_MAX      (4 * (R_RTC_ICE_TCP_FRAME_HDR + 0xffff))

typedef struct RRtcIceTcpConn RRtcIceTcpConn;
typedef struct RRtcIceTurnAlloc RRtcIceTurnAlloc;

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
  REvUDP * udp;               /* borrowed: the local UDP socket (NULL for TCP) */
  RRtcIceTcpConn * conn;      /* borrowed: the TCP connection (NULL for UDP) */
  RRtcIceTurnAlloc * alloc;   /* borrowed: TURN allocation (NULL unless relay local) */
  ruint64 priority;           /* pair priority (RFC 8445 6.1.2.3) */

  RRtcIceCheckState state;
  rboolean nominating;        /* our in-flight check carries USE-CANDIDATE */
  rboolean peer_use_candidate;/* controlled: peer nominated this pair */
  ruint8 tid[R_STUN_TRANSACTION_ID_SIZE];
  ruint nsent;

  RRtcIceTransport * ice;     /* borrowed back-pointer for the timer cb */
  RClockEntry * timer;        /* retransmission timer, or NULL */
} RRtcIceCheckPair;

/* tcptype (RFC 6544): an active candidate dials out, a passive one listens. */
typedef enum {
  R_RTC_ICE_TCP_NONE = 0,
  R_RTC_ICE_TCP_ACTIVE,
  R_RTC_ICE_TCP_PASSIVE,
} RRtcIceTcpType;

/* An established (accepted or connected) ICE-TCP byte stream, carrying
 * length-prefixed STUN / media frames to one peer. */
struct RRtcIceTcpConn {
  RRtcIceTransport * ice;     /* borrowed */
  REvTCP * tcp;               /* owned */
  RRtcIceCandidate * local;   /* owned: local TCP candidate (base) */
  RRtcIceCandidate * remotecand; /* owned: remote candidate (active dials it); NULL passive */
  RSocketAddress * remote;    /* owned: peer address */
  rboolean up;                /* connected / accepted and receiving */

  ruint8 * rx;                /* reassembly accumulator */
  rsize rxlen;
  rsize rxalloc;
};

/* Where an inbound STUN message came from, so a reply / triggered check
 * goes back the same way (a UDP socket + peer address, or a TCP conn). */
typedef struct {
  REvUDP * udp;
  RRtcIceTcpConn * conn;
  RRtcIceCandidate * local;
  RSocketAddress * addr;
  RRtcIceTurnAlloc * alloc;   /* set when the frame arrived via a TURN relay */
} RRtcIceSrc;

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

/* A STUN Binding request outstanding to a STUN server, discovering the
 * server-reflexive address of its base host socket. */
typedef struct {
  RRtcIceTransport * ice;     /* borrowed */
  RRtcIceCandidate * base;    /* owned: the host candidate reflected */
  REvUDP * udp;               /* borrowed: base's socket */
  RSocketAddress * server;    /* owned: the STUN server */
  ruint8 tid[R_STUN_TRANSACTION_ID_SIZE];
  ruint nsent;
  RClockEntry * timer;
} RRtcIceSrflxReq;

static void
r_rtc_ice_srflx_req_free (rpointer data)
{
  RRtcIceSrflxReq * req = data;

  if (req->timer != NULL && req->ice->loop != NULL)
    r_ev_loop_cancel_timer (req->ice->loop, req->timer);
  r_rtc_ice_candidate_unref (req->base);
  r_socket_address_unref (req->server);
  r_free (req);
}

static void
r_rtc_ice_tcp_conn_free (rpointer data)
{
  RRtcIceTcpConn * conn = data;

  if (conn->tcp != NULL) {
    r_ev_tcp_recv_stop (conn->tcp);
    r_ev_tcp_abort (conn->tcp, NULL, NULL, NULL);
    r_ev_tcp_unref (conn->tcp);
  }
  r_rtc_ice_candidate_unref (conn->local);
  if (conn->remotecand != NULL)
    r_rtc_ice_candidate_unref (conn->remotecand);
  if (conn->remote != NULL)
    r_socket_address_unref (conn->remote);
  r_free (conn->rx);
  r_free (conn);
}

/* Tear down a live TCP connection, invalidating the borrowed references to
 * it that the selected path and any check pairs hold, before freeing it.
 * (Not used at transport teardown, where ice->checks is already gone.) */
static void
r_rtc_ice_drop_conn (RRtcIceTransport * ice, RRtcIceTcpConn * conn)
{
  rsize i, c;

  if (ice->selected_conn == conn) {
    ice->selected_conn = NULL;
    ice->send = NULL;
    if (ice->state == R_RTC_ICE_STATE_CONNECTED)
      ice->state = R_RTC_ICE_STATE_DISCONNECTED;
  }
  for (i = 0, c = r_ptr_array_size (ice->checks); i < c; i++) {
    RRtcIceCheckPair * pair = r_ptr_array_get (ice->checks, i);
    if (pair->conn != conn)
      continue;
    if (pair->timer != NULL) {
      r_ev_loop_cancel_timer (ice->loop, pair->timer);
      pair->timer = NULL;
    }
    pair->conn = NULL;
    pair->state = R_RTC_ICE_CHECK_FAILED;
  }
  r_ptr_array_remove_first_fast (ice->tcpconns, conn);
}

static void
r_rtc_ice_transport_free (RRtcIceTransport * ice)
{
  /* Drop the checks / srflx first: cancelling their timers needs ice->loop. */
  if (ice->ta_timer != NULL && ice->loop != NULL)
    r_ev_loop_cancel_timer (ice->loop, ice->ta_timer);
  r_ptr_array_unref (ice->checks);
  r_ptr_array_unref (ice->srflx);
  r_ptr_array_unref (ice->turn);
  r_ptr_array_unref (ice->allocs);
  r_ptr_array_unref (ice->tcpconns);
  r_ptr_array_unref (ice->remote);

  if (ice->selected.local != NULL)
    r_rtc_ice_candidate_unref (ice->selected.local);
  if (ice->selected.remote != NULL)
    r_rtc_ice_candidate_unref (ice->selected.remote);
  r_hash_table_unref (ice->candidateSockets);
  r_hash_table_unref (ice->bindAddrs);

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
    ret->bindAddrs = r_hash_table_new_full (NULL, NULL,
        r_rtc_ice_candidate_unref, r_ref_unref);
    ret->remote = r_ptr_array_new ();
    ret->checks = r_ptr_array_new ();
    ret->srflx = r_ptr_array_new ();
    ret->turn = r_ptr_array_new ();
    ret->allocs = r_ptr_array_new ();
    ret->tcpconns = r_ptr_array_new ();
    R_LOG_TRACE ("RtcIceTransport %p new %s - %s", ret, ret->ufrag, ret->pwd);
  }

  return ret;
}

/* Prefix @buf with a 2-byte big-endian length (RFC 4571 framing). */
static RBuffer *
r_rtc_ice_tcp_frame (RBuffer * buf)
{
  RBuffer * ret = NULL;
  RMemMapInfo in = R_MEM_MAP_INFO_INIT;

  if (!r_buffer_map (buf, &in, R_MEM_MAP_READ))
    return NULL;

  if (in.size <= 0xffff &&
      (ret = r_buffer_new_alloc (NULL, in.size + R_RTC_ICE_TCP_FRAME_HDR, NULL)) != NULL) {
    RMemMapInfo out = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (ret, &out, R_MEM_MAP_WRITE)) {
      r_store_be16 (out.data, (ruint16) in.size);
      r_memcpy (out.data + R_RTC_ICE_TCP_FRAME_HDR, in.data, in.size);
      r_buffer_unmap (ret, &out);
      r_buffer_set_size (ret, in.size + R_RTC_ICE_TCP_FRAME_HDR);
    } else {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  r_buffer_unmap (buf, &in);
  return ret;
}

static void
r_rtc_ice_tcp_send (RRtcIceTcpConn * conn, RBuffer * buf)
{
  RBuffer * framed;

  if (conn->tcp != NULL && (framed = r_rtc_ice_tcp_frame (buf)) != NULL) {
    r_ev_tcp_send_and_forget (conn->tcp, framed);
    r_buffer_unref (framed);
  }
}

static RRtcIceTcpType
r_rtc_ice_candidate_tcptype (RRtcIceCandidate * cand)
{
  rsize i, c;

  for (i = 0, c = r_rtc_ice_candidate_ext_count (cand); i < c; i++) {
    const RStrKV * kv = r_rtc_ice_candidate_get_ext (cand, i);
    if (kv == NULL ||
        r_str_chunk_casecmp (&kv->key, R_STR_WITH_SIZE_ARGS ("tcptype")) != 0)
      continue;
    if (r_str_chunk_casecmp (&kv->val, R_STR_WITH_SIZE_ARGS ("active")) == 0)
      return R_RTC_ICE_TCP_ACTIVE;
    if (r_str_chunk_casecmp (&kv->val, R_STR_WITH_SIZE_ARGS ("passive")) == 0)
      return R_RTC_ICE_TCP_PASSIVE;
  }
  return R_RTC_ICE_TCP_NONE;
}

/* Send @buf to @peer through the TURN allocation @alloc (Send indication or,
 * once bound, ChannelData). */
static void r_rtc_ice_relay_send (RRtcIceTurnAlloc * alloc,
    RSocketAddress * peer, RBuffer * buf);

RRtcError
r_rtc_ice_transport_send_udp (rpointer rtc, RBuffer * buf)
{
  RRtcIceTransport * ice = rtc;
  REvUDP * udp;

  R_LOG_TRACE ("RtcIceTransport %p: %p:%"RSIZE_FMT, ice, buf, r_buffer_get_size (buf));

  /* The selected pair may be a TCP connection. */
  if (ice->selected_conn != NULL) {
    r_rtc_ice_tcp_send (ice->selected_conn, buf);
    return R_RTC_OK;
  }

  /* ...or a TURN relay allocation. */
  if (ice->selected_alloc != NULL) {
    r_rtc_ice_relay_send (ice->selected_alloc, ice->selected.remote->addr, buf);
    return R_RTC_OK;
  }

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

/* Send @buf back to the peer the message came from. */
static void
r_rtc_ice_reply (const RRtcIceSrc * src, RBuffer * buf)
{
  if (src->conn != NULL)
    r_rtc_ice_tcp_send (src->conn, buf);
  else if (src->alloc != NULL)
    r_rtc_ice_relay_send (src->alloc, src->addr, buf);
  else
    r_ev_udp_send (src->udp, buf, src->addr, NULL, NULL, NULL);
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

/* Build a Binding error response carrying ERROR-CODE @code (e.g. 487 Role
 * Conflict), keyed with our own password. */
static RBuffer *
r_rtc_ice_transport_create_error_response (RRtcIceTransport * ice,
    const ruint8 transaction_id[R_STUN_TRANSACTION_ID_SIZE], ruint code)
{
  RBuffer * ret;

  if ((ret = r_buffer_new_alloc (NULL, 128, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
      ruint8 err[4];
      rsize size;

      err[0] = 0; err[1] = 0;
      err[2] = (ruint8) (code / 100);
      err[3] = (ruint8) (code % 100);

      r_stun_msg_begin (&ctx, info.data, info.size,
          R_STUN_CLASS_ERROR_RESPONSE, R_STUN_METHOD_BINDING, transaction_id);
      tlv.type = R_STUN_ATTR_TYPE_ERROR_CODE;
      tlv.len = sizeof (err);
      tlv.value = err;
      r_stun_msg_add_attribute (&ctx, &tlv);
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

/* After a role switch the G/D roles flip, so every pair's priority (and thus
 * the check-list order) must be recomputed (RFC 8445 7.3.1.1). */
static void
r_rtc_ice_recompute_priorities (RRtcIceTransport * ice)
{
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->checks); i < c; i++) {
    RRtcIceCheckPair * pair = r_ptr_array_get (ice->checks, i);
    pair->priority = r_rtc_ice_pair_priority (ice->role,
        pair->local->pri, pair->remote->pri);
  }
}

typedef struct {
  rpointer sock;
  RRtcIceCandidate * local;
} RRtcIceLocalLookup;

static void
r_rtc_ice_local_for_sock_cb (rpointer key, rpointer value, rpointer user)
{
  RRtcIceLocalLookup * lookup = user;

  if (value == lookup->sock)
    lookup->local = key;
}

/* Reverse the candidate -> socket table to find the local candidate a
 * socket (UDP socket or TCP listener) was bound for. */
static RRtcIceCandidate *
r_rtc_ice_local_for_sock (RRtcIceTransport * ice, rpointer sock)
{
  RRtcIceLocalLookup lookup = { sock, NULL };

  r_hash_table_foreach (ice->candidateSockets, r_rtc_ice_local_for_sock_cb, &lookup);
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
    REvUDP * udp, RRtcIceTcpConn * conn, RRtcIceCandidate * remote)
{
  RRtcIceCheckPair * pair;

  if ((pair = r_mem_new0 (RRtcIceCheckPair)) == NULL)
    return NULL;

  pair->local = r_rtc_ice_candidate_ref (local);
  pair->remote = r_rtc_ice_candidate_ref (remote);
  pair->udp = udp;
  pair->conn = conn;
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

/* The highest-priority pair whose check has succeeded, or NULL. */
static RRtcIceCheckPair *
r_rtc_ice_best_succeeded (RRtcIceTransport * ice)
{
  RRtcIceCheckPair * best = NULL;
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->checks); i < c; i++) {
    RRtcIceCheckPair * pair = r_ptr_array_get (ice->checks, i);
    if (pair->state == R_RTC_ICE_CHECK_SUCCEEDED &&
        (best == NULL || pair->priority > best->priority))
      best = pair;
  }
  return best;
}

/* Move to FAILED once nothing can still make a pair usable: no pair is
 * waiting / in progress / succeeded, and no gathering is outstanding. */
static void
r_rtc_ice_maybe_failed (RRtcIceTransport * ice)
{
  rsize i, c;

  if (ice->nominated || ice->state == R_RTC_ICE_STATE_FAILED)
    return;
  if (ice->ta_timer != NULL ||
      r_ptr_array_size (ice->srflx) > 0 || r_ptr_array_size (ice->turn) > 0)
    return;

  for (i = 0, c = r_ptr_array_size (ice->checks); i < c; i++) {
    RRtcIceCheckPair * pair = r_ptr_array_get (ice->checks, i);
    if (pair->state != R_RTC_ICE_CHECK_FAILED)
      return;
  }

  R_LOG_INFO ("RtcIceTransport %p all checks failed", ice);
  ice->state = R_RTC_ICE_STATE_FAILED;
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
    if (pair->conn != NULL)
      r_rtc_ice_tcp_send (pair->conn, buf);
    else if (pair->alloc != NULL)
      r_rtc_ice_relay_send (pair->alloc, pair->remote->addr, buf);
    else
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
    RRtcIceTransport * ice = pair->ice;

    R_LOG_INFO ("RtcIceTransport %p check pair timed out", ice);
    pair->state = R_RTC_ICE_CHECK_FAILED;

    /* A failed nominating check must not strand a valid pair: nominate the
     * next-best succeeded one instead of giving up (RFC 8445 8.1.1). */
    if (pair->nominating && ice->role == R_RTC_ICE_ROLE_CONTROLLING &&
        !ice->nominated) {
      RRtcIceCheckPair * next = r_rtc_ice_best_succeeded (ice);
      if (next != NULL) {
        next->nominating = TRUE;
        r_rtc_ice_transmit_check (ice, next, TRUE);
        return;
      }
    }
    r_rtc_ice_maybe_failed (ice);
    return;
  }

  r_rtc_ice_transmit_check (pair->ice, pair, FALSE);
}

/* The highest-priority pair still waiting for its first check, or NULL. */
static RRtcIceCheckPair *
r_rtc_ice_next_waiting (RRtcIceTransport * ice)
{
  RRtcIceCheckPair * best = NULL;
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->checks); i < c; i++) {
    RRtcIceCheckPair * pair = r_ptr_array_get (ice->checks, i);
    if (pair->state == R_RTC_ICE_CHECK_WAITING &&
        (best == NULL || pair->priority > best->priority))
      best = pair;
  }
  return best;
}

static void r_rtc_ice_ta_tick (rpointer data, REvLoop * loop);

/* Pace ordinary connectivity checks at Ta: arm the scheduler if there is a
 * waiting pair and we can send (credentials known). */
static void
r_rtc_ice_schedule_checks (RRtcIceTransport * ice)
{
  if (ice->ta_timer != NULL || ice->nominated)
    return;
  if (ice->loop == NULL || ice->rpwd == NULL || ice->rufrag == NULL)
    return;
  if (r_rtc_ice_next_waiting (ice) == NULL)
    return;

  r_ev_loop_add_callback_later (ice->loop, &ice->ta_timer,
      R_RTC_ICE_TA, r_rtc_ice_ta_tick, ice, NULL);
}

static void
r_rtc_ice_ta_tick (rpointer data, REvLoop * loop)
{
  RRtcIceTransport * ice = data;
  RRtcIceCheckPair * pair;
  (void) loop;

  ice->ta_timer = NULL;
  if (ice->nominated)
    return;

  if ((pair = r_rtc_ice_next_waiting (ice)) != NULL)
    r_rtc_ice_transmit_check (ice, pair, TRUE);

  r_rtc_ice_schedule_checks (ice);   /* more waiting -> keep pacing */
}

/* Server-reflexive candidate priority, RFC 8445 5.1.2.1: type preference
 * 100, local preference 65535, component in the low octet. */
static ruint64
r_rtc_ice_srflx_priority (RRtcIceComponent component)
{
  ruint comp = component != R_RTC_ICE_COMPONENT_UNKNOWN ? component : 1;

  return ((ruint64) 100 << 24) | ((ruint64) 65535 << 8) | (256 - comp);
}

/* A plain STUN Binding request (no ICE attributes) for a STUN server. */
static RBuffer *
r_rtc_ice_build_stun_binding (const ruint8 * tid)
{
  RBuffer * ret;

  if ((ret = r_buffer_new_alloc (NULL, 128, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      rsize size;

      r_stun_msg_begin (&ctx, info.data, info.size,
          R_STUN_CLASS_REQUEST, R_STUN_METHOD_BINDING, tid);
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

static void r_rtc_ice_srflx_timeout (rpointer data, REvLoop * loop);

static void
r_rtc_ice_srflx_transmit (RRtcIceSrflxReq * req, rboolean fresh)
{
  RBuffer * buf;

  if (fresh) {
    r_rand_entropy_fill (req->tid, sizeof (req->tid));
    req->nsent = 0;
  }

  if ((buf = r_rtc_ice_build_stun_binding (req->tid)) != NULL) {
    r_ev_udp_send (req->udp, buf, req->server, NULL, NULL, NULL);
    r_buffer_unref (buf);
    req->nsent++;
  }

  req->timer = NULL;
  r_ev_loop_add_callback_later (req->ice->loop, &req->timer,
      R_RTC_ICE_CHECK_RTO, r_rtc_ice_srflx_timeout, req, NULL);
}

static void
r_rtc_ice_srflx_timeout (rpointer data, REvLoop * loop)
{
  RRtcIceSrflxReq * req = data;
  (void) loop;

  req->timer = NULL;
  if (req->nsent >= R_RTC_ICE_CHECK_MAX_SENDS) {
    R_LOG_INFO ("RtcIceTransport %p srflx gathering timed out", req->ice);
    r_ptr_array_remove_first_fast (req->ice->srflx, req);
    return;
  }

  r_rtc_ice_srflx_transmit (req, FALSE);
}

/* Match a Binding response against an outstanding srflx request; on a hit,
 * turn its XOR-MAPPED-ADDRESS into a server-reflexive candidate and hand it
 * to the application. Returns TRUE when the response was a srflx reply. */
static rboolean
r_rtc_ice_srflx_response (RRtcIceTransport * ice, rconstpointer msg)
{
  const ruint8 * tid = r_stun_msg_transaction_id (msg);
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->srflx); i < c; i++) {
    RRtcIceSrflxReq * req = r_ptr_array_get (ice->srflx, i);
    RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
    RSocketAddress * mapped = NULL;

    if (r_memcmp_ct (req->tid, tid, R_STUN_TRANSACTION_ID_SIZE) != 0)
      continue;

    if (r_stun_attr_tlv_first (msg, &tlv)) {
      do {
        if (tlv.type == R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS) {
          mapped = r_stun_attr_tlv_parse_xor_address (msg, &tlv);
          break;
        }
      } while (r_stun_attr_tlv_next (msg, &tlv));
    }

    if (mapped != NULL) {
      RRtcIceCandidate * cand = r_rtc_ice_candidate_new_full ("srflx", -1,
          r_rtc_ice_srflx_priority (ice->component), ice->component,
          R_RTC_ICE_PROTO_UDP, mapped, R_RTC_ICE_CANDIDATE_SRFLX);
      r_socket_address_unref (mapped);
      if (cand != NULL) {
        cand->raddr = r_socket_address_ref (req->base->addr);
        R_LOG_INFO ("RtcIceTransport %p gathered srflx candidate", ice);
        if (ice->on_candidate != NULL)
          ice->on_candidate (ice->on_candidate_data, ice, cand);
        r_rtc_ice_candidate_unref (cand);
      }
    }

    r_ptr_array_remove_first_fast (ice->srflx, req);
    return TRUE;
  }

  return FALSE;
}

/* Relay candidate priority, RFC 8445 5.1.2.1: type preference 0. */
static ruint64
r_rtc_ice_relay_priority (RRtcIceComponent component)
{
  ruint comp = component != R_RTC_ICE_COMPONENT_UNKNOWN ? component : 1;

  return ((ruint64) 65535 << 8) | (256 - comp);
}

/* A TURN Allocate outstanding to a TURN server, discovering the relayed
 * transport address for its base host socket. */
typedef struct {
  RRtcIceTransport * ice;
  RRtcIceCandidate * base;
  REvUDP * udp;
  RSocketAddress * server;
  rchar * username;
  rchar * password;
  rchar * realm;              /* learned from the 401 challenge */
  rchar * nonce;
  ruint8 tid[R_STUN_TRANSACTION_ID_SIZE];
  ruint nsent;
  rboolean authed;            /* the credentialed retry has been sent */
  RClockEntry * timer;
} RRtcIceTurnReq;

static void
r_rtc_ice_turn_req_free (rpointer data)
{
  RRtcIceTurnReq * req = data;

  if (req->timer != NULL && req->ice->loop != NULL)
    r_ev_loop_cancel_timer (req->ice->loop, req->timer);
  r_rtc_ice_candidate_unref (req->base);
  r_socket_address_unref (req->server);
  r_free (req->username);
  r_free (req->password);
  r_free (req->realm);
  r_free (req->nonce);
  r_free (req);
}

/* Long-term credential key, RFC 8489 18.5.1: MD5(username ":" realm ":" pwd). */
static rboolean
r_rtc_ice_turn_key (const rchar * username, const rchar * realm,
    const rchar * password, ruint8 out[16])
{
  RMsgDigest * md;
  rsize outlen = 0;
  rboolean ok = FALSE;

  if ((md = r_msg_digest_new_md5 ()) != NULL) {
    r_msg_digest_update (md, username, r_strlen (username));
    r_msg_digest_update (md, ":", 1);
    r_msg_digest_update (md, realm, r_strlen (realm));
    r_msg_digest_update (md, ":", 1);
    r_msg_digest_update (md, password, r_strlen (password));
    ok = r_msg_digest_get_data (md, out, 16, &outlen) && outlen == 16;
    r_msg_digest_free (md);
  }
  return ok;
}

static RBuffer *
r_rtc_ice_build_allocate (RRtcIceTurnReq * req)
{
  RBuffer * ret;

  if ((ret = r_buffer_new_alloc (NULL, 512, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
      ruint8 rt[4] = { 17, 0, 0, 0 };   /* REQUESTED-TRANSPORT: UDP (17) */
      rsize size;

      r_stun_msg_begin (&ctx, info.data, info.size,
          R_STUN_CLASS_REQUEST, R_STUN_METHOD_ALLOCATE, req->tid);

      tlv.type = R_STUN_ATTR_TYPE_REQUESTED_TRANSPORT;
      tlv.len = sizeof (rt);
      tlv.value = rt;
      r_stun_msg_add_attribute (&ctx, &tlv);

      if (req->authed) {
        ruint8 key[16];

        tlv.type = R_STUN_ATTR_TYPE_USERNAME;
        tlv.len = (ruint16) r_strlen (req->username);
        tlv.value = (const ruint8 *) req->username;
        r_stun_msg_add_attribute (&ctx, &tlv);
        tlv.type = R_STUN_ATTR_TYPE_REALM;
        tlv.len = (ruint16) r_strlen (req->realm);
        tlv.value = (const ruint8 *) req->realm;
        r_stun_msg_add_attribute (&ctx, &tlv);
        tlv.type = R_STUN_ATTR_TYPE_NONCE;
        tlv.len = (ruint16) r_strlen (req->nonce);
        tlv.value = (const ruint8 *) req->nonce;
        r_stun_msg_add_attribute (&ctx, &tlv);

        if (r_rtc_ice_turn_key (req->username, req->realm, req->password, key))
          r_stun_msg_add_message_integrity_short_cred (&ctx, key, sizeof (key));
      }

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

static void r_rtc_ice_turn_timeout (rpointer data, REvLoop * loop);

static void
r_rtc_ice_turn_transmit (RRtcIceTurnReq * req, rboolean fresh)
{
  RBuffer * buf;

  if (fresh) {
    r_rand_entropy_fill (req->tid, sizeof (req->tid));
    req->nsent = 0;
  }

  if ((buf = r_rtc_ice_build_allocate (req)) != NULL) {
    r_ev_udp_send (req->udp, buf, req->server, NULL, NULL, NULL);
    r_buffer_unref (buf);
    req->nsent++;
  }

  req->timer = NULL;
  r_ev_loop_add_callback_later (req->ice->loop, &req->timer,
      R_RTC_ICE_CHECK_RTO, r_rtc_ice_turn_timeout, req, NULL);
}

static void
r_rtc_ice_turn_timeout (rpointer data, REvLoop * loop)
{
  RRtcIceTurnReq * req = data;
  (void) loop;

  req->timer = NULL;
  if (req->nsent >= R_RTC_ICE_CHECK_MAX_SENDS) {
    R_LOG_INFO ("RtcIceTransport %p TURN allocate timed out", req->ice);
    r_ptr_array_remove_first_fast (req->ice->turn, req);
    return;
  }

  r_rtc_ice_turn_transmit (req, FALSE);
}

/* Verify a TURN response's MESSAGE-INTEGRITY against the long-term key. */
static rboolean
r_rtc_ice_turn_check_integrity (rconstpointer msg, RRtcIceTurnReq * req)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  ruint8 key[16];

  if (req->realm == NULL ||
      !r_rtc_ice_turn_key (req->username, req->realm, req->password, key) ||
      !r_stun_attr_tlv_first (msg, &tlv))
    return FALSE;
  do {
    if (tlv.type == R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY)
      return r_stun_msg_check_integrity_short_cred (msg, &tlv, key, sizeof (key));
  } while (r_stun_attr_tlv_next (msg, &tlv));
  return FALSE;
}

/* A permission installed on an allocation, authorizing traffic to and from
 * one peer. Keyed by peer IP only -- port is not significant (RFC 8656 9). */
typedef struct {
  RSocketAddress * peer;      /* owned */
  ruint8 tid[R_STUN_TRANSACTION_ID_SIZE];
} RRtcIceTurnPerm;

/* A live TURN allocation: the relayed transport address plus the permission
 * state that lets its relay candidate carry traffic to peers. Outlives the
 * RRtcIceTurnReq that discovered it. */
struct RRtcIceTurnAlloc {
  RRtcIceTransport * ice;     /* borrowed */
  RRtcIceCandidate * base;    /* owned: the reflected host candidate */
  REvUDP * udp;               /* borrowed: base socket, shared with the host cand */
  RSocketAddress * server;    /* owned: the TURN server */
  RRtcIceCandidate * cand;    /* owned: the local relay candidate */
  rchar * username;
  rchar * password;
  rchar * realm;
  rchar * nonce;
  RPtrArray * perms;          /* installed permissions (RRtcIceTurnPerm *) */
};

static void
r_rtc_ice_turn_perm_free (rpointer data)
{
  RRtcIceTurnPerm * perm = data;

  r_socket_address_unref (perm->peer);
  r_free (perm);
}

static void
r_rtc_ice_turn_alloc_free (rpointer data)
{
  RRtcIceTurnAlloc * alloc = data;

  r_ptr_array_unref (alloc->perms);
  r_rtc_ice_candidate_unref (alloc->base);
  r_rtc_ice_candidate_unref (alloc->cand);
  r_socket_address_unref (alloc->server);
  r_free (alloc->username);
  r_free (alloc->password);
  r_free (alloc->realm);
  r_free (alloc->nonce);
  r_free (alloc);
}

/* Compare two addresses by IP only (TURN permissions are port-independent). */
static rboolean
r_rtc_ice_addr_same_ip (const RSocketAddress * a, const RSocketAddress * b)
{
  RSocketFamily fa = r_socket_address_get_family (a);

  if (fa != r_socket_address_get_family (b))
    return FALSE;
  if (fa == R_SOCKET_FAMILY_IPV4)
    return r_socket_address_ipv4_get_ip (a) == r_socket_address_ipv4_get_ip (b);
  if (fa == R_SOCKET_FAMILY_IPV6) {
    ruint8 ba[16], bb[16];
    return r_socket_address_ipv6_get_ip_bytes (a, ba) &&
        r_socket_address_ipv6_get_ip_bytes (b, bb) &&
        r_memcmp (ba, bb, sizeof (ba)) == 0;
  }
  return FALSE;
}

/* Wrap @payload in a TURN Send indication carrying XOR-PEER-ADDRESS @peer. */
static RBuffer *
r_rtc_ice_build_send_indication (RSocketAddress * peer, RBuffer * payload)
{
  RBuffer * ret;
  RMemMapInfo pi = R_MEM_MAP_INFO_INIT;

  if (!r_buffer_map (payload, &pi, R_MEM_MAP_READ))
    return NULL;

  if ((ret = r_buffer_new_alloc (NULL, pi.size + 128, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
      ruint8 tid[R_STUN_TRANSACTION_ID_SIZE];
      rsize size;

      r_rand_entropy_fill (tid, sizeof (tid));
      r_stun_msg_begin (&ctx, info.data, info.size,
          R_STUN_CLASS_INDICATION, R_STUN_METHOD_SEND, tid);
      r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS, peer);
      tlv.type = R_STUN_ATTR_TYPE_DATA;
      tlv.len = (ruint16) pi.size;
      tlv.value = pi.data;
      r_stun_msg_add_attribute (&ctx, &tlv);
      size = r_stun_msg_end (&ctx, TRUE);
      r_buffer_unmap (ret, &info);
      r_buffer_set_size (ret, size);
    } else {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  r_buffer_unmap (payload, &pi);
  return ret;
}

/* Build a TURN CreatePermission request for @perm, keyed with the long-term
 * credential. */
static RBuffer *
r_rtc_ice_build_create_permission (RRtcIceTurnAlloc * alloc, RRtcIceTurnPerm * perm)
{
  RBuffer * ret;

  if ((ret = r_buffer_new_alloc (NULL, 256, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
      ruint8 key[16];
      rsize size;

      r_stun_msg_begin (&ctx, info.data, info.size,
          R_STUN_CLASS_REQUEST, R_STUN_METHOD_CREATE_PERMISSION, perm->tid);
      r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS, perm->peer);

      tlv.type = R_STUN_ATTR_TYPE_USERNAME;
      tlv.len = (ruint16) r_strlen (alloc->username);
      tlv.value = (const ruint8 *) alloc->username;
      r_stun_msg_add_attribute (&ctx, &tlv);
      tlv.type = R_STUN_ATTR_TYPE_REALM;
      tlv.len = (ruint16) r_strlen (alloc->realm);
      tlv.value = (const ruint8 *) alloc->realm;
      r_stun_msg_add_attribute (&ctx, &tlv);
      tlv.type = R_STUN_ATTR_TYPE_NONCE;
      tlv.len = (ruint16) r_strlen (alloc->nonce);
      tlv.value = (const ruint8 *) alloc->nonce;
      r_stun_msg_add_attribute (&ctx, &tlv);

      if (r_rtc_ice_turn_key (alloc->username, alloc->realm, alloc->password, key))
        r_stun_msg_add_message_integrity_short_cred (&ctx, key, sizeof (key));
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

/* Install a permission for @peer's IP if there is not one already; the
 * request is sent without awaiting the response (a dropped first datagram is
 * recovered by connectivity-check retransmission). */
static void
r_rtc_ice_turn_ensure_permission (RRtcIceTurnAlloc * alloc, RSocketAddress * peer)
{
  RRtcIceTurnPerm * perm;
  RBuffer * buf;
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (alloc->perms); i < c; i++) {
    perm = r_ptr_array_get (alloc->perms, i);
    if (r_rtc_ice_addr_same_ip (perm->peer, peer))
      return;
  }

  if ((perm = r_mem_new0 (RRtcIceTurnPerm)) == NULL)
    return;
  perm->peer = r_socket_address_ref (peer);
  r_rand_entropy_fill (perm->tid, sizeof (perm->tid));
  r_ptr_array_add (alloc->perms, perm, r_rtc_ice_turn_perm_free);

  if ((buf = r_rtc_ice_build_create_permission (alloc, perm)) != NULL) {
    r_ev_udp_send (alloc->udp, buf, alloc->server, NULL, NULL, NULL);
    r_buffer_unref (buf);
  }
}

static void
r_rtc_ice_relay_send (RRtcIceTurnAlloc * alloc, RSocketAddress * peer, RBuffer * buf)
{
  RBuffer * wrapped;

  r_rtc_ice_turn_ensure_permission (alloc, peer);
  if ((wrapped = r_rtc_ice_build_send_indication (peer, buf)) != NULL) {
    r_ev_udp_send (alloc->udp, wrapped, alloc->server, NULL, NULL, NULL);
    r_buffer_unref (wrapped);
  }
}

/* Spawn a persistent allocation from the Allocate transaction @req that just
 * succeeded, adopting its credentials and relay candidate @cand. */
static RRtcIceTurnAlloc *
r_rtc_ice_turn_alloc_new (RRtcIceTurnReq * req, RRtcIceCandidate * cand)
{
  RRtcIceTurnAlloc * alloc;

  if ((alloc = r_mem_new0 (RRtcIceTurnAlloc)) == NULL)
    return NULL;
  alloc->ice = req->ice;
  alloc->base = r_rtc_ice_candidate_ref (req->base);
  alloc->udp = req->udp;
  alloc->server = r_socket_address_ref (req->server);
  alloc->cand = r_rtc_ice_candidate_ref (cand);
  alloc->username = r_strdup (req->username);
  alloc->password = r_strdup (req->password);
  alloc->realm = r_strdup (req->realm);
  alloc->nonce = r_strdup (req->nonce);
  alloc->perms = r_ptr_array_new ();
  return alloc;
}

/* Pair @alloc's relay candidate with UDP remote @remote, so the relay path
 * takes part in connectivity checks. */
static RRtcIceCheckPair *
r_rtc_ice_alloc_add_pair (RRtcIceTurnAlloc * alloc, RRtcIceCandidate * remote)
{
  RRtcIceTransport * ice = alloc->ice;
  RRtcIceCheckPair * pair;

  if (remote->proto != R_RTC_ICE_PROTO_UDP)
    return NULL;
  if (r_rtc_ice_find_pair (ice, alloc->cand, remote->addr) != NULL)
    return NULL;
  if ((pair = r_rtc_ice_add_pair (ice, alloc->cand, NULL, NULL, remote)) == NULL)
    return NULL;
  pair->alloc = alloc;
  return pair;
}

static void
r_rtc_ice_alloc_pair_with_remotes (RRtcIceTurnAlloc * alloc)
{
  RRtcIceTransport * ice = alloc->ice;
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->remote); i < c; i++) {
    if (r_rtc_ice_alloc_add_pair (alloc, r_ptr_array_get (ice->remote, i)) != NULL)
      r_rtc_ice_schedule_checks (ice);
  }
}

/* Handle a TURN Allocate response: answer a 401 challenge with long-term
 * credentials, or turn the (integrity-verified) XOR-RELAYED-ADDRESS into a
 * relay candidate. */
static void
r_rtc_ice_turn_response (RRtcIceTransport * ice, rconstpointer msg)
{
  const ruint8 * tid = r_stun_msg_transaction_id (msg);
  rboolean err = r_stun_msg_is_err_resp (msg);
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->turn); i < c; i++) {
    RRtcIceTurnReq * req = r_ptr_array_get (ice->turn, i);
    RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
    RSocketAddress * relayed = NULL;
    rchar * realm = NULL, * nonce = NULL;
    ruint code = 0;

    if (r_memcmp_ct (req->tid, tid, R_STUN_TRANSACTION_ID_SIZE) != 0)
      continue;

    if (r_stun_attr_tlv_first (msg, &tlv)) {
      do {
        switch (tlv.type) {
          case R_STUN_ATTR_TYPE_XOR_RELAYED_ADDRESS:
            relayed = r_stun_attr_tlv_parse_xor_address (msg, &tlv);
            break;
          case R_STUN_ATTR_TYPE_ERROR_CODE:
            code = r_stun_attr_tlv_parse_error_code (msg, &tlv);
            break;
          case R_STUN_ATTR_TYPE_REALM:
            realm = r_strdup_size ((const rchar *) tlv.value, tlv.len);
            break;
          case R_STUN_ATTR_TYPE_NONCE:
            nonce = r_strdup_size ((const rchar *) tlv.value, tlv.len);
            break;
          default:
            break;
        }
      } while (r_stun_attr_tlv_next (msg, &tlv));
    }

    if (err && code == 401 && !req->authed && realm != NULL && nonce != NULL) {
      r_free (req->realm); req->realm = realm; realm = NULL;
      r_free (req->nonce); req->nonce = nonce; nonce = NULL;
      req->authed = TRUE;
      r_rtc_ice_turn_transmit (req, TRUE);
    } else if (!err && relayed != NULL &&
        r_rtc_ice_turn_check_integrity (msg, req)) {
      RRtcIceCandidate * cand = r_rtc_ice_candidate_new_full ("relay", -1,
          r_rtc_ice_relay_priority (ice->component), ice->component,
          R_RTC_ICE_PROTO_UDP, relayed, R_RTC_ICE_CANDIDATE_RELAY);
      if (cand != NULL) {
        RRtcIceTurnAlloc * alloc = r_rtc_ice_turn_alloc_new (req, cand);
        cand->raddr = r_socket_address_ref (req->base->addr);
        R_LOG_INFO ("RtcIceTransport %p gathered relay candidate", ice);
        if (ice->on_candidate != NULL)
          ice->on_candidate (ice->on_candidate_data, ice, cand);
        if (alloc != NULL) {
          r_ptr_array_add (ice->allocs, alloc, r_rtc_ice_turn_alloc_free);
          r_rtc_ice_alloc_pair_with_remotes (alloc);
        }
        r_rtc_ice_candidate_unref (cand);
      }
      r_ptr_array_remove_first_fast (ice->turn, req);
    } else {
      R_LOG_WARNING ("RtcIceTransport %p TURN allocate failed (code %u)", ice, code);
      r_ptr_array_remove_first_fast (ice->turn, req);
    }

    if (relayed != NULL)
      r_socket_address_unref (relayed);
    r_free (realm);
    r_free (nonce);
    return;
  }
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
  ice->selected_conn = pair->conn;   /* NULL for a UDP pair */
  ice->selected_alloc = pair->alloc; /* non-NULL for a relay pair */
  ice->send = r_rtc_ice_transport_send_udp;

  R_LOG_INFO ("RtcIceTransport %p pair nominated, connected (%s)", ice,
      pair->conn != NULL ? "TCP" : pair->alloc != NULL ? "relay" : "UDP");
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
    const RRtcIceSrc * src)
{
  RRtcIceCandidate * remote;
  RRtcIceCheckPair * pair;
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  rboolean use_candidate = FALSE;
  RStunAttrType peer_role = 0;
  ruint64 peer_tiebreaker = 0;
  ruint64 peer_priority = 0;
  RRtcIceProtocol proto = src->conn != NULL ? R_RTC_ICE_PROTO_TCP : R_RTC_ICE_PROTO_UDP;
  RBuffer * outbuf;

  /* The peer keys its requests with our local password. */
  if (!r_rtc_ice_check_integrity (msg, ice->pwd)) {
    R_LOG_WARNING ("RtcIceTransport %p check request failed integrity", ice);
    return;
  }

  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_USE_CANDIDATE) {
        use_candidate = TRUE;
      } else if (tlv.type == R_STUN_ATTR_TYPE_ICE_CONTROLLING ||
          tlv.type == R_STUN_ATTR_TYPE_ICE_CONTROLLED) {
        peer_role = tlv.type;
        if (tlv.len == 8)
          peer_tiebreaker = r_load_be64 (tlv.value);
      } else if (tlv.type == R_STUN_ATTR_TYPE_PRIORITY && tlv.len == 4) {
        peer_priority = r_stun_attr_tlv_parse_priority (msg, &tlv);
      }
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }

  /* Role conflict (RFC 8445 7.3.1.1): the peer claims the same role we
   * hold. The higher tie-breaker keeps controlling; the loser either
   * switches or is told to with a 487. */
  if (ice->role == R_RTC_ICE_ROLE_CONTROLLING &&
      peer_role == R_STUN_ATTR_TYPE_ICE_CONTROLLING) {
    if (ice->tiebreaker >= peer_tiebreaker) {
      if ((outbuf = r_rtc_ice_transport_create_error_response (ice,
              r_stun_msg_transaction_id (msg), 487)) != NULL) {
        r_rtc_ice_reply (src, outbuf);
        r_buffer_unref (outbuf);
      }
      return;
    }
    R_LOG_INFO ("RtcIceTransport %p role conflict, switching to controlled", ice);
    ice->role = R_RTC_ICE_ROLE_CONTROLLED;
    r_rtc_ice_recompute_priorities (ice);
  } else if (ice->role == R_RTC_ICE_ROLE_CONTROLLED &&
      peer_role == R_STUN_ATTR_TYPE_ICE_CONTROLLED) {
    if (ice->tiebreaker >= peer_tiebreaker) {
      R_LOG_INFO ("RtcIceTransport %p role conflict, switching to controlling", ice);
      ice->role = R_RTC_ICE_ROLE_CONTROLLING;
      r_rtc_ice_recompute_priorities (ice);
    } else {
      if ((outbuf = r_rtc_ice_transport_create_error_response (ice,
              r_stun_msg_transaction_id (msg), 487)) != NULL) {
        r_rtc_ice_reply (src, outbuf);
        r_buffer_unref (outbuf);
      }
      return;
    }
  }

  /* Respond, keyed with our own (local) password. */
  if ((outbuf = r_rtc_ice_transport_create_stun_response_binding (ice,
          src->addr, r_stun_msg_transaction_id (msg))) != NULL) {
    r_rtc_ice_reply (src, outbuf);
    r_buffer_unref (outbuf);
  }

  if (src->local == NULL)
    return;

  /* Learn a peer-reflexive remote candidate when the source is unknown. */
  if ((pair = r_rtc_ice_find_pair (ice, src->local, src->addr)) == NULL) {
    remote = r_rtc_ice_candidate_new_full (R_STR_WITH_SIZE_ARGS ("prflx"),
        peer_priority, ice->component, proto, src->addr, R_RTC_ICE_CANDIDATE_PRFLX);
    if (remote == NULL)
      return;
    r_ptr_array_add (ice->remote, remote, r_rtc_ice_candidate_unref);
    pair = r_rtc_ice_add_pair (ice, src->local, src->udp, src->conn, remote);
    if (pair == NULL)
      return;
    pair->alloc = src->alloc;   /* a relay-arrived request yields a relay pair */
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

  rboolean err = r_stun_msg_is_err_resp (msg);

  /* A reply from a STUN server (no ICE credentials) is handled first. */
  if (r_rtc_ice_srflx_response (ice, msg))
    return;

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

    /* A 487 Role Conflict: the peer kept the role we tried; switch and
     * re-check (RFC 8445 7.2.5.1). */
    if (err) {
      RStunAttrTLV etlv = R_STUN_ATTR_TLV_INIT;
      ruint code = 0;
      if (r_stun_attr_tlv_first (msg, &etlv)) {
        do {
          if (etlv.type == R_STUN_ATTR_TYPE_ERROR_CODE)
            code = r_stun_attr_tlv_parse_error_code (msg, &etlv);
        } while (r_stun_attr_tlv_next (msg, &etlv));
      }
      if (code == 487) {
        ice->role = ice->role == R_RTC_ICE_ROLE_CONTROLLING ?
            R_RTC_ICE_ROLE_CONTROLLED : R_RTC_ICE_ROLE_CONTROLLING;
        R_LOG_INFO ("RtcIceTransport %p got 487, switched role", ice);
        r_rtc_ice_recompute_priorities (ice);
        pair->nominating = FALSE;
        r_rtc_ice_transmit_check (ice, pair, TRUE);
      } else {
        pair->state = R_RTC_ICE_CHECK_FAILED;
      }
      return;
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

/* Dispatch one demapped STUN message from @src. */
static void
r_rtc_ice_handle_stun (RRtcIceTransport * ice, rconstpointer msg,
    const RRtcIceSrc * src)
{
  if (r_stun_msg_method_is_allocate (msg)) {
    if (r_stun_msg_is_success_resp (msg) || r_stun_msg_is_err_resp (msg))
      r_rtc_ice_turn_response (ice, msg);
  } else if (!r_stun_msg_method_is_binding (msg)) {
    R_LOG_WARNING ("RtcIceTransport %p unknown STUN method", ice);
  } else if (r_stun_msg_is_request (msg)) {
    r_rtc_ice_handle_binding_request (ice, msg, src);
  } else if (r_stun_msg_is_success_resp (msg) || r_stun_msg_is_err_resp (msg)) {
    r_rtc_ice_handle_binding_response (ice, msg);
  } else {
    R_LOG_TRACE ("RtcIceTransport %p binding indication", ice);
  }
}

/* The allocation whose TURN server is @addr, or NULL. Traffic from a server
 * we hold an allocation on is the relay's control / data path, not a peer's. */
static RRtcIceTurnAlloc *
r_rtc_ice_alloc_for_server (RRtcIceTransport * ice, const RSocketAddress * addr)
{
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->allocs); i < c; i++) {
    RRtcIceTurnAlloc * alloc = r_ptr_array_get (ice->allocs, i);
    if (r_socket_address_is_equal (alloc->server, addr))
      return alloc;
  }
  return NULL;
}

/* Unwrap a TURN Data indication: dispatch its DATA payload as if it had
 * arrived directly from the XOR-PEER-ADDRESS peer over the relay. */
static void
r_rtc_ice_turn_data_indication (RRtcIceTransport * ice, RRtcIceTurnAlloc * alloc,
    rconstpointer msg)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  RSocketAddress * peer = NULL;
  const ruint8 * payload = NULL;
  rsize plen = 0;

  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS)
        peer = r_stun_attr_tlv_parse_xor_address (msg, &tlv);
      else if (tlv.type == R_STUN_ATTR_TYPE_DATA) {
        payload = tlv.value;
        plen = tlv.len;
      }
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }

  if (peer != NULL && payload != NULL) {
    RBuffer * inner;

    /* The DATA payload sits at an odd offset in the indication; copy it into
     * an aligned buffer before the STUN parser reads 32-bit fields. */
    if ((inner = r_buffer_new_dup (payload, plen)) != NULL) {
      RMemMapInfo info = R_MEM_MAP_INFO_INIT;

      if (r_buffer_map (inner, &info, R_MEM_MAP_READ)) {
        if (r_stun_is_valid_msg (info.data, info.size)) {
          RRtcIceSrc src = { alloc->udp, NULL, alloc->cand, peer, alloc };
          r_rtc_ice_handle_stun (ice, info.data, &src);
          r_buffer_unmap (inner, &info);
        } else {
          r_buffer_unmap (inner, &info);
          ice->packet (ice->data, inner, ice);
        }
      }
      r_buffer_unref (inner);
    }
  }

  if (peer != NULL)
    r_socket_address_unref (peer);
}

/* Handle a datagram from a TURN server on the base socket: a relayed Data
 * indication, or a response to one of our own TURN transactions. */
static void
r_rtc_ice_turn_handle (RRtcIceTransport * ice, RRtcIceTurnAlloc * alloc,
    rconstpointer data, rsize size)
{
  if (!r_stun_is_valid_msg (data, size))
    return;
  if (r_stun_msg_is_indication (data) && r_stun_msg_method_is_data (data))
    r_rtc_ice_turn_data_indication (ice, alloc, data);
  else
    R_LOG_TRACE ("RtcIceTransport %p TURN control response", ice);
}

static void
r_rtc_ice_transport_udp_packet_cb (rpointer data,
    RBuffer * buf, RSocketAddress * addr, REvUDP * evudp)
{
  RRtcIceTransport * ice = data;
  RRtcIceTurnAlloc * alloc;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  R_LOG_TRACE ("RtcIceTransport %p packet", ice);

  r_buffer_map (buf, &info, R_MEM_MAP_READ);
  /* A datagram from a TURN server is relay traffic, not a peer's. (Before an
   * allocation exists, the Allocate responses fall through to the STUN path.) */
  if ((alloc = r_rtc_ice_alloc_for_server (ice, addr)) != NULL) {
    r_rtc_ice_turn_handle (ice, alloc, info.data, info.size);
    r_buffer_unmap (buf, &info);
  } else if (r_stun_is_valid_msg (info.data, info.size)) {
    RRtcIceSrc src = { evudp, NULL, r_rtc_ice_local_for_sock (ice, evudp), addr, NULL };
    r_rtc_ice_handle_stun (ice, info.data, &src);
    r_buffer_unmap (buf, &info);
  } else {
    r_buffer_unmap (buf, &info);
    ice->packet (ice->data, buf, ice);
  }
}

/* Feed a reassembled RFC 4571 frame from a TCP connection through the same
 * paths as a UDP datagram. */
static void
r_rtc_ice_tcp_dispatch (RRtcIceTcpConn * conn, const ruint8 * data, rsize size)
{
  RRtcIceTransport * ice = conn->ice;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RBuffer * buf;

  /* The frame sits at an odd offset in the reassembly accumulator; copy it
   * into an (aligned) buffer before the STUN parser reads 32-bit fields. */
  if ((buf = r_buffer_new_dup (data, size)) == NULL)
    return;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    if (r_stun_is_valid_msg (info.data, info.size)) {
      RRtcIceSrc src = { NULL, conn, conn->local, conn->remote, NULL };
      r_rtc_ice_handle_stun (ice, info.data, &src);
      r_buffer_unmap (buf, &info);
    } else {
      r_buffer_unmap (buf, &info);
      ice->packet (ice->data, buf, ice);
    }
  }
  r_buffer_unref (buf);
}

/* Accumulate received bytes and dispatch each complete length-prefixed
 * frame; a NULL @buf is end-of-stream. */
static void
r_rtc_ice_tcp_recv_cb (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RRtcIceTcpConn * conn = data;
  RRtcIceTransport * ice = conn->ice;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize off;
  (void) evtcp;

  if (buf == NULL) {   /* peer closed: drop the connection */
    r_rtc_ice_drop_conn (ice, conn);
    return;
  }

  if (!r_buffer_map (buf, &info, R_MEM_MAP_READ))
    return;

  if (conn->rxlen + info.size > conn->rxalloc) {
    rsize need = conn->rxlen + info.size;
    ruint8 * nrx;

    /* Cap the accumulator and survive OOM without dereferencing NULL or
     * leaking the old buffer (an unauthenticated peer drives this size). */
    if (need > R_RTC_ICE_TCP_RX_MAX || (nrx = r_realloc (conn->rx, need)) == NULL) {
      r_buffer_unmap (buf, &info);
      r_rtc_ice_drop_conn (ice, conn);
      return;
    }
    conn->rx = nrx;
    conn->rxalloc = need;
  }
  r_memcpy (conn->rx + conn->rxlen, info.data, info.size);
  conn->rxlen += info.size;
  r_buffer_unmap (buf, &info);

  off = 0;
  while (conn->rxlen - off >= R_RTC_ICE_TCP_FRAME_HDR) {
    rsize framelen = r_load_be16 (conn->rx + off);
    if (conn->rxlen - off < R_RTC_ICE_TCP_FRAME_HDR + framelen)
      break;
    r_rtc_ice_tcp_dispatch (conn, conn->rx + off + R_RTC_ICE_TCP_FRAME_HDR, framelen);
    off += R_RTC_ICE_TCP_FRAME_HDR + framelen;
    /* Dispatch reaches the app callback, which may have dropped this conn. */
    if (r_ptr_array_find (ice->tcpconns, conn) == R_PTR_ARRAY_INVALID_IDX)
      return;
  }

  /* Slide any partial frame down to the front. */
  if (off > 0) {
    conn->rxlen -= off;
    if (conn->rxlen > 0)
      r_memmove (conn->rx, conn->rx + off, conn->rxlen);
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

    if (remote->proto != R_RTC_ICE_PROTO_UDP)
      continue;
    if (r_rtc_ice_find_pair (ice, local, remote->addr) != NULL)
      continue;
    if ((pair = r_rtc_ice_add_pair (ice, local, udp, NULL, remote)) == NULL)
      continue;
    r_rtc_ice_schedule_checks (ice);
  }
}

/* Bind @bind_addr (the advertised @candidate address when NULL) and key
 * the socket by @candidate, so a NAT-1:1 candidate can advertise a public
 * address while binding a local one. */
static RRtcError
r_rtc_ice_transport_setup_udp (RRtcIceTransport * ice, RRtcIceCandidate * candidate,
    RSocketAddress * bind_addr)
{
  REvUDP * udp;

  if (bind_addr == NULL)
    bind_addr = candidate->addr;

  if ((udp = r_ev_udp_new (r_socket_address_get_family (bind_addr), ice->loop)) != NULL) {
    rchar * tmp = r_socket_address_to_str (bind_addr);
    R_LOG_TRACE ("RtcIceTransport %p setup UDP: %s", ice, tmp);
    r_free (tmp);

    if (r_ev_udp_bind (udp, bind_addr, TRUE)) {
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

/* @tcp and @remote ownership transfer to the new connection. */
static RRtcIceTcpConn *
r_rtc_ice_tcp_conn_new (RRtcIceTransport * ice, REvTCP * tcp,
    RRtcIceCandidate * local, RRtcIceCandidate * remotecand, RSocketAddress * remote)
{
  RRtcIceTcpConn * conn = r_mem_new0 (RRtcIceTcpConn);

  conn->ice = ice;
  conn->tcp = tcp;
  conn->local = r_rtc_ice_candidate_ref (local);
  conn->remotecand = remotecand != NULL ? r_rtc_ice_candidate_ref (remotecand) : NULL;
  conn->remote = remote;
  r_ptr_array_add (ice->tcpconns, conn, r_rtc_ice_tcp_conn_free);
  return conn;
}

/* Passive side: a peer dialed our listening socket. */
static void
r_rtc_ice_tcp_on_accept (rpointer data, REvTCP * newtcp, REvTCP * listening)
{
  RRtcIceTransport * ice = data;
  RRtcIceCandidate * local = r_rtc_ice_local_for_sock (ice, listening);
  RRtcIceTcpConn * conn;

  /* Refuse the accept if it is unknown or we are already at the connection
   * cap (an unauthenticated peer must not be able to open unbounded ones). */
  if (local == NULL ||
      r_ptr_array_size (ice->tcpconns) >= R_RTC_ICE_TCP_MAX_CONNS) {
    r_ev_tcp_abort (newtcp, NULL, NULL, NULL);
    return;
  }

  conn = r_rtc_ice_tcp_conn_new (ice, r_ev_tcp_ref (newtcp), local, NULL,
      r_ev_tcp_get_remote_address (newtcp));
  conn->up = TRUE;
  r_ev_tcp_recv_start (newtcp, NULL, r_rtc_ice_tcp_recv_cb, conn, NULL);
  R_LOG_TRACE ("RtcIceTransport %p accepted TCP connection", ice);
}

static RRtcError
r_rtc_ice_transport_setup_tcp_passive (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate)
{
  REvTCP * tcp;

  if ((tcp = r_ev_tcp_new_bind (candidate->addr, ice->loop)) == NULL)
    return R_RTC_OOM;

  if (r_ev_tcp_listen (tcp, 8, r_rtc_ice_tcp_on_accept, ice, NULL) != R_SOCKET_OK) {
    r_ev_tcp_unref (tcp);
    return R_RTC_WRONG_STATE;
  }

  r_hash_table_insert (ice->candidateSockets, r_rtc_ice_candidate_ref (candidate), tcp);
  if (ice->state == R_RTC_ICE_STATE_NEW)
    ice->state = R_RTC_ICE_STATE_CHECKING;
  return R_RTC_OK;
}

/* Active side: the TCP connection to a passive remote completed. */
static void
r_rtc_ice_tcp_connected (rpointer data, REvTCP * evtcp, int status)
{
  RRtcIceTcpConn * conn = data;
  RRtcIceTransport * ice = conn->ice;
  RRtcIceCheckPair * pair;
  (void) evtcp;

  if (status != 0) {
    R_LOG_INFO ("RtcIceTransport %p TCP connect failed (%d)", ice, status);
    r_ptr_array_remove_first_fast (ice->tcpconns, conn);
    return;
  }

  conn->up = TRUE;
  r_ev_tcp_recv_start (conn->tcp, NULL, r_rtc_ice_tcp_recv_cb, conn, NULL);
  R_LOG_TRACE ("RtcIceTransport %p TCP connected", ice);

  if ((pair = r_rtc_ice_find_pair (ice, conn->local, conn->remote)) == NULL)
    pair = r_rtc_ice_add_pair (ice, conn->local, NULL, conn, conn->remotecand);
  if (pair != NULL)
    r_rtc_ice_schedule_checks (ice);
}

/* Dial a passive remote from an active local candidate. */
static void
r_rtc_ice_tcp_connect (RRtcIceTransport * ice, RRtcIceCandidate * local,
    RRtcIceCandidate * remote)
{
  REvTCP * tcp;
  RRtcIceTcpConn * conn;
  RSocketStatus st;

  if ((tcp = r_ev_tcp_new (r_socket_address_get_family (remote->addr), ice->loop)) == NULL)
    return;

  conn = r_rtc_ice_tcp_conn_new (ice, tcp, local, remote,
      r_socket_address_ref (remote->addr));
  /* An async connect reports WOULD_BLOCK; the result arrives via the cb. */
  st = r_ev_tcp_connect (tcp, remote->addr, r_rtc_ice_tcp_connected, conn, NULL);
  if (st != R_SOCKET_OK && st != R_SOCKET_WOULD_BLOCK)
    r_ptr_array_remove_first_fast (ice->tcpconns, conn);
}

static rboolean
r_rtc_ice_tcp_conn_exists (RRtcIceTransport * ice, RRtcIceCandidate * local,
    RSocketAddress * remote_addr)
{
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (ice->tcpconns); i < c; i++) {
    RRtcIceTcpConn * conn = r_ptr_array_get (ice->tcpconns, i);
    if (conn->local == local && conn->remote != NULL &&
        r_socket_address_is_equal (conn->remote, remote_addr))
      return TRUE;
  }
  return FALSE;
}

/* An active local TCP candidate dials each passive remote TCP candidate;
 * a passive local candidate waits to be dialed (see on_accept). */
static void
r_rtc_ice_tcp_start_candidate (RRtcIceTransport * ice, RRtcIceCandidate * local)
{
  rsize i, c;

  if (r_rtc_ice_candidate_tcptype (local) != R_RTC_ICE_TCP_ACTIVE)
    return;
  if (ice->loop == NULL || ice->rpwd == NULL || ice->rufrag == NULL)
    return;

  for (i = 0, c = r_ptr_array_size (ice->remote); i < c; i++) {
    RRtcIceCandidate * remote = r_ptr_array_get (ice->remote, i);
    if (remote->proto == R_RTC_ICE_PROTO_TCP &&
        r_rtc_ice_candidate_tcptype (remote) == R_RTC_ICE_TCP_PASSIVE &&
        !r_rtc_ice_tcp_conn_exists (ice, local, remote->addr))
      r_rtc_ice_tcp_connect (ice, local, remote);
  }
}

static void
_candidate_socket_start (rpointer key, rpointer value, rpointer user)
{
  RRtcIceCandidate * candidate = key;
  RRtcIceTransport * ice = user;

  if (candidate->proto == R_RTC_ICE_PROTO_TCP) {
    if (r_rtc_ice_candidate_tcptype (candidate) == R_RTC_ICE_TCP_PASSIVE) {
      if (value == NULL)
        r_rtc_ice_transport_setup_tcp_passive (ice, candidate);
    } else {
      r_rtc_ice_tcp_start_candidate (ice, candidate);
    }
  } else if (value == NULL) {
    r_rtc_ice_transport_setup_udp (ice, candidate,
        r_hash_table_lookup (ice->bindAddrs, candidate));
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

  if (candidate->proto == R_RTC_ICE_PROTO_UDP)
    r_ev_udp_recv_stop (value);
  else
    r_ev_tcp_close (value, NULL, NULL, NULL);   /* TCP listener */
  r_hash_table_insert (ice->candidateSockets, r_rtc_ice_candidate_ref (candidate), NULL);
}

RRtcError
r_rtc_ice_transport_close (RRtcIceTransport * ice)
{
  r_hash_table_foreach (ice->candidateSockets, _candidate_socket_close, ice);
  ice->state = R_RTC_ICE_STATE_CLOSED;

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

static RRtcError
r_rtc_ice_add_host_candidate (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate, RSocketAddress * bind_addr)
{
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;
  if (R_UNLIKELY (candidate == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (candidate->type != R_RTC_ICE_CANDIDATE_HOST))
    return R_RTC_INVALID_TYPE;
  if (R_UNLIKELY (candidate->proto != R_RTC_ICE_PROTO_UDP &&
        candidate->proto != R_RTC_ICE_PROTO_TCP))
    return R_RTC_INVALID_TYPE;
  if (R_UNLIKELY (r_hash_table_contains (ice->candidateSockets, candidate) == R_HASH_TABLE_OK))
    return R_RTC_ALREADY_FOUND;

  if (candidate->proto == R_RTC_ICE_PROTO_TCP) {
    /* A passive candidate listens; an active one only dials out, so it has
     * no socket of its own until it pairs with a passive remote. */
    if (ice->loop != NULL &&
        r_rtc_ice_candidate_tcptype (candidate) == R_RTC_ICE_TCP_PASSIVE)
      return r_rtc_ice_transport_setup_tcp_passive (ice, candidate);

    r_hash_table_insert (ice->candidateSockets, r_rtc_ice_candidate_ref (candidate), NULL);
    if (ice->loop != NULL)
      r_rtc_ice_tcp_start_candidate (ice, candidate);
    return R_RTC_OK;
  }

  if (bind_addr != NULL)
    r_hash_table_insert (ice->bindAddrs, r_rtc_ice_candidate_ref (candidate),
        r_socket_address_copy (bind_addr));

  if (ice->loop != NULL)
    return r_rtc_ice_transport_setup_udp (ice, candidate, bind_addr);

  r_hash_table_insert (ice->candidateSockets, r_rtc_ice_candidate_ref (candidate), NULL);
  return R_RTC_OK;
}

RRtcError
r_rtc_ice_transport_add_local_host_candidate (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate)
{
  return r_rtc_ice_add_host_candidate (ice, candidate, NULL);
}

RRtcError
r_rtc_ice_transport_add_local_host_candidate_mapped (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate, RSocketAddress * bind_addr)
{
  if (R_UNLIKELY (bind_addr == NULL)) return R_RTC_INVAL;
  return r_rtc_ice_add_host_candidate (ice, candidate, bind_addr);
}

/* Host candidate priority, RFC 8445 5.1.2.1: type preference 126, local
 * preference 65535, and the component in the low octet. */
static ruint64
r_rtc_ice_host_priority (RRtcIceComponent component)
{
  ruint comp = component != R_RTC_ICE_COMPONENT_UNKNOWN ? component : 1;

  return ((ruint64) 126 << 24) | ((ruint64) 65535 << 8) | (256 - comp);
}

RRtcError
r_rtc_ice_transport_gather_host_candidates (RRtcIceTransport * ice,
    RRtcIceInterfaceFilter filter, rpointer user)
{
  RPtrArray * ifaces;
  rsize i, c;

  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;

  ifaces = r_net_query_interfaces ();
  for (i = 0, c = r_ptr_array_size (ifaces); i < c; i++) {
    RNetInterface * iface = r_ptr_array_get (ifaces, i);
    rsize j, n;

    for (j = 0, n = r_ptr_array_size (iface->addrs); j < n; j++) {
      RNetInterfaceAddr * ia = r_ptr_array_get (iface->addrs, j);
      RRtcIceCandidate * cand;
      rchar * foundation;

      if (filter != NULL) {
        if (!filter (iface, ia->addr, user))
          continue;
      } else if (!(iface->flags & R_NET_IFACE_UP) ||
          (iface->flags & R_NET_IFACE_LOOPBACK)) {
        continue;
      }

      foundation = r_strprintf ("%"RSIZE_FMT"-%"RSIZE_FMT, i, j);
      cand = r_rtc_ice_candidate_new_full (foundation, -1,
          r_rtc_ice_host_priority (ice->component), ice->component,
          R_RTC_ICE_PROTO_UDP, ia->addr, R_RTC_ICE_CANDIDATE_HOST);
      r_free (foundation);
      if (cand != NULL) {
        r_rtc_ice_transport_add_local_host_candidate (ice, cand);
        r_rtc_ice_candidate_unref (cand);
      }
    }
  }
  r_ptr_array_unref (ifaces);

  return R_RTC_OK;
}

RRtcError
r_rtc_ice_transport_set_on_local_candidate (RRtcIceTransport * ice,
    RRtcIceCandidateCb cb, rpointer data)
{
  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;

  ice->on_candidate = cb;
  ice->on_candidate_data = data;
  return R_RTC_OK;
}

typedef struct {
  RRtcIceTransport * ice;
  RSocketAddress * server;
} RRtcIceSrflxGather;

static void
r_rtc_ice_gather_srflx_cb (rpointer key, rpointer value, rpointer user)
{
  RRtcIceCandidate * base = key;
  REvUDP * udp = value;
  RRtcIceSrflxGather * ctx = user;
  RRtcIceSrflxReq * req;

  /* srflx over UDP only; a TCP entry's socket is a listener. */
  if (udp == NULL || base->proto != R_RTC_ICE_PROTO_UDP)
    return;

  req = r_mem_new0 (RRtcIceSrflxReq);
  req->ice = ctx->ice;
  req->base = r_rtc_ice_candidate_ref (base);
  req->udp = udp;
  req->server = r_socket_address_ref (ctx->server);
  r_ptr_array_add (ctx->ice->srflx, req, r_rtc_ice_srflx_req_free);
  r_rtc_ice_srflx_transmit (req, TRUE);
}

RRtcError
r_rtc_ice_transport_gather_srflx_candidates (RRtcIceTransport * ice,
    RSocketAddress * stun_server)
{
  RRtcIceSrflxGather ctx;

  if (R_UNLIKELY (ice == NULL || stun_server == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;
  if (R_UNLIKELY (ice->loop == NULL)) return R_RTC_WRONG_STATE;

  ctx.ice = ice;
  ctx.server = stun_server;
  r_hash_table_foreach (ice->candidateSockets, r_rtc_ice_gather_srflx_cb, &ctx);
  return R_RTC_OK;
}

typedef struct {
  RRtcIceTransport * ice;
  RSocketAddress * server;
  const rchar * username;
  const rchar * password;
} RRtcIceRelayGather;

static void
r_rtc_ice_gather_relay_cb (rpointer key, rpointer value, rpointer user)
{
  RRtcIceCandidate * base = key;
  REvUDP * udp = value;
  RRtcIceRelayGather * ctx = user;
  RRtcIceTurnReq * req;

  if (udp == NULL || base->proto != R_RTC_ICE_PROTO_UDP)
    return;

  req = r_mem_new0 (RRtcIceTurnReq);
  req->ice = ctx->ice;
  req->base = r_rtc_ice_candidate_ref (base);
  req->udp = udp;
  req->server = r_socket_address_ref (ctx->server);
  req->username = r_strdup (ctx->username);
  req->password = r_strdup (ctx->password);
  r_ptr_array_add (ctx->ice->turn, req, r_rtc_ice_turn_req_free);
  r_rtc_ice_turn_transmit (req, TRUE);
}

RRtcError
r_rtc_ice_transport_gather_relay_candidates (RRtcIceTransport * ice,
    RSocketAddress * turn_server, const rchar * username, const rchar * password)
{
  RRtcIceRelayGather ctx;

  if (R_UNLIKELY (ice == NULL || turn_server == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (username == NULL || password == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;
  if (R_UNLIKELY (ice->loop == NULL)) return R_RTC_WRONG_STATE;

  ctx.ice = ice;
  ctx.server = turn_server;
  ctx.username = username;
  ctx.password = password;
  r_hash_table_foreach (ice->candidateSockets, r_rtc_ice_gather_relay_cb, &ctx);
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
  RRtcIceCandidate ** out = user;

  if (out[0] == NULL && value != NULL)
    out[0] = key;
}

RSocketAddress *
r_rtc_ice_transport_get_local_address (const RRtcIceTransport * ice)
{
  RRtcIceCandidate * cand = NULL;
  RSocketAddress * addr;
  rpointer sock;

  if (R_UNLIKELY (ice == NULL)) return NULL;

  r_hash_table_foreach (ice->candidateSockets, r_rtc_ice_first_socket_cb, &cand);
  if (cand == NULL || (sock = r_hash_table_lookup (ice->candidateSockets, cand)) == NULL)
    return NULL;

  /* Both accessors return a newly-owned address (getsockname); hand it
   * straight back rather than copying and leaking the original. */
  addr = cand->proto == R_RTC_ICE_PROTO_TCP ?
      r_ev_tcp_get_local_address (sock) : r_ev_udp_get_local_address (sock);
  return addr;
}

RRtcError
r_rtc_ice_transport_set_role (RRtcIceTransport * ice, RRtcIceRole role)
{
  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;

  ice->role = role;
  return R_RTC_OK;
}

RRtcIceRole
r_rtc_ice_transport_get_role (const RRtcIceTransport * ice)
{
  return ice->role;
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

  /* Active TCP locals dial passive remotes; handled separately. */
  if (local->proto == R_RTC_ICE_PROTO_TCP) {
    r_rtc_ice_tcp_start_candidate (ctx->ice, local);
    return;
  }
  if (udp == NULL || ctx->remote->proto != R_RTC_ICE_PROTO_UDP)
    return;
  if (r_rtc_ice_find_pair (ctx->ice, local, ctx->remote->addr) != NULL)
    return;
  if ((pair = r_rtc_ice_add_pair (ctx->ice, local, udp, NULL, ctx->remote)) == NULL)
    return;
  r_rtc_ice_schedule_checks (ctx->ice);
}

RRtcError
r_rtc_ice_transport_add_remote_candidate (RRtcIceTransport * ice,
    RRtcIceCandidate * candidate)
{
  RRtcIcePairRemote ctx;

  if (R_UNLIKELY (ice == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (candidate == NULL)) return R_RTC_INVAL;
  if (R_UNLIKELY (ice->send == r_rtc_ice_transport_send_fake)) return R_RTC_WRONG_STATE;
  if (R_UNLIKELY (candidate->proto != R_RTC_ICE_PROTO_UDP &&
        candidate->proto != R_RTC_ICE_PROTO_TCP))
    return R_RTC_INVALID_TYPE;

  r_ptr_array_add (ice->remote, r_rtc_ice_candidate_ref (candidate),
      r_rtc_ice_candidate_unref);

  /* Pair the new remote with every local candidate: UDP locals form a
   * pair per socket; active TCP locals dial a passive TCP remote. */
  ctx.ice = ice;
  ctx.remote = candidate;
  r_hash_table_foreach (ice->candidateSockets, r_rtc_ice_pair_new_remote_cb, &ctx);

  /* ...and with every relay allocation's local candidate. */
  {
    rsize i, c;
    for (i = 0, c = r_ptr_array_size (ice->allocs); i < c; i++) {
      if (r_rtc_ice_alloc_add_pair (r_ptr_array_get (ice->allocs, i),
              candidate) != NULL)
        r_rtc_ice_schedule_checks (ice);
    }
  }

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

