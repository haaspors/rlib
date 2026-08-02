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

/* A minimal standalone TURN server (RFC 8656) built on rlib's public STUN,
 * event-loop and crypto primitives. It authenticates with a single long-term
 * credential, allocates a relayed UDP transport address per client, and
 * relays traffic via Send/Data indications and ChannelData. It is an example,
 * not a hardened deployment: one realm / user, in-memory state, UDP only. */

#include <rlib/rlib.h>
#include <rlib/ev/revloop.h>
#include <rlib/ev/revudp.h>
#include <rlib/net/proto/rstun.h>

#define TURN_LIFETIME       600     /* seconds granted per allocation */
#define TURN_MAX_MSG        1600

typedef struct {
  ruint16 number;
  RSocketAddress * peer;            /* owned */
} TurnChannel;

typedef struct _TurnServer TurnServer;

typedef struct {
  TurnServer * srv;                 /* borrowed */
  RSocketAddress * client;          /* owned: the client's transport address */
  REvUDP * relay;                   /* owned: the relayed socket */
  RSocketAddress * relayaddr;       /* owned: the relayed transport address */
  RPtrArray * perms;                /* installed peers, RSocketAddress * (IP) */
  RPtrArray * channels;             /* TurnChannel * */
  ruint16 next_channel;
} TurnAlloc;

struct _TurnServer {
  REvLoop * loop;
  REvUDP * listener;
  RSocketAddress * ip;              /* the address to bind relay sockets to */
  const rchar * realm;
  const rchar * user;
  const rchar * pass;
  rchar nonce[17];
  ruint8 key[16];                   /* MD5(user:realm:pass) */
  RPtrArray * allocs;               /* TurnAlloc * */
};

/* --- small helpers ------------------------------------------------------- */

static rboolean
turn_addr_same_ip (const RSocketAddress * a, const RSocketAddress * b)
{
  RSocketFamily fa = r_socket_address_get_family (a);
  if (fa != r_socket_address_get_family (b))
    return FALSE;
  if (fa == R_SOCKET_FAMILY_IPV4)
    return r_socket_address_ipv4_get_ip (a) == r_socket_address_ipv4_get_ip (b);
  return r_socket_address_is_equal (a, b);
}

static void
turn_send (REvUDP * sock, RSocketAddress * to, rconstpointer data, rsize size)
{
  RBuffer * buf = r_buffer_new_dup (data, size);
  if (buf != NULL) {
    r_ev_udp_send (sock, buf, to, NULL, NULL, NULL);
    r_buffer_unref (buf);
  }
}

/* --- allocation bookkeeping --------------------------------------------- */

static void
turn_channel_free (rpointer data)
{
  TurnChannel * chan = data;
  r_socket_address_unref (chan->peer);
  r_free (chan);
}

static void
turn_alloc_free (rpointer data)
{
  TurnAlloc * alloc = data;
  if (alloc->relay != NULL) {
    r_ev_udp_recv_stop (alloc->relay);
    r_ev_udp_unref (alloc->relay);
  }
  if (alloc->relayaddr != NULL)
    r_socket_address_unref (alloc->relayaddr);
  r_socket_address_unref (alloc->client);
  r_ptr_array_unref (alloc->perms);
  r_ptr_array_unref (alloc->channels);
  r_free (alloc);
}

static TurnAlloc *
turn_alloc_by_client (TurnServer * srv, const RSocketAddress * client)
{
  rsize i, c;
  for (i = 0, c = r_ptr_array_size (srv->allocs); i < c; i++) {
    TurnAlloc * alloc = r_ptr_array_get (srv->allocs, i);
    if (r_socket_address_is_equal (alloc->client, client))
      return alloc;
  }
  return NULL;
}

static rboolean
turn_alloc_has_perm (TurnAlloc * alloc, const RSocketAddress * peer)
{
  rsize i, c;
  for (i = 0, c = r_ptr_array_size (alloc->perms); i < c; i++) {
    if (turn_addr_same_ip (r_ptr_array_get (alloc->perms, i), peer))
      return TRUE;
  }
  return FALSE;
}

static TurnChannel *
turn_alloc_channel_by_number (TurnAlloc * alloc, ruint16 number)
{
  rsize i, c;
  for (i = 0, c = r_ptr_array_size (alloc->channels); i < c; i++) {
    TurnChannel * chan = r_ptr_array_get (alloc->channels, i);
    if (chan->number == number)
      return chan;
  }
  return NULL;
}

static TurnChannel *
turn_alloc_channel_by_peer (TurnAlloc * alloc, const RSocketAddress * peer)
{
  rsize i, c;
  for (i = 0, c = r_ptr_array_size (alloc->channels); i < c; i++) {
    TurnChannel * chan = r_ptr_array_get (alloc->channels, i);
    if (r_socket_address_is_equal (chan->peer, peer))
      return chan;
  }
  return NULL;
}

/* Relay a datagram from a peer back to the client: a bound channel uses
 * ChannelData, otherwise a Data indication. */
static void
turn_relay_to_client (TurnAlloc * alloc, RSocketAddress * peer,
    rconstpointer data, rsize size)
{
  TurnChannel * chan = turn_alloc_channel_by_peer (alloc, peer);
  ruint8 out[TURN_MAX_MSG];
  rsize len;

  if (chan != NULL) {
    len = r_stun_channel_data_encode (out, sizeof (out), chan->number, data, size);
    if (len > 0)
      turn_send (alloc->srv->listener, alloc->client, out, len);
  } else {
    RStunMsgCtx ctx;
    ruint8 tid[R_STUN_TRANSACTION_ID_SIZE] = { 0 };
    r_rand_entropy_fill (tid, sizeof (tid));
    if (r_stun_msg_begin (&ctx, out, sizeof (out), R_STUN_CLASS_INDICATION,
            R_STUN_METHOD_DATA, tid)) {
      r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS, peer);
      r_stun_msg_add_data (&ctx, data, size);
      len = r_stun_msg_end (&ctx, TRUE);
      turn_send (alloc->srv->listener, alloc->client, out, len);
    }
  }
}

static void
turn_relay_recv (rpointer data, RBuffer * buf, RSocketAddress * addr, REvUDP * udp)
{
  TurnAlloc * alloc = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  (void) udp;

  /* Only forward from a permitted peer (RFC 8656 8). */
  if (!turn_alloc_has_perm (alloc, addr))
    return;
  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    turn_relay_to_client (alloc, addr, info.data, info.size);
    r_buffer_unmap (buf, &info);
  }
}

/* --- request handling ---------------------------------------------------- */

/* Locate the USERNAME and MESSAGE-INTEGRITY and verify the long-term
 * credential; @c TRUE if the request is authenticated for our user. */
static rboolean
turn_check_auth (TurnServer * srv, rconstpointer msg)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT, mi = R_STUN_ATTR_TLV_INIT;
  const rchar * user = NULL;
  rsize ulen = 0;
  rboolean have_mi = FALSE;

  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_USERNAME) {
        user = (const rchar *) tlv.value;
        ulen = tlv.len;
      } else if (tlv.type == R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY) {
        mi = tlv;
        have_mi = TRUE;
      }
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }

  if (!have_mi || user == NULL ||
      ulen != r_strlen (srv->user) || r_memcmp (user, srv->user, ulen) != 0)
    return FALSE;
  return r_stun_msg_check_integrity_short_cred (msg, &mi, srv->key, sizeof (srv->key));
}

/* Reply to an unauthenticated request with a 401 challenge carrying our realm
 * and nonce. */
static void
turn_send_challenge (TurnServer * srv, RSocketAddress * to, RStunMethod method,
    const ruint8 * tid)
{
  RStunMsgCtx ctx;
  ruint8 out[256];
  rsize len;

  if (r_stun_msg_begin (&ctx, out, sizeof (out), R_STUN_CLASS_ERROR_RESPONSE, method, tid)) {
    r_stun_msg_add_error_code (&ctx, 401, "Unauthorized");
    r_stun_msg_add_string (&ctx, R_STUN_ATTR_TYPE_REALM, srv->realm, -1);
    r_stun_msg_add_string (&ctx, R_STUN_ATTR_TYPE_NONCE, srv->nonce, -1);
    len = r_stun_msg_end (&ctx, TRUE);
    turn_send (srv->listener, to, out, len);
  }
}

static void
turn_handle_allocate (TurnServer * srv, rconstpointer msg, RSocketAddress * from)
{
  const ruint8 * tid = r_stun_msg_transaction_id (msg);
  TurnAlloc * alloc;
  RStunMsgCtx ctx;
  ruint8 out[256];
  rsize len;

  if (!turn_check_auth (srv, msg)) {
    turn_send_challenge (srv, from, R_STUN_METHOD_ALLOCATE, tid);
    return;
  }

  if ((alloc = turn_alloc_by_client (srv, from)) == NULL) {
    if ((alloc = r_mem_new0 (TurnAlloc)) == NULL)
      return;
    alloc->srv = srv;
    alloc->client = r_socket_address_ref (from);
    alloc->perms = r_ptr_array_new ();
    alloc->channels = r_ptr_array_new ();
    alloc->next_channel = 0x4000;
    alloc->relay = r_ev_udp_new (r_socket_address_get_family (srv->ip), srv->loop);
    if (alloc->relay == NULL || !r_ev_udp_bind (alloc->relay, srv->ip, TRUE)) {
      turn_alloc_free (alloc);
      return;
    }
    alloc->relayaddr = r_ev_udp_get_local_address (alloc->relay);
    r_ev_udp_recv_start (alloc->relay, NULL, turn_relay_recv, alloc, NULL);
    r_ptr_array_add (srv->allocs, alloc, turn_alloc_free);
    r_print ("TURN: allocation for a new client\n");
  }

  if (r_stun_msg_begin (&ctx, out, sizeof (out), R_STUN_CLASS_SUCCESS_RESPONSE,
          R_STUN_METHOD_ALLOCATE, tid)) {
    r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_RELAYED_ADDRESS, alloc->relayaddr);
    r_stun_msg_add_lifetime (&ctx, TURN_LIFETIME);
    r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, from);
    r_stun_msg_add_message_integrity_short_cred (&ctx, srv->key, sizeof (srv->key));
    len = r_stun_msg_end (&ctx, TRUE);
    turn_send (srv->listener, from, out, len);
  }
}

/* Respond to an authenticated request (Refresh / CreatePermission /
 * ChannelBind) with a success carrying an optional LIFETIME. */
static void
turn_send_success (TurnServer * srv, RSocketAddress * to, RStunMethod method,
    const ruint8 * tid, rboolean with_lifetime, ruint32 lifetime)
{
  RStunMsgCtx ctx;
  ruint8 out[128];
  rsize len;

  if (r_stun_msg_begin (&ctx, out, sizeof (out), R_STUN_CLASS_SUCCESS_RESPONSE, method, tid)) {
    if (with_lifetime)
      r_stun_msg_add_lifetime (&ctx, lifetime);
    r_stun_msg_add_message_integrity_short_cred (&ctx, srv->key, sizeof (srv->key));
    len = r_stun_msg_end (&ctx, TRUE);
    turn_send (srv->listener, to, out, len);
  }
}

static void
turn_handle_refresh (TurnServer * srv, rconstpointer msg, RSocketAddress * from)
{
  const ruint8 * tid = r_stun_msg_transaction_id (msg);
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  ruint32 lifetime = TURN_LIFETIME;
  TurnAlloc * alloc;

  if (!turn_check_auth (srv, msg)) {
    turn_send_challenge (srv, from, R_STUN_METHOD_REFRESH, tid);
    return;
  }
  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_LIFETIME && tlv.len >= 4)
        lifetime = r_stun_attr_tlv_parse_lifetime (msg, &tlv);
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }

  if (lifetime == 0 && (alloc = turn_alloc_by_client (srv, from)) != NULL) {
    r_print ("TURN: releasing allocation\n");
    r_ptr_array_remove_first_fast (srv->allocs, alloc);
  }
  turn_send_success (srv, from, R_STUN_METHOD_REFRESH, tid, TRUE, lifetime);
}

static void
turn_handle_create_permission (TurnServer * srv, rconstpointer msg, RSocketAddress * from)
{
  const ruint8 * tid = r_stun_msg_transaction_id (msg);
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  TurnAlloc * alloc;

  if (!turn_check_auth (srv, msg)) {
    turn_send_challenge (srv, from, R_STUN_METHOD_CREATE_PERMISSION, tid);
    return;
  }
  if ((alloc = turn_alloc_by_client (srv, from)) == NULL)
    return;

  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS) {
        RSocketAddress * peer = r_stun_attr_tlv_parse_xor_address (msg, &tlv);
        if (peer != NULL) {
          if (!turn_alloc_has_perm (alloc, peer))
            r_ptr_array_add (alloc->perms, r_socket_address_ref (peer), r_socket_address_unref);
          r_socket_address_unref (peer);
        }
      }
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }
  turn_send_success (srv, from, R_STUN_METHOD_CREATE_PERMISSION, tid, FALSE, 0);
}

static void
turn_handle_channel_bind (TurnServer * srv, rconstpointer msg, RSocketAddress * from)
{
  const ruint8 * tid = r_stun_msg_transaction_id (msg);
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  RSocketAddress * peer = NULL;
  ruint16 number = 0;
  TurnAlloc * alloc;

  if (!turn_check_auth (srv, msg)) {
    turn_send_challenge (srv, from, R_STUN_METHOD_CHANNEL_BIND, tid);
    return;
  }
  if ((alloc = turn_alloc_by_client (srv, from)) == NULL)
    return;

  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_CHANNEL_NUMBER && tlv.len >= 2)
        number = RUINT16_FROM_BE (*(const ruint16 *) tlv.value);
      else if (tlv.type == R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS)
        peer = r_stun_attr_tlv_parse_xor_address (msg, &tlv);
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }

  if (peer != NULL && number >= 0x4000 && number <= 0x7fff) {
    TurnChannel * chan = turn_alloc_channel_by_number (alloc, number);
    if (chan == NULL) {
      chan = r_mem_new0 (TurnChannel);
      chan->number = number;
      chan->peer = r_socket_address_ref (peer);
      r_ptr_array_add (alloc->channels, chan, turn_channel_free);
    }
    /* A channel bind also installs a permission (RFC 8656 12). */
    if (!turn_alloc_has_perm (alloc, peer))
      r_ptr_array_add (alloc->perms, r_socket_address_ref (peer), r_socket_address_unref);
    turn_send_success (srv, from, R_STUN_METHOD_CHANNEL_BIND, tid, FALSE, 0);
  }
  if (peer != NULL)
    r_socket_address_unref (peer);
}

/* A Send indication (or ChannelData) from the client carries data outbound to
 * a peer; forward it from the relay socket. */
static void
turn_handle_send (TurnServer * srv, rconstpointer msg, RSocketAddress * from)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  RSocketAddress * peer = NULL;
  const ruint8 * data = NULL;
  rsize dlen = 0;
  TurnAlloc * alloc = turn_alloc_by_client (srv, from);

  if (alloc == NULL)
    return;
  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS)
        peer = r_stun_attr_tlv_parse_xor_address (msg, &tlv);
      else if (tlv.type == R_STUN_ATTR_TYPE_DATA) {
        data = tlv.value;
        dlen = tlv.len;
      }
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }

  if (peer != NULL && data != NULL && turn_alloc_has_perm (alloc, peer))
    turn_send (alloc->relay, peer, data, dlen);
  if (peer != NULL)
    r_socket_address_unref (peer);
}

static void
turn_handle_channel_data (TurnServer * srv, rconstpointer buf, rsize size,
    RSocketAddress * from)
{
  TurnAlloc * alloc = turn_alloc_by_client (srv, from);
  TurnChannel * chan;
  ruint16 number = 0;
  rconstpointer data = NULL;
  rsize dlen = 0;

  if (alloc == NULL || !r_stun_channel_data_parse (buf, size, &number, &data, &dlen))
    return;
  if ((chan = turn_alloc_channel_by_number (alloc, number)) != NULL &&
      turn_alloc_has_perm (alloc, chan->peer))
    turn_send (alloc->relay, chan->peer, data, dlen);
}

static void
turn_listener_recv (rpointer data, RBuffer * buf, RSocketAddress * addr, REvUDP * udp)
{
  TurnServer * srv = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  (void) udp;

  if (!r_buffer_map (buf, &info, R_MEM_MAP_READ))
    return;

  if (r_stun_is_channel_data (info.data, info.size)) {
    turn_handle_channel_data (srv, info.data, info.size, addr);
  } else if (r_stun_is_valid_msg (info.data, info.size) &&
      r_stun_msg_is_request (info.data)) {
    if (r_stun_msg_method_is_allocate (info.data))
      turn_handle_allocate (srv, info.data, addr);
    else if (r_stun_msg_method_is_refresh (info.data))
      turn_handle_refresh (srv, info.data, addr);
    else if (r_stun_msg_method_is_create_permission (info.data))
      turn_handle_create_permission (srv, info.data, addr);
    else if (r_stun_msg_method_is_channel_bind (info.data))
      turn_handle_channel_bind (srv, info.data, addr);
  } else if (r_stun_is_valid_msg (info.data, info.size) &&
      r_stun_msg_is_indication (info.data) && r_stun_msg_method_is_send (info.data)) {
    turn_handle_send (srv, info.data, addr);
  }

  r_buffer_unmap (buf, &info);
}

/* --- main ---------------------------------------------------------------- */

int
main (int argc, char ** argv)
{
  RArgParser * parser = r_arg_parser_new (NULL, "1.0");
  RArgParseCtx * ctx;
  RArgParseResult res;
  int ret = 0;
  const RArgOptionEntry entries[] = {
    { "ip",    'i', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Listen / relay IPv4 address", NULL, "127.0.0.1" },
    { "port",  'p', R_ARG_OPTION_TYPE_INT,    R_ARG_OPTION_FLAG_NONE, "Listen UDP port", NULL, "3478" },
    { "realm", 'r', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Authentication realm", NULL, "rlib" },
    { "user",  'u', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Long-term credential username", NULL, "user" },
    { "pass",  'w', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Long-term credential password", NULL, "pass" },
  };

  r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries));

  if ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***) &argv, &res)) != NULL) {
    TurnServer srv = { 0 };
    rchar * ip = r_arg_parse_ctx_get_option_string (ctx, "ip");
    int port = r_arg_parse_ctx_get_option_int (ctx, "port");
    rchar * realm = r_arg_parse_ctx_get_option_string (ctx, "realm");
    rchar * user = r_arg_parse_ctx_get_option_string (ctx, "user");
    rchar * pass = r_arg_parse_ctx_get_option_string (ctx, "pass");
    RSocketAddress * bind;

    srv.realm = realm; srv.user = user; srv.pass = pass;
    r_memcpy (srv.nonce, "rlibnonce0000000", 17);
    r_stun_turn_long_term_key (user, realm, pass, srv.key);

    srv.loop = r_ev_loop_new ();
    srv.ip = r_socket_address_ipv4_new_from_string (ip, 0);
    srv.allocs = r_ptr_array_new ();
    bind = r_socket_address_ipv4_new_from_string (ip, (ruint16) port);
    srv.listener = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, srv.loop);

    if (srv.listener != NULL && r_ev_udp_bind (srv.listener, bind, TRUE)) {
      r_ev_udp_recv_start (srv.listener, NULL, turn_listener_recv, &srv, NULL);
      r_print ("TURN server listening on %s:%d (realm '%s', user '%s')\n",
          ip, port, realm, user);
      r_ev_loop_run (srv.loop, R_EV_LOOP_RUN_LOOP);
    } else {
      r_print ("Failed to bind %s:%d\n", ip, port);
      ret = -1;
    }

    r_ptr_array_unref (srv.allocs);
    if (srv.listener != NULL) {
      r_ev_udp_recv_stop (srv.listener);
      r_ev_udp_unref (srv.listener);
    }
    r_socket_address_unref (srv.ip);
    r_socket_address_unref (bind);
    r_ev_loop_unref (srv.loop);
    r_free (ip); r_free (realm); r_free (user); r_free (pass);
    r_arg_parse_ctx_unref (ctx);
  } else {
    r_arg_parser_print_error (parser, R_ARG_PARSE_FLAG_NONE);
    ret = -1;
  }

  r_arg_parser_unref (parser);
  return ret;
}
