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

/* Two in-process ICE agents that connect over loopback and exchange a
 * datagram each way through the public raw-transport API. With --turn each
 * agent instead gathers a relay candidate from a TURN server and the two
 * connect exclusively through it, so the payload travels host -> TURN -> host
 * (run example/rturnserver in another terminal first). */

#include <rlib/rlib.h>
#include <rlib/ev/revloop.h>
#include <rlib/rrtc.h>

typedef struct {
  const rchar * name;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * raw;
  RRtcIceCandidate * relay;         /* captured relay candidate, or NULL */
  ruint got;                        /* datagrams received */
} Agent;

static void
on_candidate (rpointer data, RRtcIceTransport * ice, RRtcIceCandidate * cand)
{
  Agent * a = data;
  (void) ice;

  if (r_rtc_ice_candidate_get_type (cand) == R_RTC_ICE_CANDIDATE_RELAY &&
      a->relay == NULL) {
    rchar * s = r_rtc_ice_candidate_to_string (cand);
    a->relay = r_rtc_ice_candidate_ref (cand);
    r_print ("%s: gathered relay candidate %s\n", a->name, s);
    r_free (s);
  }
}

static void
on_packet (rpointer data, RBuffer * buf, rpointer ctx)
{
  Agent * a = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  (void) ctx;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    r_print ("%s: received \"%.*s\"\n", a->name, (int) info.size, (const rchar *) info.data);
    a->got++;
    r_buffer_unmap (buf, &info);
  }
}

static void
send_text (Agent * a, const rchar * text)
{
  RBuffer * buf = r_buffer_new_dup (text, r_strlen (text));
  if (buf != NULL) {
    r_rtc_crypto_transport_send (a->raw, buf);
    r_buffer_unref (buf);
  }
}

int
main (int argc, char ** argv)
{
  RArgParser * parser = r_arg_parser_new (NULL, "1.0");
  RArgParseCtx * ctx;
  RArgParseResult res;
  int ret = 0;
  const RArgOptionEntry entries[] = {
    { "turn",      't', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "TURN server IPv4 address (enables relay mode)", NULL, NULL },
    { "turn-port", 'p', R_ARG_OPTION_TYPE_INT,    R_ARG_OPTION_FLAG_NONE, "TURN server UDP port", NULL, "3478" },
    { "turn-user", 'u', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "TURN username", NULL, "user" },
    { "turn-pass", 'w', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "TURN password", NULL, "pass" },
  };

  r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries));

  if ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***) &argv, &res)) != NULL) {
    RPrng * prng = r_prng_new_mt ();
    REvLoop * loop = r_ev_loop_new ();
    RRtcSession * sa = r_rtc_session_new (prng);
    RRtcSession * sb = r_rtc_session_new (prng);
    Agent a = { "A", NULL, NULL, NULL, 0 };
    Agent b = { "B", NULL, NULL, NULL, 0 };
    RSocketAddress * lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0);
    RRtcIceCandidate * ca, * cb;
    rchar * turn = r_arg_parse_ctx_get_option_string (ctx, "turn");
    ruint i;

    a.ice = r_rtc_session_create_ice_transport (sa,
        R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567"));
    b.ice = r_rtc_session_create_ice_transport (sb,
        R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567"));
    a.raw = r_rtc_session_create_raw_transport (sa, a.ice);
    b.raw = r_rtc_session_create_raw_transport (sb, b.ice);
    r_rtc_crypto_transport_set_on_packet (a.raw, on_packet, &a, NULL);
    r_rtc_crypto_transport_set_on_packet (b.raw, on_packet, &b, NULL);
    r_rtc_ice_transport_set_on_local_candidate (a.ice, on_candidate, &a);
    r_rtc_ice_transport_set_on_local_candidate (b.ice, on_candidate, &b);

    r_rtc_ice_transport_set_role (a.ice, R_RTC_ICE_ROLE_CONTROLLING);
    r_rtc_ice_transport_set_role (b.ice, R_RTC_ICE_ROLE_CONTROLLED);
    r_rtc_ice_transport_set_remote_credentials (a.ice,
        R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567"));
    r_rtc_ice_transport_set_remote_credentials (b.ice,
        R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567"));

    /* Each agent binds a loopback host socket (also the base for a TURN
     * allocation). */
    ca = r_rtc_ice_candidate_new_full (R_STR_WITH_SIZE_ARGS ("1"),
        (((ruint64) 126 << 24) | ((ruint64) 65535 << 8) | 255),
        R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, lo, R_RTC_ICE_CANDIDATE_HOST);
    cb = r_rtc_ice_candidate_new_full (R_STR_WITH_SIZE_ARGS ("1"),
        (((ruint64) 126 << 24) | ((ruint64) 65535 << 8) | 255),
        R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, lo, R_RTC_ICE_CANDIDATE_HOST);
    r_rtc_ice_transport_add_local_host_candidate (a.ice, ca);
    r_rtc_ice_transport_add_local_host_candidate (b.ice, cb);
    r_rtc_ice_candidate_unref (ca);
    r_rtc_ice_candidate_unref (cb);

    r_rtc_crypto_transport_start (a.raw, loop);
    r_rtc_crypto_transport_start (b.raw, loop);

    if (turn != NULL) {
      /* Relay mode: gather a relay candidate on each agent, then cross ONLY
       * those, so all traffic is forced through the TURN server. */
      RSocketAddress * ts = r_socket_address_ipv4_new_from_string (turn,
          (ruint16) r_arg_parse_ctx_get_option_int (ctx, "turn-port"));
      rchar * user = r_arg_parse_ctx_get_option_string (ctx, "turn-user");
      rchar * pass = r_arg_parse_ctx_get_option_string (ctx, "turn-pass");

      r_print ("Relay mode: allocating on TURN server %s\n", turn);
      r_rtc_ice_transport_gather_relay_candidates (a.ice, ts, user, pass);
      r_rtc_ice_transport_gather_relay_candidates (b.ice, ts, user, pass);

      for (i = 0; i < 400 && (a.relay == NULL || b.relay == NULL); i++)
        r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

      if (a.relay != NULL && b.relay != NULL) {
        r_rtc_ice_transport_add_remote_candidate (a.ice, b.relay);
        r_rtc_ice_transport_add_remote_candidate (b.ice, a.relay);
      } else {
        r_print ("Failed to gather relay candidates (is rturnserver running?)\n");
        ret = -1;
      }
      r_socket_address_unref (ts);
      r_free (user); r_free (pass);
    } else {
      /* Host mode: exchange the bound loopback addresses directly. */
      RSocketAddress * aa = r_rtc_ice_transport_get_local_address (a.ice);
      RSocketAddress * ba = r_rtc_ice_transport_get_local_address (b.ice);
      RRtcIceCandidate * ra = r_rtc_ice_candidate_new_full (R_STR_WITH_SIZE_ARGS ("1"),
          1, R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, aa, R_RTC_ICE_CANDIDATE_HOST);
      RRtcIceCandidate * rb = r_rtc_ice_candidate_new_full (R_STR_WITH_SIZE_ARGS ("1"),
          1, R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, ba, R_RTC_ICE_CANDIDATE_HOST);
      r_rtc_ice_transport_add_remote_candidate (a.ice, rb);
      r_rtc_ice_transport_add_remote_candidate (b.ice, ra);
      r_rtc_ice_candidate_unref (ra);
      r_rtc_ice_candidate_unref (rb);
      r_socket_address_unref (aa);
      r_socket_address_unref (ba);
    }

    if (ret == 0) {
      for (i = 0; i < 400 &&
          !(r_rtc_ice_transport_get_state (a.ice) == R_RTC_ICE_STATE_CONNECTED &&
            r_rtc_ice_transport_get_state (b.ice) == R_RTC_ICE_STATE_CONNECTED); i++)
        r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

      if (r_rtc_ice_transport_get_state (a.ice) == R_RTC_ICE_STATE_CONNECTED &&
          r_rtc_ice_transport_get_state (b.ice) == R_RTC_ICE_STATE_CONNECTED) {
        r_print ("Connected%s.\n", turn != NULL ? " (via TURN relay)" : "");
        send_text (&a, "ping");
        send_text (&b, "pong");
        for (i = 0; i < 200 && (a.got == 0 || b.got == 0); i++)
          r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
      } else {
        r_print ("ICE did not connect\n");
        ret = -1;
      }
      if (a.got == 0 || b.got == 0)
        ret = -1;
    }

    r_rtc_ice_transport_close (a.ice);
    r_rtc_ice_transport_close (b.ice);
    for (i = 0; i < 16; i++)
      r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

    if (a.relay != NULL) r_rtc_ice_candidate_unref (a.relay);
    if (b.relay != NULL) r_rtc_ice_candidate_unref (b.relay);
    r_rtc_crypto_transport_unref (a.raw);
    r_rtc_crypto_transport_unref (b.raw);
    r_rtc_ice_transport_unref (a.ice);
    r_rtc_ice_transport_unref (b.ice);
    r_rtc_session_unref (sa);
    r_rtc_session_unref (sb);
    r_socket_address_unref (lo);
    r_ev_loop_unref (loop);
    r_prng_unref (prng);
    r_free (turn);
    r_arg_parse_ctx_unref (ctx);
  } else {
    r_arg_parser_print_error (parser, R_ARG_PARSE_FLAG_NONE);
    ret = -1;
  }

  r_arg_parser_unref (parser);
  return ret;
}
