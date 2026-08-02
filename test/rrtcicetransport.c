#include <rlib/rrtc.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/ev/revudp.h>
#include <rlib/net/proto/rstun.h>

/* Host candidate priority (RFC 8445 5.1.2.1): type pref 126, local pref
 * 65535, component 1. The exact value only affects pair ordering here. */
#define TEST_ICE_HOST_PRI  (((ruint64) 126 << 24) | ((ruint64) 65535 << 8) | 255)

static RRtcIceCandidate *
test_ice_host_candidate (const rchar * foundation, RSocketAddress * addr)
{
  return r_rtc_ice_candidate_new_full (foundation, -1, TEST_ICE_HOST_PRI,
      R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, addr, R_RTC_ICE_CANDIDATE_HOST);
}

RTEST (rrtcicetransport, connectivity_check, RTEST_FAST | RTEST_SYSTEM)
{
  /* Two ICE transports over a real 127.0.0.1 UDP loopback run STUN
   * connectivity checks against each other; the controlling side
   * nominates a pair and both reach the connected state. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * sa, * sb;
  RRtcIceTransport * a, * b;
  RRtcCryptoTransport * ra, * rb;
  RSocketAddress * lo, * addra, * addrb;
  RRtcIceCandidate * ca, * cb;
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((sa = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((sb = r_rtc_session_new (prng)), !=, NULL);

  r_assert_cmpptr ((a = r_rtc_session_create_ice_transport (sa,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567"))), !=, NULL);
  r_assert_cmpptr ((b = r_rtc_session_create_ice_transport (sb,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567"))), !=, NULL);

  /* A raw transport wires the ready / packet callbacks the ICE transport
   * fires; without an upper layer there is nothing to notify. */
  r_assert_cmpptr ((ra = r_rtc_session_create_raw_transport (sa, a)), !=, NULL);
  r_assert_cmpptr ((rb = r_rtc_session_create_raw_transport (sb, b)), !=, NULL);

  r_assert_cmpint (r_rtc_ice_transport_set_role (a, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_role (b, R_RTC_ICE_ROLE_CONTROLLED), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (a,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567")), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (b,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567")), ==, R_RTC_OK);

  /* Bind each side to an OS-assigned loopback port. */
  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_host_candidate ("1", lo)), !=, NULL);
  r_assert_cmpptr ((cb = test_ice_host_candidate ("1", lo)), !=, NULL);
  r_socket_address_unref (lo);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (a, ca), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (b, cb), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);

  r_assert_cmpint (r_rtc_ice_transport_start (a, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (b, loop), ==, R_RTC_OK);

  /* Exchange the actual bound addresses as each other's remote candidate. */
  r_assert_cmpptr ((addra = r_rtc_ice_transport_get_local_address (a)), !=, NULL);
  r_assert_cmpptr ((addrb = r_rtc_ice_transport_get_local_address (b)), !=, NULL);
  r_assert_cmpptr ((cb = test_ice_host_candidate ("1", addrb)), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_host_candidate ("1", addra)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (a, cb), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (b, ca), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);
  r_socket_address_unref (addra);
  r_socket_address_unref (addrb);

  /* Pump the loop until both sides nominate a pair (bounded so a failure
   * cannot hang the suite). */
  for (i = 0; i < 200; i++) {
    if (r_rtc_ice_transport_get_state (a) == R_RTC_ICE_STATE_CONNECTED &&
        r_rtc_ice_transport_get_state (b) == R_RTC_ICE_STATE_CONNECTED)
      break;
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  }

  r_assert_cmpint (r_rtc_ice_transport_get_state (a), ==, R_RTC_ICE_STATE_CONNECTED);
  r_assert_cmpint (r_rtc_ice_transport_get_state (b), ==, R_RTC_ICE_STATE_CONNECTED);

  r_rtc_ice_transport_close (a);
  r_rtc_ice_transport_close (b);
  /* Drain any in-flight socket operations before releasing the loop. */
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_rtc_crypto_transport_unref (ra);
  r_rtc_crypto_transport_unref (rb);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (sa);
  r_rtc_session_unref (sb);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

typedef struct {
  ruint responses;
} TestCheckObserver;

static void
test_check_recv (rpointer data, RBuffer * buf, RSocketAddress * addr, REvUDP * udp)
{
  TestCheckObserver * o = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  (void) addr; (void) udp;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    if (r_stun_is_valid_msg (info.data, info.size) &&
        r_stun_msg_method_is_binding (info.data) &&
        r_stun_msg_is_success_resp (info.data))
      o->responses++;
    r_buffer_unmap (buf, &info);
  }
}

/* Build a Binding connectivity check with USERNAME @username, keyed with
 * short-term credential @pwd. */
static rsize
test_build_check (ruint8 * dst, rsize dstsize, const ruint8 * tid,
    const rchar * username, const rchar * pwd)
{
  RStunMsgCtx ctx;
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  ruint8 prio[4];
  ruint8 tb[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };

  r_store_be32 (prio, 0x7e0000ffu);
  r_stun_msg_begin (&ctx, dst, dstsize, R_STUN_CLASS_REQUEST, R_STUN_METHOD_BINDING, tid);
  tlv.type = R_STUN_ATTR_TYPE_USERNAME;
  tlv.len = (ruint16) r_strlen (username);
  tlv.value = (const ruint8 *) username;
  r_stun_msg_add_attribute (&ctx, &tlv);
  tlv.type = R_STUN_ATTR_TYPE_PRIORITY; tlv.len = 4; tlv.value = prio;
  r_stun_msg_add_attribute (&ctx, &tlv);
  tlv.type = R_STUN_ATTR_TYPE_ICE_CONTROLLING; tlv.len = 8; tlv.value = tb;
  r_stun_msg_add_attribute (&ctx, &tlv);
  r_stun_msg_add_message_integrity_short_cred (&ctx, pwd, r_strlen (pwd));
  return r_stun_msg_end (&ctx, TRUE);
}

static void
test_send_check (REvUDP * from, RSocketAddress * to, const rchar * username,
    const rchar * pwd)
{
  RBuffer * out = r_buffer_new_alloc (NULL, 256, NULL);
  RMemMapInfo oi = R_MEM_MAP_INFO_INIT;

  if (out != NULL && r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
    ruint8 tid[R_STUN_TRANSACTION_ID_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    rsize sz = test_build_check (oi.data, oi.size, tid, username, pwd);
    r_buffer_unmap (out, &oi);
    r_buffer_set_size (out, sz);
    r_ev_udp_send (from, out, to, NULL, NULL, NULL);
  }
  if (out != NULL)
    r_buffer_unref (out);
}

RTEST (rrtcicetransport, username_ufrag_rejected, RTEST_FAST | RTEST_SYSTEM)
{
  /* A Binding check whose USERNAME local fragment is not our ufrag is
   * rejected even though its MESSAGE-INTEGRITY is valid (RFC 8445 7.3): the
   * agent does not answer it, but answers the same check with the right
   * ufrag. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * s;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * raw;
  REvUDP * peer;
  RSocketAddress * lo, * addr, * peeraddr;
  RRtcIceCandidate * cand;
  TestCheckObserver obs = { 0 };
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((s = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (s,
          R_STR_WITH_SIZE_ARGS ("auf"), R_STR_WITH_SIZE_ARGS ("apassword01234567"))), !=, NULL);
  r_assert_cmpptr ((raw = r_rtc_session_create_raw_transport (s, ice)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_set_role (ice, R_RTC_ICE_ROLE_CONTROLLED), ==, R_RTC_OK);

  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((cand = test_ice_host_candidate ("1", lo)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (ice, cand), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (ice, loop), ==, R_RTC_OK);
  r_assert_cmpptr ((addr = r_rtc_ice_transport_get_local_address (ice)), !=, NULL);

  r_assert_cmpptr ((peer = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_bind (peer, lo, TRUE));
  r_assert (r_ev_udp_recv_start (peer, NULL, test_check_recv, &obs, NULL));
  r_assert_cmpptr ((peeraddr = r_ev_udp_get_local_address (peer)), !=, NULL);

  /* Wrong local ufrag -> no answer. */
  test_send_check (peer, addr, "wrong:puf", "apassword01234567");
  for (i = 0; i < 40; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
  r_assert_cmpuint (obs.responses, ==, 0);

  /* Correct local ufrag -> answered. */
  test_send_check (peer, addr, "auf:puf", "apassword01234567");
  for (i = 0; i < 40 && obs.responses == 0; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  r_assert_cmpuint (obs.responses, ==, 1);

  r_rtc_ice_transport_close (ice);
  r_ev_udp_recv_stop (peer);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_socket_address_unref (addr);
  r_socket_address_unref (peeraddr);
  r_socket_address_unref (lo);
  r_ev_udp_unref (peer);
  r_rtc_ice_candidate_unref (cand);
  r_rtc_crypto_transport_unref (raw);
  r_rtc_ice_transport_unref (ice);
  r_rtc_session_unref (s);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrtcicetransport, mapped_host_candidate_binds_local, RTEST_FAST | RTEST_SYSTEM)
{
  /* A NAT-1:1 host candidate advertises one address but binds another:
   * advertise a non-routable TEST-NET address (RFC 5737) yet bind
   * loopback, and confirm the socket actually bound loopback. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * s;
  RRtcIceTransport * ice;
  RSocketAddress * advertised, * bind_addr, * local;
  RRtcIceCandidate * cand;
  rchar * str;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((s = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (s,
          R_STR_WITH_SIZE_ARGS ("uf"), R_STR_WITH_SIZE_ARGS ("password01234567"))), !=, NULL);

  r_assert_cmpptr ((advertised = r_socket_address_ipv4_new_from_string ("192.0.2.1", 9999)), !=, NULL);
  r_assert_cmpptr ((bind_addr = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((cand = test_ice_host_candidate ("1", advertised)), !=, NULL);

  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate_mapped (ice, cand, NULL), ==, R_RTC_INVAL);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate_mapped (ice, cand, bind_addr), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (ice, loop), ==, R_RTC_OK);

  /* The bound socket is on loopback, not the advertised 192.0.2.1. */
  r_assert_cmpptr ((local = r_rtc_ice_transport_get_local_address (ice)), !=, NULL);
  r_assert_cmpptr ((str = r_socket_address_ipv4_to_str (local, FALSE)), !=, NULL);
  r_assert_cmpstr (str, ==, "127.0.0.1");
  r_free (str);
  r_socket_address_unref (local);

  r_rtc_ice_transport_close (ice);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_rtc_ice_candidate_unref (cand);
  r_socket_address_unref (advertised);
  r_socket_address_unref (bind_addr);
  r_rtc_ice_transport_unref (ice);
  r_rtc_session_unref (s);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

/* Deterministic gathering for the test: keep only the IPv4 loopback
 * address so the two agents pair over 127.0.0.1 regardless of the host's
 * real interfaces. */
static rboolean
test_ice_only_loopback (const RNetInterface * iface, const RSocketAddress * addr,
    rpointer user)
{
  (void) user;
  return (iface->flags & R_NET_IFACE_LOOPBACK) != 0 &&
      r_socket_address_get_family (addr) == R_SOCKET_FAMILY_IPV4;
}

RTEST (rrtcicetransport, gather_host_candidates, RTEST_FAST | RTEST_SYSTEM)
{
  /* gather_host_candidates enumerates the interfaces and binds a host
   * candidate per selected address; drive a full connectivity check over
   * the gathered loopback candidates. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * sa, * sb;
  RRtcIceTransport * a, * b;
  RRtcCryptoTransport * ra, * rb;
  RSocketAddress * addra, * addrb;
  RRtcIceCandidate * ca, * cb;
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((sa = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((sb = r_rtc_session_new (prng)), !=, NULL);

  r_assert_cmpptr ((a = r_rtc_session_create_ice_transport (sa,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567"))), !=, NULL);
  r_assert_cmpptr ((b = r_rtc_session_create_ice_transport (sb,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567"))), !=, NULL);
  r_assert_cmpptr ((ra = r_rtc_session_create_raw_transport (sa, a)), !=, NULL);
  r_assert_cmpptr ((rb = r_rtc_session_create_raw_transport (sb, b)), !=, NULL);

  r_assert_cmpint (r_rtc_ice_transport_set_role (a, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_role (b, R_RTC_ICE_ROLE_CONTROLLED), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (a,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567")), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (b,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567")), ==, R_RTC_OK);

  r_assert_cmpint (r_rtc_ice_transport_gather_host_candidates (a,
          test_ice_only_loopback, NULL), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_gather_host_candidates (b,
          test_ice_only_loopback, NULL), ==, R_RTC_OK);

  r_assert_cmpint (r_rtc_ice_transport_start (a, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (b, loop), ==, R_RTC_OK);

  /* A loopback host candidate must have been gathered and bound. */
  r_assert_cmpptr ((addra = r_rtc_ice_transport_get_local_address (a)), !=, NULL);
  r_assert_cmpptr ((addrb = r_rtc_ice_transport_get_local_address (b)), !=, NULL);
  r_assert_cmpptr ((cb = test_ice_host_candidate ("1", addrb)), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_host_candidate ("1", addra)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (a, cb), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (b, ca), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);
  r_socket_address_unref (addra);
  r_socket_address_unref (addrb);

  for (i = 0; i < 200; i++) {
    if (r_rtc_ice_transport_get_state (a) == R_RTC_ICE_STATE_CONNECTED &&
        r_rtc_ice_transport_get_state (b) == R_RTC_ICE_STATE_CONNECTED)
      break;
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  }

  r_assert_cmpint (r_rtc_ice_transport_get_state (a), ==, R_RTC_ICE_STATE_CONNECTED);
  r_assert_cmpint (r_rtc_ice_transport_get_state (b), ==, R_RTC_ICE_STATE_CONNECTED);

  r_rtc_ice_transport_close (a);
  r_rtc_ice_transport_close (b);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_rtc_crypto_transport_unref (ra);
  r_rtc_crypto_transport_unref (rb);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (sa);
  r_rtc_session_unref (sb);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

/* A minimal STUN server: answer every Binding request with a success
 * response whose XOR-MAPPED-ADDRESS echoes the request's source address. */
static void
test_stun_responder (rpointer data, RBuffer * buf, RSocketAddress * addr,
    REvUDP * udp)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  (void) data;

  if (!r_buffer_map (buf, &info, R_MEM_MAP_READ))
    return;
  if (r_stun_is_valid_msg (info.data, info.size) &&
      r_stun_msg_is_request (info.data) &&
      r_stun_msg_method_is_binding (info.data)) {
    RBuffer * out = r_buffer_new_alloc (NULL, 128, NULL);
    RMemMapInfo oi = R_MEM_MAP_INFO_INIT;

    if (out != NULL && r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      rsize sz;

      r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_SUCCESS_RESPONSE,
          R_STUN_METHOD_BINDING, r_stun_msg_transaction_id (info.data));
      r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, addr);
      sz = r_stun_msg_end (&ctx, TRUE);
      r_buffer_unmap (out, &oi);
      r_buffer_set_size (out, sz);
      r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
    }
    if (out != NULL)
      r_buffer_unref (out);
  }
  r_buffer_unmap (buf, &info);
}

typedef struct {
  ruint count;
  RRtcIceCandidateType type;
  RSocketAddress * addr;
} TestSrflxObserver;

static void
test_srflx_on_candidate (rpointer data, RRtcIceTransport * ice,
    RRtcIceCandidate * candidate)
{
  TestSrflxObserver * obs = data;
  (void) ice;

  obs->count++;
  obs->type = r_rtc_ice_candidate_get_type (candidate);
  obs->addr = r_rtc_ice_candidate_get_addr (candidate);
}

RTEST (rrtcicetransport, gather_srflx_candidates, RTEST_FAST | RTEST_SYSTEM)
{
  /* Point srflx gathering at an in-process STUN server on loopback; the
   * reflexive address it reports (the host socket's own loopback address,
   * there being no NAT) is delivered as a server-reflexive candidate. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * s;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * raw;
  REvUDP * stun;
  RSocketAddress * lo, * stunaddr, * hostaddr;
  TestSrflxObserver obs = { 0, R_RTC_ICE_CANDIDATE_HOST, NULL };
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((s = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (s,
          R_STR_WITH_SIZE_ARGS ("uf"), R_STR_WITH_SIZE_ARGS ("password01234567"))), !=, NULL);
  r_assert_cmpptr ((raw = r_rtc_session_create_raw_transport (s, ice)), !=, NULL);

  /* Bring up the fake STUN server. */
  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((stun = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_bind (stun, lo, TRUE));
  r_assert (r_ev_udp_recv_start (stun, NULL, test_stun_responder, NULL, NULL));
  r_assert_cmpptr ((stunaddr = r_ev_udp_get_local_address (stun)), !=, NULL);

  r_rtc_ice_transport_set_on_local_candidate (ice, test_srflx_on_candidate, &obs);
  r_assert_cmpint (r_rtc_ice_transport_gather_host_candidates (ice,
          test_ice_only_loopback, NULL), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (ice, loop), ==, R_RTC_OK);
  r_assert_cmpptr ((hostaddr = r_rtc_ice_transport_get_local_address (ice)), !=, NULL);

  r_assert_cmpint (r_rtc_ice_transport_gather_srflx_candidates (ice, stunaddr), ==, R_RTC_OK);

  for (i = 0; i < 200 && obs.count == 0; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  /* A single server-reflexive candidate, its address the host socket's own
   * (loopback, no NAT in the path). */
  r_assert_cmpuint (obs.count, ==, 1);
  r_assert_cmpint (obs.type, ==, R_RTC_ICE_CANDIDATE_SRFLX);
  r_assert_cmpptr (obs.addr, !=, NULL);
  r_assert (r_socket_address_is_equal (obs.addr, hostaddr));

  r_socket_address_unref (obs.addr);
  r_socket_address_unref (hostaddr);
  r_rtc_ice_transport_close (ice);
  r_ev_udp_recv_stop (stun);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_ev_udp_unref (stun);
  r_socket_address_unref (lo);
  r_rtc_crypto_transport_unref (raw);
  r_rtc_ice_transport_unref (ice);
  r_rtc_session_unref (s);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

/* The multi-round-trip framed TCP handshake needs a backend that observes
 * loopback socket readiness promptly; the Windows WSAEventSelect readiness
 * (rpoll) backend does not, so gate this off there as revtcp does. */
#if !(defined (R_OS_WIN32) && defined (R_EV_USE_RPOLL))
static RRtcIceCandidate *
test_ice_tcp_candidate (const rchar * foundation, RSocketAddress * addr,
    const rchar * tcptype)
{
  RRtcIceCandidate * c = r_rtc_ice_candidate_new_full (foundation, -1,
      TEST_ICE_HOST_PRI, R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_TCP, addr,
      R_RTC_ICE_CANDIDATE_HOST);
  if (c != NULL)
    r_rtc_ice_candidate_add_ext (c, R_STR_WITH_SIZE_ARGS ("tcptype"),
        tcptype, -1);
  return c;
}

RTEST (rrtcicetransport, connectivity_check_tcp, RTEST_FAST | RTEST_SYSTEM)
{
  /* An active ICE-TCP agent dials a passive one over loopback; STUN
   * connectivity checks flow RFC 4571-framed over the connection and the
   * controlling side nominates a pair. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * sa, * sb;
  RRtcIceTransport * a, * b;   /* a: active/controlling, b: passive/controlled */
  RRtcCryptoTransport * ra, * rb;
  RSocketAddress * active_addr, * lo, * blisten;
  RRtcIceCandidate * ca, * cb, * rem;
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((sa = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((sb = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((a = r_rtc_session_create_ice_transport (sa,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567"))), !=, NULL);
  r_assert_cmpptr ((b = r_rtc_session_create_ice_transport (sb,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567"))), !=, NULL);
  r_assert_cmpptr ((ra = r_rtc_session_create_raw_transport (sa, a)), !=, NULL);
  r_assert_cmpptr ((rb = r_rtc_session_create_raw_transport (sb, b)), !=, NULL);

  r_assert_cmpint (r_rtc_ice_transport_set_role (a, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_role (b, R_RTC_ICE_ROLE_CONTROLLED), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (a,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567")), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (b,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567")), ==, R_RTC_OK);

  /* b listens (passive) on an OS-assigned loopback port; a is active and
   * has no socket of its own until it dials. */
  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((active_addr = r_socket_address_ipv4_new_from_string ("127.0.0.1", 9)), !=, NULL);
  r_assert_cmpptr ((cb = test_ice_tcp_candidate ("1", lo, "passive")), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_tcp_candidate ("1", active_addr, "active")), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (b, cb), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (a, ca), ==, R_RTC_OK);

  r_assert_cmpint (r_rtc_ice_transport_start (a, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (b, loop), ==, R_RTC_OK);

  /* Give a the passive remote (b's real listen address) -> a dials it. */
  r_assert_cmpptr ((blisten = r_rtc_ice_transport_get_local_address (b)), !=, NULL);
  r_assert_cmpptr ((rem = test_ice_tcp_candidate ("1", blisten, "passive")), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (a, rem), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (rem);
  /* b learns a from the incoming connection (peer-reflexive). */
  r_assert_cmpptr ((rem = test_ice_tcp_candidate ("1", active_addr, "active")), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (b, rem), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (rem);

  for (i = 0; i < 300; i++) {
    if (r_rtc_ice_transport_get_state (a) == R_RTC_ICE_STATE_CONNECTED &&
        r_rtc_ice_transport_get_state (b) == R_RTC_ICE_STATE_CONNECTED)
      break;
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  }

  r_assert_cmpint (r_rtc_ice_transport_get_state (a), ==, R_RTC_ICE_STATE_CONNECTED);
  r_assert_cmpint (r_rtc_ice_transport_get_state (b), ==, R_RTC_ICE_STATE_CONNECTED);

  r_rtc_ice_transport_close (a);
  r_rtc_ice_transport_close (b);
  for (i = 0; i < 16; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);
  r_socket_address_unref (lo);
  r_socket_address_unref (active_addr);
  r_socket_address_unref (blisten);
  r_rtc_crypto_transport_unref (ra);
  r_rtc_crypto_transport_unref (rb);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (sa);
  r_rtc_session_unref (sb);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;
RTEST (rrtcicetransport, tcp_peer_close_disconnects, RTEST_FAST | RTEST_SYSTEM)
{
  /* Once a TCP pair is nominated, the peer tearing the connection down must
   * transition the survivor to DISCONNECTED and invalidate the borrowed
   * connection pointers (no use-after-free), rather than dangle them. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * sa, * sb;
  RRtcIceTransport * a, * b;
  RRtcCryptoTransport * ra, * rb;
  RSocketAddress * active_addr, * lo, * blisten;
  RRtcIceCandidate * ca, * cb, * rem;
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((sa = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((sb = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((a = r_rtc_session_create_ice_transport (sa,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567"))), !=, NULL);
  r_assert_cmpptr ((b = r_rtc_session_create_ice_transport (sb,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567"))), !=, NULL);
  r_assert_cmpptr ((ra = r_rtc_session_create_raw_transport (sa, a)), !=, NULL);
  r_assert_cmpptr ((rb = r_rtc_session_create_raw_transport (sb, b)), !=, NULL);

  r_assert_cmpint (r_rtc_ice_transport_set_role (a, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_role (b, R_RTC_ICE_ROLE_CONTROLLED), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (a,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567")), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (b,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567")), ==, R_RTC_OK);

  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((active_addr = r_socket_address_ipv4_new_from_string ("127.0.0.1", 9)), !=, NULL);
  r_assert_cmpptr ((cb = test_ice_tcp_candidate ("1", lo, "passive")), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_tcp_candidate ("1", active_addr, "active")), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (b, cb), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (a, ca), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (a, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (b, loop), ==, R_RTC_OK);

  r_assert_cmpptr ((blisten = r_rtc_ice_transport_get_local_address (b)), !=, NULL);
  r_assert_cmpptr ((rem = test_ice_tcp_candidate ("1", blisten, "passive")), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (a, rem), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (rem);

  for (i = 0; i < 300; i++) {
    if (r_rtc_ice_transport_get_state (a) == R_RTC_ICE_STATE_CONNECTED)
      break;
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  }
  r_assert_cmpint (r_rtc_ice_transport_get_state (a), ==, R_RTC_ICE_STATE_CONNECTED);

  /* Tear b down entirely; its connection aborts, resetting a's stream. */
  r_rtc_crypto_transport_unref (rb);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (sb);
  for (i = 0; i < 32 &&
      r_rtc_ice_transport_get_state (a) == R_RTC_ICE_STATE_CONNECTED; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  /* a saw the reset, cleared its selected connection, and did not crash. */
  r_assert_cmpint (r_rtc_ice_transport_get_state (a), ==, R_RTC_ICE_STATE_DISCONNECTED);

  r_rtc_ice_transport_close (a);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);
  r_socket_address_unref (lo);
  r_socket_address_unref (active_addr);
  r_socket_address_unref (blisten);
  r_rtc_crypto_transport_unref (ra);
  r_rtc_ice_transport_unref (a);
  r_rtc_session_unref (sa);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;
#endif /* not Windows rpoll */

/* A minimal TURN server: challenge the first Allocate with 401 + REALM +
 * NONCE, then answer the credentialed retry with a relayed address. */
static rboolean
test_turn_has_integrity (rconstpointer msg)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;

  if (r_stun_attr_tlv_first (msg, &tlv)) {
    do {
      if (tlv.type == R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY)
        return TRUE;
    } while (r_stun_attr_tlv_next (msg, &tlv));
  }
  return FALSE;
}

static void
test_turn_responder (rpointer data, RBuffer * buf, RSocketAddress * addr, REvUDP * udp)
{
  RSocketAddress * relayed = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  if (!r_buffer_map (buf, &info, R_MEM_MAP_READ))
    return;
  if (r_stun_is_valid_msg (info.data, info.size) &&
      r_stun_msg_is_request (info.data) &&
      r_stun_msg_method_is_allocate (info.data)) {
    RBuffer * out = r_buffer_new_alloc (NULL, 256, NULL);
    RMemMapInfo oi = R_MEM_MAP_INFO_INIT;
    rboolean authed = test_turn_has_integrity (info.data);

    if (out != NULL && r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
      rsize sz;

      if (authed) {
        /* Long-term key MD5("user:rlib:pass") to sign the success. */
        RMsgDigest * md = r_msg_digest_new_md5 ();
        ruint8 key[16];
        rsize klen = 0;

        r_msg_digest_update (md, R_STR_WITH_SIZE_ARGS ("user:rlib:pass"));
        r_msg_digest_get_data (md, key, sizeof (key), &klen);
        r_msg_digest_free (md);

        r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_SUCCESS_RESPONSE,
            R_STUN_METHOD_ALLOCATE, r_stun_msg_transaction_id (info.data));
        r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_RELAYED_ADDRESS, relayed);
        r_stun_msg_add_message_integrity_short_cred (&ctx, key, sizeof (key));
      } else {
        ruint8 errcode[] = { 0, 0, 4, 1, 'U','n','a','u','t','h' };  /* 401 */
        r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_ERROR_RESPONSE,
            R_STUN_METHOD_ALLOCATE, r_stun_msg_transaction_id (info.data));
        tlv.type = R_STUN_ATTR_TYPE_ERROR_CODE;
        tlv.len = sizeof (errcode); tlv.value = errcode;
        r_stun_msg_add_attribute (&ctx, &tlv);
        tlv.type = R_STUN_ATTR_TYPE_REALM;
        tlv.len = 4; tlv.value = (const ruint8 *) "rlib";
        r_stun_msg_add_attribute (&ctx, &tlv);
        tlv.type = R_STUN_ATTR_TYPE_NONCE;
        tlv.len = 8; tlv.value = (const ruint8 *) "nonce123";
        r_stun_msg_add_attribute (&ctx, &tlv);
      }
      sz = r_stun_msg_end (&ctx, TRUE);
      r_buffer_unmap (out, &oi);
      r_buffer_set_size (out, sz);
      r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
    }
    if (out != NULL)
      r_buffer_unref (out);
  }
  r_buffer_unmap (buf, &info);
}

RTEST (rrtcicetransport, gather_relay_candidates, RTEST_FAST | RTEST_SYSTEM)
{
  /* Point relay gathering at an in-process TURN server on loopback; after
   * the 401 challenge and credentialed retry the allocated address is
   * delivered as a relay candidate. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * s;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * raw;
  REvUDP * turn;
  RSocketAddress * lo, * turnaddr, * relayed;
  TestSrflxObserver obs = { 0, R_RTC_ICE_CANDIDATE_HOST, NULL };
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((s = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (s,
          R_STR_WITH_SIZE_ARGS ("uf"), R_STR_WITH_SIZE_ARGS ("password01234567"))), !=, NULL);
  r_assert_cmpptr ((raw = r_rtc_session_create_raw_transport (s, ice)), !=, NULL);

  r_assert_cmpptr ((relayed = r_socket_address_ipv4_new_from_string ("203.0.113.1", 50000)), !=, NULL);
  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((turn = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_bind (turn, lo, TRUE));
  r_assert (r_ev_udp_recv_start (turn, NULL, test_turn_responder, relayed, NULL));
  r_assert_cmpptr ((turnaddr = r_ev_udp_get_local_address (turn)), !=, NULL);

  r_rtc_ice_transport_set_on_local_candidate (ice, test_srflx_on_candidate, &obs);
  r_assert_cmpint (r_rtc_ice_transport_gather_host_candidates (ice,
          test_ice_only_loopback, NULL), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (ice, loop), ==, R_RTC_OK);

  r_assert_cmpint (r_rtc_ice_transport_gather_relay_candidates (ice, turnaddr,
          "user", "pass"), ==, R_RTC_OK);

  for (i = 0; i < 200 && obs.count == 0; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert_cmpuint (obs.count, ==, 1);
  r_assert_cmpint (obs.type, ==, R_RTC_ICE_CANDIDATE_RELAY);
  r_assert_cmpptr (obs.addr, !=, NULL);
  r_assert (r_socket_address_is_equal (obs.addr, relayed));

  r_socket_address_unref (obs.addr);
  r_rtc_ice_transport_close (ice);
  r_ev_udp_recv_stop (turn);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_ev_udp_unref (turn);
  r_socket_address_unref (lo);
  r_socket_address_unref (relayed);
  r_rtc_crypto_transport_unref (raw);
  r_rtc_ice_transport_unref (ice);
  r_rtc_session_unref (s);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

/* The remote ICE password the relayed peer signs its Binding responses with;
 * the agent verifies them against this as its remote credential. */
#define TEST_RELAY_REMOTE_PWD "peerpwd012345678"

static void
test_turn_longterm_key (ruint8 key[16])
{
  /* MD5("user:rlib:pass") -- the long-term credential key. */
  RMsgDigest * md = r_msg_digest_new_md5 ();
  rsize klen = 0;

  r_msg_digest_update (md, R_STR_WITH_SIZE_ARGS ("user:rlib:pass"));
  r_msg_digest_get_data (md, key, 16, &klen);
  r_msg_digest_free (md);
}

typedef struct {
  RSocketAddress * relayed;   /* the address handed back as XOR-RELAYED-ADDRESS */
  ruint relayed_checks;       /* relayed Binding checks answered */
  ruint relayed_media;        /* relayed non-STUN datagrams seen */
} TestTurnRelayState;

/* A relaying in-process TURN server: allocate (with the 401 challenge),
 * install permissions, and -- the point of this test -- answer a relayed
 * Binding check by wrapping a Binding success in a Data indication, so the
 * agent's relay pair completes a connectivity check end to end. */
static void
test_turn_relay_responder (rpointer data, RBuffer * buf, RSocketAddress * addr,
    REvUDP * udp)
{
  TestTurnRelayState * st = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  if (!r_buffer_map (buf, &info, R_MEM_MAP_READ))
    return;
  if (!r_stun_is_valid_msg (info.data, info.size)) {
    r_buffer_unmap (buf, &info);
    return;
  }

  if (r_stun_msg_method_is_allocate (info.data) && r_stun_msg_is_request (info.data)) {
    RBuffer * out = r_buffer_new_alloc (NULL, 256, NULL);
    RMemMapInfo oi = R_MEM_MAP_INFO_INIT;

    if (out != NULL && r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
      rsize sz;

      if (test_turn_has_integrity (info.data)) {
        ruint8 key[16];
        test_turn_longterm_key (key);
        r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_SUCCESS_RESPONSE,
            R_STUN_METHOD_ALLOCATE, r_stun_msg_transaction_id (info.data));
        r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_RELAYED_ADDRESS, st->relayed);
        r_stun_msg_add_message_integrity_short_cred (&ctx, key, sizeof (key));
      } else {
        ruint8 errcode[] = { 0, 0, 4, 1, 'U','n','a','u','t','h' };  /* 401 */
        r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_ERROR_RESPONSE,
            R_STUN_METHOD_ALLOCATE, r_stun_msg_transaction_id (info.data));
        tlv.type = R_STUN_ATTR_TYPE_ERROR_CODE;
        tlv.len = sizeof (errcode); tlv.value = errcode;
        r_stun_msg_add_attribute (&ctx, &tlv);
        tlv.type = R_STUN_ATTR_TYPE_REALM;
        tlv.len = 4; tlv.value = (const ruint8 *) "rlib";
        r_stun_msg_add_attribute (&ctx, &tlv);
        tlv.type = R_STUN_ATTR_TYPE_NONCE;
        tlv.len = 8; tlv.value = (const ruint8 *) "nonce123";
        r_stun_msg_add_attribute (&ctx, &tlv);
      }
      sz = r_stun_msg_end (&ctx, TRUE);
      r_buffer_unmap (out, &oi);
      r_buffer_set_size (out, sz);
      r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
    }
    if (out != NULL)
      r_buffer_unref (out);
  } else if (r_stun_msg_method_is_create_permission (info.data) &&
      r_stun_msg_is_request (info.data)) {
    RBuffer * out = r_buffer_new_alloc (NULL, 128, NULL);
    RMemMapInfo oi = R_MEM_MAP_INFO_INIT;

    if (out != NULL && r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      ruint8 key[16];
      rsize sz;

      test_turn_longterm_key (key);
      r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_SUCCESS_RESPONSE,
          R_STUN_METHOD_CREATE_PERMISSION, r_stun_msg_transaction_id (info.data));
      r_stun_msg_add_message_integrity_short_cred (&ctx, key, sizeof (key));
      sz = r_stun_msg_end (&ctx, TRUE);
      r_buffer_unmap (out, &oi);
      r_buffer_set_size (out, sz);
      r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
    }
    if (out != NULL)
      r_buffer_unref (out);
  } else if (r_stun_msg_is_indication (info.data) &&
      (r_stun_msg_type (info.data) & R_STUN_TYPE_METHOD_MASK) == R_STUN_METHOD_SEND) {
    RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
    RSocketAddress * peer = NULL;
    const ruint8 * payload = NULL;
    rsize plen = 0;

    if (r_stun_attr_tlv_first (info.data, &tlv)) {
      do {
        if (tlv.type == R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS)
          peer = r_stun_attr_tlv_parse_xor_address (info.data, &tlv);
        else if (tlv.type == R_STUN_ATTR_TYPE_DATA) {
          payload = tlv.value;
          plen = tlv.len;
        }
      } while (r_stun_attr_tlv_next (info.data, &tlv));
    }

    if (peer != NULL && payload != NULL &&
        r_stun_is_valid_msg (payload, plen) &&
        r_stun_msg_method_is_binding (payload) && r_stun_msg_is_request (payload)) {
      RBuffer * inner = r_buffer_new_alloc (NULL, 256, NULL);
      RBuffer * out = r_buffer_new_alloc (NULL, 512, NULL);
      RMemMapInfo ii = R_MEM_MAP_INFO_INIT, oi = R_MEM_MAP_INFO_INIT;

      if (inner != NULL && out != NULL &&
          r_buffer_map (inner, &ii, R_MEM_MAP_WRITE) &&
          r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
        RStunMsgCtx ctx;
        RStunAttrTLV a = R_STUN_ATTR_TLV_INIT;
        ruint8 tid[R_STUN_TRANSACTION_ID_SIZE] = { 0 };
        rsize isz, osz;

        /* Inner: a Binding success echoing the check's transaction id, keyed
         * with the agent's remote password. */
        r_stun_msg_begin (&ctx, ii.data, ii.size, R_STUN_CLASS_SUCCESS_RESPONSE,
            R_STUN_METHOD_BINDING, r_stun_msg_transaction_id (payload));
        r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, peer);
        r_stun_msg_add_message_integrity_short_cred (&ctx,
            R_STR_WITH_SIZE_ARGS (TEST_RELAY_REMOTE_PWD));
        isz = r_stun_msg_end (&ctx, TRUE);

        /* Outer: a Data indication carrying the inner response as DATA. */
        r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_INDICATION,
            R_STUN_METHOD_DATA, tid);
        r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS, peer);
        a.type = R_STUN_ATTR_TYPE_DATA;
        a.len = (ruint16) isz;
        a.value = ii.data;
        r_stun_msg_add_attribute (&ctx, &a);
        osz = r_stun_msg_end (&ctx, TRUE);

        r_buffer_unmap (out, &oi);
        r_buffer_unmap (inner, &ii);
        r_buffer_set_size (out, osz);
        r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
        st->relayed_checks++;
      }
      if (inner != NULL)
        r_buffer_unref (inner);
      if (out != NULL)
        r_buffer_unref (out);
    } else if (payload != NULL) {
      st->relayed_media++;
    }
    if (peer != NULL)
      r_socket_address_unref (peer);
  }

  r_buffer_unmap (buf, &info);
}

RTEST (rrtcicetransport, turn_relay_connectivity, RTEST_FAST | RTEST_SYSTEM)
{
  /* Gather a relay candidate from an in-process relaying TURN server, then
   * pair it with a peer at an unroutable address so that only the relay path
   * -- Send indications out, Data indications back -- can complete a check.
   * The agent reaching CONNECTED proves the relay data path works. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * s;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * raw;
  REvUDP * turn;
  RSocketAddress * lo, * turnaddr, * relayed, * peeraddr;
  RRtcIceCandidate * peercand;
  TestSrflxObserver obs = { 0, R_RTC_ICE_CANDIDATE_HOST, NULL };
  TestTurnRelayState st = { NULL, 0, 0 };
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((s = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (s,
          R_STR_WITH_SIZE_ARGS ("uf"), R_STR_WITH_SIZE_ARGS ("password01234567"))), !=, NULL);
  r_assert_cmpptr ((raw = r_rtc_session_create_raw_transport (s, ice)), !=, NULL);

  r_assert_cmpptr ((relayed = r_socket_address_ipv4_new_from_string ("203.0.113.1", 50000)), !=, NULL);
  st.relayed = relayed;

  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((turn = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_bind (turn, lo, TRUE));
  r_assert (r_ev_udp_recv_start (turn, NULL, test_turn_relay_responder, &st, NULL));
  r_assert_cmpptr ((turnaddr = r_ev_udp_get_local_address (turn)), !=, NULL);

  r_rtc_ice_transport_set_on_local_candidate (ice, test_srflx_on_candidate, &obs);
  r_assert_cmpint (r_rtc_ice_transport_gather_host_candidates (ice,
          test_ice_only_loopback, NULL), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_role (ice, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (ice,
          R_STR_WITH_SIZE_ARGS ("peer"), R_STR_WITH_SIZE_ARGS (TEST_RELAY_REMOTE_PWD)), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (ice, loop), ==, R_RTC_OK);

  r_assert_cmpint (r_rtc_ice_transport_gather_relay_candidates (ice, turnaddr,
          "user", "pass"), ==, R_RTC_OK);

  for (i = 0; i < 200 && obs.count == 0; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  r_assert_cmpuint (obs.count, ==, 1);
  r_assert_cmpint (obs.type, ==, R_RTC_ICE_CANDIDATE_RELAY);

  /* An unroutable TEST-NET peer: the direct host pair to it can never answer,
   * so only the relayed pair can be nominated. */
  r_assert_cmpptr ((peeraddr = r_socket_address_ipv4_new_from_string ("198.51.100.7", 3478)), !=, NULL);
  r_assert_cmpptr ((peercand = test_ice_host_candidate ("2", peeraddr)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (ice, peercand), ==, R_RTC_OK);

  for (i = 0; i < 400 &&
      r_rtc_ice_transport_get_state (ice) != R_RTC_ICE_STATE_CONNECTED; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert_cmpint (r_rtc_ice_transport_get_state (ice), ==, R_RTC_ICE_STATE_CONNECTED);
  r_assert_cmpuint (st.relayed_checks, >=, 1);

  r_socket_address_unref (obs.addr);
  r_rtc_ice_transport_close (ice);
  r_ev_udp_recv_stop (turn);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_rtc_ice_candidate_unref (peercand);
  r_socket_address_unref (peeraddr);
  r_ev_udp_unref (turn);
  r_socket_address_unref (lo);
  r_socket_address_unref (relayed);
  r_socket_address_unref (turnaddr);
  r_rtc_crypto_transport_unref (raw);
  r_rtc_ice_transport_unref (ice);
  r_rtc_session_unref (s);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

typedef struct {
  RSocketAddress * relayed;
  ruint32 lifetime;           /* advertised in Allocate / Refresh success */
  ruint refreshes;            /* Refresh requests seen */
  rboolean sent_stale;        /* answered a Refresh with 438 once */
  rboolean got_fresh_nonce;   /* a Refresh arrived carrying the post-438 nonce */
  rboolean released;          /* a Refresh with LIFETIME=0 arrived */
} TestTurnRefreshState;

/* A TURN server with a short allocation lifetime that also exercises the
 * keepalive path: it 438s the first Refresh (forcing a fresh-nonce replay)
 * and records the LIFETIME=0 release sent on close. */
static void
test_turn_refresh_responder (rpointer data, RBuffer * buf, RSocketAddress * addr,
    REvUDP * udp)
{
  TestTurnRefreshState * st = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RBuffer * out;
  RMemMapInfo oi = R_MEM_MAP_INFO_INIT;
  RStunMsgCtx ctx;
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  ruint8 key[16];
  rsize sz;

  if (!r_buffer_map (buf, &info, R_MEM_MAP_READ))
    return;
  if (!r_stun_is_valid_msg (info.data, info.size) ||
      !r_stun_msg_is_request (info.data)) {
    r_buffer_unmap (buf, &info);
    return;
  }

  if ((out = r_buffer_new_alloc (NULL, 256, NULL)) == NULL ||
      !r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
    if (out != NULL) r_buffer_unref (out);
    r_buffer_unmap (buf, &info);
    return;
  }

  if (r_stun_msg_method_is_allocate (info.data)) {
    if (test_turn_has_integrity (info.data)) {
      ruint8 lt[4];
      r_store_be32 (lt, st->lifetime);
      test_turn_longterm_key (key);
      r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_SUCCESS_RESPONSE,
          R_STUN_METHOD_ALLOCATE, r_stun_msg_transaction_id (info.data));
      r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_RELAYED_ADDRESS, st->relayed);
      tlv.type = R_STUN_ATTR_TYPE_LIFETIME; tlv.len = sizeof (lt); tlv.value = lt;
      r_stun_msg_add_attribute (&ctx, &tlv);
      r_stun_msg_add_message_integrity_short_cred (&ctx, key, sizeof (key));
    } else {
      ruint8 errcode[] = { 0, 0, 4, 1, 'U','n','a','u','t','h' };  /* 401 */
      r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_ERROR_RESPONSE,
          R_STUN_METHOD_ALLOCATE, r_stun_msg_transaction_id (info.data));
      tlv.type = R_STUN_ATTR_TYPE_ERROR_CODE; tlv.len = sizeof (errcode); tlv.value = errcode;
      r_stun_msg_add_attribute (&ctx, &tlv);
      tlv.type = R_STUN_ATTR_TYPE_REALM; tlv.len = 4; tlv.value = (const ruint8 *) "rlib";
      r_stun_msg_add_attribute (&ctx, &tlv);
      tlv.type = R_STUN_ATTR_TYPE_NONCE; tlv.len = 8; tlv.value = (const ruint8 *) "nonce123";
      r_stun_msg_add_attribute (&ctx, &tlv);
    }
    sz = r_stun_msg_end (&ctx, TRUE);
    r_buffer_unmap (out, &oi); r_buffer_set_size (out, sz);
    r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
  } else if (r_stun_msg_method_is_refresh (info.data)) {
    RStunAttrTLV it = R_STUN_ATTR_TLV_INIT;
    ruint32 req_lifetime = 0;
    rchar * req_nonce = NULL;

    st->refreshes++;
    if (r_stun_attr_tlv_first (info.data, &it)) {
      do {
        if (it.type == R_STUN_ATTR_TYPE_LIFETIME && it.len >= 4)
          req_lifetime = r_load_be32 (it.value);
        else if (it.type == R_STUN_ATTR_TYPE_NONCE)
          req_nonce = r_strdup_size ((const rchar *) it.value, it.len);
      } while (r_stun_attr_tlv_next (info.data, &it));
    }

    if (req_lifetime == 0) {
      st->released = TRUE;
    } else if (!st->sent_stale) {
      st->sent_stale = TRUE;
    }
    if (req_nonce != NULL && r_str_equals (req_nonce, "nonce456"))
      st->got_fresh_nonce = TRUE;

    if (req_lifetime != 0 && st->sent_stale && !st->got_fresh_nonce &&
        (req_nonce == NULL || !r_str_equals (req_nonce, "nonce456"))) {
      /* Challenge the first (non-release) Refresh with a stale-nonce error. */
      ruint8 errcode[] = { 0, 0, 4, 38, 'S','t','a','l','e' };  /* 438 */
      r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_ERROR_RESPONSE,
          R_STUN_METHOD_REFRESH, r_stun_msg_transaction_id (info.data));
      tlv.type = R_STUN_ATTR_TYPE_ERROR_CODE; tlv.len = sizeof (errcode); tlv.value = errcode;
      r_stun_msg_add_attribute (&ctx, &tlv);
      tlv.type = R_STUN_ATTR_TYPE_REALM; tlv.len = 4; tlv.value = (const ruint8 *) "rlib";
      r_stun_msg_add_attribute (&ctx, &tlv);
      tlv.type = R_STUN_ATTR_TYPE_NONCE; tlv.len = 8; tlv.value = (const ruint8 *) "nonce456";
      r_stun_msg_add_attribute (&ctx, &tlv);
    } else {
      ruint8 lt[4];
      r_store_be32 (lt, req_lifetime);
      test_turn_longterm_key (key);
      r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_SUCCESS_RESPONSE,
          R_STUN_METHOD_REFRESH, r_stun_msg_transaction_id (info.data));
      tlv.type = R_STUN_ATTR_TYPE_LIFETIME; tlv.len = sizeof (lt); tlv.value = lt;
      r_stun_msg_add_attribute (&ctx, &tlv);
      r_stun_msg_add_message_integrity_short_cred (&ctx, key, sizeof (key));
    }
    sz = r_stun_msg_end (&ctx, TRUE);
    r_buffer_unmap (out, &oi); r_buffer_set_size (out, sz);
    r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
    r_free (req_nonce);
  } else {
    r_buffer_unmap (out, &oi);
  }

  r_buffer_unref (out);
  r_buffer_unmap (buf, &info);
}

RTEST (rrtcicetransport, turn_allocation_refresh, RTEST_FAST | RTEST_SYSTEM)
{
  /* With a short (2 s) allocation lifetime the agent refreshes at ~1 s. The
   * server 438s the first Refresh, and the agent must adopt the fresh nonce
   * and replay; on close it releases the allocation with LIFETIME=0. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * s;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * raw;
  REvUDP * turn;
  RSocketAddress * lo, * turnaddr, * relayed;
  TestSrflxObserver obs = { 0, R_RTC_ICE_CANDIDATE_HOST, NULL };
  TestTurnRefreshState st = { NULL, 2, 0, FALSE, FALSE, FALSE };
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((s = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (s,
          R_STR_WITH_SIZE_ARGS ("uf"), R_STR_WITH_SIZE_ARGS ("password01234567"))), !=, NULL);
  r_assert_cmpptr ((raw = r_rtc_session_create_raw_transport (s, ice)), !=, NULL);

  r_assert_cmpptr ((relayed = r_socket_address_ipv4_new_from_string ("203.0.113.1", 50000)), !=, NULL);
  st.relayed = relayed;

  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((turn = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_bind (turn, lo, TRUE));
  r_assert (r_ev_udp_recv_start (turn, NULL, test_turn_refresh_responder, &st, NULL));
  r_assert_cmpptr ((turnaddr = r_ev_udp_get_local_address (turn)), !=, NULL);

  r_rtc_ice_transport_set_on_local_candidate (ice, test_srflx_on_candidate, &obs);
  r_assert_cmpint (r_rtc_ice_transport_gather_host_candidates (ice,
          test_ice_only_loopback, NULL), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (ice, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_gather_relay_candidates (ice, turnaddr,
          "user", "pass"), ==, R_RTC_OK);

  for (i = 0; i < 200 && obs.count == 0; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  r_assert_cmpuint (obs.count, ==, 1);

  /* Run long enough for the refresh timer to fire and the 438 replay to land. */
  for (i = 0; i < 40 && !st.got_fresh_nonce; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert_cmpuint (st.refreshes, >=, 2);
  r_assert (st.got_fresh_nonce);

  r_socket_address_unref (obs.addr);
  r_rtc_ice_transport_close (ice);
  for (i = 0; i < 20 && !st.released; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  r_assert (st.released);

  r_ev_udp_recv_stop (turn);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_ev_udp_unref (turn);
  r_socket_address_unref (lo);
  r_socket_address_unref (relayed);
  r_socket_address_unref (turnaddr);
  r_rtc_crypto_transport_unref (raw);
  r_rtc_ice_transport_unref (ice);
  r_rtc_session_unref (s);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

typedef struct {
  RSocketAddress * relayed;
  ruint16 channel;            /* channel number the agent bound (0 = none) */
  RSocketAddress * chanpeer;  /* peer bound to `channel` */
  ruint channel_binds;        /* ChannelBind requests seen */
  ruint channel_data_rx;      /* ChannelData frames received from the agent */
} TestTurnChannelState;

/* Build a Binding success for @req_tid (XOR-MAPPED-ADDRESS @peer) keyed with
 * the agent's remote password, into @dst; returns its size. */
static rsize
test_build_binding_success (ruint8 * dst, rsize dstsize,
    const ruint8 * req_tid, RSocketAddress * peer)
{
  RStunMsgCtx ctx;

  r_stun_msg_begin (&ctx, dst, dstsize, R_STUN_CLASS_SUCCESS_RESPONSE,
      R_STUN_METHOD_BINDING, req_tid);
  r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, peer);
  r_stun_msg_add_message_integrity_short_cred (&ctx,
      R_STR_WITH_SIZE_ARGS (TEST_RELAY_REMOTE_PWD));
  return r_stun_msg_end (&ctx, TRUE);
}

static void
test_send_channel_data (REvUDP * udp, RSocketAddress * addr, ruint16 number,
    const ruint8 * payload, rsize plen)
{
  RBuffer * out = r_buffer_new_alloc (NULL, 4 + ((plen + 3) & ~(rsize) 3), NULL);
  RMemMapInfo oi = R_MEM_MAP_INFO_INIT;

  if (out != NULL && r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
    rsize padded = (plen + 3) & ~(rsize) 3;
    r_store_be16 (oi.data, number);
    r_store_be16 ((ruint8 *) oi.data + 2, (ruint16) plen);
    r_memcpy ((ruint8 *) oi.data + 4, payload, plen);
    if (padded > plen)
      r_memset ((ruint8 *) oi.data + 4 + plen, 0, padded - plen);
    r_buffer_unmap (out, &oi);
    r_buffer_set_size (out, 4 + padded);
    r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
  }
  if (out != NULL)
    r_buffer_unref (out);
}

/* A relaying TURN server that promotes the peer to a channel: it answers
 * ChannelBind, and once bound replies to relayed Binding checks over
 * ChannelData, so both directions of the channel path are exercised. */
static void
test_turn_channel_responder (rpointer data, RBuffer * buf, RSocketAddress * addr,
    REvUDP * udp)
{
  TestTurnChannelState * st = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  if (!r_buffer_map (buf, &info, R_MEM_MAP_READ))
    return;

  if (r_stun_is_channel_data (info.data, info.size)) {
    ruint16 len = r_load_be16 ((const ruint8 *) info.data + 2);
    const ruint8 * payload = (const ruint8 *) info.data + 4;

    st->channel_data_rx++;
    if ((rsize) 4 + len <= info.size && r_stun_is_valid_msg (payload, len) &&
        r_stun_msg_method_is_binding (payload) && r_stun_msg_is_request (payload) &&
        st->chanpeer != NULL) {
      ruint8 ib[256];
      rsize isz = test_build_binding_success (ib, sizeof (ib),
          r_stun_msg_transaction_id (payload), st->chanpeer);
      test_send_channel_data (udp, addr, st->channel, ib, isz);
    }
    r_buffer_unmap (buf, &info);
    return;
  }

  if (!r_stun_is_valid_msg (info.data, info.size) ||
      !(r_stun_msg_is_request (info.data) || r_stun_msg_is_indication (info.data))) {
    r_buffer_unmap (buf, &info);
    return;
  }

  if (r_stun_msg_method_is_allocate (info.data) ||
      r_stun_msg_method_is_create_permission (info.data) ||
      r_stun_msg_method_is_channel_bind (info.data)) {
    RBuffer * out = r_buffer_new_alloc (NULL, 256, NULL);
    RMemMapInfo oi = R_MEM_MAP_INFO_INIT;

    if (out != NULL && r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
      RStunMsgCtx ctx;
      RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
      ruint8 key[16];
      rsize sz;

      if (r_stun_msg_method_is_allocate (info.data) &&
          !test_turn_has_integrity (info.data)) {
        ruint8 errcode[] = { 0, 0, 4, 1, 'U','n','a','u','t','h' };  /* 401 */
        r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_ERROR_RESPONSE,
            R_STUN_METHOD_ALLOCATE, r_stun_msg_transaction_id (info.data));
        tlv.type = R_STUN_ATTR_TYPE_ERROR_CODE; tlv.len = sizeof (errcode); tlv.value = errcode;
        r_stun_msg_add_attribute (&ctx, &tlv);
        tlv.type = R_STUN_ATTR_TYPE_REALM; tlv.len = 4; tlv.value = (const ruint8 *) "rlib";
        r_stun_msg_add_attribute (&ctx, &tlv);
        tlv.type = R_STUN_ATTR_TYPE_NONCE; tlv.len = 8; tlv.value = (const ruint8 *) "nonce123";
        r_stun_msg_add_attribute (&ctx, &tlv);
      } else {
        RStunMethod method = r_stun_msg_type (info.data) & R_STUN_TYPE_METHOD_MASK;
        test_turn_longterm_key (key);
        r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_SUCCESS_RESPONSE,
            method, r_stun_msg_transaction_id (info.data));
        if (method == R_STUN_METHOD_ALLOCATE)
          r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_RELAYED_ADDRESS, st->relayed);
        if (method == R_STUN_METHOD_CHANNEL_BIND) {
          RStunAttrTLV it = R_STUN_ATTR_TLV_INIT;
          st->channel_binds++;
          if (r_stun_attr_tlv_first (info.data, &it)) {
            do {
              if (it.type == R_STUN_ATTR_TYPE_CHANNEL_NUMBER && it.len >= 2)
                st->channel = r_load_be16 (it.value);
              else if (it.type == R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS) {
                if (st->chanpeer != NULL)
                  r_socket_address_unref (st->chanpeer);
                st->chanpeer = r_stun_attr_tlv_parse_xor_address (info.data, &it);
              }
            } while (r_stun_attr_tlv_next (info.data, &it));
          }
        }
        r_stun_msg_add_message_integrity_short_cred (&ctx, key, sizeof (key));
      }
      sz = r_stun_msg_end (&ctx, TRUE);
      r_buffer_unmap (out, &oi);
      r_buffer_set_size (out, sz);
      r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
    }
    if (out != NULL)
      r_buffer_unref (out);
  } else if (r_stun_msg_is_indication (info.data) &&
      (r_stun_msg_type (info.data) & R_STUN_TYPE_METHOD_MASK) == R_STUN_METHOD_SEND) {
    RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
    RSocketAddress * peer = NULL;
    const ruint8 * payload = NULL;
    rsize plen = 0;

    if (r_stun_attr_tlv_first (info.data, &tlv)) {
      do {
        if (tlv.type == R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS)
          peer = r_stun_attr_tlv_parse_xor_address (info.data, &tlv);
        else if (tlv.type == R_STUN_ATTR_TYPE_DATA) {
          payload = tlv.value;
          plen = tlv.len;
        }
      } while (r_stun_attr_tlv_next (info.data, &tlv));
    }

    if (peer != NULL && payload != NULL && r_stun_is_valid_msg (payload, plen) &&
        r_stun_msg_method_is_binding (payload) && r_stun_msg_is_request (payload)) {
      ruint8 ib[256];
      rsize isz = test_build_binding_success (ib, sizeof (ib),
          r_stun_msg_transaction_id (payload), peer);

      /* Once the channel is bound, answer over ChannelData; otherwise wrap the
       * success in a Data indication. */
      if (st->channel != 0 && st->chanpeer != NULL &&
          r_socket_address_is_equal (st->chanpeer, peer)) {
        test_send_channel_data (udp, addr, st->channel, ib, isz);
      } else {
        RBuffer * out = r_buffer_new_alloc (NULL, 512, NULL);
        RMemMapInfo oi = R_MEM_MAP_INFO_INIT;
        if (out != NULL && r_buffer_map (out, &oi, R_MEM_MAP_WRITE)) {
          RStunMsgCtx ctx;
          RStunAttrTLV a = R_STUN_ATTR_TLV_INIT;
          ruint8 tid[R_STUN_TRANSACTION_ID_SIZE] = { 0 };
          rsize osz;
          r_stun_msg_begin (&ctx, oi.data, oi.size, R_STUN_CLASS_INDICATION,
              R_STUN_METHOD_DATA, tid);
          r_stun_msg_add_xor_address (&ctx, R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS, peer);
          a.type = R_STUN_ATTR_TYPE_DATA; a.len = (ruint16) isz; a.value = ib;
          r_stun_msg_add_attribute (&ctx, &a);
          osz = r_stun_msg_end (&ctx, TRUE);
          r_buffer_unmap (out, &oi);
          r_buffer_set_size (out, osz);
          r_ev_udp_send (udp, out, addr, NULL, NULL, NULL);
        }
        if (out != NULL)
          r_buffer_unref (out);
      }
    }
    if (peer != NULL)
      r_socket_address_unref (peer);
  }

  r_buffer_unmap (buf, &info);
}

RTEST (rrtcicetransport, turn_channel_data, RTEST_FAST | RTEST_SYSTEM)
{
  /* The relay path promotes the peer to a channel: the agent sends a
   * ChannelBind, and once bound carries checks over ChannelData. Reaching
   * CONNECTED requires decoding an inbound ChannelData reply, and the server
   * observing a ChannelData frame proves the outbound channel path. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * s;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * raw;
  REvUDP * turn;
  RSocketAddress * lo, * turnaddr, * relayed, * peeraddr;
  RRtcIceCandidate * peercand;
  TestSrflxObserver obs = { 0, R_RTC_ICE_CANDIDATE_HOST, NULL };
  TestTurnChannelState st = { NULL, 0, NULL, 0, 0 };
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((s = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (s,
          R_STR_WITH_SIZE_ARGS ("uf"), R_STR_WITH_SIZE_ARGS ("password01234567"))), !=, NULL);
  r_assert_cmpptr ((raw = r_rtc_session_create_raw_transport (s, ice)), !=, NULL);

  r_assert_cmpptr ((relayed = r_socket_address_ipv4_new_from_string ("203.0.113.1", 50000)), !=, NULL);
  st.relayed = relayed;

  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((turn = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_bind (turn, lo, TRUE));
  r_assert (r_ev_udp_recv_start (turn, NULL, test_turn_channel_responder, &st, NULL));
  r_assert_cmpptr ((turnaddr = r_ev_udp_get_local_address (turn)), !=, NULL);

  r_rtc_ice_transport_set_on_local_candidate (ice, test_srflx_on_candidate, &obs);
  r_assert_cmpint (r_rtc_ice_transport_gather_host_candidates (ice,
          test_ice_only_loopback, NULL), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_role (ice, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (ice,
          R_STR_WITH_SIZE_ARGS ("peer"), R_STR_WITH_SIZE_ARGS (TEST_RELAY_REMOTE_PWD)), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (ice, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_gather_relay_candidates (ice, turnaddr,
          "user", "pass"), ==, R_RTC_OK);

  for (i = 0; i < 200 && obs.count == 0; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  r_assert_cmpuint (obs.count, ==, 1);

  r_assert_cmpptr ((peeraddr = r_socket_address_ipv4_new_from_string ("198.51.100.7", 3478)), !=, NULL);
  r_assert_cmpptr ((peercand = test_ice_host_candidate ("2", peeraddr)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (ice, peercand), ==, R_RTC_OK);

  for (i = 0; i < 400 &&
      r_rtc_ice_transport_get_state (ice) != R_RTC_ICE_STATE_CONNECTED; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert_cmpint (r_rtc_ice_transport_get_state (ice), ==, R_RTC_ICE_STATE_CONNECTED);
  r_assert_cmpuint (st.channel_binds, >=, 1);
  r_assert_cmpuint (st.channel_data_rx, >=, 1);

  r_socket_address_unref (obs.addr);
  r_rtc_ice_transport_close (ice);
  r_ev_udp_recv_stop (turn);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  if (st.chanpeer != NULL)
    r_socket_address_unref (st.chanpeer);
  r_rtc_ice_candidate_unref (peercand);
  r_socket_address_unref (peeraddr);
  r_ev_udp_unref (turn);
  r_socket_address_unref (lo);
  r_socket_address_unref (relayed);
  r_socket_address_unref (turnaddr);
  r_rtc_crypto_transport_unref (raw);
  r_rtc_ice_transport_unref (ice);
  r_rtc_session_unref (s);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrtcicetransport, role_conflict, RTEST_FAST | RTEST_SYSTEM)
{
  /* Both agents start controlling; the role conflict (RFC 8445 7.3.1.1)
   * is resolved via the tie-breaker (one switches / is sent a 487) and the
   * pair is still nominated. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * sa, * sb;
  RRtcIceTransport * a, * b;
  RRtcCryptoTransport * ra, * rb;
  RSocketAddress * lo, * addra, * addrb;
  RRtcIceCandidate * ca, * cb;
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((sa = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((sb = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((a = r_rtc_session_create_ice_transport (sa,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567"))), !=, NULL);
  r_assert_cmpptr ((b = r_rtc_session_create_ice_transport (sb,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567"))), !=, NULL);
  r_assert_cmpptr ((ra = r_rtc_session_create_raw_transport (sa, a)), !=, NULL);
  r_assert_cmpptr ((rb = r_rtc_session_create_raw_transport (sb, b)), !=, NULL);

  /* Both sides claim the controlling role. */
  r_assert_cmpint (r_rtc_ice_transport_set_role (a, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_role (b, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (a,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567")), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (b,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567")), ==, R_RTC_OK);

  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_host_candidate ("1", lo)), !=, NULL);
  r_assert_cmpptr ((cb = test_ice_host_candidate ("1", lo)), !=, NULL);
  r_socket_address_unref (lo);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (a, ca), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (b, cb), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);

  r_assert_cmpint (r_rtc_ice_transport_start (a, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (b, loop), ==, R_RTC_OK);

  r_assert_cmpptr ((addra = r_rtc_ice_transport_get_local_address (a)), !=, NULL);
  r_assert_cmpptr ((addrb = r_rtc_ice_transport_get_local_address (b)), !=, NULL);
  r_assert_cmpptr ((cb = test_ice_host_candidate ("1", addrb)), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_host_candidate ("1", addra)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (a, cb), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (b, ca), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);
  r_socket_address_unref (addra);
  r_socket_address_unref (addrb);

  for (i = 0; i < 300; i++) {
    if (r_rtc_ice_transport_get_state (a) == R_RTC_ICE_STATE_CONNECTED &&
        r_rtc_ice_transport_get_state (b) == R_RTC_ICE_STATE_CONNECTED)
      break;
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  }

  r_assert_cmpint (r_rtc_ice_transport_get_state (a), ==, R_RTC_ICE_STATE_CONNECTED);
  r_assert_cmpint (r_rtc_ice_transport_get_state (b), ==, R_RTC_ICE_STATE_CONNECTED);
  /* Exactly one side ended up controlled. */
  r_assert (r_rtc_ice_transport_get_role (a) != r_rtc_ice_transport_get_role (b));

  r_rtc_ice_transport_close (a);
  r_rtc_ice_transport_close (b);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_rtc_crypto_transport_unref (ra);
  r_rtc_crypto_transport_unref (rb);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (sa);
  r_rtc_session_unref (sb);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrtcicetransport, check_scheduler_orders_pairs, RTEST_FAST | RTEST_SYSTEM)
{
  /* Give the controlling side a bogus higher-priority remote alongside the
   * real one. The Ta-paced scheduler tries the higher-priority pair first,
   * but its failure must not stop the working pair from nominating. */
  RPrng * prng;
  REvLoop * loop;
  RRtcSession * sa, * sb;
  RRtcIceTransport * a, * b;
  RRtcCryptoTransport * ra, * rb;
  RSocketAddress * lo, * addra, * addrb, * bogus;
  RRtcIceCandidate * ca, * cb, * hi;
  ruint i;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((sa = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((sb = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((a = r_rtc_session_create_ice_transport (sa,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567"))), !=, NULL);
  r_assert_cmpptr ((b = r_rtc_session_create_ice_transport (sb,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567"))), !=, NULL);
  r_assert_cmpptr ((ra = r_rtc_session_create_raw_transport (sa, a)), !=, NULL);
  r_assert_cmpptr ((rb = r_rtc_session_create_raw_transport (sb, b)), !=, NULL);

  r_assert_cmpint (r_rtc_ice_transport_set_role (a, R_RTC_ICE_ROLE_CONTROLLING), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_role (b, R_RTC_ICE_ROLE_CONTROLLED), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (a,
          R_STR_WITH_SIZE_ARGS ("bufrag"), R_STR_WITH_SIZE_ARGS ("bpassword01234567")), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_set_remote_credentials (b,
          R_STR_WITH_SIZE_ARGS ("aufrag"), R_STR_WITH_SIZE_ARGS ("apassword01234567")), ==, R_RTC_OK);

  r_assert_cmpptr ((lo = r_socket_address_ipv4_new_from_string ("127.0.0.1", 0)), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_host_candidate ("1", lo)), !=, NULL);
  r_assert_cmpptr ((cb = test_ice_host_candidate ("1", lo)), !=, NULL);
  r_socket_address_unref (lo);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (a, ca), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_local_host_candidate (b, cb), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);

  r_assert_cmpint (r_rtc_ice_transport_start (a, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_start (b, loop), ==, R_RTC_OK);

  r_assert_cmpptr ((addra = r_rtc_ice_transport_get_local_address (a)), !=, NULL);
  r_assert_cmpptr ((addrb = r_rtc_ice_transport_get_local_address (b)), !=, NULL);

  /* A bogus, unreachable remote with a higher priority than the real one. */
  r_assert_cmpptr ((bogus = r_socket_address_ipv4_new_from_string ("127.0.0.1", 1)), !=, NULL);
  r_assert_cmpptr ((hi = r_rtc_ice_candidate_new_full ("9", -1, TEST_ICE_HOST_PRI + 1000,
          R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, bogus, R_RTC_ICE_CANDIDATE_HOST)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (a, hi), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (hi);

  r_assert_cmpptr ((cb = test_ice_host_candidate ("1", addrb)), !=, NULL);
  r_assert_cmpptr ((ca = test_ice_host_candidate ("1", addra)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (a, cb), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_ice_transport_add_remote_candidate (b, ca), ==, R_RTC_OK);
  r_rtc_ice_candidate_unref (ca);
  r_rtc_ice_candidate_unref (cb);
  r_socket_address_unref (addra);
  r_socket_address_unref (addrb);
  r_socket_address_unref (bogus);

  for (i = 0; i < 400; i++) {
    if (r_rtc_ice_transport_get_state (a) == R_RTC_ICE_STATE_CONNECTED &&
        r_rtc_ice_transport_get_state (b) == R_RTC_ICE_STATE_CONNECTED)
      break;
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  }

  r_assert_cmpint (r_rtc_ice_transport_get_state (a), ==, R_RTC_ICE_STATE_CONNECTED);
  r_assert_cmpint (r_rtc_ice_transport_get_state (b), ==, R_RTC_ICE_STATE_CONNECTED);

  r_rtc_ice_transport_close (a);
  r_rtc_ice_transport_close (b);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_rtc_crypto_transport_unref (ra);
  r_rtc_crypto_transport_unref (rb);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (sa);
  r_rtc_session_unref (sb);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
}
RTEST_END;
