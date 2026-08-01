#include <rlib/rrtc.h>
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
#endif /* not Windows rpoll */
