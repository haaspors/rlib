#include <rlib/rev.h>

RTEST (rresolve, sync_error_translation, RTEST_FAST | RTEST_SYSTEM)
{
  /* getaddrinfo's EAI_BADFLAGS / EAI_NONAME error codes were collapsed
   * into the generic R_RESOLVE_ERROR; verify the specific results now
   * land in the right enum slots. */
  RResolveResult res;

  /* Bogus flag bit -> R_RESOLVE_BAD_FLAGS. */
  r_assert_cmpptr (r_resolve_sync ("127.0.0.1", NULL,
        (RResolveAddrFlags) 0x40000000, NULL, &res), ==, NULL);
  r_assert_cmpint (res, ==, R_RESOLVE_BAD_FLAGS);

  /* A name that should never resolve to anything via DNS / NSS;
   * NUMERICHOST forces resolution to treat the literal as already-numeric,
   * so a non-IP literal short-circuits with EAI_NONAME. */
  r_assert_cmpptr (r_resolve_sync ("not-a-numeric-host", NULL,
        R_RESOLVE_ADDR_FLAG_NUMERICHOST, NULL, &res), ==, NULL);
  r_assert_cmpint (res, ==, R_RESOLVE_NO_DATA);
}
RTEST_END;

RTEST (rresolve, sync_addr_host, RTEST_FAST | RTEST_SYSTEM)
{
  RResolveResult res;
  RResolvedAddr * addr, * it;

  r_assert_cmpptr ((addr = r_resolve_sync ("127.0.0.1", NULL,
          R_RESOLVE_ADDR_FLAG_PASSIVE, NULL, &res)), !=, NULL);
  r_assert_cmpint (res, ==, R_RESOLVE_OK);

  for (it = addr; it != NULL; it = it->next) {
    r_assert_cmpptr (r_socket_address_get_family (addr->addr), ==, addr->hints.family);
    switch (addr->hints.family) {
      case R_SOCKET_FAMILY_IPV4:
        r_assert_cmpuint (r_socket_address_ipv4_get_port (addr->addr), ==, 0);
        r_assert_cmpuint (r_socket_address_ipv4_get_ip (addr->addr), ==, R_SOCKET_ADDRESS_IPV4_LOOPBACK);
        break;
      case R_SOCKET_FAMILY_IPV6: {
        static const ruint8 ip6_loopback[16] = {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        };
        ruint8 ip[16];
        r_assert_cmpuint (r_socket_address_ipv6_get_port (addr->addr), ==, 0);
        r_assert (r_socket_address_ipv6_get_ip_bytes (addr->addr, ip));
        r_assert_cmpmem (ip, ==, ip6_loopback, 16);
        break;
      }
      default:
        r_assert_not_reached ();
    }
  }

  r_resolved_addr_free (addr);
}
RTEST_END;

static void
resolved_addr_cb (rpointer data, RResolvedAddr * addr, RResolveResult res)
{
  (void) res;
  *((const RResolvedAddr **)data) = addr;
}

RTEST (revresolve, addr_host, RTEST_FAST | RTEST_SYSTEM)
{
  RClock * clock;
  REvLoop * loop;
  REvResolve * resolve;
  const RResolvedAddr * addr = NULL, * it;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr (addr, ==, NULL);
  r_assert_cmpptr ((resolve = r_ev_resolve_addr_new ("127.0.0.1", NULL,
          R_RESOLVE_ADDR_FLAG_PASSIVE, NULL,
          loop, resolved_addr_cb, &addr, NULL)), !=, NULL);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpptr (addr, !=, NULL);

  for (it = addr; it != NULL; it = it->next) {
    r_assert_cmpptr (r_socket_address_get_family (addr->addr), ==, addr->hints.family);
    switch (addr->hints.family) {
      case R_SOCKET_FAMILY_IPV4:
        r_assert_cmpuint (r_socket_address_ipv4_get_port (addr->addr), ==, 0);
        r_assert_cmpuint (r_socket_address_ipv4_get_ip (addr->addr), ==, R_SOCKET_ADDRESS_IPV4_LOOPBACK);
        break;
      case R_SOCKET_FAMILY_IPV6: {
        static const ruint8 ip6_loopback[16] = {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        };
        ruint8 ip[16];
        r_assert_cmpuint (r_socket_address_ipv6_get_port (addr->addr), ==, 0);
        r_assert (r_socket_address_ipv6_get_ip_bytes (addr->addr, ip));
        r_assert_cmpmem (ip, ==, ip6_loopback, 16);
        break;
      }
      default:
        r_assert_not_reached ();
    }
  }

  r_ev_resolve_unref (resolve);
  r_ev_loop_unref (loop);
}
RTEST_END;

SKIP_RTEST (revresolve, live_addr, RTEST_FAST | RTEST_SYSTEM)
{
  RClock * clock;
  REvLoop * loop;
  REvResolve * resolve;
  const RResolvedAddr * addr = NULL;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr (addr, ==, NULL);
  r_assert_cmpptr ((resolve = r_ev_resolve_addr_new ("google.com", "http",
          R_RESOLVE_ADDR_FLAG_PASSIVE, NULL,
          loop, resolved_addr_cb, &addr, NULL)), !=, NULL);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpptr (addr, !=, NULL);

  r_ev_resolve_unref (resolve);
  r_ev_loop_unref (loop);
}
RTEST_END;

