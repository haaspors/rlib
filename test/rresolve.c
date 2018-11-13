#include <rlib/rev.h>

RTEST (rresolve, sync_addr_loopback, RTEST_FAST | RTEST_SYSTEM)
{
  RResolveResult res;
  RResolvedAddr * addr, * tmp;

  r_assert_cmpptr ((addr = r_resolve_sync ("127.0.0.1", NULL,
          R_RESOLVE_ADDR_FLAG_PASSIVE, NULL, &res)), !=, NULL);
  r_assert_cmpint (res, ==, R_RESOLVE_OK);

  do {
    RSocketAddress * saddr;
    r_assert_cmpptr ((saddr = r_resolved_addr_get_socket_addr (addr)), !=, NULL);
    r_assert_cmpuint (r_resolved_addr_get_family (addr), ==, r_socket_address_get_family (saddr));

    switch (r_resolved_addr_get_family (addr)) {
      case R_SOCKET_FAMILY_IPV4:
        r_assert_cmpuint (r_socket_address_ipv4_get_port (saddr), ==, 0);
        r_assert_cmpuint (r_socket_address_ipv4_get_ip (saddr), ==, R_SOCKET_ADDRESS_IPV4_LOOPBACK);
        break;
      case R_SOCKET_FAMILY_IPV6:
#if 0
        r_assert_cmpuint (r_socket_address_ipv6_get_port (saddr), ==, 0);
        r_assert_cmpuint (r_socket_address_ipv6_get_ip (saddr), ==, R_SOCKET_ADDRESS_IPV6_LOOPBACK);
#endif
        break;
      default:
        r_assert_not_reached ();
    }
    r_socket_address_unref (saddr);

    addr = r_resolved_addr_get_next ((tmp = addr));
    r_resolved_addr_unref (tmp);
  } while (addr != NULL);
}
RTEST_END;

static void
resolved_addr_cb (rpointer data, RResolvedAddr * addr, RResolveResult res)
{
  RResolvedAddr ** paddr = data;

  (void) res;

  if (*paddr)
    r_resolved_addr_unref (*paddr);
  *paddr = r_resolved_addr_ref (addr);
}

RTEST (revresolve, addr_host, RTEST_FAST | RTEST_SYSTEM)
{
  RClock * clock;
  REvLoop * loop;
  REvResolve * resolve;
  RResolvedAddr * addr = NULL, * tmp;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((resolve = r_ev_resolve_addr_new ("127.0.0.1", NULL,
          R_RESOLVE_ADDR_FLAG_PASSIVE, NULL,
          loop, resolved_addr_cb, &addr, NULL)), !=, NULL);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpptr (addr, !=, NULL);

  do {
    RSocketAddress * saddr;
    r_assert_cmpptr ((saddr = r_resolved_addr_get_socket_addr (addr)), !=, NULL);
    r_assert_cmpuint (r_resolved_addr_get_family (addr), ==, r_socket_address_get_family (saddr));
    switch (r_resolved_addr_get_family (addr)) {
      case R_SOCKET_FAMILY_IPV4:
        r_assert_cmpuint (r_socket_address_ipv4_get_port (saddr), ==, 0);
        r_assert_cmpuint (r_socket_address_ipv4_get_ip (saddr), ==, R_SOCKET_ADDRESS_IPV4_LOOPBACK);
        break;
      case R_SOCKET_FAMILY_IPV6:
#if 0
        r_assert_cmpuint (r_socket_address_ipv6_get_port (saddr), ==, 0);
        r_assert_cmpuint (r_socket_address_ipv6_get_ip (saddr), ==, R_SOCKET_ADDRESS_IPV6_LOOPBACK);
#endif
        break;
      default:
        r_assert_not_reached ();
    }
    r_socket_address_unref (saddr);

    addr = r_resolved_addr_get_next ((tmp = addr));
    r_resolved_addr_unref (tmp);
  } while (addr != NULL);

  r_ev_resolve_unref (resolve);
  r_ev_loop_unref (loop);
}
RTEST_END;

SKIP_RTEST (revresolve, live_addr, RTEST_FAST | RTEST_SYSTEM)
{
  RClock * clock;
  REvLoop * loop;
  REvResolve * resolve;
  RResolvedAddr * addr = NULL;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr (addr, ==, NULL);
  r_assert_cmpptr ((resolve = r_ev_resolve_addr_new ("google.com", "http",
          R_RESOLVE_ADDR_FLAG_PASSIVE, NULL,
          loop, resolved_addr_cb, &addr, NULL)), !=, NULL);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpptr (addr, !=, NULL);

  r_resolved_addr_unref (addr);
  r_ev_resolve_unref (resolve);
  r_ev_loop_unref (loop);
}
RTEST_END;
