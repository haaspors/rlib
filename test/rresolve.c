#include <rlib/rev.h>

#ifdef R_OS_WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

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
        r_assert_cmpuint (r_socket_address_ipv4_get_ip (addr->addr), ==, INADDR_LOOPBACK);
        break;
      case R_SOCKET_FAMILY_IPV6:
#if 0
        r_assert_cmpuint (r_socket_address_ipv6_get_port (addr->addr), ==, 0);
        r_assert_cmpuint (r_socket_address_ipv6_get_ip (addr->addr), ==, IN6ADDR_LOOPBACK);
#endif
        break;
      default:
        r_assert_not_reached ();
    }
  }

  r_resolved_addr_free (addr);
}
RTEST_END;

#if !defined (R_OS_WIN32)
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
        r_assert_cmpuint (r_socket_address_ipv4_get_ip (addr->addr), ==, INADDR_LOOPBACK);
        break;
      case R_SOCKET_FAMILY_IPV6:
#if 0
        r_assert_cmpuint (r_socket_address_ipv6_get_port (addr->addr), ==, 0);
        r_assert_cmpuint (r_socket_address_ipv6_get_ip (addr->addr), ==, IN6ADDR_LOOPBACK);
#endif
        break;
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
#endif

