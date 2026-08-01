#include <rlib/rlib.h>

RTEST (rnetif, query_interfaces, RTEST_FAST | RTEST_SYSTEM)
{
  RPtrArray * ifaces;
  rsize i, c;
  rboolean found_loopback = FALSE;
  const RNetInterface * lo = NULL;

  r_assert_cmpptr ((ifaces = r_net_query_interfaces ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (ifaces), >, 0);

  for (i = 0, c = r_ptr_array_size (ifaces); i < c; i++) {
    RNetInterface * iface = r_ptr_array_get (ifaces, i);
    rsize j, n;

    r_assert_cmpptr (iface->name, !=, NULL);
    r_assert_cmpptr (iface->addrs, !=, NULL);

    /* Every reported address is a well-formed IPv4 / IPv6 address, and its
     * prefix length fits the family. */
    for (j = 0, n = r_ptr_array_size (iface->addrs); j < n; j++) {
      RNetInterfaceAddr * ia = r_ptr_array_get (iface->addrs, j);
      RSocketFamily family;

      r_assert_cmpptr (ia->addr, !=, NULL);
      family = r_socket_address_get_family (ia->addr);
      r_assert (family == R_SOCKET_FAMILY_IPV4 || family == R_SOCKET_FAMILY_IPV6);
      r_assert_cmpuint (ia->prefixlen, <=, family == R_SOCKET_FAMILY_IPV4 ? 32 : 128);
    }

    /* find-by-name / find-by-index resolve back to this same entry. */
    r_assert_cmpptr (r_net_interfaces_find_by_name (ifaces, iface->name), ==, iface);

    if (iface->flags & R_NET_IFACE_LOOPBACK) {
      found_loopback = TRUE;
      lo = iface;
    }
  }

  /* The loopback interface exists, is up and carries at least one address. */
  r_assert (found_loopback);
  r_assert_cmpptr (lo, !=, NULL);
  r_assert_cmpint (lo->type, ==, R_NET_IFACE_TYPE_LOOPBACK);
  r_assert (lo->flags & R_NET_IFACE_UP);
  r_assert_cmpuint (r_ptr_array_size (lo->addrs), >, 0);
  if (lo->index != 0)
    r_assert_cmpptr (r_net_interfaces_find_by_index (ifaces, lo->index), ==, lo);

  r_assert_cmpptr (r_net_interfaces_find_by_name (ifaces, "definitely-not-an-iface"), ==, NULL);

  r_ptr_array_unref (ifaces);
}
RTEST_END;

RTEST (rnetif, hwaddr_to_str, RTEST_FAST)
{
  RNetInterface iface = { NULL, 0, 0, R_NET_IFACE_TYPE_UNKNOWN, 0, {0}, 0, NULL };
  rchar * str;

  /* No hardware address -> NULL. */
  r_assert_cmpptr (r_net_interface_hwaddr_to_str (&iface), ==, NULL);

  iface.hwaddr[0] = 0x00; iface.hwaddr[1] = 0x1b; iface.hwaddr[2] = 0x2c;
  iface.hwaddr[3] = 0x3d; iface.hwaddr[4] = 0x4e; iface.hwaddr[5] = 0x5f;
  iface.hwaddrlen = 6;
  r_assert_cmpptr ((str = r_net_interface_hwaddr_to_str (&iface)), !=, NULL);
  r_assert_cmpstr (str, ==, "00:1b:2c:3d:4e:5f");
  r_free (str);
}
RTEST_END;
