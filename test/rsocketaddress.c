#include <rlib/rlib.h>

#ifdef R_OS_WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

RTEST (rsocketaddress, ipv4_native, RTEST_FAST)
{
  struct sockaddr_in ipv4;
  RSocketAddress * addr;

  r_memset (&ipv4, 0, sizeof (ipv4));
  ipv4.sin_family = R_AF_INET;
  ipv4.sin_port = r_htons (42);
  ipv4.sin_addr.s_addr = R_SOCKET_ADDRESS_IPV4_LOOPBACK;

  r_assert_cmpptr (r_socket_address_new_from_native (NULL, 0), ==, NULL);
  r_assert_cmpptr (r_socket_address_new_from_native (&ipv4, 0), ==, NULL);
  r_assert_cmpptr ((addr = r_socket_address_new_from_native (&ipv4, sizeof (ipv4))), !=, NULL);

  r_assert_cmpptr (r_socket_address_get_family (addr), ==, R_SOCKET_FAMILY_IPV4);

  r_socket_address_unref (addr);
}
RTEST_END;

RTEST (rsocketaddress, ipv4_new, RTEST_FAST)
{
  RSocketAddress * addr_u32, * addr_u8, * addr_str;

  r_assert_cmpptr ((addr_u32 = r_socket_address_ipv4_new_uint32 (R_SOCKET_ADDRESS_IPV4_LOOPBACK, 42)), !=, NULL);
  r_assert_cmpptr (r_socket_address_get_family (addr_u32), ==, R_SOCKET_FAMILY_IPV4);
  r_assert_cmpuint (r_socket_address_ipv4_get_port (addr_u32), ==, 42);
  r_assert_cmpuint (r_socket_address_ipv4_get_ip (addr_u32), ==, R_SOCKET_ADDRESS_IPV4_LOOPBACK);

  r_assert_cmpptr ((addr_u8 = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 42)), !=, NULL);
  r_assert_cmpptr (r_socket_address_get_family (addr_u8), ==, R_SOCKET_FAMILY_IPV4);
  r_assert_cmpuint (r_socket_address_ipv4_get_port (addr_u8), ==, 42);
  r_assert_cmpuint (r_socket_address_ipv4_get_ip (addr_u8), ==, R_SOCKET_ADDRESS_IPV4_LOOPBACK);

  r_assert_cmpptr (r_socket_address_ipv4_new_from_string (NULL, 42), ==, NULL);
  r_assert_cmpptr (r_socket_address_ipv4_new_from_string ("foobar", 42), ==, NULL);
  r_assert_cmpptr ((addr_str = r_socket_address_ipv4_new_from_string ("127.0.0.1", 42)), !=, NULL);
  r_assert_cmpptr (r_socket_address_get_family (addr_str), ==, R_SOCKET_FAMILY_IPV4);
  r_assert_cmpuint (r_socket_address_ipv4_get_port (addr_str), ==, 42);
  r_assert_cmpuint (r_socket_address_ipv4_get_ip (addr_str), ==, R_SOCKET_ADDRESS_IPV4_LOOPBACK);

  r_assert_cmpint (r_socket_address_cmp (addr_u32, addr_u8), ==, 0);
  r_assert_cmpint (r_socket_address_cmp (addr_str, addr_u8), ==, 0);

  r_socket_address_unref (addr_str);
  r_socket_address_unref (addr_u32);
  r_socket_address_unref (addr_u8);
}
RTEST_END;

RTEST (rsocketaddress, ipv4_to_str, RTEST_FAST)
{
  RSocketAddress * addr_u32, * addr_str;
  rchar str[22], * dupstr;

  r_assert_cmpptr ((addr_u32 = r_socket_address_ipv4_new_uint32 (R_SOCKET_ADDRESS_IPV4_LOOPBACK, 42)), !=, NULL);
  r_assert_cmpptr ((addr_str = r_socket_address_ipv4_new_from_string ("192.168.100.200", RUINT16_MAX-1)), !=, NULL);

  r_assert (!r_socket_address_ipv4_build_str (NULL, TRUE, str, sizeof (str)));
  r_assert (!r_socket_address_ipv4_build_str (addr_u32, TRUE, NULL, 0));
  r_assert (!r_socket_address_ipv4_build_str (addr_u32, TRUE, str, 0));
  r_assert (!r_socket_address_ipv4_build_str (addr_u32, TRUE, str, 12));

  r_assert (r_socket_address_ipv4_build_str (addr_u32, TRUE, str, sizeof (str)));
  r_assert_cmpstr (str, ==, "127.0.0.1:42");
  r_assert_cmpptr ((dupstr = r_socket_address_ipv4_to_str (addr_str, TRUE)), !=, NULL);
  r_assert_cmpstr (dupstr, ==, "192.168.100.200:65534");
  r_free (dupstr);

  r_assert (r_socket_address_ipv4_build_str (addr_u32, FALSE, str, 12));
  r_assert_cmpstr (str, ==, "127.0.0.1");
  r_assert_cmpptr ((dupstr = r_socket_address_ipv4_to_str (addr_str, FALSE)), !=, NULL);
  r_assert_cmpstr (dupstr, ==, "192.168.100.200");
  r_free (dupstr);

  r_socket_address_unref (addr_str);
  r_socket_address_unref (addr_u32);
}
RTEST_END;

RTEST (rsocketaddress, copy, RTEST_FAST)
{
  RSocketAddress * addr, * copy;

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint32 (R_SOCKET_ADDRESS_IPV4_LOOPBACK, 42)), !=, NULL);
  r_assert_cmpptr ((copy = r_socket_address_copy (addr)), !=, NULL);
  r_socket_address_unref (addr);

  r_assert_cmpptr (r_socket_address_get_family (copy), ==, R_SOCKET_FAMILY_IPV4);
  r_assert_cmpuint (r_socket_address_ipv4_get_port (copy), ==, 42);
  r_assert_cmpuint (r_socket_address_ipv4_get_ip (copy), ==, R_SOCKET_ADDRESS_IPV4_LOOPBACK);
  r_socket_address_unref (copy);
}
RTEST_END;

RTEST (rsocketaddress, to_str, RTEST_FAST)
{
  RSocketAddress * addr;
  rchar * tmp;

  /* ipv4 */
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint32 (R_SOCKET_ADDRESS_IPV4_LOOPBACK, 42)), !=, NULL);
  r_assert_cmpstr ((tmp = r_socket_address_to_str (addr)), ==, "127.0.0.1:42"); r_free (tmp);
  r_socket_address_unref (addr);

  /* ipv6 */
  /* FIXME */
}
RTEST_END;


