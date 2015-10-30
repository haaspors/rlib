#include <rlib/rlib.h>

RTEST (rstr, prefix_suffix, RTEST_FAST)
{
  r_assert ( r_str_has_prefix ("foobar", "foo"));
  r_assert (!r_str_has_prefix ("foobar", "bar"));
  r_assert (!r_str_has_prefix ("foobar", NULL));
  r_assert (!r_str_has_prefix (NULL, "bar"));
  r_assert (!r_str_has_prefix ("foo", "foobar"));

  r_assert (!r_str_has_suffix ("foobar", "foo"));
  r_assert ( r_str_has_suffix ("foobar", "bar"));
  r_assert (!r_str_has_suffix ("foobar", NULL));
  r_assert (!r_str_has_suffix (NULL, "bar"));
  r_assert (!r_str_has_suffix ("foo", "foobar"));
}
RTEST_END;
