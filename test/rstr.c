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

RTEST (rstr, strv, RTEST_FAST)
{
  rchar ** strv;

  r_assert_cmpptr (r_strv_new (NULL), ==, NULL);
  r_assert_cmpptr ((strv = r_strv_new ("foobar", NULL)), !=, NULL);
  r_assert_cmpuint (r_strv_len (strv), ==, 1);
  r_assert_cmpstr (strv[0], ==, "foobar");
  r_assert_cmpptr (strv[1], ==, NULL);
  r_strv_free (strv);
}
RTEST_END;

RTEST (rstr, strv_join, RTEST_FAST)
{
  rchar ** strv;
  rchar * join;

  r_assert_cmpptr ((strv = r_strv_new ("foobar", NULL)), !=, NULL);
  r_assert_cmpstr ((join = r_strv_join (strv, "")), ==, "foobar"); r_free (join);
  r_strv_free (strv);
  r_assert_cmpptr ((strv = r_strv_new ("foo", "bar", NULL)), !=, NULL);
  r_assert_cmpstr ((join = r_strv_join (strv, "")), ==, "foobar"); r_free (join);
  r_assert_cmpstr ((join = r_strv_join (strv, "-")), ==, "foo-bar"); r_free (join);
  r_strv_free (strv);
}
RTEST_END;

RTEST (rstr, strv_contains, RTEST_FAST)
{
  rchar ** strv;

  r_assert_cmpptr ((strv = r_strv_new ("foo", "bar", NULL)), !=, NULL);
  r_assert ( r_strv_contains (strv, "foo"));
  r_assert (!r_strv_contains (strv, "foobar"));
  r_assert ( r_strv_contains (strv, "bar"));
  r_strv_free (strv);
}
RTEST_END;

