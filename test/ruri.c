#include <rlib/rlib.h>

RTEST (ruri, new_escaped, RTEST_FAST)
{
  RUri * uri;
  rchar * tmp;

  r_assert_cmpptr ((uri = r_uri_new_escaped (NULL, -1)), ==, NULL);
  r_assert_cmpptr ((uri = r_uri_new_escaped ("", -1)), ==, NULL);

  r_assert_cmpptr ((uri = r_uri_new_escaped ("http://ieei@github.com/ieei/rlib", -1)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "http"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, "ieei"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, "github.com"); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_authority (uri)), ==, "ieei@github.com"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "/ieei/rlib"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);

  /* from rfc3986 */
  r_assert_cmpptr ((uri = r_uri_new_escaped ("ftp://ftp.is.co.za/rfc/rfc1808.txt", -1)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "ftp"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, "ftp.is.co.za"); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "/rfc/rfc1808.txt"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);

  r_assert_cmpptr ((uri = r_uri_new_escaped ("http://www.ietf.org/rfc/rfc2396.txt", -1)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "http"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, "www.ietf.org"); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "/rfc/rfc2396.txt"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);

  r_assert_cmpptr ((uri = r_uri_new_escaped ("ldap://[2001:db8::7]/c=GB?objectClass?one", -1)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "ldap"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, "2001:db8::7"); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "/c=GB"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, "objectClass?one"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_pqf (uri)), ==, "/c=GB?objectClass?one"); r_free (tmp);
  r_uri_unref (uri);

  r_assert_cmpptr ((uri = r_uri_new_escaped ("mailto:John.Doe@example.com", -1)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "mailto"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, ""); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "John.Doe@example.com"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);

  r_assert_cmpptr ((uri = r_uri_new_escaped ("news:comp.infosystems.www.servers.unix", -1)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "news"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, ""); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "comp.infosystems.www.servers.unix"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);

  r_assert_cmpptr ((uri = r_uri_new_escaped ("tel:+1-816-555-1212", -1)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "tel"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, ""); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "+1-816-555-1212"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);

  r_assert_cmpptr ((uri = r_uri_new_escaped ("urn:oasis:names:specification:docbook:dtd:xml:4.1.2", -1)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "urn"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, ""); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "oasis:names:specification:docbook:dtd:xml:4.1.2"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);
}
RTEST_END;

RTEST (ruri, new_http, RTEST_FAST)
{
  RUri * uri;
  rchar * tmp;

  r_assert_cmpptr ((uri = r_uri_new_http (NULL, NULL)), ==, NULL);
  r_assert_cmpptr ((uri = r_uri_new_http ("", "")), ==, NULL);

  r_assert_cmpptr ((uri = r_uri_new_http ("example.org", "/foo/bar?test")), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "http"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, "example.org"); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "/foo/bar"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, "test"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);

  r_assert_cmpptr ((uri = r_uri_new_http (NULL, "http://example.org/foo/bar?test")), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_scheme (uri)), ==, "http"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_userinfo (uri)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_hostname (uri)), ==, "example.org"); r_free (tmp);
  r_assert_cmpuint (r_uri_get_port (uri), ==, 0);
  r_assert_cmpstr ((tmp = r_uri_get_path (uri)), ==, "/foo/bar"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_query (uri)), ==, "test"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_uri_get_fragment (uri)), ==, ""); r_free (tmp);
  r_uri_unref (uri);

}
RTEST_END;

