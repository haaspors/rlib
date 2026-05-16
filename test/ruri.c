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


RTEST (ruri, escape_unescape, RTEST_FAST)
{
  /* r_uri_escape_str / r_uri_unescape_str used to be stub no-ops that
   * just duped the input.  Verify they now percent-encode/decode per
   * RFC 3986. */
  rchar * out;
  rsize sz;

  /* Unreserved chars are preserved as-is. */
  r_assert_cmpptr ((out = r_uri_escape_str ("abc-._~XYZ09", -1, &sz)),
      !=, NULL);
  r_assert_cmpstr (out, ==, "abc-._~XYZ09");
  r_assert_cmpuint (sz, ==, 12);
  r_free (out);

  /* Reserved gen-delims/sub-delims survive (so URI structure stays
   * intact when the whole URI is fed through escape_str). */
  r_assert_cmpptr ((out = r_uri_escape_str ("http://a:b@c/d?e#f", -1, &sz)),
      !=, NULL);
  r_assert_cmpstr (out, ==, "http://a:b@c/d?e#f");
  r_free (out);

  /* Space and quote get percent-encoded. */
  r_assert_cmpptr ((out = r_uri_escape_str ("foo bar\"baz", -1, &sz)),
      !=, NULL);
  r_assert_cmpstr (out, ==, "foo%20bar%22baz");
  r_free (out);

  /* Non-ASCII byte (e.g. UTF-8 'ø' = 0xC3 0xB8). */
  r_assert_cmpptr ((out = r_uri_escape_str ("\xC3\xB8", -1, &sz)),
      !=, NULL);
  r_assert_cmpstr (out, ==, "%C3%B8");
  r_free (out);

  /* Already-encoded triplets pass through unchanged. */
  r_assert_cmpptr ((out = r_uri_escape_str ("a%20b", -1, &sz)),
      !=, NULL);
  r_assert_cmpstr (out, ==, "a%20b");
  r_free (out);

  /* unescape: decode triplets back. */
  r_assert_cmpptr ((out = r_uri_unescape_str ("foo%20bar", -1, &sz)),
      !=, NULL);
  r_assert_cmpstr (out, ==, "foo bar");
  r_assert_cmpuint (sz, ==, 7);
  r_free (out);

  /* Stray %-not-followed-by-hex stays literal. */
  r_assert_cmpptr ((out = r_uri_unescape_str ("100%done", -1, &sz)),
      !=, NULL);
  r_assert_cmpstr (out, ==, "100%done");
  r_free (out);

  /* Round-trip a string with reserved and unsafe chars. */
  r_assert_cmpptr ((out = r_uri_escape_str ("hello world!", -1, &sz)),
      !=, NULL);
  {
    rchar * back = r_uri_unescape_str (out, (rssize) sz, NULL);
    r_assert_cmpstr (back, ==, "hello world!");
    r_free (back);
  }
  r_free (out);
}
RTEST_END;
