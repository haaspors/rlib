#include <rlib/rlib.h>

static const rchar foobar[] = "foobar";
static const rchar foo[] = "foo";
static const rchar bar[] = "bar";
static const rchar foobar_padding[] = "\t\n \rfoobar\r \t\n";

RTEST (rstr, cmp, RTEST_FAST)
{
  r_assert_cmpint (r_strcmp (foobar, foobar), ==, 0);
  r_assert_cmpint (r_strcmp (foobar, bar), >, 0);
  r_assert_cmpint (r_strcmp (bar, foobar), <, 0);
  r_assert_cmpint (r_strcmp (foobar, foo), >, 0);
  r_assert_cmpint (r_strcmp (NULL, foobar), <, 0);
  r_assert_cmpint (r_strcmp (foobar, NULL), >, 0);
  r_assert_cmpint (r_strcmp (NULL, NULL), ==, 0);

  r_assert ( r_str_equals (foobar, foobar));
  r_assert (!r_str_equals (foobar, foo));

  r_assert_cmpint (r_strncmp (foobar, foobar, 6), ==, 0);
  r_assert_cmpint (r_strncmp (foobar, foobar, 9), ==, 0);
  r_assert_cmpint (r_strncmp (foobar, foo, 3), ==, 0);
  r_assert_cmpint (r_strncmp (foobar, foo, 6), >, 0);
  r_assert_cmpint (r_strncmp (NULL, foobar, 6), <, 0);
  r_assert_cmpint (r_strncmp (foobar, NULL, 6), >, 0);
  r_assert_cmpint (r_strncmp (NULL, NULL, 0), ==, 0);
}
RTEST_END;

RTEST (rstr, prefix_suffix, RTEST_FAST)
{
  r_assert ( r_str_has_prefix (foobar, foo));
  r_assert (!r_str_has_prefix (foobar, bar));
  r_assert (!r_str_has_prefix (foobar, NULL));
  r_assert (!r_str_has_prefix (NULL, bar));
  r_assert (!r_str_has_prefix (foo, foobar));

  r_assert (!r_str_has_suffix (foobar, foo));
  r_assert ( r_str_has_suffix (foobar, bar));
  r_assert (!r_str_has_suffix (foobar, NULL));
  r_assert (!r_str_has_suffix (NULL, bar));
  r_assert (!r_str_has_suffix (foo, foobar));
}
RTEST_END;

RTEST (rstr, cpy, RTEST_FAST)
{
  rchar dst[100];

  /* strcpy */
  r_assert_cmpptr (r_strcpy (&dst[50], foobar), ==, &dst[50]);
  r_assert_cmpstr (&dst[50], ==, foobar);
  r_assert_cmpptr (r_strcpy (dst, &dst[50]), ==, dst);
  r_assert_cmpstr (dst, ==, foobar);
  r_assert_cmpptr (r_strcpy (NULL, foobar), ==, NULL);
  r_assert_cmpptr (r_strcpy (dst, NULL), ==, dst);

  /* strncpy */
  memset (dst, 0, sizeof (dst));
  r_assert_cmpptr (r_strncpy (dst, foo, 6), ==, dst);
  r_assert_cmpstr (dst, ==, foo);
  r_assert_cmpptr (r_strncpy (dst, foobar, 6), ==, dst);
  r_assert_cmpstr (dst, ==, foobar);
  r_assert_cmpptr (r_strncpy (dst, bar, 3), ==, dst);
  r_assert_cmpstr (dst, ==, "barbar");
  r_assert_cmpptr (r_strncpy (dst, foo, 6), ==, dst);
  r_assert_cmpmem (dst, ==, "foo\0\0\0", 6);
  r_assert_cmpptr (r_strncpy (NULL, foobar, 6), ==, NULL);
  r_assert_cmpptr (r_strncpy (dst, NULL, 0), ==, dst);
  r_assert_cmpptr (r_strncpy (dst, NULL, 6), ==, dst);
  r_assert_cmpmem (dst, ==, "\0\0\0\0\0\0", 6);

  /* stpcpy */
  memset (dst, 0, sizeof (dst));
  r_assert_cmpptr (r_stpcpy (&dst[50], foobar), ==, &dst[50] + 6);
  r_assert_cmpstr (&dst[50], ==, foobar);
  r_assert_cmpptr (r_stpcpy (dst, &dst[50]), ==, dst + 6);
  r_assert_cmpstr (dst, ==, foobar);
  r_assert_cmpptr (r_stpcpy (NULL, foobar), ==, NULL);
  r_assert_cmpptr (r_stpcpy (dst, NULL), ==, dst);

  /* stpncpy */
  memset (dst, 0, sizeof (dst));
  r_assert_cmpptr (r_stpncpy (dst, foo, 6), ==, dst + 3);
  r_assert_cmpstr (dst, ==, foo);
  r_assert_cmpptr (r_stpncpy (dst, foobar, 6), ==, dst + 6);
  r_assert_cmpstr (dst, ==, foobar);
  r_assert_cmpptr (r_stpncpy (dst, bar, 3), ==, dst + 3);
  r_assert_cmpstr (dst, ==, "barbar");
  r_assert_cmpptr (r_stpncpy (dst, foo, 6), ==, dst + 3);
  r_assert_cmpmem (dst, ==, "foo\0\0\0", 6);
  r_assert_cmpptr (r_stpncpy (NULL, foobar, 6), ==, NULL);
  r_assert_cmpptr (r_stpncpy (dst, NULL, 0), ==, dst);
  r_assert_cmpptr (r_stpncpy (dst, NULL, 6), ==, dst);
  r_assert_cmpmem (dst, ==, "\0\0\0\0\0\0", 6);
}
RTEST_END;

RTEST (rstr, dup, RTEST_FAST)
{
  rchar * tmp;

  /* strdup */
  r_assert_cmpptr (r_strdup (NULL), ==, NULL);
  r_assert_cmpptr ((tmp = r_strdup (foobar)), !=, NULL);
  r_assert_cmpptr (tmp, !=, foobar);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);

  /* strndup */
  r_assert_cmpptr (r_strndup (NULL, 0), ==, NULL);
  r_assert_cmpptr (r_strndup (NULL, 6), ==, NULL);
  r_assert_cmpptr ((tmp = r_strndup (foobar, 9)), !=, NULL);
  r_assert_cmpptr (tmp, !=, foobar);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
  r_assert_cmpptr ((tmp = r_strndup (foobar, 3)), !=, NULL);
  r_assert_cmpptr (tmp, !=, foobar);
  r_assert_cmpstr (tmp, ==, foo);
  r_free (tmp);
}
RTEST_END;

RTEST (rstr, dup_strip, RTEST_FAST)
{
  rchar * tmp;

  r_assert_cmpptr (r_strdup_strip (NULL), ==, NULL);
  r_assert_cmpptr ((tmp = r_strdup_strip (foobar)), !=, NULL);
  r_assert_cmpptr (tmp, !=, foobar);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);

  r_assert_cmpptr ((tmp = r_strdup_strip (foobar_padding)), !=, NULL);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
  r_assert_cmpptr ((tmp = r_strdup_strip ("  foobar  ")), !=, NULL);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
}
RTEST_END;

RTEST (rstr, strip, RTEST_FAST)
{
  rchar tmp[24], * ret;

  /* strlwstrip */
  r_assert_cmpptr (r_strlwstrip (NULL), ==, NULL);
  r_assert_cmpptr (r_strlwstrip (foobar_padding), ==, foobar_padding + 4);
  r_assert_cmpstr (r_strlwstrip (foobar_padding), ==, "foobar\r \t\n");

  /* strtwstrip */
  r_assert_cmpptr (r_strtwstrip (NULL), ==, NULL);
  r_strcpy (tmp, foobar_padding);
  r_assert_cmpptr (r_strtwstrip (tmp), ==, tmp);
  r_assert_cmpstr (tmp, !=, foobar_padding);
  r_assert_cmpstr (tmp, ==, "\t\n \rfoobar");

  /* strstrip */
  r_assert_cmpptr (r_strtwstrip (NULL), ==, NULL);
  r_strcpy (tmp, foobar_padding);
  r_assert_cmpptr ((ret = r_strstrip (tmp)), ==, tmp + 4);
  r_assert_cmpstr (ret, !=, foobar_padding);
  r_assert_cmpstr (ret, ==, foobar);
}
RTEST_END;

RTEST (rstr, asprintf, RTEST_FAST)
{
  rchar * str = NULL;

  r_assert_cmpint (r_asprintf (&str, "%s: %u", foobar, 42), ==, 10);
  r_assert_cmpptr (str, !=, NULL);
  r_assert_cmpstr (str, ==, "foobar: 42");
  r_free (str);
  r_assert_cmpint (r_asprintf (NULL, "%s: %u", foobar, 42), ==, 0);
  r_assert_cmpint (r_asprintf (&str, NULL), ==, 0);
  r_assert_cmpptr (str, ==, NULL);
  /*r_assert_cmpint (r_asprintf (&str, ""), ==, 0); * Compiler complains */
  /*r_assert_cmpptr (str, !=, NULL);*/
  /*r_assert_cmpstr (str, ==, "");*/
  /*r_free (str);*/
}
RTEST_END;

RTEST (rstr, printf, RTEST_FAST)
{
  rchar * str = NULL;

  r_assert_cmpint ((str = r_strprintf ("%s: %u", foobar, 42)), !=, NULL);
  r_assert_cmpstr (str, ==, "foobar: 42");
  r_free (str);
  r_assert_cmpptr (r_strprintf (NULL), ==, NULL);
  /*r_assert_cmpptr ((str = r_strprintf ("")), !=, NULL); * compiler complains */
  /*r_assert_cmpstr (str, ==, "");*/
  /*r_free (str);*/
}
RTEST_END;

RTEST (rstr, strv, RTEST_FAST)
{
  rchar ** strv;

  r_assert_cmpptr (r_strv_new (NULL), ==, NULL);
  r_assert_cmpptr ((strv = r_strv_new (foobar, NULL)), !=, NULL);
  r_assert_cmpuint (r_strv_len (strv), ==, 1);
  r_assert_cmpstr (strv[0], ==, foobar);
  r_assert_cmpptr (strv[1], ==, NULL);
  r_strv_free (strv);
}
RTEST_END;

RTEST (rstr, strv_join, RTEST_FAST)
{
  rchar ** strv;
  rchar * join;

  r_assert_cmpptr ((strv = r_strv_new (foobar, NULL)), !=, NULL);
  r_assert_cmpstr ((join = r_strv_join (strv, "")), ==, foobar); r_free (join);
  r_strv_free (strv);
  r_assert_cmpptr ((strv = r_strv_new (foo, bar, NULL)), !=, NULL);
  r_assert_cmpstr ((join = r_strv_join (strv, "")), ==, foobar); r_free (join);
  r_assert_cmpstr ((join = r_strv_join (strv, "-")), ==, "foo-bar"); r_free (join);
  r_strv_free (strv);
}
RTEST_END;

RTEST (rstr, strv_contains, RTEST_FAST)
{
  rchar ** strv;

  r_assert_cmpptr ((strv = r_strv_new (foo, bar, NULL)), !=, NULL);
  r_assert ( r_strv_contains (strv, foo));
  r_assert (!r_strv_contains (strv, foobar));
  r_assert ( r_strv_contains (strv, bar));
  r_strv_free (strv);
}
RTEST_END;

