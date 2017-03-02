#include <rlib/rlib.h>

static const rchar foobar[] = "foobar";
static const rchar FOOBAR[] = "FOOBAR";
static const rchar foo[] = "foo";
static const rchar FOO[] = "FOO";
static const rchar bar[] = "bar";
static const rchar BAR[] = "BAR";
static const rchar foobar_padding[] = "\t\n \rfoobar\r \t\n";

RTEST (rstr, len, RTEST_FAST)
{
  r_assert_cmpuint (r_strlen (NULL), ==, 0);
  r_assert_cmpuint (r_strlen (""), ==, 0);
  r_assert_cmpuint (r_strlen (foo), ==, 3);
  r_assert_cmpuint (r_strlen (foobar), ==, 6);
}
RTEST_END;

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

RTEST (rstr, casecmp, RTEST_FAST)
{
  r_assert_cmpint (r_strcasecmp (NULL, NULL), ==, 0);
  r_assert_cmpint (r_strcasecmp (NULL, foobar), <, 0);
  r_assert_cmpint (r_strcasecmp (foobar, NULL), >, 0);
  r_assert_cmpint (r_strcasecmp (foobar, foobar), ==, 0);
  r_assert_cmpint (r_strcasecmp (foobar, FOOBAR), ==, 0);
  r_assert_cmpint (r_strcasecmp (foobar, bar), >, 0);
  r_assert_cmpint (r_strcasecmp (bar, foobar), <, 0);
  r_assert_cmpint (r_strcasecmp (foobar, foo), >, 0);
  r_assert_cmpint (r_strcasecmp (foobar, FOO), >, 0);

  r_assert_cmpint (r_strncasecmp (NULL, NULL, 0), ==, 0);
  r_assert_cmpint (r_strncasecmp (NULL, foobar, 6), <, 0);
  r_assert_cmpint (r_strncasecmp (foobar, NULL, 6), >, 0);
  r_assert_cmpint (r_strncasecmp (foobar, foobar, 6), ==, 0);
  r_assert_cmpint (r_strncasecmp (foobar, FOOBAR, 6), ==, 0);
  r_assert_cmpint (r_strncasecmp (foobar, bar, 3), >, 0);
  r_assert_cmpint (r_strncasecmp (bar, foobar, 3), <, 0);
  r_assert_cmpint (r_strncasecmp (foobar, foo, 3), ==, 0);
  r_assert_cmpint (r_strncasecmp (foobar, FOO, 3), ==, 0);
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

RTEST (rstr, idx_of_c, RTEST_FAST)
{
  r_assert_cmpint (r_str_idx_of_c (NULL, 0, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_c (foobar, 0, 'f'), ==, -1);
  r_assert_cmpint (r_str_idx_of_c (foobar, -1, 'f'), ==, 0);
  r_assert_cmpint (r_str_idx_of_c (foobar, -1, 'F'), ==, -1);
  r_assert_cmpint (r_str_idx_of_c (foobar, -1, 'a'), ==, 4);
  r_assert_cmpint (r_str_idx_of_c (foobar, -1, 'A'), ==, -1);
  r_assert_cmpint (r_str_idx_of_c (foobar, -1, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_c (foobar, sizeof (foobar), 0), ==, 6);
}
RTEST_END;

RTEST (rstr, idx_of_c_case, RTEST_FAST)
{
  r_assert_cmpint (r_str_idx_of_c_case (NULL, 0, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_c_case (foobar, 0, 'f'), ==, -1);
  r_assert_cmpint (r_str_idx_of_c_case (foobar, -1, 'f'), ==, 0);
  r_assert_cmpint (r_str_idx_of_c_case (foobar, -1, 'F'), ==, 0);
  r_assert_cmpint (r_str_idx_of_c_case (foobar, -1, 'a'), ==, 4);
  r_assert_cmpint (r_str_idx_of_c_case (foobar, -1, 'A'), ==, 4);
  r_assert_cmpint (r_str_idx_of_c_case (foobar, -1, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_c_case (foobar, sizeof (foobar), 0), ==, 6);
}
RTEST_END;

RTEST (rstr, idx_of_c_any, RTEST_FAST)
{
  r_assert_cmpint (r_str_idx_of_c_any (NULL, 0, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_c_any (foobar, 0, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_c_any (foobar, -1, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_c_any (foobar, -1, "f", 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_c_any (foobar, -1, "f", -1), ==, 0);
  r_assert_cmpint (r_str_idx_of_c_any (foobar, -1, "F", -1), ==, -1);
  r_assert_cmpint (r_str_idx_of_c_any (foobar, -1, "Ff", -1), ==, 0);
  r_assert_cmpint (r_str_idx_of_c_any (foobar, -1, "FRab", -1), ==, 3);
}
RTEST_END;

RTEST (rstr, idx_of_str, RTEST_FAST)
{
  r_assert_cmpint (r_str_idx_of_str (NULL, 0, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_str (foobar, 0, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_str (foobar, -1, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_str (foobar, -1, "f", 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_str (foobar, -1, "f", -1), ==, 0);
  r_assert_cmpint (r_str_idx_of_str (foobar, -1, foo, -1), ==, 0);
  r_assert_cmpint (r_str_idx_of_str (foobar, -1, bar, -1), ==, 3);
  r_assert_cmpint (r_str_idx_of_str ("---BEGIN PRIVATE KEY-----", -1,
        "-----BEGIN", -1), ==, -1);

  r_assert_cmpint (r_str_idx_of_str ("fobrfbfoobar", -1, foo, -1), ==, 6);
  r_assert_cmpint (r_str_idx_of_str ("fobrfbfoobar", -1, FOO, -1), <, 0);
  r_assert_cmpint (r_str_idx_of_str ("fobrfbfoobar", -1, bar, -1), ==, 9);
  r_assert_cmpint (r_str_idx_of_str ("fobrfbfoobar", -1, BAR, -1), <, 0);
}
RTEST_END;

RTEST (rstr, idx_of_str_case, RTEST_FAST)
{
  r_assert_cmpint (r_str_idx_of_str_case (NULL, 0, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_str_case (foobar, 0, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_str_case (foobar, -1, NULL, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_str_case (foobar, -1, foo, 0), ==, -1);
  r_assert_cmpint (r_str_idx_of_str_case (foobar, -1, foo, -1), ==, 0);
  r_assert_cmpint (r_str_idx_of_str_case (FOOBAR, -1, foo, -1), ==, 0);
  r_assert_cmpint (r_str_idx_of_str_case (foobar, -1, bar, -1), ==, 3);
  r_assert_cmpint (r_str_idx_of_str_case (foobar, -1, BAR, -1), ==, 3);
  r_assert_cmpint (r_str_idx_of_str_case ("---BEGIN PRIVATE KEY-----", -1,
        "-----BEGIN", -1), ==, -1);
  r_assert_cmpint (r_str_idx_of_str_case ("-----BEGIN PRIVATE KEY-----", -1,
        "-----begIn", -1), ==, 0);

  r_assert_cmpint (r_str_idx_of_str_case ("fobrfbfoobar", -1, foo, -1), ==, 6);
  r_assert_cmpint (r_str_idx_of_str_case ("fobrfbfoobar", -1, FOO, -1), ==, 6);
  r_assert_cmpint (r_str_idx_of_str_case ("fobrfbfoobar", -1, bar, -1), ==, 9);
  r_assert_cmpint (r_str_idx_of_str_case ("fobrfbfoobar", -1, BAR, -1), ==, 9);
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
  r_memclear (dst, sizeof (dst));
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
  r_memclear (dst, sizeof (dst));
  r_assert_cmpptr (r_stpcpy (&dst[50], foobar), ==, &dst[50] + 6);
  r_assert_cmpstr (&dst[50], ==, foobar);
  r_assert_cmpptr (r_stpcpy (dst, &dst[50]), ==, dst + 6);
  r_assert_cmpstr (dst, ==, foobar);
  r_assert_cmpptr (r_stpcpy (NULL, foobar), ==, NULL);
  r_assert_cmpptr (r_stpcpy (dst, NULL), ==, dst);

  /* stpncpy */
  r_memclear (dst, sizeof (dst));
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

RTEST (rstr, strchr, RTEST_FAST)
{
  r_assert_cmpptr (r_strchr (NULL, ' '), ==, NULL);
  r_assert_cmpptr (r_strchr (foobar, ' '), ==, NULL);
  r_assert_cmpptr (r_strchr (foobar, 255), ==, NULL);
  r_assert_cmpptr (r_strchr (foobar, 'f'), ==, &foobar[0]);
  r_assert_cmpptr (r_strchr (foobar, 'o'), ==, &foobar[1]);
  r_assert_cmpptr (r_strchr (foobar, 'b'), ==, &foobar[3]);
  r_assert_cmpptr (r_strchr (foobar, 'r'), ==, &foobar[5]);
}
RTEST_END;

RTEST (rstr, strrchr, RTEST_FAST)
{
  r_assert_cmpptr (r_strrchr (NULL, ' '), ==, NULL);
  r_assert_cmpptr (r_strrchr (foobar, ' '), ==, NULL);
  r_assert_cmpptr (r_strrchr (foobar, 255), ==, NULL);
  r_assert_cmpptr (r_strrchr (foobar, 'f'), ==, &foobar[0]);
  r_assert_cmpptr (r_strrchr (foobar, 'o'), ==, &foobar[2]);
  r_assert_cmpptr (r_strrchr (foobar, 'b'), ==, &foobar[3]);
  r_assert_cmpptr (r_strrchr (foobar, 'r'), ==, &foobar[5]);
}
RTEST_END;

RTEST (rstr, strnstr, RTEST_FAST)
{
  r_assert_cmpptr (r_strnstr (NULL, NULL, 0), ==, NULL);
  r_assert_cmpptr (r_strnstr (foo, NULL, 0), ==, NULL);
  r_assert_cmpptr (r_strnstr (foo, bar, 0), ==, NULL);
  r_assert_cmpptr (r_strnstr (foo, foo, 0), ==, NULL);
  r_assert_cmpptr (r_strnstr (foo, foo, 1), ==, NULL);
  r_assert_cmpptr (r_strnstr (foo, foo, 3), ==, foo);
  r_assert_cmpptr (r_strnstr (foobar, foo, 3), ==, foobar);
  r_assert_cmpptr (r_strnstr (foobar, bar, 4), ==, NULL);
  r_assert_cmpptr (r_strnstr (foobar, bar, 6), ==, foobar + 3);
}
RTEST_END;

RTEST (rstr, to_int8_base0, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;

  /* int8 */
  r_assert_cmpint (r_str_to_int8 (NULL, &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpptr (e, ==, NULL);
  r_assert_cmpint (r_str_to_int8 ("", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int8 ("e", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int8 ("42", &e, 0, &res), ==, 42);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int8 ("-42e", &e, 0, &res), ==, -42);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int8 ("127e", &e, 0, &res), ==, RINT8_MAX);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int8 ("-128", &e, 0, &res), ==, RINT8_MIN);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int8 ("128", &e, 0, &res), ==, RINT8_MAX);
  r_assert_cmpint (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int8 ("-129", &e, 0, &res), ==, RINT8_MIN);
  r_assert_cmpint (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr (e, ==, "");

  /* uint8 */
  r_assert_cmpuint (r_str_to_uint8 (NULL, &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpptr  (e, ==, NULL);
  r_assert_cmpuint (r_str_to_uint8 ("e", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "e");
  r_assert_cmpuint (r_str_to_uint8 ("-42", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "-42");
  r_assert_cmpuint (r_str_to_uint8 ("42", &e, 0, &res), ==, 42);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
  r_assert_cmpuint (r_str_to_uint8 ("255", &e, 0, &res), ==, RUINT8_MAX);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
  r_assert_cmpuint (r_str_to_uint8 ("256e", &e, 0, &res), ==, RUINT8_MAX);
  r_assert_cmpint  (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr  (e, ==, "e");
}
RTEST_END;

RTEST (rstr, to_int16_base0, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;

  /* int16 */
  r_assert_cmpint (r_str_to_int16 (NULL, &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpptr (e, ==, NULL);
  r_assert_cmpint (r_str_to_int16 ("", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int16 ("e", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int16 ("42", &e, 0, &res), ==, 42);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int16 ("-4200e", &e, 0, &res), ==, -4200);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int16 ("32767e", &e, 0, &res), ==, RINT16_MAX);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int16 ("-32768", &e, 0, &res), ==, RINT16_MIN);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int16 ("32768", &e, 0, &res), ==, RINT16_MAX);
  r_assert_cmpint (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int16 ("-32769", &e, 0, &res), ==, RINT16_MIN);
  r_assert_cmpint (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr (e, ==, "");

  /* uint16 */
  r_assert_cmpuint (r_str_to_uint16 (NULL, &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpptr  (e, ==, NULL);
  r_assert_cmpuint (r_str_to_uint16 ("e", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "e");
  r_assert_cmpuint (r_str_to_uint16 ("-42", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "-42");
  r_assert_cmpuint (r_str_to_uint16 ("42", &e, 0, &res), ==, 42);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
  r_assert_cmpuint (r_str_to_uint16 ("65535", &e, 0, &res), ==, RUINT16_MAX);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
  r_assert_cmpuint (r_str_to_uint16 ("65536e", &e, 0, &res), ==, RUINT16_MAX);
  r_assert_cmpint  (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr  (e, ==, "e");
}
RTEST_END;

RTEST (rstr, to_int32_base0, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;

  /* int32 */
  r_assert_cmpint (r_str_to_int32 (NULL, &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpptr (e, ==, NULL);
  r_assert_cmpint (r_str_to_int32 ("", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int32 ("e", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int32 ("0", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int32 ("-4200000e", &e, 0, &res), ==, -4200000);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int32 ("2147483647e", &e, 0, &res), ==, RINT32_MAX);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int32 ("-2147483648", &e, 0, &res), ==, RINT32_MIN);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int32 ("2147483648", &e, 0, &res), ==, RINT32_MAX);
  r_assert_cmpint (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int32 ("-2147483649", &e, 0, &res), ==, RINT32_MIN);
  r_assert_cmpint (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr (e, ==, "");

  /* uint32 */
  r_assert_cmpuint (r_str_to_uint32 (NULL, &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpptr  (e, ==, NULL);
  r_assert_cmpuint (r_str_to_uint32 ("e", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "e");
  r_assert_cmpuint (r_str_to_uint32 ("-42", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "-42");
  r_assert_cmpuint (r_str_to_uint32 ("0", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
  r_assert_cmpuint (r_str_to_uint32 ("4294967295", &e, 0, &res), ==, RUINT32_MAX);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
  r_assert_cmpuint (r_str_to_uint32 ("4294967296e", &e, 0, &res), ==, RUINT32_MAX);
  r_assert_cmpint  (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr  (e, ==, "e");
}
RTEST_END;

RTEST (rstr, to_int64_base0, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;

  /* int64 */
  r_assert_cmpint (r_str_to_int64 (NULL, &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpptr (e, ==, NULL);
  r_assert_cmpint (r_str_to_int64 ("", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int64 ("e", &e, 0, &res), ==, 0);
  r_assert_cmpint (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int64 ("42", &e, 0, &res), ==, 42);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int64 ("-4200000000000000e", &e, 0, &res), ==,
      RUINT64_CONSTANT (-4200000000000000));
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int64 ("9223372036854775807e", &e, 0, &res), ==, RINT64_MAX);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "e");
  r_assert_cmpint (r_str_to_int64 ("-9223372036854775808", &e, 0, &res), ==, RINT64_MIN);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int64 ("9223372036854775808", &e, 0, &res), ==, RINT64_MAX);
  r_assert_cmpint (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr (e, ==, "");
  r_assert_cmpint (r_str_to_int64 ("-9223372036854775809", &e, 0, &res), ==, RINT64_MIN);
  r_assert_cmpint (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr (e, ==, "");

  /* uint64 */
  r_assert_cmpuint (r_str_to_uint64 (NULL, &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpptr  (e, ==, NULL);
  r_assert_cmpuint (r_str_to_uint64 ("e", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "e");
  r_assert_cmpuint (r_str_to_uint64 ("-42", &e, 0, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "-42");
  r_assert_cmpuint (r_str_to_uint64 ("42", &e, 0, &res), ==, 42);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
  r_assert_cmpuint (r_str_to_uint64 ("18446744073709551615", &e, 0, &res), ==, RUINT64_MAX);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
  r_assert_cmpuint (r_str_to_uint64 ("18446744073709551616e", &e, 0, &res), ==, RUINT64_MAX);
  r_assert_cmpint  (res, ==, R_STR_PARSE_RANGE);
  r_assert_cmpstr  (e, ==, "e");
}
RTEST_END;

RTEST (rstr, to_int_base16, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;

  /* int */
  r_assert_cmpint (r_str_to_int64 ("-0xFfG", &e, 0, &res), ==, -0xFF);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "G");
  r_assert_cmpint (r_str_to_int64 ("-Ffg", &e, 16, &res), ==, -0xFF);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "g");

  /* uint */
  r_assert_cmpuint (r_str_to_uint64 ("0xfFH", &e, 0, &res), ==, 0xFF);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "H");
  r_assert_cmpuint (r_str_to_uint64 ("AAbbCCdDEefF12", &e, 16, &res), ==,
      0xAABBCCDDEEFF12);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "");
}
RTEST_END;

RTEST (rstr, to_int_base8, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;

  /* int */
  r_assert_cmpint (r_str_to_int64 ("-0778", &e, 0, &res), ==, -077);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "8");
  r_assert_cmpint (r_str_to_int64 ("-0778", &e, 8, &res), ==, -077);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "8");

  /* uint */
  r_assert_cmpuint (r_str_to_uint64 ("0778", &e, 0, &res), ==, 077);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "8");
  r_assert_cmpuint (r_str_to_uint64 ("0778", &e, 8, &res), ==, 077);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "8");
}
RTEST_END;

RTEST (rstr, to_int_base2, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;

  /* int */
  r_assert_cmpint (r_str_to_int64 ("-01102", &e, 2, &res), ==, -0x6);
  r_assert_cmpint (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr (e, ==, "2");

  /* uint */
  r_assert_cmpuint (r_str_to_uint64 ("01112", &e, 2, &res), ==, 0x7);
  r_assert_cmpint  (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr  (e, ==, "2");
}
RTEST_END;

RTEST (rstr, to_int_base_error, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;

  r_assert_cmpuint (r_str_to_uint64 ("1", &e, 1, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "1");
  r_assert_cmpuint (r_str_to_uint64 ("1", &e, 37, &res), ==, 0);
  r_assert_cmpint  (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpstr  (e, ==, "1");
}
RTEST_END;

RTEST (rstr, to_float, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;
  rfloat v;

  r_assert_cmpfloat (r_str_to_float (NULL, &e, &res), ==, .0);
  r_assert_cmpint   (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpfloat (r_str_to_float ("0", &e, &res), ==, .0);
  r_assert_cmpint   (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr   (e, ==, "");
  r_assert_cmpfloat ((v = r_str_to_float ("-3.1415pi", &e, &res)), ==, -3.1415);
  r_assert_cmpint   (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr   (e, ==, "pi");
  r_assert          (!r_float_isinf (v));
  r_assert          (r_float_isfinite (v));
  r_assert          (r_float_signbit (v));
  r_assert_cmpfloat ((v = r_str_to_float ("1e+20pi", &e, &res)), ==, 1e20);
  r_assert_cmpint   (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr   (e, ==, "pi");
  r_assert          (!r_float_isinf (v));
  r_assert          (r_float_isfinite (v));
  r_assert          (!r_float_signbit (v));
  r_assert_cmpfloat ((v = r_str_to_float ("-INFINITYpi", &e, &res)), ==, -RFLOAT_INFINITY);
  r_assert_cmpint   (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr   (e, ==, "pi");
  r_assert          (r_float_isinf (v));
  r_assert          (r_float_signbit (v));
  r_assert_cmpfloat ((v = r_str_to_float ("NaNpi", &e, &res)), !=, 0.0);
  r_assert_cmpint   (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr   (e, ==, "pi");
  r_assert          (r_float_isnan (v));
}
RTEST_END;

RTEST (rstr, to_double, RTEST_FAST)
{
  RStrParse res = R_STR_PARSE_OK;
  const rchar * e;
  rdouble v;

  r_assert_cmpdouble (r_str_to_double (NULL, &e, &res), ==, .0);
  r_assert_cmpint    (res, ==, R_STR_PARSE_INVAL);
  r_assert_cmpdouble (r_str_to_double ("0", &e, &res), ==, .0);
  r_assert_cmpint    (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr    (e, ==, "");
  r_assert_cmpdouble ((v = r_str_to_double ("-3.1415pi", &e, &res)), ==, -3.1415);
  r_assert_cmpint    (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr    (e, ==, "pi");
  r_assert           (!r_double_isinf (v));
  r_assert           (r_double_isfinite (v));
  r_assert           (r_double_signbit (v));
  r_assert_cmpdouble ((v = r_str_to_double ("1e+21pi", &e, &res)), ==, 1e21);
  r_assert_cmpint    (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr    (e, ==, "pi");
  r_assert           (!r_double_isinf (v));
  r_assert           (r_double_isfinite (v));
  r_assert           (!r_double_signbit (v));
  r_assert_cmpdouble ((v = r_str_to_double ("-INFINITYpi", &e, &res)), ==, -RDOUBLE_INFINITY);
  r_assert_cmpint    (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr    (e, ==, "pi");
  r_assert           (r_double_isinf (v));
  r_assert           (r_double_signbit (v));
  r_assert_cmpdouble ((v = r_str_to_double ("NaNpi", &e, &res)), !=, 0.0);
  r_assert_cmpint    (res, ==, R_STR_PARSE_OK);
  r_assert_cmpstr    (e, ==, "pi");
  r_assert           (r_double_isnan (v));
}
RTEST_END;

RTEST (rstr, dup, RTEST_FAST)
{
  rchar * tmp;
  static rchar foobar_no_0[] = { 'f', 'o', 'o', 'b', 'a', 'r' };
  static rchar foobar_0_yes[] = { 'f', 'o', 'o', 'b', 'a', 'r', 0, 'y', 'e', 's' };

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
  r_assert_cmpptr ((tmp = r_strndup (foobar_no_0, sizeof (foobar_no_0))), !=, NULL);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
  r_assert_cmpptr ((tmp = r_strndup (foobar_0_yes, sizeof (foobar_0_yes))), !=, NULL);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
}
RTEST_END;

RTEST (rstr, dup_wstrip, RTEST_FAST)
{
  rchar * tmp;

  r_assert_cmpptr (r_strdup_wstrip (NULL), ==, NULL);
  r_assert_cmpptr ((tmp = r_strdup_wstrip (foobar)), !=, NULL);
  r_assert_cmpptr (tmp, !=, foobar);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);

  r_assert_cmpptr ((tmp = r_strdup_wstrip (foobar_padding)), !=, NULL);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
  r_assert_cmpptr ((tmp = r_strdup_wstrip ("  foobar  ")), !=, NULL);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
}
RTEST_END;

RTEST (rstr, dup_strip, RTEST_FAST)
{
  rchar * tmp;

  r_assert_cmpptr (r_strdup_strip (NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_strdup_strip (NULL, foo), ==, NULL);
  r_assert_cmpptr ((tmp = r_strdup_strip (foobar, "xy")), !=, NULL);
  r_assert_cmpptr (tmp, !=, foobar);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);

  r_assert_cmpptr ((tmp = r_strdup_strip (foobar_padding, "\t \r\n")), !=, NULL);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
  r_assert_cmpptr ((tmp = r_strdup_strip ("x foobar x", "x ")), !=, NULL);
  r_assert_cmpstr (tmp, ==, foobar);
  r_free (tmp);
}
RTEST_END;

RTEST (rstr, wstrip, RTEST_FAST)
{
  rchar tmp[24], * ret;

  /* str_lwstrip */
  r_assert_cmpptr (r_str_lwstrip (NULL), ==, NULL);
  r_assert_cmpptr (r_str_lwstrip (foobar_padding), ==, foobar_padding + 4);
  r_assert_cmpstr (r_str_lwstrip (foobar_padding), ==, "foobar\r \t\n");

  /* str_twstrip */
  r_assert_cmpptr (r_str_twstrip (NULL), ==, NULL);
  r_strcpy (tmp, foobar_padding);
  r_assert_cmpptr (r_str_twstrip (tmp), ==, tmp);
  r_assert_cmpstr (tmp, !=, foobar_padding);
  r_assert_cmpstr (tmp, ==, "\t\n \rfoobar");

  /* str_wstrip */
  r_assert_cmpptr (r_str_wstrip (NULL), ==, NULL);
  r_strcpy (tmp, foobar_padding);
  r_assert_cmpptr ((ret = r_str_wstrip (tmp)), ==, tmp + 4);
  r_assert_cmpstr (ret, !=, foobar_padding);
  r_assert_cmpstr (ret, ==, foobar);
}
RTEST_END;

RTEST (rstr, strip, RTEST_FAST)
{
  rchar tmp[24], * ret;

  /* str_lstrip */
  r_assert_cmpptr (r_str_lstrip (NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_str_lstrip (NULL, foo), ==, NULL);
  r_assert_cmpptr (r_str_lstrip (foobar, "fo"), ==, foobar + 3);
  r_assert_cmpstr (r_str_lstrip (foobar, "fo"), ==, bar);

  /* str_tstrip */
  r_assert_cmpptr (r_str_tstrip (NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_str_tstrip (NULL, foo), ==, NULL);
  r_strcpy (tmp, foobar);
  r_assert_cmpptr (r_str_tstrip (tmp, "rba"), ==, tmp);
  r_assert_cmpstr (tmp, ==, foo);

  /* str_strip */
  r_assert_cmpptr (r_str_strip (NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_str_strip (NULL, foo), ==, NULL);
  r_strcpy (tmp, foobar);
  r_assert_cmpptr ((ret = r_str_strip (tmp, "fra")), ==, tmp + 1);
  r_assert_cmpstr (ret, ==, "oob");
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

RTEST (rstr_list, new, RTEST_FAST)
{
  RSList * lst;

  r_assert_cmpptr ((lst = r_str_list_new (foo, bar, NULL)), !=, NULL);
  r_assert_cmpuint (r_slist_len (lst), ==, 2);
  r_assert_cmpstr (r_slist_data (lst), ==, foo);
  r_assert_cmpstr (r_slist_data (r_slist_next (lst)), ==, bar);
  r_slist_destroy_full (lst, r_free);
}
RTEST_END;

RTEST (rstrv, basic, RTEST_FAST)
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

RTEST (rstrv, copy, RTEST_FAST)
{
  rchar ** strv, ** copy;
  r_assert_cmpptr ((strv = r_strv_new (foo, bar, foobar, NULL)), !=, NULL);
  r_assert_cmpuint (r_strv_len (strv), ==, 3);
  r_assert_cmpptr ((copy = r_strv_copy (strv)), !=, NULL);
  r_strv_free (strv);
  r_assert_cmpuint (r_strv_len (copy), ==, 3);

  r_assert_cmpstr (copy[0], ==, foo);
  r_assert_cmpstr (copy[1], ==, bar);
  r_assert_cmpstr (copy[2], ==, foobar);
  r_assert_cmpptr (copy[3], ==, NULL);
  r_strv_free (copy);
}
RTEST_END;

RTEST (rstrv, join, RTEST_FAST)
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

static void
charwise_add (rpointer data, rpointer user)
{
  rchar * str, * add = user;
  for (str = data; *str != 0; str++)
    *str += *add;
}

RTEST (rstrv, foreach, RTEST_FAST)
{
  rchar ** strv;
  rchar add = 2;

  r_assert_cmpptr ((strv = r_strv_new (foo, bar, NULL)), !=, NULL);
  r_assert ( r_strv_contains (strv, foo));
  r_assert ( r_strv_contains (strv, bar));
  r_assert (!r_strv_contains (strv, "hqq"));
  r_assert (!r_strv_contains (strv, "dct"));
  r_strv_foreach (strv, charwise_add, &add);
  r_assert (!r_strv_contains (strv, foo));
  r_assert (!r_strv_contains (strv, bar));
  r_assert ( r_strv_contains (strv, "hqq"));
  r_assert ( r_strv_contains (strv, "dct"));
  r_strv_free (strv);
}
RTEST_END;

RTEST (rstrv, contains, RTEST_FAST)
{
  rchar ** strv;

  r_assert_cmpptr ((strv = r_strv_new (foo, bar, NULL)), !=, NULL);
  r_assert ( r_strv_contains (strv, foo));
  r_assert (!r_strv_contains (strv, foobar));
  r_assert (!r_strv_contains (strv, NULL));
  r_assert ( r_strv_contains (strv, bar));
  r_strv_free (strv);
}
RTEST_END;

RTEST (rstr, join_dup, RTEST_FAST)
{
  rchar * join;

  r_assert_cmpptr (r_strjoin_dup (NULL, foo, bar, NULL), ==, NULL);

  r_assert_cmpstr ((join = r_strjoin_dup ("", foo, bar, NULL)), ==, foobar); r_free (join);
  r_assert_cmpstr ((join = r_strjoin_dup ("", foobar, NULL)), ==, foobar); r_free (join);
  r_assert_cmpstr ((join = r_strjoin_dup ("-", foo, bar, NULL)), ==, "foo-bar"); r_free (join);
}
RTEST_END;

RTEST (rstr, join, RTEST_FAST)
{
  rchar join[24];

  r_assert_cmpstr (r_strnjoin (NULL, 0, NULL, NULL), ==, NULL);
  r_assert_cmpstr (r_strnjoin (join, 24, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_strnjoin (join, 24, NULL, foo, bar, NULL), ==, NULL);
  r_assert_cmpptr (r_strnjoin (join, 4, "", foo, bar, NULL), ==, NULL);

  r_assert_cmpstr (r_strnjoin (join, 24, "", foo, bar, NULL), ==, foobar);
  r_assert_cmpstr (r_strnjoin (join, 24, "", foobar, NULL), ==, foobar);
  r_assert_cmpstr (r_strnjoin (join, 24, "-", foo, bar, NULL), ==, "foo-bar");
}
RTEST_END;

RTEST (rstr, split, RTEST_FAST)
{
  const rchar str[] = "foo bar bar foo foobar";
  rchar ** strv;

  r_assert_cmpptr ((strv = r_strsplit (str, " ", 42)), !=, NULL);
  r_assert_cmpuint (r_strv_len (strv), ==, 5);
  r_assert_cmpstr (strv[0], ==, foo);
  r_assert_cmpstr (strv[2], ==, bar);
  r_assert_cmpstr (strv[4], ==, foobar);
  r_strv_free (strv);
  r_assert_cmpptr ((strv = r_strsplit (str, " ", 4)), !=, NULL);
  r_assert_cmpuint (r_strv_len (strv), ==, 4);
  r_assert_cmpstr (strv[0], ==, foo);
  r_assert_cmpstr (strv[1], ==, bar);
  r_assert_cmpstr (strv[2], ==, bar);
  r_assert_cmpstr (strv[3], ==, "foo foobar");
  r_strv_free (strv);

  r_assert_cmpptr (r_strsplit (NULL, " ", 42), ==, NULL);
  r_assert_cmpptr (r_strsplit (foobar, "", 42), ==, NULL);
  r_assert_cmpptr (r_strsplit (foobar, NULL, 42), ==, NULL);
  r_assert_cmpptr (r_strsplit (foobar, "", 0), ==, NULL);
}
RTEST_END;

RTEST (rstr, mem_dump, RTEST_FAST)
{
  const ruint8 data[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  const rsize size = R_N_ELEMENTS (data);
  const ruint8 str[] = "abcdefgh";
  rchar * tmp;
#if RLIB_SIZEOF_VOID_P == 8
  ruint offset = 18;
#else
  ruint offset = 10;
#endif

  r_assert_cmpptr (r_str_mem_dump_dup (NULL, 0, 0), ==, NULL);
  r_assert_cmpptr (r_str_mem_dump_dup (data, 0, 0), ==, NULL);
  r_assert_cmpptr (r_str_mem_dump_dup (data, size, 0), ==, NULL);
  r_assert_cmpptr (r_str_mem_dump_dup (data, 0, size), ==, NULL);

  r_assert_cmpptr ((tmp = r_str_mem_dump_dup (data, size, size)), !=, NULL);
  r_assert_cmpstr (tmp + offset, ==,
      "00 01 02 03 04 05 06 07 08 09  \"........ ..\"");
  r_free (tmp);

  r_assert_cmpptr ((tmp = r_str_mem_dump_dup (str, 4, 4)), !=, NULL);
  r_assert_cmpstr (tmp + offset, ==, "61 62 63 64  \"abcd\"");
  r_free (tmp);

  r_assert_cmpptr ((tmp = r_str_mem_dump_dup (str, 6, 16)), !=, NULL);
  r_assert_cmpstr (tmp + offset, ==,
      "61 62 63 64 65 66                               "
      " \"abcdef           \"");
  r_free (tmp);

  {
    rchar * r = r_strprintf (
#if RLIB_SIZEOF_VOID_P == 8
        "%16p: 00 01 02 03 04  \".....\"\n%16p: 05 06 07 08 09  \".....\"",
#else
        "%8p: 00 01 02 03 04  \".....\"\n%8p: 05 06 07 08 09  \".....\"",
#endif
        data, data + 5);
    r_assert_cmpptr ((tmp = r_str_mem_dump_dup (data, size, 5)), !=, NULL);
    r_assert_cmpstr (tmp, ==, r);
    r_free (r);
    r_free (tmp);
  }
}
RTEST_END;

RTEST (rstr, mem_hex, RTEST_FAST)
{
  const ruint8 data[] = { 250, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  rchar * tmp;

  r_assert_cmpptr (r_str_mem_hex (NULL, 0), ==, NULL);
  r_assert_cmpptr (r_str_mem_hex (data, 0), ==, NULL);
  r_assert_cmpstr ((tmp = r_str_mem_hex (data, 6)), ==, "fa0102030405");
  r_free (tmp);
}
RTEST_END;

RTEST (rstr, mem_hex_full, RTEST_FAST)
{
  const ruint8 data[] = { 250, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  rchar * tmp;

  r_assert_cmpptr (r_str_mem_hex_full (NULL, 0, ":", 2), ==, NULL);
  r_assert_cmpptr (r_str_mem_hex_full (data, 0, ":", 2), ==, NULL);
  r_assert_cmpstr ((tmp = r_str_mem_hex_full (data, 6, "", 2)), ==, "fa0102030405");
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_str_mem_hex_full (data, 6, ":", 1)), ==, "fa:01:02:03:04:05");
  r_free (tmp);
  r_assert_cmpstr ((tmp = r_str_mem_hex_full (data, 9, ", ", 4)), ==, "fa010203, 04050607, 08");
  r_free (tmp);
}
RTEST_END;

RTEST (rstr, hex_mem, RTEST_FAST)
{
  ruint8 * bin;
  rsize size;
  ruint8 data[8];
  ruint8 expected[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
  ruint8 expected_wierd[] = { 0x01, 0x12, 0x23, 0x34, 0x45 };

  r_assert_cmpuint (r_str_hex_to_binary (NULL, NULL, 0), ==, 0);
  r_assert_cmpuint (r_str_hex_to_binary ("00112233", data, 0), ==, 0);
  r_assert_cmpuint (r_str_hex_to_binary ("00112233", data, sizeof (data)), ==, 4);
  r_assert_cmpmem (data, ==, expected, 4);

  r_assert_cmpptr (r_str_hex_mem (NULL, NULL), ==, NULL);
  r_assert_cmpptr ((bin = r_str_hex_mem ("00112233", NULL)), !=, NULL);
  r_assert_cmpmem (bin, ==, expected, 4);
  r_free (bin);
  r_assert_cmpptr ((bin = r_str_hex_mem ("0011223344556677", &size)), !=, NULL);
  r_assert_cmpuint (size, ==, 8);
  r_assert_cmpmem (bin, ==, expected, size);
  r_free (bin);

  /* Error cases */
  r_assert_cmpptr (r_str_hex_mem ("0x0x00", NULL), ==, NULL);
  r_assert_cmpptr (r_str_hex_mem ("0x012", NULL), ==, NULL);
  r_assert_cmpptr (r_str_hex_mem ("012", NULL), ==, NULL);

  r_assert_cmpptr ((bin = r_str_hex_mem ("  0x0112233445 56677", &size)), !=, NULL);
  r_assert_cmpuint (size, ==, 5);
  r_assert_cmpmem (bin, ==, expected_wierd, size);
  r_free (bin);
}
RTEST_END;

RTEST (rstr, ascii_xdigit_value, RTEST_FAST)
{
  rchar i;
  r_assert_cmpint (r_ascii_digit_value (0), <, 0);
  r_assert_cmpint (r_ascii_digit_value (0xff), <, 0);
  r_assert_cmpint (r_ascii_xdigit_value (0xff), <, 0);

  for (i = 0; i < 10; i++)
    r_assert_cmpint (r_ascii_digit_value ('0' + i), ==, i);
  for (i = 0; i < 6; i++) {
    r_assert_cmpint (r_ascii_digit_value ('a' + i), <, 0);
    r_assert_cmpint (r_ascii_digit_value ('A' + i), <, 0);
  }

  for (i = 0; i < 10; i++)
    r_assert_cmpint (r_ascii_xdigit_value ('0' + i), ==, i);
  for (i = 0; i < 6; i++) {
    r_assert_cmpint (r_ascii_xdigit_value ('a' + i), ==, 10 + i);
    r_assert_cmpint (r_ascii_xdigit_value ('A' + i), ==, 10 + i);
  }
  r_assert_cmpint (r_ascii_xdigit_value ('g'), <, 0);
  r_assert_cmpint (r_ascii_xdigit_value ('G'), <, 0);
}
RTEST_END;

RTEST (rstr, ascii_upper_lower, RTEST_FAST)
{
  rchar foo[] = "* 12this 453 is foobar?";

  r_assert_cmpint (r_ascii_upper (';'), ==, ';');
  r_assert_cmpint (r_ascii_upper ('a'), ==, 'A');
  r_assert_cmpint (r_ascii_upper ('A'), ==, 'A');
  r_assert_cmpint (r_ascii_upper ('x'), ==, 'X');
  r_assert_cmpint (r_ascii_upper ('X'), ==, 'X');

  r_assert_cmpint (r_ascii_lower (';'), ==, ';');
  r_assert_cmpint (r_ascii_lower ('a'), ==, 'a');
  r_assert_cmpint (r_ascii_lower ('A'), ==, 'a');
  r_assert_cmpint (r_ascii_lower ('x'), ==, 'x');
  r_assert_cmpint (r_ascii_lower ('X'), ==, 'x');

  r_assert_cmpstr (r_ascii_make_upper (foo, -1), ==, "* 12THIS 453 IS FOOBAR?");
  r_assert_cmpstr (foo, ==, "* 12THIS 453 IS FOOBAR?");
  r_assert_cmpstr (r_ascii_make_lower (foo, -1), ==, "* 12this 453 is foobar?");
  r_assert_cmpstr (foo, ==, "* 12this 453 is foobar?");

  r_assert_cmpstr (r_ascii_make_upper (foo, 7), ==, "* 12THIs 453 is foobar?");
}
RTEST_END;

RTEST (rstr, match_simple_pattern, RTEST_FAST)
{
  const rchar foo[] = "this is my foobar string?";

  r_assert (!r_str_match_simple_pattern (NULL, 0, NULL));
  r_assert (!r_str_match_simple_pattern (foo, 0, NULL));
  r_assert (!r_str_match_simple_pattern (foo, -1, NULL));

  r_assert (!r_str_match_simple_pattern (foo, -1, "foo"));
  r_assert (r_str_match_simple_pattern (foo, -1, "*"));
  r_assert (r_str_match_simple_pattern (foo, -1, "*\\?"));
  r_assert (r_str_match_simple_pattern (foo, -1, "*foobar*"));
  r_assert (r_str_match_simple_pattern (foo, -1, "this*??*foobar*?"));
  r_assert (!r_str_match_simple_pattern (foo, -1, "?this*"));
  r_assert (r_str_match_simple_pattern (foo, -1, "this*foobar*"));
  r_assert (!r_str_match_simple_pattern (foo, -1, "this*foobar"));
  r_assert (r_str_match_simple_pattern (foo, -1, "this*\\f\\oobar*"));
}
RTEST_END;

RTEST (rstr, match_pattern, RTEST_FAST)
{
  RStrMatchResult * res;
  const rchar foo[] = "this is my foobar string?";

  r_assert_cmpuint (r_str_match_pattern (NULL, 0, NULL, NULL), ==, R_STR_MATCH_RESULT_INVAL);
  r_assert_cmpuint (r_str_match_pattern (foo, 0, NULL, NULL), ==, R_STR_MATCH_RESULT_INVAL);
  r_assert_cmpuint (r_str_match_pattern (foo, -1, NULL, NULL), ==, R_STR_MATCH_RESULT_INVAL);
  r_assert_cmpuint (r_str_match_pattern (foo, -1, "*", NULL), ==, R_STR_MATCH_RESULT_INVAL);

  r_assert_cmpuint (r_str_match_pattern (foo, -1, "*", &res), ==, R_STR_MATCH_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 1);
  r_assert_cmpuint (res->token[0].chunk.size, ==, r_strlen (foo));
  r_assert_cmpptr (res->token[0].chunk.str, ==, &foo[0]);
  r_free (res);

  r_assert_cmpuint (r_str_match_pattern (foo, -1, "this?is*foobar*\\?", &res), ==, R_MEM_SCAN_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 7);
  r_assert_cmpuint (res->token[0].chunk.size, ==, 4);
  r_assert_cmpuint (res->token[1].chunk.size, ==, 1);
  r_assert_cmpuint (res->token[2].chunk.size, ==, 2);
  r_assert_cmpuint (res->token[3].chunk.size, ==, 4);
  r_assert_cmpuint (res->token[4].chunk.size, ==, 6);
  r_assert_cmpuint (res->token[5].chunk.size, ==, 7);
  r_assert_cmpuint (res->token[6].chunk.size, ==, 1);
  r_assert_cmpptr (res->token[0].chunk.str, ==, &foo[0]);
  r_assert_cmpptr (res->token[1].chunk.str, ==, &foo[4]);
  r_assert_cmpptr (res->token[2].chunk.str, ==, &foo[5]);
  r_assert_cmpptr (res->token[3].chunk.str, ==, &foo[7]);
  r_assert_cmpptr (res->token[4].chunk.str, ==, &foo[11]);
  r_assert_cmpptr (res->token[5].chunk.str, ==, &foo[17]);
  r_assert_cmpptr (res->token[6].chunk.str, ==, &foo[24]);
  r_free (res);
}
RTEST_END;

RTEST (rstr, match_http_request_line, RTEST_FAST)
{
  RStrMatchResult * res;

  r_assert_cmpint (r_str_match_pattern (
        R_STR_WITH_SIZE_ARGS ("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"),
        "* * *\n*", &res), ==, R_STR_MATCH_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 7);
  r_assert_cmpuint (res->token[0].chunk.size, ==, 3);
  r_assert_cmpmem (res->token[0].chunk.str, ==, "GET", 3);
  r_assert_cmpuint (res->token[2].chunk.size, ==, 1);
  r_assert_cmpmem (res->token[2].chunk.str, ==, "/", 1);
  r_assert_cmpuint (res->token[4].chunk.size, ==, 9);
  r_assert_cmpmem (res->token[4].chunk.str, ==, "HTTP/1.1\r", 1);
  r_assert_cmpuint (res->token[6].chunk.size, >, 4);
  r_assert_cmpmem (res->token[6].chunk.str, ==, "Host", 4);

  r_free (res);
}
RTEST_END;

RTEST (rstr, chunk_next_line, RTEST_FAST)
{
  RStrChunk a = { R_STR_WITH_SIZE_ARGS ("foo\r\nbar\nfoobar") };
  RStrChunk b = R_STR_CHUNK_INIT;

  r_assert_cmpint (r_str_chunk_next_line (NULL, NULL), ==, R_STR_PARSE_INVAL);
  r_assert_cmpint (r_str_chunk_next_line (&a, NULL), ==, R_STR_PARSE_INVAL);
  r_assert_cmpint (r_str_chunk_next_line (NULL, &b), ==, R_STR_PARSE_INVAL);
  r_assert_cmpint (r_str_chunk_next_line (&b, &b), ==, R_STR_PARSE_INVAL);

  r_assert_cmpint (r_str_chunk_next_line (&a, &b), ==, R_STR_PARSE_OK);
  r_assert_cmpptr (b.str, ==, a.str); r_assert_cmpuint (b.size, ==, 3);
  r_assert_cmpint (r_str_chunk_next_line (&a, &b), ==, R_STR_PARSE_OK);
  r_assert_cmpptr (b.str, ==, a.str + 5); r_assert_cmpuint (b.size, ==, 3);
  r_assert_cmpint (r_str_chunk_next_line (&a, &b), ==, R_STR_PARSE_OK);
  r_assert_cmpptr (b.str, ==, a.str + 9); r_assert_cmpuint (b.size, ==, 6);
  r_assert_cmpint (r_str_chunk_next_line (&a, &b), ==, R_STR_PARSE_RANGE);
}
RTEST_END;

RTEST (rstr, kv_parse, RTEST_FAST)
{
  RStrKV kv = R_STR_KV_INIT;

  r_assert_cmpint (r_str_kv_parse (NULL, "foo:bar", -1, ":", NULL), ==, R_STR_PARSE_INVAL);
  r_assert_cmpint (r_str_kv_parse (&kv, NULL, -1, ":", NULL), ==, R_STR_PARSE_INVAL);
  r_assert_cmpint (r_str_kv_parse (&kv, "foo:bar", -1, ":", NULL), ==, R_STR_PARSE_OK);
  r_assert_cmpint (r_str_kv_parse (&kv, "foo:bar", 5, ":", NULL), ==, R_STR_PARSE_OK);
  r_assert_cmpint (r_str_kv_parse (&kv, "foo: bar", -1, "=", NULL), ==, R_STR_PARSE_RANGE);
  r_assert_cmpint (r_str_kv_parse (&kv, R_STR_WITH_SIZE_ARGS ("foo\0: bar"), ":", NULL), ==, R_STR_PARSE_OK);
}
RTEST_END;

RTEST (rstr, kv_dup, RTEST_FAST)
{
  RStrKV kv = R_STR_KV_INIT;
  rchar * tmp;

  r_assert_cmpint (r_str_kv_parse (&kv, "foo= bar", -1, "=", NULL), ==, R_STR_PARSE_OK);

  r_assert_cmpstr ((tmp = r_str_kv_dup_key (&kv)), ==, "foo"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_str_kv_dup_value (&kv)), ==, "bar"); r_free (tmp);
}
RTEST_END;

