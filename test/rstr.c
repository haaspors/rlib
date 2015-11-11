#include <rlib/rlib.h>

static const rchar foobar[] = "foobar";
static const rchar foo[] = "foo";
static const rchar bar[] = "bar";
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

RTEST (rstr, join, RTEST_FAST)
{
  rchar * join;

  r_assert_cmpstr ((join = r_strjoin ("", foo, bar, NULL)), ==, foobar); r_free (join);
  r_assert_cmpstr ((join = r_strjoin ("", foobar, NULL)), ==, foobar); r_free (join);
  r_assert_cmpstr ((join = r_strjoin ("-", foo, bar, NULL)), ==, "foo-bar"); r_free (join);
  r_assert_cmpstr (r_strjoin (NULL, foo, bar, NULL), ==, NULL);
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
  ruint offset = 16;
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
}
RTEST_END;

