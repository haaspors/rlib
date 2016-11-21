#include <rlib/rlib.h>

RTEST (rstring, new_n_free, RTEST_FAST)
{
  RString * str = r_string_new ("foobar");
  r_assert_cmpptr (str, !=, NULL);
  r_string_free (str);
}
RTEST_END;

RTEST (rstring, new_sized, RTEST_FAST)
{
  RString * str = r_string_new_sized (64);
  r_assert_cmpptr (str, !=, NULL);
  r_string_free (str);
}
RTEST_END;

RTEST (rstring, free_keep, RTEST_FAST)
{
  RString * str = r_string_new ("foobar");
  rchar * cstr = r_string_free_keep (str);
  r_assert_cmpstr (cstr, ==, "foobar");
  r_free (cstr);
}
RTEST_END;

RTEST (rstring, length_n_size, RTEST_FAST)
{
  RString * str = r_string_new_sized (64);
  r_assert_cmpuint (r_string_length (str), ==, 0);
  r_assert_cmpuint (r_string_alloc_size (str), >=, 64);
  r_string_free (str);
}
RTEST_END;

RTEST (rstring, cmp, RTEST_FAST)
{
  RString * str1 = r_string_new ("foobar 42");
  RString * str2 = r_string_new ("barfoo");
  RString * str3 = r_string_new ("foobar 42");

  r_assert_cmpint (r_string_cmp (str1, str2), !=, 0);
  r_assert_cmpint (r_string_cmp (str1, str3), ==, 0);
  r_assert_cmpint (r_string_cmp_cstr (str1, "test"), !=, 0);
  r_assert_cmpint (r_string_cmp_cstr (str1, "foobar 42"), ==, 0);

  r_string_free (str1);
  r_string_free (str2);
  r_string_free (str3);
}
RTEST_END;

RTEST (rstring, reset, RTEST_FAST)
{
  RString * str = r_string_new ("foo");

  r_assert_cmpint (r_string_cmp_cstr (str, "test"), !=, 0);
  r_assert_cmpint (r_string_reset (str, "test"), ==, 4);
  r_assert_cmpint (r_string_cmp_cstr (str, "test"), ==, 0);

  r_string_free (str);
}
RTEST_END;

RTEST (rstring, append, RTEST_FAST)
{
  RString * str = r_string_new ("foo");

  r_assert_cmpint (r_string_append (str, "bar"), ==, 3);
  r_assert_cmpint (r_string_cmp_cstr (str, "foobar"), ==, 0);

  r_assert_cmpint (r_string_append_len (str, "42 foobar", 2), ==, 2);
  r_assert_cmpint (r_string_cmp_cstr (str, "foobar42"), ==, 0);

  r_string_free (str);
}
RTEST_END;

RTEST (rstring, append_printf, RTEST_FAST)
{
  RString * str = r_string_new_sized (64);
  rchar * cstr;

  r_assert_cmpuint (12, ==,
      r_string_append_printf (str, "%u: %s %u", 0, "foobar", 42));
  cstr = r_string_free_keep (str);
  r_assert_cmpstr (cstr, ==, "0: foobar 42");
  r_free (cstr);
}
RTEST_END;

RTEST (rstring, prepend, RTEST_FAST)
{
  RString * str = r_string_new ("bar");

  r_assert_cmpuint (r_string_prepend (str, "foo"), ==, 3);
  r_assert_cmpuint (r_string_cmp_cstr (str, "foobar"), ==, 0);

  r_assert_cmpuint (r_string_prepend_len (str, "0: foobar 42", 3), ==, 3);
  r_assert_cmpuint (r_string_cmp_cstr (str, "0: foobar"), ==, 0);

  r_string_free (str);
}
RTEST_END;

RTEST (rstring, prepend_printf, RTEST_FAST)
{
  RString * str = r_string_new ("foobar");
  rchar * cstr;

  r_string_prepend_printf (str, "%s %u ", "test:", 42);
  cstr = r_string_free_keep (str);
  r_assert_cmpstr (cstr, ==, "test: 42 foobar");
  r_free (cstr);
}
RTEST_END;

RTEST (rstring, prepend_printf_sized, RTEST_FAST)
{
  static const rchar combined[] = "testorgno";
  RString * str = r_string_new_sized (256);
  rchar * cstr;

  r_string_prepend_printf (str, "%s=%.*s",  "CN", 4, &combined[0]);
  r_string_prepend_printf (str, "%s=%.*s,",  "O", 3, &combined[4]);
  cstr = r_string_free_keep (str);
  r_assert_cmpstr (cstr, ==, "O=org,CN=test");
  r_free (cstr);
}
RTEST_END;

RTEST (rstring, insert, RTEST_FAST)
{
  RString * str = r_string_new ("foobar");
  rchar * cstr;

  r_assert_cmpuint (r_string_insert (str, 8, "=2"), ==, 2);
  r_assert_cmpuint (r_string_cmp_cstr (str, "foobar=2"), ==, 0);
  r_assert_cmpuint (r_string_insert (str, 7, "4"), ==, 1);
  r_assert_cmpuint (r_string_length (str), ==, 9);
  cstr = r_string_free_keep (str);
  r_assert_cmpstr (cstr, ==, "foobar=42");
  r_free (cstr);
}
RTEST_END;

RTEST (rstring, insert_len, RTEST_FAST)
{
  RString * str = r_string_new ("foobar");

  r_assert_cmpuint (r_string_insert_len (str, 3, "foobar 42", 3), ==, 3);
  r_assert_cmpuint (r_string_cmp_cstr (str, "foofoobar"), ==, 0);
  r_assert_cmpuint (r_string_length (str), ==, 9);
  r_assert_cmpuint (r_string_insert_len (str, 3, "bar 42", 4), ==, 4);
  r_assert_cmpuint (r_string_cmp_cstr (str, "foobar foobar"), ==, 0);
  r_assert_cmpuint (r_string_length (str), ==, 13);
  r_string_free (str);
}
RTEST_END;

RTEST (rstring, overwrite, RTEST_FAST)
{
  RString * str = r_string_new ("foobar 42");
  rchar * cstr;

  r_assert_cmpuint (r_string_overwrite (str, 6, "=1"), ==, 2);
  r_assert_cmpuint (r_string_cmp_cstr (str, "foobar=12"), ==, 0);
  r_assert_cmpuint (r_string_overwrite (str, 7, "666"), ==, 3);
  r_assert_cmpuint (r_string_length (str), ==, 10);
  cstr = r_string_free_keep (str);
  r_assert_cmpstr (cstr, ==, "foobar=666");
  r_free (cstr);
}
RTEST_END;

RTEST (rstring, overwrite_len, RTEST_FAST)
{
  RString * str = r_string_new ("foobar");

  r_assert_cmpuint (r_string_overwrite_len (str, 3, "foobar 42", 3), ==, 3);
  r_assert_cmpuint (r_string_cmp_cstr (str, "foofoo"), ==, 0);
  r_assert_cmpuint (r_string_length (str), ==, 6);
  r_assert_cmpuint (r_string_overwrite_len (str, 0, "bardkjf", 3), ==, 3);
  r_assert_cmpuint (r_string_cmp_cstr (str, "barfoo"), ==, 0);
  r_assert_cmpuint (r_string_length (str), ==, 6);
  r_string_free (str);
}
RTEST_END;

RTEST (rstring, truncate, RTEST_FAST)
{
  RString * str = r_string_new ("foobar 42");
  rchar * cstr;

  r_assert_cmpuint (r_string_truncate (str, 42), ==, 0);
  r_assert_cmpuint (r_string_truncate (str, 6), ==, 3);
  cstr = r_string_free_keep (str);
  r_assert_cmpstr (cstr, ==, "foobar");
  r_free (cstr);
}
RTEST_END;

RTEST (rstring, erase, RTEST_FAST)
{
  RString * str = r_string_new ("foobar 42");
  rchar * cstr;

  r_assert_cmpuint (r_string_erase (str, 42, 3), ==, 0);
  r_assert_cmpuint (r_string_erase (str, 3, 3), ==, 6);
  cstr = r_string_free_keep (str);
  r_assert_cmpstr (cstr, ==, "foo 42");
  r_free (cstr);
}
RTEST_END;

RTEST (rstring, check_for_null, RTEST_FAST)
{
  RString * str = r_string_new (NULL);

  r_assert_cmpuint (r_string_length (str), ==, 0);

  r_assert_cmpuint (r_string_append (str, NULL), ==, 0);
  r_assert_cmpuint (r_string_append_len (str, NULL, 2), ==, 0);
  r_assert_cmpuint (r_string_prepend (str, NULL), ==, 0);
  r_assert_cmpuint (r_string_prepend_len (str, NULL, 2), ==, 0);
  r_assert_cmpuint (r_string_reset (str, "foobar"), ==, 6);
  r_assert_cmpuint (r_string_insert (str, 0, NULL), ==, 0);
  r_assert_cmpuint (r_string_insert_len (str, 0, NULL, 3), ==, 0);
  r_assert_cmpuint (r_string_overwrite (str, 0, NULL), ==, 0);
  r_assert_cmpuint (r_string_overwrite_len (str, 0, NULL, 3), ==, 0);
  r_assert_cmpuint (r_string_reset (str, NULL), ==, 0);

  r_assert_cmpuint (r_string_length (str), ==, 0);
  r_string_free (str);
}
RTEST_END;
