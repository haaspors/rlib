#include <rlib/rlib.h>

RTEST (renv, set_get_unset, RTEST_FAST)
{
  static const rchar key[] = "R_TEST_RENV_VAR";

  /* Start from a known-unset state. */
  r_unsetenv (key);
  r_assert_cmpptr (r_getenv (key), ==, NULL);

  r_assert (r_setenv (key, "hello", TRUE));
  r_assert_cmpstr (r_getenv (key), ==, "hello");

  /* always == FALSE keeps the existing value but reports success. */
  r_assert (r_setenv (key, "world", FALSE));
  r_assert_cmpstr (r_getenv (key), ==, "hello");

  /* always == TRUE overwrites. */
  r_assert (r_setenv (key, "world", TRUE));
  r_assert_cmpstr (r_getenv (key), ==, "world");

  r_assert (r_unsetenv (key));
  r_assert_cmpptr (r_getenv (key), ==, NULL);
}
RTEST_END;

RTEST (renv, utf8_roundtrip, RTEST_FAST)
{
  static const rchar key[] = "R_TEST_RENV_UTF8";
  /* "æøå -> :)" with non-ASCII (2-byte), an arrow (3-byte) and an emoji
   * (4-byte, a surrogate pair in UTF-16): exercises the win32 UTF-8<->UTF-16
   * conversion across the full BMP/astral range. */
  static const rchar val[] =
      "\xc3\xa6\xc3\xb8\xc3\xa5 \xe2\x86\x92 \xf0\x9f\x98\x80";

  r_unsetenv (key);
  r_assert (r_setenv (key, val, TRUE));
  r_assert_cmpstr (r_getenv (key), ==, val);
  r_assert (r_unsetenv (key));
  r_assert_cmpptr (r_getenv (key), ==, NULL);
}
RTEST_END;

RTEST (renv, get_survives_other_lookup, RTEST_FAST)
{
  const rchar * a;

  r_assert (r_setenv ("R_TEST_RENV_A", "aaa", TRUE));
  r_assert (r_setenv ("R_TEST_RENV_B", "bbb", TRUE));

  a = r_getenv ("R_TEST_RENV_A");
  r_assert_cmpstr (a, ==, "aaa");
  /* Looking up a different variable must not invalidate an earlier result:
   * callers hold getenv pointers across other lookups (r_fs_get_tmp_dir
   * caches r_getenv ("TEMP") for the process lifetime). */
  r_assert_cmpstr (r_getenv ("R_TEST_RENV_B"), ==, "bbb");
  r_assert_cmpstr (a, ==, "aaa");

  r_assert (r_unsetenv ("R_TEST_RENV_A"));
  r_assert (r_unsetenv ("R_TEST_RENV_B"));
}
RTEST_END;

RTEST (renv, null_args, RTEST_FAST)
{
  r_assert_cmpptr (r_getenv (NULL), ==, NULL);
  r_assert (!r_setenv (NULL, "x", TRUE));
  r_assert (!r_setenv ("x", NULL, TRUE));
  r_assert (!r_unsetenv (NULL));
}
RTEST_END;
