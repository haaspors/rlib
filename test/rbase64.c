#include <rlib/rlib.h>

RTEST (rbase64, encode, RTEST_FAST)
{
  rchar * tmp;
  rsize out;

  r_assert_cmpptr (r_base64_encode (NULL, 0, NULL), ==, NULL);
  r_assert_cmpptr (r_base64_encode ("foobar", 0, NULL), ==, NULL);

  r_assert_cmpptr ((tmp = r_base64_encode ("foobar", 6, NULL)), !=, NULL);
  r_free (tmp);
  r_assert_cmpstr ((tmp = r_base64_encode ("foobar", 6, &out)), ==, "Zm9vYmFy");
  r_assert_cmpuint (out, ==, 8);
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_base64_encode ("hello", 5, &out)), ==, "aGVsbG8=");
  r_assert_cmpuint (out, ==, 8);
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_base64_encode ("BAAD", 4, &out)), ==, "QkFBRA==");
  r_assert_cmpuint (out, ==, 8);
  r_free (tmp);
}
RTEST_END;

RTEST (rbase64, decode, RTEST_FAST)
{
  ruint8 * tmp;
  rsize out;

  r_assert_cmpptr (r_base64_decode (NULL, 0, NULL), ==, NULL);
  r_assert_cmpptr (r_base64_decode ("foobar", 0, NULL), ==, NULL);

  r_assert_cmpptr ((tmp = r_base64_decode ("Zm9vYmFy", 8, NULL)), !=, NULL);
  r_free (tmp);
  r_assert_cmpptr ((tmp = r_base64_decode ("Zm9vYmFy", -1, NULL)), !=, NULL);
  r_free (tmp);

  tmp = r_base64_decode ("Zm9vYmFy", 8, &out);
  r_assert_cmpuint (out, ==, 6);
  r_assert_cmpmem (tmp, ==, "foobar", out);
  r_free (tmp);

  tmp = r_base64_decode ("aGVsbG8=", -1, &out);
  r_assert_cmpuint (out, ==, 5);
  r_assert_cmpmem (tmp, ==, "hello", out);
  r_free (tmp);

  tmp = r_base64_decode ("QkFBRA==", -1, &out);
  r_assert_cmpuint (out, ==, 4);
  r_assert_cmpmem (tmp, ==, "BAAD", out);
  r_free (tmp);
}
RTEST_END;

RTEST (rbase64, decode_invalid, RTEST_FAST)
{
  ruint8 * tmp;
  rsize out;

  tmp = r_base64_decode ("QkFBRA", -1, &out); /* missing '=' padding */
  r_assert_cmpuint (out, ==, 4);
  r_assert_cmpmem (tmp, ==, "BAAD", out);
  r_free (tmp);

  tmp = r_base64_decode ("QkFB==", -1, &out); /* invalid '=' padding */
  r_assert_cmpuint (out, ==, 3);
  r_assert_cmpmem (tmp, ==, "BAA", out);
  r_free (tmp);

  tmp = r_base64_decode ("Q=", -1, &out); /* invalid '=' padding */
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);

  tmp = r_base64_decode ("===", -1, &out); /* invalid '=' padding */
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);

  tmp = r_base64_decode ("Q", -1, &out); /* 6bits isn't enough for one byte */
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);

  tmp = r_base64_decode ("QkFBR", -1, &out); /* missing bits */
  r_assert_cmpuint (out, ==, 3);
  r_assert_cmpmem (tmp, ==, "BAA", out);
  r_free (tmp);

  tmp = r_base64_decode ("QkFBRP", -1, &out); /* "QkFBRA==" == "QkFBRP" */
  r_assert_cmpuint (out, ==, 4);
  r_assert_cmpmem (tmp, ==, "BAAD", out);
  r_free (tmp);

  tmp = r_base64_decode ("===", -1, &out);
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);
}
RTEST_END;

RTEST (rbase64, decode_spacing, RTEST_FAST)
{
  ruint8 * tmp;
  rsize out;

  tmp = r_base64_decode ("    \n\n\n\n ===", -1, &out);
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);

  tmp = r_base64_decode (" Z \nm9\nvY\nm   Fy\n ===", -1, &out);
  r_assert_cmpuint (out, ==, 6);
  r_assert_cmpmem (tmp, ==, "foobar", out);
  r_free (tmp);
}
RTEST_END;

