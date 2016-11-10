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

RTEST (rbase64, encode_full_rand, RTEST_FAST)
{
  RPrng * prng;
  ruint8 r[757];
  rchar * b64;
  rsize b64size;

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (r_prng_fill (prng, r, sizeof (r)));
  r_prng_unref (prng);

  r_assert_cmpptr ((b64 = r_base64_encode_full (r, sizeof (r), 64, &b64size)), !=, NULL);
  r_assert_cmpuint (b64size, ==, ((757 + 2) / 3) * 4 + 15);
  r_assert_cmpuint (r_strlen (b64), ==, b64size);
  r_free (b64);
}
RTEST_END;

RTEST (rbase64, encode_lines, RTEST_FAST)
{
  rchar * tmp;
  rsize out;
  static rchar rawlong[] = "BAADfoobarCAFebaBE0034asdfbdifdwhfasdhsadk357q3895";
  static rchar b64long[] =
    "QkFBRGZvb2JhckNB\n"
    "RmViYUJFMDAzNGFz\n"
    "ZGZiZGlmZHdoZmFz\n"
    "ZGhzYWRrMzU3cTM4\n"
    "OTU=";

  r_assert_cmpptr (r_base64_encode_full (NULL, 0, 0, NULL), ==, NULL);
  r_assert_cmpptr (r_base64_encode_full ("foobar", 0, 0, NULL), ==, NULL);

  r_assert_cmpstr ((tmp = r_base64_encode_full ("foobar", 6, 0, NULL)), ==, "Zm9vYmFy");
  r_free (tmp);
  r_assert_cmpstr ((tmp = r_base64_encode_full ("foobar", 6, 0, &out)), ==, "Zm9vYmFy");
  r_assert_cmpuint (out, ==, 8);
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_base64_encode_full ("BAAD", 4, 3, &out)), ==, "QkFB\nRA==");
  r_assert_cmpuint (out, ==, 9);
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_base64_encode_full (rawlong, sizeof (rawlong) - 1, 16, &out)), ==, b64long);
  r_assert_cmpuint (out, ==, sizeof (b64long) - 1);
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

