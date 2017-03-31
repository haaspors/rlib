#include <rlib/rlib.h>

RTEST (rbase64, is_valid_char, RTEST_FAST)
{
  rsize count;
  rchar c;

  for (c = 0, count = 0; c < RCHAR_MAX; c++)
    if (r_base64_is_valid_char (c)) count++;

  r_assert_cmpuint (count, ==, 64);
}
RTEST_END;

RTEST (rbase64, encode, RTEST_FAST)
{
  static const ruint8 r6[] = { 'f', 'o', 'o', 'b', 'a', 'r' };
  static const ruint8 r5[] = { 'h', 'e', 'l', 'l', 'o' };
  static const ruint8 r4[] = { 'B', 'A', 'A', 'D' };
  static const ruint8 r3[] = { 'F', 'O', 'O' };
  rchar b64[8];

  r_assert_cmpuint (r_base64_encode (NULL, 0, r6, sizeof (r6)), ==, 0);
  r_assert_cmpuint (r_base64_encode (b64, sizeof (b64), NULL, sizeof (r6)), ==, 0);
  r_assert_cmpuint (r_base64_encode (b64, sizeof (b64), r6, 0), ==, 0);

  r_assert_cmpuint (r_base64_encode (b64, sizeof (b64), r6, sizeof (r6)), ==, 8);
  r_assert_cmpstrn (b64, ==, "Zm9vYmFy", 8);
  r_assert_cmpuint (r_base64_encode (b64, sizeof (b64), r5, sizeof (r5)), ==, 8);
  r_assert_cmpstrn (b64, ==, "aGVsbG8=", 8);
  r_assert_cmpuint (r_base64_encode (b64, sizeof (b64), r4, sizeof (r4)), ==, 8);
  r_assert_cmpstrn (b64, ==, "QkFBRA==", 8);
  r_assert_cmpuint (r_base64_encode (b64, sizeof (b64), r3, sizeof (r3)), ==, 4);
  r_assert_cmpstrn (b64, ==, "Rk9P", 4);
}
RTEST_END;

RTEST (rbase64, decode, RTEST_FAST)
{
  static const ruint8 r6[] = { 'f', 'o', 'o', 'b', 'a', 'r' };
  static const ruint8 r5[] = { 'h', 'e', 'l', 'l', 'o' };
  static const ruint8 r4[] = { 'B', 'A', 'A', 'D' };
  static const ruint8 r3[] = { 'F', 'O', 'O' };
  ruint8 r[8];

  r_assert_cmpuint (r_base64_decode (r, sizeof (r), NULL, 0), ==, 0);
  r_assert_cmpuint (r_base64_decode (r, sizeof (r), NULL, 0), ==, 0);

  r_assert_cmpuint (r_base64_decode (r, sizeof (r), R_STR_WITH_SIZE_ARGS ("Zm9vYmFy")), ==, sizeof (r6));
  r_assert_cmpmem (r, ==, r6, sizeof (r6));
  r_assert_cmpuint (r_base64_decode (r, sizeof (r), R_STR_WITH_SIZE_ARGS ("aGVsbG8=")), ==, sizeof (r5));
  r_assert_cmpmem (r, ==, r5, sizeof (r5));
  r_assert_cmpuint (r_base64_decode (r, sizeof (r), R_STR_WITH_SIZE_ARGS ("aGVsbG8")), ==, sizeof (r5));
  r_assert_cmpmem (r, ==, r5, sizeof (r5));
  r_assert_cmpuint (r_base64_decode (r, sizeof (r), R_STR_WITH_SIZE_ARGS ("QkFBRA==")), ==, sizeof (r4));
  r_assert_cmpmem (r, ==, r4, sizeof (r4));
  r_assert_cmpuint (r_base64_decode (r, sizeof (r), R_STR_WITH_SIZE_ARGS ("QkFBRA=")), ==, sizeof (r4));
  r_assert_cmpmem (r, ==, r4, sizeof (r4));
  r_assert_cmpuint (r_base64_decode (r, sizeof (r), R_STR_WITH_SIZE_ARGS ("QkFBRA")), ==, sizeof (r4));
  r_assert_cmpmem (r, ==, r4, sizeof (r4));
  r_assert_cmpuint (r_base64_decode (r, sizeof (r), R_STR_WITH_SIZE_ARGS ("Rk9P")), ==, sizeof (r3));
  r_assert_cmpmem (r, ==, r3, sizeof (r3));
}
RTEST_END;

RTEST (rbase64, encode_dup, RTEST_FAST)
{
  rchar * tmp;
  rsize out;

  r_assert_cmpptr (r_base64_encode_dup (NULL, 0, NULL), ==, NULL);
  r_assert_cmpptr (r_base64_encode_dup ("foobar", 0, NULL), ==, NULL);

  r_assert_cmpptr ((tmp = r_base64_encode_dup ("foobar", 6, NULL)), !=, NULL);
  r_free (tmp);
  r_assert_cmpstr ((tmp = r_base64_encode_dup ("foobar", 6, &out)), ==, "Zm9vYmFy");
  r_assert_cmpuint (out, ==, 8);
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_base64_encode_dup ("hello", 5, &out)), ==, "aGVsbG8=");
  r_assert_cmpuint (out, ==, 8);
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_base64_encode_dup ("BAAD", 4, &out)), ==, "QkFBRA==");
  r_assert_cmpuint (out, ==, 8);
  r_free (tmp);
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

  r_assert_cmpptr (r_base64_encode_dup_full (NULL, 0, 0, NULL), ==, NULL);
  r_assert_cmpptr (r_base64_encode_dup_full ("foobar", 0, 0, NULL), ==, NULL);

  r_assert_cmpstr ((tmp = r_base64_encode_dup_full ("foobar", 6, 0, NULL)), ==, "Zm9vYmFy");
  r_free (tmp);
  r_assert_cmpstr ((tmp = r_base64_encode_dup_full ("foobar", 6, 0, &out)), ==, "Zm9vYmFy");
  r_assert_cmpuint (out, ==, 8);
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_base64_encode_dup_full ("BAAD", 4, 3, &out)), ==, "QkFB\nRA==");
  r_assert_cmpuint (out, ==, 9);
  r_free (tmp);

  r_assert_cmpstr ((tmp = r_base64_encode_dup_full (rawlong, sizeof (rawlong) - 1, 16, &out)), ==, b64long);
  r_assert_cmpuint (out, ==, sizeof (b64long) - 1);
  r_free (tmp);
}
RTEST_END;

RTEST (rbase64, decode_dup, RTEST_FAST)
{
  ruint8 * tmp;
  rsize out;

  r_assert_cmpptr (r_base64_decode_dup (NULL, 0, NULL), ==, NULL);
  r_assert_cmpptr (r_base64_decode_dup ("foobar", 0, NULL), ==, NULL);

  r_assert_cmpptr ((tmp = r_base64_decode_dup ("Zm9vYmFy", 8, NULL)), !=, NULL);
  r_free (tmp);
  r_assert_cmpptr ((tmp = r_base64_decode_dup ("Zm9vYmFy", -1, NULL)), !=, NULL);
  r_free (tmp);

  tmp = r_base64_decode_dup ("Zm9vYmFy", 8, &out);
  r_assert_cmpuint (out, ==, 6);
  r_assert_cmpmem (tmp, ==, "foobar", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("aGVsbG8=", -1, &out);
  r_assert_cmpuint (out, ==, 5);
  r_assert_cmpmem (tmp, ==, "hello", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("QkFBRA==", -1, &out);
  r_assert_cmpuint (out, ==, 4);
  r_assert_cmpmem (tmp, ==, "BAAD", out);
  r_free (tmp);
}
RTEST_END;

RTEST (rbase64, decode_invalid, RTEST_FAST)
{
  ruint8 * tmp;
  rsize out;

  tmp = r_base64_decode_dup ("QkFBRA", -1, &out); /* missing '=' padding */
  r_assert_cmpuint (out, ==, 4);
  r_assert_cmpmem (tmp, ==, "BAAD", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("QkFB==", -1, &out); /* invalid '=' padding */
  r_assert_cmpuint (out, ==, 3);
  r_assert_cmpmem (tmp, ==, "BAA", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("Q=", -1, &out); /* invalid '=' padding */
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("===", -1, &out); /* invalid '=' padding */
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("Q", -1, &out); /* 6bits isn't enough for one byte */
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("QkFBR", -1, &out); /* missing bits */
  r_assert_cmpuint (out, ==, 3);
  r_assert_cmpmem (tmp, ==, "BAA", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("QkFBRP", -1, &out); /* "QkFBRA==" == "QkFBRP" */
  r_assert_cmpuint (out, ==, 4);
  r_assert_cmpmem (tmp, ==, "BAAD", out);
  r_free (tmp);

  tmp = r_base64_decode_dup ("===", -1, &out);
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);
}
RTEST_END;

RTEST (rbase64, decode_spacing, RTEST_FAST)
{
  ruint8 * tmp;
  rsize out;

  tmp = r_base64_decode_dup ("    \n\n\n\n ===", -1, &out);
  r_assert_cmpuint (out, ==, 0);
  r_assert_cmpmem (tmp, ==, "", out);
  r_free (tmp);

  tmp = r_base64_decode_dup (" Z \nm9\nvY\nm   Fy\n ===", -1, &out);
  r_assert_cmpuint (out, ==, 6);
  r_assert_cmpmem (tmp, ==, "foobar", out);
  r_free (tmp);
}
RTEST_END;

