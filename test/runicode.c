#include <rlib/rlib.h>

RTEST (runicode, utf16_to_utf8, RTEST_FAST)
{
  runichar2 utf16[64], * utf16end;
  rchar * utf8;
  rsize u8len;
  RUnicodeResult res;

  utf16[0] = 0x61; utf16[1] = 0x62; utf16[2] = 0x63;
  utf16[3] = 0x31; utf16[4] = 0x32; utf16[5] = 0x33;
  utf16[6] = 0x21; utf16[7] = 0x22; utf16[8] = 0x23; utf16[9] = 0;
  r_assert_cmpptr ((utf8 = r_utf16_to_utf8_dup (utf16, 9, &res, &u8len, &utf16end)), !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpstr (utf8, ==, "abc123!\"#");
  r_assert_cmpuint (u8len, ==, 9);
  r_assert_cmpptr (utf16end, ==, utf16 + 9);
  r_free (utf8);

  /* 2byte UTF-8 */
  utf16[0] = 0x3b1; utf16[1] = 0x3b2; utf16[2] = 0x3b3; utf16[3] = 0;
  r_assert_cmpptr ((utf8 = r_utf16_to_utf8_dup (utf16, 3, &res, &u8len, &utf16end)), !=, NULL);
  r_assert_cmpstr (utf8, ==, "\xCE\xB1\xCE\xB2\xCE\xB3");
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (u8len, ==, 6);
  r_assert_cmpptr (utf16end, ==, utf16 + 3);
  r_free (utf8);

  /* Maxium UTF-16: 0x10FFFF = 0xD8FF 0xDFFFF = 4byte UTF-8*/
  utf16[0] = 0xDBFF; utf16[1] = 0xDFFF; utf16[2] = 0;
  r_assert_cmpptr ((utf8 = r_utf16_to_utf8_dup (utf16, 4, &res, &u8len, &utf16end)), !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpmem (utf8, ==, "\xF4\x8F\xBF\xBF", 4);
  r_assert_cmpuint (u8len, ==, 4);
  r_assert_cmpptr (utf16end, ==, utf16 + 2);
  r_free (utf8);

  /* Partial UTF-16, missing low surrogate. srcendptr points AT the
   * unconsumed high surrogate so the caller can resume from there
   * once more units arrive. */
  utf16[0] = 0x78; utf16[1] = 0x79; utf16[2] = 0xd801; utf16[3] = 0;
  r_assert_cmpptr ((utf8 = r_utf16_to_utf8_dup (utf16, 3, &res, &u8len, &utf16end)), ==, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (u8len, ==, 2);
  r_assert_cmpptr (utf16end, ==, utf16 + 2);

  /* Invalid UTF-16, missing high surrogate */
  utf16[0] = 0x79; utf16[1] = 0x7A; utf16[2] = 0xdc01; utf16[3] = 0;
  r_assert_cmpptr ((utf8 = r_utf16_to_utf8_dup (utf16, 3, &res, &u8len, &utf16end)), ==, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (u8len, ==, 2);
  r_assert_cmpptr (utf16end, ==, utf16 + 2);
}
RTEST_END;

RTEST (runicode, utf8_to_utf16, RTEST_FAST)
{
  runichar2 utf16[64], * ptr;
  rchar * utf8end;
  rsize u16len;
  RUnicodeResult res;
  const rchar * utf8;

  utf8 = "abc123!\"#";
  r_assert_cmpptr ((ptr = r_utf8_to_utf16_dup (utf8, -1, &res, &u16len, &utf8end)), !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (u16len, ==, 9);
  r_assert_cmpptr (utf8end, ==, utf8 + 9);
  utf16[0] = 0x61; utf16[1] = 0x62; utf16[2] = 0x63;
  utf16[3] = 0x31; utf16[4] = 0x32; utf16[5] = 0x33;
  utf16[6] = 0x21; utf16[7] = 0x22; utf16[8] = 0x23; utf16[9] = 0;
  r_assert_cmpmem (ptr, ==, utf16, sizeof (runichar2) * 9);
  r_free (ptr);

  utf8 = "\xCE\xB1\xCE\xB2\xCE\xB3";
  r_assert_cmpptr ((ptr = r_utf8_to_utf16_dup (utf8, -1, &res, &u16len, &utf8end)), !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (u16len, ==, 3);
  r_assert_cmpptr (utf8end, ==, utf8 + 6);
  utf16[0] = 0x3b1; utf16[1] = 0x3b2; utf16[2] = 0x3b3; utf16[3] = 0;
  r_assert_cmpmem (ptr, ==, utf16, sizeof (runichar2) * 3);
  r_free (ptr);

  /* Error, partial utf8 codepoint (missing 0x80 in second byte) */
  utf8 = "\xCE\xB1\xCE\xB2\xCE\x33";
  r_assert_cmpptr ((ptr = r_utf8_to_utf16_dup (utf8, -1, &res, &u16len, &utf8end)), ==, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (u16len, ==, 2);
  r_assert_cmpptr (utf8end, ==, utf8 + 4);

  /* Error, invalid utf8 codepoint */
  utf8 = "\xCE\xB1\xFE\xB2\xCE\xC3";
  r_assert_cmpptr ((ptr = r_utf8_to_utf16_dup (utf8, -1, &res, &u16len, &utf8end)), ==, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (u16len, ==, 1);
  r_assert_cmpptr (utf8end, ==, utf8 + 2);
}
RTEST_END;


RTEST (runicode, utf16_to_utf8_bom, RTEST_FAST)
{
  runichar2 utf16[8], * utf16end;
  rchar * utf8;
  rsize u8len;
  RUnicodeResult res;

  /* Leading native-order BOM (0xFEFF) must be silently stripped. */
  utf16[0] = 0xFEFF;
  utf16[1] = 0x61; utf16[2] = 0x62; utf16[3] = 0x63; utf16[4] = 0;
  r_assert_cmpptr (
      (utf8 = r_utf16_to_utf8_dup (utf16, 4, &res, &u8len, &utf16end)),
      !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpstr (utf8, ==, "abc");
  r_assert_cmpuint (u8len, ==, 3);
  r_free (utf8);

  /* Byte-swapped BOM (0xFFFE) means the caller's data is in the wrong
   * endianness for our typed ruint16 input -- refuse. */
  utf16[0] = 0xFFFE;
  utf16[1] = 0x61; utf16[2] = 0;
  r_assert_cmpptr (
      r_utf16_to_utf8_dup (utf16, 2, &res, &u8len, &utf16end), ==, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_INVAL);

  /* A non-BOM 0xFEFF deeper in the stream is a zero-width no-break space
   * code point and must be passed through, not stripped. */
  utf16[0] = 0x61; utf16[1] = 0xFEFF; utf16[2] = 0x62; utf16[3] = 0;
  r_assert_cmpptr (
      (utf8 = r_utf16_to_utf8_dup (utf16, 3, &res, &u8len, &utf16end)),
      !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpmem (utf8, ==, "a\xEF\xBB\xBF" "b", 5);
  r_free (utf8);
}
RTEST_END;

RTEST (runicode, utf8_to_utf16_bom, RTEST_FAST)
{
  runichar2 * ptr;
  rchar * utf8end;
  rsize u16len;
  RUnicodeResult res;
  const rchar * utf8;

  /* Leading UTF-8 BOM (0xEF 0xBB 0xBF) must be silently stripped. */
  utf8 = "\xEF\xBB\xBF" "abc";
  r_assert_cmpptr ((ptr = r_utf8_to_utf16_dup (utf8, -1, &res, &u16len, &utf8end)),
      !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (u16len, ==, 3);
  r_assert_cmphex (ptr[0], ==, 'a');
  r_assert_cmphex (ptr[1], ==, 'b');
  r_assert_cmphex (ptr[2], ==, 'c');
  r_free (ptr);

  /* A non-leading 0xEF 0xBB 0xBF sequence is a normal U+FEFF code point. */
  utf8 = "a\xEF\xBB\xBF" "b";
  r_assert_cmpptr ((ptr = r_utf8_to_utf16_dup (utf8, -1, &res, &u16len, &utf8end)),
      !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (u16len, ==, 3);
  r_assert_cmphex (ptr[0], ==, 'a');
  r_assert_cmphex (ptr[1], ==, 0xFEFF);
  r_assert_cmphex (ptr[2], ==, 'b');
  r_free (ptr);
}
RTEST_END;

/* ---- UTF-32 conversions ------------------------------------------ */

RTEST (runicode, utf8_to_utf32, RTEST_FAST)
{
  runichar4 utf32[16];
  rchar * utf8end;
  rsize n;
  RUnicodeResult res;

  /* ASCII round-trip. */
  res = r_utf8_to_utf32 (utf32, R_N_ELEMENTS (utf32), "abc123!\"#", 9,
      &n, &utf8end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 9);
  r_assert_cmpuint (utf32[0], ==, 'a');
  r_assert_cmpuint (utf32[8], ==, '#');
  r_assert_cmpuint (utf32[9], ==, 0);
  r_assert_cmpptr (utf8end, ==, (rchar *)"abc123!\"#" + 9);

  /* 2-byte UTF-8: U+03B1, U+03B2, U+03B3. */
  res = r_utf8_to_utf32 (utf32, R_N_ELEMENTS (utf32),
      "\xCE\xB1\xCE\xB2\xCE\xB3", 6, &n, &utf8end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 3);
  r_assert_cmpuint (utf32[0], ==, 0x3b1);
  r_assert_cmpuint (utf32[1], ==, 0x3b2);
  r_assert_cmpuint (utf32[2], ==, 0x3b3);

  /* 4-byte UTF-8: U+10FFFF (max codepoint). */
  res = r_utf8_to_utf32 (utf32, R_N_ELEMENTS (utf32),
      "\xF4\x8F\xBF\xBF", 4, &n, &utf8end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (utf32[0], ==, 0x10FFFF);
}
RTEST_END;

RTEST (runicode, utf8_to_utf32_overflow, RTEST_FAST)
{
  runichar4 utf32[4];   /* Capacity 3 + NUL. */
  rchar * utf8end;
  rsize n;
  RUnicodeResult res;

  res = r_utf8_to_utf32 (utf32, R_N_ELEMENTS (utf32), "abcdef", 6,
      &n, &utf8end);
  r_assert_cmpint (res, ==, R_UNICODE_OVERFLOW);
  r_assert_cmpuint (n, ==, 3);
}
RTEST_END;

RTEST (runicode, utf8_to_utf32_incomplete, RTEST_FAST)
{
  runichar4 utf32[8];
  rchar * utf8end;
  rsize n;
  RUnicodeResult res;

  /* "ab" + truncated 2-byte sequence (0xCE without continuation). */
  res = r_utf8_to_utf32 (utf32, R_N_ELEMENTS (utf32), "ab\xCE", 3,
      &n, &utf8end);
  r_assert_cmpint (res, ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (n, ==, 2);
  r_assert_cmpuint (utf32[0], ==, 'a');
  r_assert_cmpuint (utf32[1], ==, 'b');
}
RTEST_END;

RTEST (runicode, utf8_to_utf32_invalid, RTEST_FAST)
{
  runichar4 utf32[8];
  rchar * utf8end;
  rsize n;
  RUnicodeResult res;

  /* UTF-8 encoding of U+D800 (high surrogate) - valid bit pattern
   * but the codepoint is invalid. */
  res = r_utf8_to_utf32 (utf32, R_N_ELEMENTS (utf32), "a\xED\xA0\x80", 4,
      &n, &utf8end);
  r_assert_cmpint (res, ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (utf32[0], ==, 'a');
}
RTEST_END;

RTEST (runicode, utf32_to_utf8, RTEST_FAST)
{
  runichar4 utf32[16];
  runichar4 * utf32end;
  rchar utf8[64];
  rsize n;
  RUnicodeResult res;

  utf32[0] = 'a'; utf32[1] = 'b'; utf32[2] = 'c'; utf32[3] = 0;
  res = r_utf32_to_utf8 (utf8, sizeof (utf8), utf32, 3, &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 3);
  r_assert_cmpstr (utf8, ==, "abc");

  /* 2-byte UTF-8 outputs. */
  utf32[0] = 0x3b1; utf32[1] = 0x3b2; utf32[2] = 0x3b3; utf32[3] = 0;
  res = r_utf32_to_utf8 (utf8, sizeof (utf8), utf32, 3, &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 6);
  r_assert_cmpmem (utf8, ==, "\xCE\xB1\xCE\xB2\xCE\xB3", 6);

  /* Max codepoint -> 4-byte UTF-8. */
  utf32[0] = 0x10FFFF; utf32[1] = 0;
  res = r_utf32_to_utf8 (utf8, sizeof (utf8), utf32, 1, &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 4);
  r_assert_cmpmem (utf8, ==, "\xF4\x8F\xBF\xBF", 4);
}
RTEST_END;

RTEST (runicode, utf32_to_utf8_overflow, RTEST_FAST)
{
  runichar4 utf32[4];
  runichar4 * utf32end;
  rchar utf8[4];   /* Capacity 3 + NUL; "abcdef" needs 6 + 1. */
  rsize n;
  RUnicodeResult res;

  utf32[0] = 'a'; utf32[1] = 'b'; utf32[2] = 'c'; utf32[3] = 'd';
  res = r_utf32_to_utf8 (utf8, sizeof (utf8), utf32, 4, &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_OVERFLOW);
  r_assert_cmpuint (n, ==, 3);
}
RTEST_END;

RTEST (runicode, utf32_to_utf8_invalid, RTEST_FAST)
{
  runichar4 utf32[4];
  runichar4 * utf32end;
  rchar utf8[16];
  rsize n;
  RUnicodeResult res;

  /* Out-of-range codepoint. */
  utf32[0] = 'a'; utf32[1] = 0x110000;
  res = r_utf32_to_utf8 (utf8, sizeof (utf8), utf32, 2, &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);

  /* Surrogate-half codepoint. */
  utf32[0] = 'a'; utf32[1] = 0xd800;
  res = r_utf32_to_utf8 (utf8, sizeof (utf8), utf32, 2, &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);
}
RTEST_END;

RTEST (runicode, utf16_to_utf32, RTEST_FAST)
{
  runichar4 utf32[16];
  runichar2 utf16[16];
  runichar2 * utf16end;
  rsize n;
  RUnicodeResult res;

  utf16[0] = 'a'; utf16[1] = 'b'; utf16[2] = 'c'; utf16[3] = 0;
  res = r_utf16_to_utf32 (utf32, R_N_ELEMENTS (utf32), utf16, 3,
      &n, &utf16end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 3);
  r_assert_cmpuint (utf32[0], ==, 'a');

  /* Surrogate pair: U+10000. */
  utf16[0] = 0xD800; utf16[1] = 0xDC00;
  res = r_utf16_to_utf32 (utf32, R_N_ELEMENTS (utf32), utf16, 2,
      &n, &utf16end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (utf32[0], ==, 0x10000);

  /* Surrogate pair: U+10FFFF. */
  utf16[0] = 0xDBFF; utf16[1] = 0xDFFF;
  res = r_utf16_to_utf32 (utf32, R_N_ELEMENTS (utf32), utf16, 2,
      &n, &utf16end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (utf32[0], ==, 0x10FFFF);
}
RTEST_END;

RTEST (runicode, utf16_to_utf32_overflow, RTEST_FAST)
{
  runichar4 utf32[4];
  runichar2 utf16[8];
  runichar2 * utf16end;
  rsize n;
  RUnicodeResult res;

  utf16[0] = 'a'; utf16[1] = 'b'; utf16[2] = 'c';
  utf16[3] = 'd'; utf16[4] = 'e'; utf16[5] = 'f';
  res = r_utf16_to_utf32 (utf32, R_N_ELEMENTS (utf32), utf16, 6,
      &n, &utf16end);
  r_assert_cmpint (res, ==, R_UNICODE_OVERFLOW);
  r_assert_cmpuint (n, ==, 3);
}
RTEST_END;

RTEST (runicode, utf16_to_utf32_incomplete, RTEST_FAST)
{
  runichar4 utf32[8];
  runichar2 utf16[4];
  runichar2 * utf16end;
  rsize n;
  RUnicodeResult res;

  /* High surrogate with no following low surrogate. */
  utf16[0] = 'x'; utf16[1] = 'y'; utf16[2] = 0xD801;
  res = r_utf16_to_utf32 (utf32, R_N_ELEMENTS (utf32), utf16, 3,
      &n, &utf16end);
  r_assert_cmpint (res, ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (n, ==, 2);
}
RTEST_END;

RTEST (runicode, utf16_to_utf32_invalid, RTEST_FAST)
{
  runichar4 utf32[8];
  runichar2 utf16[4];
  runichar2 * utf16end;
  rsize n;
  RUnicodeResult res;

  /* Low surrogate with no preceding high surrogate. */
  utf16[0] = 'y'; utf16[1] = 'z'; utf16[2] = 0xDC01;
  res = r_utf16_to_utf32 (utf32, R_N_ELEMENTS (utf32), utf16, 3,
      &n, &utf16end);
  r_assert_cmpint (res, ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 2);
}
RTEST_END;

RTEST (runicode, utf32_to_utf16, RTEST_FAST)
{
  runichar4 utf32[16];
  runichar4 * utf32end;
  runichar2 utf16[16];
  rsize n;
  RUnicodeResult res;

  utf32[0] = 'a'; utf32[1] = 'b'; utf32[2] = 'c';
  res = r_utf32_to_utf16 (utf16, R_N_ELEMENTS (utf16), utf32, 3,
      &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 3);
  r_assert_cmpuint (utf16[0], ==, 'a');

  /* Beyond-BMP codepoint emits surrogate pair. */
  utf32[0] = 0x10000;
  res = r_utf32_to_utf16 (utf16, R_N_ELEMENTS (utf16), utf32, 1,
      &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 2);
  r_assert_cmpuint (utf16[0], ==, 0xD800);
  r_assert_cmpuint (utf16[1], ==, 0xDC00);

  utf32[0] = 0x10FFFF;
  res = r_utf32_to_utf16 (utf16, R_N_ELEMENTS (utf16), utf32, 1,
      &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 2);
  r_assert_cmpuint (utf16[0], ==, 0xDBFF);
  r_assert_cmpuint (utf16[1], ==, 0xDFFF);
}
RTEST_END;

RTEST (runicode, utf32_to_utf16_overflow, RTEST_FAST)
{
  runichar4 utf32[4];
  runichar4 * utf32end;
  runichar2 utf16[3];   /* Capacity 2 + NUL. */
  rsize n;
  RUnicodeResult res;

  utf32[0] = 'a'; utf32[1] = 'b'; utf32[2] = 'c';
  res = r_utf32_to_utf16 (utf16, R_N_ELEMENTS (utf16), utf32, 3,
      &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_OVERFLOW);
  r_assert_cmpuint (n, ==, 2);
}
RTEST_END;

RTEST (runicode, utf32_to_utf16_invalid, RTEST_FAST)
{
  runichar4 utf32[4];
  runichar4 * utf32end;
  runichar2 utf16[16];
  rsize n;
  RUnicodeResult res;

  /* Out-of-range. */
  utf32[0] = 'a'; utf32[1] = 0x110000;
  res = r_utf32_to_utf16 (utf16, R_N_ELEMENTS (utf16), utf32, 2,
      &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);

  /* Surrogate-half. */
  utf32[0] = 'a'; utf32[1] = 0xDC00;
  res = r_utf32_to_utf16 (utf16, R_N_ELEMENTS (utf16), utf32, 2,
      &n, &utf32end);
  r_assert_cmpint (res, ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);
}
RTEST_END;

RTEST (runicode, utf8_to_utf32_dup_roundtrip, RTEST_FAST)
{
  const rchar * input = "abc\xCE\xB1\xCE\xB2\xCE\xB3\xF4\x8F\xBF\xBF";
  runichar4 * utf32;
  rchar * back;
  rchar * end;
  runichar4 * end32;
  RUnicodeResult res;
  rsize len;

  utf32 = r_utf8_to_utf32_dup (input, -1, &res, &len, &end);
  r_assert_cmpptr (utf32, !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (len, ==, 7);  /* 3 ASCII + 3 Greek + 1 supplementary */

  back = r_utf32_to_utf8_dup (utf32, len, &res, &len, &end32);
  r_assert_cmpptr (back, !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpstr (back, ==, input);

  r_free (utf32);
  r_free (back);
}
RTEST_END;

RTEST (runicode, utf16_to_utf32_dup_roundtrip, RTEST_FAST)
{
  runichar2 utf16[6];
  runichar4 * utf32;
  runichar2 * back;
  runichar2 * end16;
  runichar4 * end32;
  RUnicodeResult res;
  rsize len;

  utf16[0] = 'a'; utf16[1] = 'b'; utf16[2] = 0x3B1;
  utf16[3] = 0xD800; utf16[4] = 0xDC00;     /* U+10000 surrogate pair */
  utf16[5] = 'z';

  utf32 = r_utf16_to_utf32_dup (utf16, 6, &res, &len, &end16);
  r_assert_cmpptr (utf32, !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (len, ==, 5);
  r_assert_cmpuint (utf32[3], ==, 0x10000);

  back = r_utf32_to_utf16_dup (utf32, len, &res, &len, &end32);
  r_assert_cmpptr (back, !=, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_OK);
  r_assert_cmpuint (len, ==, 6);
  r_assert_cmpuint (back[3], ==, 0xD800);
  r_assert_cmpuint (back[4], ==, 0xDC00);

  r_free (utf32);
  r_free (back);
}
RTEST_END;

/* ========================================================================
 * Canonical Unicode-conversion stress vectors.
 *
 * Sourced from:
 *  - Unicode Standard Table 3-7 (well-formed UTF-8 byte sequences).
 *  - Markus Kuhn's "UTF-8 decoder capability and stress test"
 *    (https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt) -
 *    the de-facto Unicode-encoding conformance suite.
 *  - RFC 3629 §3 (forbidden UTF-8 sequences).
 *
 * Layout: a single positive table of boundary codepoints round-tripped
 * across all four conversion pairs, plus per-direction negative tests
 * exercising each rejection path the spec defines.
 * ======================================================================= */

typedef struct {
  const rchar * name;
  runichar4 codepoint;
  /* UTF-8 canonical encoding. */
  const ruint8 * utf8;
  rsize utf8_len;
  /* UTF-16 canonical encoding (1 unit for BMP, 2 for supplementary). */
  runichar2 utf16_a;
  runichar2 utf16_b;        /* 0 when single-unit. */
} RUnicodeBoundary;

#define BOUNDARY_U8(...) ((const ruint8 []){__VA_ARGS__})
#define BOUNDARY_U8_LEN(...) (sizeof ((const ruint8 []){__VA_ARGS__}))

/* Note: U+0000 is excluded - the in-buffer functions stop the loop on
 * `src[i] != 0`, so an embedded NUL terminates input early. The
 * Unicode Standard considers U+0000 valid; the rlib API simply
 * treats it as the C string terminator. */
static const RUnicodeBoundary boundaries[] = {
  /* Unicode Standard §3.9 boundary codepoints (Kuhn §2.1 / §2.3). */
  { "U+007F (max 1-byte)",   0x007F,
      BOUNDARY_U8 (0x7f), 1,
      0x007F, 0 },
  { "U+0080 (min 2-byte)",   0x0080,
      BOUNDARY_U8 (0xc2, 0x80), 2,
      0x0080, 0 },
  { "U+07FF (max 2-byte)",   0x07FF,
      BOUNDARY_U8 (0xdf, 0xbf), 2,
      0x07FF, 0 },
  { "U+0800 (min 3-byte)",   0x0800,
      BOUNDARY_U8 (0xe0, 0xa0, 0x80), 3,
      0x0800, 0 },
  { "U+D7FF (last before surrogates)", 0xD7FF,
      BOUNDARY_U8 (0xed, 0x9f, 0xbf), 3,
      0xD7FF, 0 },
  { "U+E000 (first after surrogates)", 0xE000,
      BOUNDARY_U8 (0xee, 0x80, 0x80), 3,
      0xE000, 0 },
  { "U+FFFD (replacement char)", 0xFFFD,
      BOUNDARY_U8 (0xef, 0xbf, 0xbd), 3,
      0xFFFD, 0 },
  { "U+FFFF (max 3-byte / max BMP)", 0xFFFF,
      BOUNDARY_U8 (0xef, 0xbf, 0xbf), 3,
      0xFFFF, 0 },
  { "U+10000 (min 4-byte / first supplementary)", 0x10000,
      BOUNDARY_U8 (0xf0, 0x90, 0x80, 0x80), 4,
      0xD800, 0xDC00 },
  { "U+10FFFF (max Unicode)", 0x10FFFF,
      BOUNDARY_U8 (0xf4, 0x8f, 0xbf, 0xbf), 4,
      0xDBFF, 0xDFFF },
};

RTEST_LOOP (runicode, boundary_utf8_to_utf16, RTEST_FAST,
    0, R_N_ELEMENTS (boundaries))
{
  const RUnicodeBoundary * b = &boundaries[__i];
  runichar2 dst[8];
  rchar * endptr;
  rsize n;
  rsize expected_units = (b->utf16_b != 0) ? 2 : 1;

  r_assert_cmpint (r_utf8_to_utf16 (dst, R_N_ELEMENTS (dst),
        (const rchar *)b->utf8, b->utf8_len, &n, &endptr),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, expected_units);
  r_assert_cmpuint (dst[0], ==, b->utf16_a);
  if (b->utf16_b != 0)
    r_assert_cmpuint (dst[1], ==, b->utf16_b);
}
RTEST_END;

RTEST_LOOP (runicode, boundary_utf16_to_utf8, RTEST_FAST,
    0, R_N_ELEMENTS (boundaries))
{
  const RUnicodeBoundary * b = &boundaries[__i];
  runichar2 src[2];
  runichar2 * endptr;
  rchar dst[8];
  rsize n;
  rsize srclen = (b->utf16_b != 0) ? 2 : 1;

  src[0] = b->utf16_a;
  src[1] = b->utf16_b;
  r_assert_cmpint (r_utf16_to_utf8 (dst, sizeof (dst), src, srclen,
        &n, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, b->utf8_len);
  r_assert_cmpmem (dst, ==, b->utf8, b->utf8_len);
}
RTEST_END;

RTEST_LOOP (runicode, boundary_utf8_to_utf32, RTEST_FAST,
    0, R_N_ELEMENTS (boundaries))
{
  const RUnicodeBoundary * b = &boundaries[__i];
  runichar4 dst[4];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf32 (dst, R_N_ELEMENTS (dst),
        (const rchar *)b->utf8, b->utf8_len, &n, &endptr),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (dst[0], ==, b->codepoint);
}
RTEST_END;

RTEST_LOOP (runicode, boundary_utf32_to_utf8, RTEST_FAST,
    0, R_N_ELEMENTS (boundaries))
{
  const RUnicodeBoundary * b = &boundaries[__i];
  runichar4 src[1];
  runichar4 * endptr;
  rchar dst[8];
  rsize n;

  src[0] = b->codepoint;
  r_assert_cmpint (r_utf32_to_utf8 (dst, sizeof (dst), src, 1, &n, &endptr),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, b->utf8_len);
  r_assert_cmpmem (dst, ==, b->utf8, b->utf8_len);
}
RTEST_END;

RTEST_LOOP (runicode, boundary_utf16_to_utf32, RTEST_FAST,
    0, R_N_ELEMENTS (boundaries))
{
  const RUnicodeBoundary * b = &boundaries[__i];
  runichar2 src[2];
  runichar2 * endptr;
  runichar4 dst[4];
  rsize n;
  rsize srclen = (b->utf16_b != 0) ? 2 : 1;

  src[0] = b->utf16_a;
  src[1] = b->utf16_b;
  r_assert_cmpint (r_utf16_to_utf32 (dst, R_N_ELEMENTS (dst), src, srclen,
        &n, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (dst[0], ==, b->codepoint);
}
RTEST_END;

RTEST_LOOP (runicode, boundary_utf32_to_utf16, RTEST_FAST,
    0, R_N_ELEMENTS (boundaries))
{
  const RUnicodeBoundary * b = &boundaries[__i];
  runichar4 src[1];
  runichar4 * endptr;
  runichar2 dst[4];
  rsize n;
  rsize expected_units = (b->utf16_b != 0) ? 2 : 1;

  src[0] = b->codepoint;
  r_assert_cmpint (r_utf32_to_utf16 (dst, R_N_ELEMENTS (dst), src, 1,
        &n, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, expected_units);
  r_assert_cmpuint (dst[0], ==, b->utf16_a);
  if (b->utf16_b != 0)
    r_assert_cmpuint (dst[1], ==, b->utf16_b);
}
RTEST_END;

/* ---- Kuhn §4: overlong UTF-8 sequences -------------------------------
 * RFC 3629 §3 forbids encoding a codepoint in more bytes than the
 * canonical form requires. r_utf8_to_unichar flags these with the
 * internal R_UTF8_OVERLONG sentinel; both the UTF-16 and UTF-32
 * paths surface them as R_UNICODE_INVALID_CODE_POINT. */

typedef struct {
  const rchar * name;
  const ruint8 bytes[8];
  rsize len;
} RUnicodeBadUtf8;

static const RUnicodeBadUtf8 overlong_vectors[] = {
  /* Kuhn §4.1 - overlong "/". */
  { "overlong 2B '/'", { 0xc0, 0xaf }, 2 },
  { "overlong 3B '/'", { 0xe0, 0x80, 0xaf }, 3 },
  { "overlong 4B '/'", { 0xf0, 0x80, 0x80, 0xaf }, 4 },
  /* Kuhn §4.2 - maximum overlong at each length. */
  { "max overlong 2B (U+007F as 2B)", { 0xc1, 0xbf }, 2 },
  { "max overlong 3B (U+07FF as 3B)", { 0xe0, 0x9f, 0xbf }, 3 },
  { "max overlong 4B (U+FFFF as 4B)", { 0xf0, 0x8f, 0xbf, 0xbf }, 4 },
  /* Kuhn §4.3 - overlong NUL. */
  { "overlong 2B NUL", { 0xc0, 0x80 }, 2 },
  { "overlong 3B NUL", { 0xe0, 0x80, 0x80 }, 3 },
  { "overlong 4B NUL", { 0xf0, 0x80, 0x80, 0x80 }, 4 },
};

RTEST_LOOP (runicode, overlong_utf8_rejected_to_utf16, RTEST_FAST,
    0, R_N_ELEMENTS (overlong_vectors))
{
  const RUnicodeBadUtf8 * v = &overlong_vectors[__i];
  runichar2 dst[8];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf16 (dst, R_N_ELEMENTS (dst),
        (const rchar *)v->bytes, v->len, &n, &endptr),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 0);
}
RTEST_END;

RTEST_LOOP (runicode, overlong_utf8_rejected_to_utf32, RTEST_FAST,
    0, R_N_ELEMENTS (overlong_vectors))
{
  const RUnicodeBadUtf8 * v = &overlong_vectors[__i];
  runichar4 dst[8];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf32 (dst, R_N_ELEMENTS (dst),
        (const rchar *)v->bytes, v->len, &n, &endptr),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 0);
}
RTEST_END;

/* ---- Kuhn §5.1 / §5.2: surrogate codepoints in UTF-8 ------------------
 * The byte pattern is bit-valid 3-byte UTF-8 but the decoded value is
 * a surrogate half (U+D800..U+DFFF). RFC 3629 §3 requires rejection. */
static const RUnicodeBadUtf8 surrogate_in_utf8_vectors[] = {
  { "U+D800 as UTF-8 (high surrogate)", { 0xed, 0xa0, 0x80 }, 3 },
  { "U+DBFF as UTF-8 (last high surrogate)", { 0xed, 0xaf, 0xbf }, 3 },
  { "U+DC00 as UTF-8 (low surrogate)", { 0xed, 0xb0, 0x80 }, 3 },
  { "U+DFFF as UTF-8 (last low surrogate)", { 0xed, 0xbf, 0xbf }, 3 },
  /* Kuhn §5.2 - paired surrogates encoded as two 3-byte sequences. */
  { "paired surrogates as UTF-8",
      { 0xed, 0xa0, 0x80, 0xed, 0xb0, 0x80 }, 6 },
};

RTEST_LOOP (runicode, surrogate_in_utf8_rejected_to_utf16, RTEST_FAST,
    0, R_N_ELEMENTS (surrogate_in_utf8_vectors))
{
  const RUnicodeBadUtf8 * v = &surrogate_in_utf8_vectors[__i];
  runichar2 dst[8];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf16 (dst, R_N_ELEMENTS (dst),
        (const rchar *)v->bytes, v->len, &n, &endptr),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 0);
}
RTEST_END;

RTEST_LOOP (runicode, surrogate_in_utf8_rejected_to_utf32, RTEST_FAST,
    0, R_N_ELEMENTS (surrogate_in_utf8_vectors))
{
  const RUnicodeBadUtf8 * v = &surrogate_in_utf8_vectors[__i];
  runichar4 dst[8];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf32 (dst, R_N_ELEMENTS (dst),
        (const rchar *)v->bytes, v->len, &n, &endptr),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 0);
}
RTEST_END;

/* ---- Kuhn §3: malformed UTF-8 ----------------------------------------
 * Sequences that don't even form a valid bit pattern - lone
 * continuation bytes, impossible 0xFE / 0xFF, and truncated
 * multi-byte sequences. */
static const RUnicodeBadUtf8 malformed_utf8_vectors[] = {
  /* Kuhn §3.1: lone continuation bytes. */
  { "lone 0x80", { 0x80 }, 1 },
  { "lone 0xBF", { 0xbf }, 1 },
  /* Kuhn §3.3: missing continuation. */
  { "2-byte start missing continuation", { 0xc2 }, 1 },
  { "3-byte start missing 1 of 2 continuations", { 0xe0, 0xa0 }, 2 },
  { "4-byte start missing 1 of 3 continuations",
      { 0xf0, 0x90, 0x80 }, 3 },
  /* Kuhn §3.5: impossible bytes (RFC 3629 forbids 0xFE / 0xFF). */
  { "impossible byte 0xFE", { 0xfe }, 1 },
  { "impossible byte 0xFF", { 0xff }, 1 },
  /* Pre-RFC-3629 5-byte and 6-byte lead bytes (0xF8..0xFD). These
   * could only encode codepoints >= U+200000, never assignable;
   * RFC 3629 §3 forbids them outright. */
  { "5-byte lead 0xF8", { 0xf8, 0x88, 0x80, 0x80, 0x80 }, 5 },
  { "5-byte lead 0xFB", { 0xfb, 0xbf, 0xbf, 0xbf, 0xbf }, 5 },
  { "6-byte lead 0xFC", { 0xfc, 0x84, 0x80, 0x80, 0x80, 0x80 }, 6 },
  { "6-byte lead 0xFD", { 0xfd, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf }, 6 },
};

RTEST_LOOP (runicode, malformed_utf8_rejected_to_utf16, RTEST_FAST,
    0, R_N_ELEMENTS (malformed_utf8_vectors))
{
  const RUnicodeBadUtf8 * v = &malformed_utf8_vectors[__i];
  runichar2 dst[8];
  rchar * endptr;
  rsize n;
  RUnicodeResult r;

  r = r_utf8_to_utf16 (dst, R_N_ELEMENTS (dst),
      (const rchar *)v->bytes, v->len, &n, &endptr);
  r_assert (r == R_UNICODE_INCOMPLETE_CODE_POINT ||
            r == R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 0);
}
RTEST_END;

RTEST_LOOP (runicode, malformed_utf8_rejected_to_utf32, RTEST_FAST,
    0, R_N_ELEMENTS (malformed_utf8_vectors))
{
  const RUnicodeBadUtf8 * v = &malformed_utf8_vectors[__i];
  runichar4 dst[8];
  rchar * endptr;
  rsize n;
  RUnicodeResult r;

  r = r_utf8_to_utf32 (dst, R_N_ELEMENTS (dst),
      (const rchar *)v->bytes, v->len, &n, &endptr);
  r_assert (r == R_UNICODE_INCOMPLETE_CODE_POINT ||
            r == R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 0);
}
RTEST_END;

/* ---- UTF-8 codepoint out of Unicode range ----------------------------
 * Bit pattern is valid 4-byte UTF-8 but decodes to a codepoint
 * > U+10FFFF (RFC 3629 §3). */
RTEST (runicode, utf8_codepoint_out_of_range_to_utf16, RTEST_FAST)
{
  static const ruint8 src[4] = { 0xf4, 0x90, 0x80, 0x80 };  /* U+110000 */
  runichar2 dst[8];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf16 (dst, R_N_ELEMENTS (dst),
        (const rchar *)src, 4, &n, &endptr),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 0);
}
RTEST_END;

RTEST (runicode, utf8_codepoint_out_of_range_to_utf32, RTEST_FAST)
{
  static const ruint8 src[4] = { 0xf4, 0x90, 0x80, 0x80 };  /* U+110000 */
  runichar4 dst[8];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf32 (dst, R_N_ELEMENTS (dst),
        (const rchar *)src, 4, &n, &endptr),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (n, ==, 0);
}
RTEST_END;

/* ---- UTF-32 BOM stripping ------------------------------------------
 * UTF-8 ↔ UTF-16 BOM behaviour is covered by the legacy
 * `utf*_bom` tests above. The new UTF-32 paths strip a leading
 * 0xFEFF code point from any input where it could occur. */

RTEST (runicode, utf8_bom_to_utf32, RTEST_FAST)
{
  static const ruint8 src[] = { 0xef, 0xbb, 0xbf, 'a', 'b', 'c' };
  runichar4 dst[8];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf32 (dst, R_N_ELEMENTS (dst),
        (const rchar *)src, sizeof (src), &n, &endptr),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 3);
  r_assert_cmpuint (dst[0], ==, 'a');
}
RTEST_END;

RTEST (runicode, utf16_bom_to_utf32, RTEST_FAST)
{
  runichar2 src[] = { 0xFEFF, 'a', 'b', 'c' };
  runichar4 dst[8];
  runichar2 * endptr;
  rsize n;

  r_assert_cmpint (r_utf16_to_utf32 (dst, R_N_ELEMENTS (dst),
        src, R_N_ELEMENTS (src), &n, &endptr),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 3);
  r_assert_cmpuint (dst[0], ==, 'a');
}
RTEST_END;

RTEST (runicode, utf32_bom_to_utf8, RTEST_FAST)
{
  runichar4 src[] = { 0xFEFF, 'a', 'b', 'c' };
  runichar4 * endptr;
  rchar dst[16];
  rsize n;

  r_assert_cmpint (r_utf32_to_utf8 (dst, sizeof (dst),
        src, R_N_ELEMENTS (src), &n, &endptr),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 3);
  r_assert_cmpstr (dst, ==, "abc");
}
RTEST_END;

RTEST (runicode, utf32_bom_to_utf16, RTEST_FAST)
{
  runichar4 src[] = { 0xFEFF, 'a', 'b', 'c' };
  runichar4 * endptr;
  runichar2 dst[8];
  rsize n;

  r_assert_cmpint (r_utf32_to_utf16 (dst, R_N_ELEMENTS (dst),
        src, R_N_ELEMENTS (src), &n, &endptr),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 3);
  r_assert_cmpuint (dst[0], ==, 'a');
}
RTEST_END;

/* ---- Streaming resume via srcendptr --------------------------------
 * `R_UNICODE_INCOMPLETE_CODE_POINT` is the explicit signal that the
 * source ended mid-codepoint and the caller should resume from
 * `srcendptr` once more bytes arrive. Verify that a concatenated
 * (first-chunk-truncated, then-rest) pass produces the same result
 * as a single-shot conversion. */

RTEST (runicode, utf8_streaming_resume_to_utf16, RTEST_FAST)
{
  /* "α" = U+03B1 = 0xCE 0xB1 (2-byte UTF-8). Feed just 0xCE first. */
  static const ruint8 chunk1[] = { 'a', 0xce };           /* 'a' + half α */
  static const ruint8 chunk2[] = { 0xb1, 'b' };            /* tail of α + 'b' */
  runichar2 dst[8];
  rchar * endptr;
  rsize n;

  r_assert_cmpint (r_utf8_to_utf16 (dst, R_N_ELEMENTS (dst),
        (const rchar *)chunk1, sizeof (chunk1), &n, &endptr),
      ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (dst[0], ==, 'a');
  /* srcendptr points at the start of the incomplete sequence (0xCE). */
  r_assert_cmpptr (endptr, ==, (rchar *)chunk1 + 1);

  /* Concatenate the unconsumed tail with chunk2 and convert again. */
  {
    ruint8 joined[8];
    runichar2 dst2[8];
    rchar * endptr2;
    rsize joined_len = sizeof (chunk1) - (rsize)(endptr - (rchar *)chunk1);

    r_memcpy (joined, endptr, joined_len);
    r_memcpy (joined + joined_len, chunk2, sizeof (chunk2));
    r_assert_cmpint (r_utf8_to_utf16 (dst2, R_N_ELEMENTS (dst2),
          (const rchar *)joined, joined_len + sizeof (chunk2),
          &n, &endptr2), ==, R_UNICODE_OK);
    r_assert_cmpuint (n, ==, 2);
    r_assert_cmpuint (dst2[0], ==, 0x3B1);
    r_assert_cmpuint (dst2[1], ==, 'b');
  }
}
RTEST_END;

RTEST (runicode, utf8_streaming_resume_to_utf32, RTEST_FAST)
{
  /* "𐀀" = U+10000 = F0 90 80 80 (4-byte UTF-8). Truncate after 2. */
  static const ruint8 chunk1[] = { 'x', 0xf0, 0x90 };
  static const ruint8 chunk2[] = { 0x80, 0x80, 'y' };
  runichar4 dst[8];
  rchar * endptr;
  rsize n;
  ruint8 joined[8];
  runichar4 dst2[8];
  rchar * endptr2;
  rsize joined_len;

  r_assert_cmpint (r_utf8_to_utf32 (dst, R_N_ELEMENTS (dst),
        (const rchar *)chunk1, sizeof (chunk1), &n, &endptr),
      ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (dst[0], ==, 'x');
  r_assert_cmpptr (endptr, ==, (rchar *)chunk1 + 1);

  joined_len = sizeof (chunk1) - (rsize)(endptr - (rchar *)chunk1);
  r_memcpy (joined, endptr, joined_len);
  r_memcpy (joined + joined_len, chunk2, sizeof (chunk2));
  r_assert_cmpint (r_utf8_to_utf32 (dst2, R_N_ELEMENTS (dst2),
        (const rchar *)joined, joined_len + sizeof (chunk2),
        &n, &endptr2), ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 2);
  r_assert_cmpuint (dst2[0], ==, 0x10000);
  r_assert_cmpuint (dst2[1], ==, 'y');
}
RTEST_END;

RTEST (runicode, utf16_streaming_resume_to_utf8, RTEST_FAST)
{
  /* Surrogate pair for U+10000 split across chunks. */
  runichar2 chunk1[] = { 'x', 0xD800 };
  runichar2 chunk2[] = { 0xDC00, 'y' };
  rchar dst[16];
  runichar2 * endptr;
  rsize n;
  runichar2 joined[8];
  rchar dst2[16];
  runichar2 * endptr2;
  rsize joined_len;

  r_assert_cmpint (r_utf16_to_utf8 (dst, sizeof (dst),
        chunk1, R_N_ELEMENTS (chunk1), &n, &endptr),
      ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint ((ruint8)dst[0], ==, 'x');

  joined_len = R_N_ELEMENTS (chunk1) - (rsize)(endptr - chunk1);
  r_memcpy (joined, endptr, joined_len * sizeof (runichar2));
  r_memcpy (joined + joined_len, chunk2, sizeof (chunk2));
  r_assert_cmpint (r_utf16_to_utf8 (dst2, sizeof (dst2),
        joined, joined_len + R_N_ELEMENTS (chunk2), &n, &endptr2),
      ==, R_UNICODE_OK);
  /* "𐀀" + "y" = 4 + 1 UTF-8 bytes. */
  r_assert_cmpuint (n, ==, 5);
  r_assert_cmpmem (dst2, ==, "\xF0\x90\x80\x80y", 5);
}
RTEST_END;

RTEST (runicode, utf16_streaming_resume_to_utf32, RTEST_FAST)
{
  runichar2 chunk1[] = { 'x', 0xD800 };
  runichar2 chunk2[] = { 0xDC00, 'y' };
  runichar4 dst[8];
  runichar2 * endptr;
  rsize n;
  runichar2 joined[8];
  runichar4 dst2[8];
  runichar2 * endptr2;
  rsize joined_len;

  r_assert_cmpint (r_utf16_to_utf32 (dst, R_N_ELEMENTS (dst),
        chunk1, R_N_ELEMENTS (chunk1), &n, &endptr),
      ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (n, ==, 1);
  r_assert_cmpuint (dst[0], ==, 'x');

  joined_len = R_N_ELEMENTS (chunk1) - (rsize)(endptr - chunk1);
  r_memcpy (joined, endptr, joined_len * sizeof (runichar2));
  r_memcpy (joined + joined_len, chunk2, sizeof (chunk2));
  r_assert_cmpint (r_utf16_to_utf32 (dst2, R_N_ELEMENTS (dst2),
        joined, joined_len + R_N_ELEMENTS (chunk2), &n, &endptr2),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 2);
  r_assert_cmpuint (dst2[0], ==, 0x10000);
  r_assert_cmpuint (dst2[1], ==, 'y');
}
RTEST_END;

/* ---- NULL out-pointer robustness -----------------------------------
 * The impl docstrings say `dstoutsize` and `srcendptr` are optional.
 * Confirm that passing NULL for either works and the conversion
 * still produces correct output. */

RTEST (runicode, null_out_params_utf8_to_utf16, RTEST_FAST)
{
  runichar2 dst[8];
  r_assert_cmpint (r_utf8_to_utf16 (dst, R_N_ELEMENTS (dst), "abc", 3,
        NULL, NULL), ==, R_UNICODE_OK);
  r_assert_cmpuint (dst[0], ==, 'a');
}
RTEST_END;

RTEST (runicode, null_out_params_utf16_to_utf8, RTEST_FAST)
{
  runichar2 src[] = { 'a', 'b', 'c' };
  rchar dst[8];
  r_assert_cmpint (r_utf16_to_utf8 (dst, sizeof (dst), src, 3,
        NULL, NULL), ==, R_UNICODE_OK);
  r_assert_cmpstr (dst, ==, "abc");
}
RTEST_END;

RTEST (runicode, null_out_params_utf8_to_utf32, RTEST_FAST)
{
  runichar4 dst[8];
  r_assert_cmpint (r_utf8_to_utf32 (dst, R_N_ELEMENTS (dst), "abc", 3,
        NULL, NULL), ==, R_UNICODE_OK);
  r_assert_cmpuint (dst[0], ==, 'a');
}
RTEST_END;

RTEST (runicode, null_out_params_utf32_to_utf8, RTEST_FAST)
{
  runichar4 src[] = { 'a', 'b', 'c' };
  rchar dst[8];
  r_assert_cmpint (r_utf32_to_utf8 (dst, sizeof (dst), src, 3,
        NULL, NULL), ==, R_UNICODE_OK);
  r_assert_cmpstr (dst, ==, "abc");
}
RTEST_END;

RTEST (runicode, null_out_params_utf16_to_utf32, RTEST_FAST)
{
  runichar2 src[] = { 'a', 'b', 'c' };
  runichar4 dst[8];
  r_assert_cmpint (r_utf16_to_utf32 (dst, R_N_ELEMENTS (dst), src, 3,
        NULL, NULL), ==, R_UNICODE_OK);
  r_assert_cmpuint (dst[0], ==, 'a');
}
RTEST_END;

RTEST (runicode, null_out_params_utf32_to_utf16, RTEST_FAST)
{
  runichar4 src[] = { 'a', 'b', 'c' };
  runichar2 dst[8];
  r_assert_cmpint (r_utf32_to_utf16 (dst, R_N_ELEMENTS (dst), src, 3,
        NULL, NULL), ==, R_UNICODE_OK);
  r_assert_cmpuint (dst[0], ==, 'a');
}
RTEST_END;

/* ---- Encoding-validation entry points ------------------------------
 * Scan-only counterparts to the conversion functions. Each validator
 * applies the same rejection rules as its conversion sibling but
 * allocates no destination buffer. */

RTEST (runicode, utf8_validate_ok, RTEST_FAST)
{
  rchar * endptr;
  r_assert_cmpint (r_utf8_validate ("abc", 3, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpptr (endptr, ==, (rchar *)"abc" + 3);

  r_assert_cmpint (r_utf8_validate ("\xCE\xB1\xCE\xB2", 4, NULL),
      ==, R_UNICODE_OK);

  /* Length via r_strlen. */
  r_assert_cmpint (r_utf8_validate ("abc", -1, NULL), ==, R_UNICODE_OK);
}
RTEST_END;

RTEST_LOOP (runicode, utf8_validate_rejects_overlong, RTEST_FAST,
    0, R_N_ELEMENTS (overlong_vectors))
{
  const RUnicodeBadUtf8 * v = &overlong_vectors[__i];
  r_assert_cmpint (r_utf8_validate ((const rchar *)v->bytes, v->len, NULL),
      ==, R_UNICODE_INVALID_CODE_POINT);
}
RTEST_END;

RTEST_LOOP (runicode, utf8_validate_rejects_surrogate_in_utf8, RTEST_FAST,
    0, R_N_ELEMENTS (surrogate_in_utf8_vectors))
{
  const RUnicodeBadUtf8 * v = &surrogate_in_utf8_vectors[__i];
  r_assert_cmpint (r_utf8_validate ((const rchar *)v->bytes, v->len, NULL),
      ==, R_UNICODE_INVALID_CODE_POINT);
}
RTEST_END;

RTEST_LOOP (runicode, utf8_validate_rejects_malformed, RTEST_FAST,
    0, R_N_ELEMENTS (malformed_utf8_vectors))
{
  const RUnicodeBadUtf8 * v = &malformed_utf8_vectors[__i];
  RUnicodeResult r = r_utf8_validate ((const rchar *)v->bytes, v->len, NULL);
  r_assert (r == R_UNICODE_INVALID_CODE_POINT ||
            r == R_UNICODE_INCOMPLETE_CODE_POINT);
}
RTEST_END;

RTEST (runicode, utf8_validate_endptr_on_failure, RTEST_FAST)
{
  /* "ab" + overlong "/" (\xC0\xAF). endptr should point at the start
   * of the overlong sequence. */
  static const ruint8 src[4] = { 'a', 'b', 0xc0, 0xaf };
  rchar * endptr;

  r_assert_cmpint (r_utf8_validate ((const rchar *)src, sizeof (src),
        &endptr), ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpptr (endptr, ==, (rchar *)src + 2);
}
RTEST_END;

RTEST (runicode, utf8_validate_endptr_on_incomplete, RTEST_FAST)
{
  /* Resumable position: "a" + half of α. */
  static const ruint8 src[2] = { 'a', 0xce };
  rchar * endptr;

  r_assert_cmpint (r_utf8_validate ((const rchar *)src, sizeof (src),
        &endptr), ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpptr (endptr, ==, (rchar *)src + 1);
}
RTEST_END;

RTEST (runicode, utf8_validate_strips_bom, RTEST_FAST)
{
  static const ruint8 src[6] = { 0xef, 0xbb, 0xbf, 'a', 'b', 'c' };
  r_assert_cmpint (r_utf8_validate ((const rchar *)src, sizeof (src), NULL),
      ==, R_UNICODE_OK);
}
RTEST_END;

RTEST (runicode, utf8_validate_null_src, RTEST_FAST)
{
  r_assert_cmpint (r_utf8_validate (NULL, 0, NULL), ==, R_UNICODE_INVAL);
}
RTEST_END;

RTEST (runicode, utf16_validate_ok, RTEST_FAST)
{
  runichar2 src[] = { 'a', 'b', 'c' };
  runichar2 * endptr;

  r_assert_cmpint (r_utf16_validate (src, 3, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpptr (endptr, ==, src + 3);
}
RTEST_END;

RTEST (runicode, utf16_validate_surrogate_pair, RTEST_FAST)
{
  runichar2 src[] = { 'a', 0xD800, 0xDC00, 'z' };
  r_assert_cmpint (r_utf16_validate (src, 4, NULL), ==, R_UNICODE_OK);
}
RTEST_END;

RTEST (runicode, utf16_validate_incomplete, RTEST_FAST)
{
  runichar2 src[] = { 'a', 0xD800 };
  runichar2 * endptr;

  r_assert_cmpint (r_utf16_validate (src, 2, &endptr),
      ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpptr (endptr, ==, src + 1);
}
RTEST_END;

RTEST (runicode, utf16_validate_invalid_lone_low, RTEST_FAST)
{
  runichar2 src[] = { 'a', 0xDC00, 'z' };
  runichar2 * endptr;

  r_assert_cmpint (r_utf16_validate (src, 3, &endptr),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpptr (endptr, ==, src + 1);
}
RTEST_END;

RTEST (runicode, utf16_validate_strips_bom_rejects_swap, RTEST_FAST)
{
  runichar2 with_bom[] = { 0xFEFF, 'a', 'b' };
  runichar2 with_swap[] = { 0xFFFE, 'a', 'b' };

  r_assert_cmpint (r_utf16_validate (with_bom, 3, NULL), ==, R_UNICODE_OK);
  r_assert_cmpint (r_utf16_validate (with_swap, 3, NULL),
      ==, R_UNICODE_INVAL);
}
RTEST_END;

RTEST (runicode, utf16_validate_null_src, RTEST_FAST)
{
  r_assert_cmpint (r_utf16_validate (NULL, 0, NULL), ==, R_UNICODE_INVAL);
}
RTEST_END;

RTEST (runicode, utf32_validate_ok, RTEST_FAST)
{
  runichar4 src[] = { 'a', 0x10FFFF, 'z' };
  runichar4 * endptr;

  r_assert_cmpint (r_utf32_validate (src, 3, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpptr (endptr, ==, src + 3);
}
RTEST_END;

RTEST (runicode, utf32_validate_rejects_out_of_range, RTEST_FAST)
{
  runichar4 src[] = { 'a', 0x110000, 'z' };
  runichar4 * endptr;

  r_assert_cmpint (r_utf32_validate (src, 3, &endptr),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpptr (endptr, ==, src + 1);
}
RTEST_END;

RTEST (runicode, utf32_validate_rejects_surrogate, RTEST_FAST)
{
  runichar4 src_high[] = { 'a', 0xD800 };
  runichar4 src_low[] = { 'a', 0xDFFF };

  r_assert_cmpint (r_utf32_validate (src_high, 2, NULL),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpint (r_utf32_validate (src_low, 2, NULL),
      ==, R_UNICODE_INVALID_CODE_POINT);
}
RTEST_END;

RTEST (runicode, utf32_validate_strips_bom, RTEST_FAST)
{
  runichar4 src[] = { 0xFEFF, 'a', 'b' };
  r_assert_cmpint (r_utf32_validate (src, 3, NULL), ==, R_UNICODE_OK);
}
RTEST_END;

RTEST (runicode, utf32_validate_null_src, RTEST_FAST)
{
  r_assert_cmpint (r_utf32_validate (NULL, 0, NULL), ==, R_UNICODE_INVAL);
}
RTEST_END;

/* ---- Single-codepoint encode / decode ------------------------------ */

RTEST (runicode, utf8_decode_codepoint_ascii, RTEST_FAST)
{
  runichar4 uc;
  rsize consumed;

  r_assert_cmpint (r_utf8_decode_codepoint ("abc", 3, &uc, &consumed),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (uc, ==, 'a');
  r_assert_cmpuint (consumed, ==, 1);
}
RTEST_END;

RTEST (runicode, utf8_decode_codepoint_multibyte, RTEST_FAST)
{
  runichar4 uc;
  rsize consumed;

  /* α = U+03B1 = CE B1. */
  r_assert_cmpint (r_utf8_decode_codepoint ("\xCE\xB1", 2, &uc, &consumed),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (uc, ==, 0x3B1);
  r_assert_cmpuint (consumed, ==, 2);

  /* U+10FFFF = F4 8F BF BF. */
  r_assert_cmpint (r_utf8_decode_codepoint ("\xF4\x8F\xBF\xBF", 4, &uc,
        &consumed), ==, R_UNICODE_OK);
  r_assert_cmpuint (uc, ==, 0x10FFFF);
  r_assert_cmpuint (consumed, ==, 4);
}
RTEST_END;

RTEST (runicode, utf8_decode_codepoint_rejects_bad, RTEST_FAST)
{
  runichar4 uc;
  rsize consumed;

  /* Overlong. */
  r_assert_cmpint (r_utf8_decode_codepoint ("\xC0\xAF", 2, &uc, &consumed),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpuint (consumed, ==, 0);

  /* UTF-8-encoded surrogate. */
  r_assert_cmpint (r_utf8_decode_codepoint ("\xED\xA0\x80", 3, &uc,
        &consumed), ==, R_UNICODE_INVALID_CODE_POINT);

  /* Truncated. */
  r_assert_cmpint (r_utf8_decode_codepoint ("\xCE", 1, &uc, &consumed),
      ==, R_UNICODE_INCOMPLETE_CODE_POINT);

  /* NULL / zero-size. */
  r_assert_cmpint (r_utf8_decode_codepoint (NULL, 0, &uc, &consumed),
      ==, R_UNICODE_INVAL);
  r_assert_cmpint (r_utf8_decode_codepoint ("a", 0, &uc, &consumed),
      ==, R_UNICODE_INVAL);
}
RTEST_END;

RTEST (runicode, utf8_encode_codepoint, RTEST_FAST)
{
  rchar dst[8];
  rsize written;

  r_assert_cmpint (r_utf8_encode_codepoint ('a', dst, sizeof (dst),
        &written), ==, R_UNICODE_OK);
  r_assert_cmpuint (written, ==, 1);
  r_assert_cmpuint ((ruint8)dst[0], ==, 'a');

  r_assert_cmpint (r_utf8_encode_codepoint (0x3B1, dst, sizeof (dst),
        &written), ==, R_UNICODE_OK);
  r_assert_cmpuint (written, ==, 2);
  r_assert_cmpmem (dst, ==, "\xCE\xB1", 2);

  r_assert_cmpint (r_utf8_encode_codepoint (0x10FFFF, dst, sizeof (dst),
        &written), ==, R_UNICODE_OK);
  r_assert_cmpuint (written, ==, 4);
  r_assert_cmpmem (dst, ==, "\xF4\x8F\xBF\xBF", 4);
}
RTEST_END;

RTEST (runicode, utf8_encode_codepoint_rejects_bad, RTEST_FAST)
{
  rchar dst[8];
  rsize written;

  /* Surrogate codepoint. */
  r_assert_cmpint (r_utf8_encode_codepoint (0xD800, dst, sizeof (dst),
        &written), ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpint (r_utf8_encode_codepoint (0xDFFF, dst, sizeof (dst),
        &written), ==, R_UNICODE_INVALID_CODE_POINT);

  /* Out of range. */
  r_assert_cmpint (r_utf8_encode_codepoint (0x110000, dst, sizeof (dst),
        &written), ==, R_UNICODE_INVALID_CODE_POINT);

  /* Buffer too small. */
  r_assert_cmpint (r_utf8_encode_codepoint (0x3B1, dst, 1, &written),
      ==, R_UNICODE_OVERFLOW);
}
RTEST_END;

RTEST (runicode, utf16_decode_codepoint, RTEST_FAST)
{
  runichar2 src[2];
  runichar4 uc;
  rsize consumed;

  /* BMP. */
  src[0] = 'a';
  r_assert_cmpint (r_utf16_decode_codepoint (src, 1, &uc, &consumed),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (uc, ==, 'a');
  r_assert_cmpuint (consumed, ==, 1);

  /* Surrogate pair. */
  src[0] = 0xD800; src[1] = 0xDC00;
  r_assert_cmpint (r_utf16_decode_codepoint (src, 2, &uc, &consumed),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (uc, ==, 0x10000);
  r_assert_cmpuint (consumed, ==, 2);
}
RTEST_END;

RTEST (runicode, utf16_decode_codepoint_rejects_bad, RTEST_FAST)
{
  runichar2 src[2];
  runichar4 uc;
  rsize consumed;

  /* High surrogate alone -> INCOMPLETE. */
  src[0] = 0xD801;
  r_assert_cmpint (r_utf16_decode_codepoint (src, 1, &uc, &consumed),
      ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (consumed, ==, 0);

  /* High surrogate followed by non-low -> INVALID. */
  src[0] = 0xD801; src[1] = 'a';
  r_assert_cmpint (r_utf16_decode_codepoint (src, 2, &uc, &consumed),
      ==, R_UNICODE_INVALID_CODE_POINT);

  /* Lone low surrogate. */
  src[0] = 0xDC01;
  r_assert_cmpint (r_utf16_decode_codepoint (src, 1, &uc, &consumed),
      ==, R_UNICODE_INVALID_CODE_POINT);
}
RTEST_END;

RTEST (runicode, utf16_encode_codepoint, RTEST_FAST)
{
  runichar2 dst[2];
  rsize written;

  r_assert_cmpint (r_utf16_encode_codepoint ('a', dst, 2, &written),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (written, ==, 1);
  r_assert_cmpuint (dst[0], ==, 'a');

  r_assert_cmpint (r_utf16_encode_codepoint (0x10000, dst, 2, &written),
      ==, R_UNICODE_OK);
  r_assert_cmpuint (written, ==, 2);
  r_assert_cmpuint (dst[0], ==, 0xD800);
  r_assert_cmpuint (dst[1], ==, 0xDC00);

  /* Out of range + surrogate. */
  r_assert_cmpint (r_utf16_encode_codepoint (0xD800, dst, 2, &written),
      ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpint (r_utf16_encode_codepoint (0x110000, dst, 2, &written),
      ==, R_UNICODE_INVALID_CODE_POINT);

  /* Single-unit buffer too small for surrogate pair. */
  r_assert_cmpint (r_utf16_encode_codepoint (0x10000, dst, 1, &written),
      ==, R_UNICODE_OVERFLOW);
}
RTEST_END;

/* ---- Codepoint counting and advance -------------------------------- */

RTEST (runicode, utf8_strlen_codepoints_basic, RTEST_FAST)
{
  RUnicodeResult r;

  /* ASCII: 1 byte = 1 codepoint. */
  r_assert_cmpuint (r_utf8_strlen_codepoints ("abc", 3, &r), ==, 3);
  r_assert_cmpint (r, ==, R_UNICODE_OK);

  /* Mixed ASCII + 2-byte + 4-byte. */
  r_assert_cmpuint (r_utf8_strlen_codepoints (
        "a\xCE\xB1\xF0\x9F\x98\x80", 7, &r), ==, 3);
  r_assert_cmpint (r, ==, R_UNICODE_OK);

  /* -1 size falls back to r_strlen. */
  r_assert_cmpuint (r_utf8_strlen_codepoints ("hello", -1, NULL), ==, 5);
}
RTEST_END;

RTEST (runicode, utf8_strlen_codepoints_rejects, RTEST_FAST)
{
  RUnicodeResult r;

  /* Stops at the first malformed sequence; reports partial count. */
  r_assert_cmpuint (r_utf8_strlen_codepoints ("ab\xC0\xAF", 4, &r),
      ==, 2);
  r_assert_cmpint (r, ==, R_UNICODE_INVALID_CODE_POINT);

  /* Truncated. */
  r_assert_cmpuint (r_utf8_strlen_codepoints ("a\xCE", 2, &r), ==, 1);
  r_assert_cmpint (r, ==, R_UNICODE_INCOMPLETE_CODE_POINT);

  r_assert_cmpuint (r_utf8_strlen_codepoints (NULL, 0, &r), ==, 0);
  r_assert_cmpint (r, ==, R_UNICODE_INVAL);
}
RTEST_END;

RTEST (runicode, utf8_advance_basic, RTEST_FAST)
{
  static const rchar * input = "a\xCE\xB1\xF0\x9F\x98\x80z";
  RUnicodeResult r;
  const rchar * p;

  /* 0 advance: same pointer. */
  p = r_utf8_advance (input, -1, 0, &r);
  r_assert_cmpptr (p, ==, input);
  r_assert_cmpint (r, ==, R_UNICODE_OK);

  /* Past the ASCII 'a': second byte ('\xCE'). */
  p = r_utf8_advance (input, -1, 1, &r);
  r_assert_cmpptr (p, ==, input + 1);
  r_assert_cmpint (r, ==, R_UNICODE_OK);

  /* Past 'a' + 'α': index 3 (start of 4-byte 😀). */
  p = r_utf8_advance (input, -1, 2, &r);
  r_assert_cmpptr (p, ==, input + 3);

  /* Past all 4 codepoints: end of string. */
  p = r_utf8_advance (input, -1, 4, &r);
  r_assert_cmpint (r, ==, R_UNICODE_OK);
  r_assert_cmpuint ((rsize)(p - input), ==, 8);
}
RTEST_END;

RTEST (runicode, utf8_advance_overflow, RTEST_FAST)
{
  RUnicodeResult r;
  const rchar * p;

  /* "abc" has 3 codepoints; ask for 5. */
  p = r_utf8_advance ("abc", 3, 5, &r);
  r_assert_cmpint (r, ==, R_UNICODE_OVERFLOW);
  r_assert_cmpptr (p, ==, (rchar *)"abc" + 3);
}
RTEST_END;

RTEST (runicode, utf16_strlen_codepoints, RTEST_FAST)
{
  runichar2 src[] = { 'a', 0x3B1, 0xD800, 0xDC00, 'z' };
  RUnicodeResult r;

  /* 5 code units = 4 codepoints (surrogate pair counts as one). */
  r_assert_cmpuint (r_utf16_strlen_codepoints (src, 5, &r), ==, 4);
  r_assert_cmpint (r, ==, R_UNICODE_OK);

  /* High surrogate not followed by a low surrogate -> INCOMPLETE,
   * matching the convention r_utf16_to_utf8 / _to_utf32 / _validate
   * all use (high without a proper low = pair incomplete, whether
   * truncated or followed by garbage). */
  src[2] = 0xD800; src[3] = 'x';
  r_assert_cmpuint (r_utf16_strlen_codepoints (src, 4, &r), ==, 2);
  r_assert_cmpint (r, ==, R_UNICODE_INCOMPLETE_CODE_POINT);

  /* Lone low surrogate -> INVALID. */
  src[0] = 'a'; src[1] = 0xDC00;
  r_assert_cmpuint (r_utf16_strlen_codepoints (src, 2, &r), ==, 1);
  r_assert_cmpint (r, ==, R_UNICODE_INVALID_CODE_POINT);

  r_assert_cmpuint (r_utf16_strlen_codepoints (NULL, 0, &r), ==, 0);
  r_assert_cmpint (r, ==, R_UNICODE_INVAL);
}
RTEST_END;

/* ---- Explicit-endianness UTF-16 / UTF-32 -> UTF-8 ------------------ */

RTEST (runicode, utf16be_to_utf8_basic, RTEST_FAST)
{
  /* "hello" = each char zero-extended; 5 BMP code units = 10 bytes BE. */
  static const ruint8 src[10] = {
    0x00, 'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o'
  };
  rchar dst[16];
  ruint8 * endptr;
  rsize n;

  r_assert_cmpint (r_utf16be_to_utf8 (dst, sizeof (dst), src, sizeof (src),
        &n, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 5);
  r_assert_cmpstr (dst, ==, "hello");
}
RTEST_END;

RTEST (runicode, utf16le_to_utf8_basic, RTEST_FAST)
{
  static const ruint8 src[10] = {
    'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00
  };
  rchar dst[16];
  ruint8 * endptr;
  rsize n;

  r_assert_cmpint (r_utf16le_to_utf8 (dst, sizeof (dst), src, sizeof (src),
        &n, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 5);
  r_assert_cmpstr (dst, ==, "hello");
}
RTEST_END;

RTEST (runicode, utf16be_to_utf8_surrogate_pair, RTEST_FAST)
{
  /* U+10000 = D800 DC00 (BE). */
  static const ruint8 src[4] = { 0xD8, 0x00, 0xDC, 0x00 };
  rchar dst[8];
  ruint8 * endptr;
  rsize n;

  r_assert_cmpint (r_utf16be_to_utf8 (dst, sizeof (dst), src, sizeof (src),
        &n, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 4);
  r_assert_cmpmem (dst, ==, "\xF0\x90\x80\x80", 4);
}
RTEST_END;

RTEST (runicode, utf16be_to_utf8_rejects_odd_length, RTEST_FAST)
{
  static const ruint8 src[3] = { 0x00, 'h', 0x00 };
  rchar dst[8];

  r_assert_cmpint (r_utf16be_to_utf8 (dst, sizeof (dst), src, sizeof (src),
        NULL, NULL), ==, R_UNICODE_INVAL);
}
RTEST_END;

RTEST (runicode, utf32be_to_utf8_basic, RTEST_FAST)
{
  /* "hi" + α (U+03B1) + 😀 (U+1F600). */
  static const ruint8 src[16] = {
    0x00, 0x00, 0x00, 'h',
    0x00, 0x00, 0x00, 'i',
    0x00, 0x00, 0x03, 0xb1,
    0x00, 0x01, 0xf6, 0x00,
  };
  rchar dst[16];
  ruint8 * endptr;
  rsize n;

  r_assert_cmpint (r_utf32be_to_utf8 (dst, sizeof (dst), src, sizeof (src),
        &n, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpuint (n, ==, 8);   /* 1 + 1 + 2 + 4 */
  r_assert_cmpmem (dst, ==, "hi\xCE\xB1\xF0\x9F\x98\x80", 8);
}
RTEST_END;

RTEST (runicode, utf32le_to_utf8_basic, RTEST_FAST)
{
  static const ruint8 src[8] = {
    'h', 0x00, 0x00, 0x00,
    'i', 0x00, 0x00, 0x00,
  };
  rchar dst[8];
  ruint8 * endptr;
  rsize n;

  r_assert_cmpint (r_utf32le_to_utf8 (dst, sizeof (dst), src, sizeof (src),
        &n, &endptr), ==, R_UNICODE_OK);
  r_assert_cmpstr (dst, ==, "hi");
  r_assert_cmpuint (n, ==, 2);
}
RTEST_END;

RTEST (runicode, utf32be_to_utf8_rejects_invalid, RTEST_FAST)
{
  /* U+D800 (surrogate codepoint). */
  static const ruint8 src_surr[4] = { 0x00, 0x00, 0xD8, 0x00 };
  /* U+110000. */
  static const ruint8 src_oor[4]  = { 0x00, 0x11, 0x00, 0x00 };
  /* Length not multiple of 4. */
  static const ruint8 src_odd[3]  = { 0x00, 0x00, 0x00 };
  rchar dst[8];

  r_assert_cmpint (r_utf32be_to_utf8 (dst, sizeof (dst), src_surr,
        sizeof (src_surr), NULL, NULL), ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpint (r_utf32be_to_utf8 (dst, sizeof (dst), src_oor,
        sizeof (src_oor), NULL, NULL), ==, R_UNICODE_INVALID_CODE_POINT);
  r_assert_cmpint (r_utf32be_to_utf8 (dst, sizeof (dst), src_odd,
        sizeof (src_odd), NULL, NULL), ==, R_UNICODE_INVAL);
}
RTEST_END;

RTEST (runicode, utf16_wire_dup_roundtrip, RTEST_FAST)
{
  static const ruint8 be[10] = {
    0x00, 'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o'
  };
  static const ruint8 le[10] = {
    'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00
  };
  rchar * out_be, * out_le;
  RUnicodeResult r;
  ruint8 * end;

  out_be = r_utf16be_to_utf8_dup (be, sizeof (be), &r, NULL, &end);
  r_assert_cmpptr (out_be, !=, NULL);
  r_assert_cmpint (r, ==, R_UNICODE_OK);
  r_assert_cmpstr (out_be, ==, "hello");

  out_le = r_utf16le_to_utf8_dup (le, sizeof (le), &r, NULL, &end);
  r_assert_cmpptr (out_le, !=, NULL);
  r_assert_cmpstr (out_le, ==, "hello");

  r_free (out_be);
  r_free (out_le);
}
RTEST_END;

/* ---- ASCII classification ----------------------------------------- */

RTEST (runicode, ascii_classifiers, RTEST_FAST)
{
  /* Exhaustive over [0, 0x100) plus a couple of non-ASCII spot checks
   * to confirm everything outside the ASCII range answers FALSE. */
  runichar4 i;

  /* is_ascii. */
  r_assert (r_unichar_is_ascii ('a'));
  r_assert (r_unichar_is_ascii (0x7F));
  r_assert (!r_unichar_is_ascii (0x80));
  r_assert (!r_unichar_is_ascii (0x3B1));     /* α */
  r_assert (!r_unichar_is_ascii (0x10000));

  /* letter. */
  r_assert (r_unichar_is_ascii_letter ('A'));
  r_assert (r_unichar_is_ascii_letter ('Z'));
  r_assert (r_unichar_is_ascii_letter ('a'));
  r_assert (r_unichar_is_ascii_letter ('z'));
  r_assert (!r_unichar_is_ascii_letter ('@'));
  r_assert (!r_unichar_is_ascii_letter ('['));
  r_assert (!r_unichar_is_ascii_letter ('`'));
  r_assert (!r_unichar_is_ascii_letter ('{'));
  r_assert (!r_unichar_is_ascii_letter (0x3B1));

  /* digit. */
  r_assert (r_unichar_is_ascii_digit ('0'));
  r_assert (r_unichar_is_ascii_digit ('9'));
  r_assert (!r_unichar_is_ascii_digit ('/'));
  r_assert (!r_unichar_is_ascii_digit (':'));
  /* U+0660 = Arabic-Indic 0 -- a digit per UCD but not ASCII. */
  r_assert (!r_unichar_is_ascii_digit (0x0660));

  /* alnum. */
  r_assert (r_unichar_is_ascii_alnum ('A'));
  r_assert (r_unichar_is_ascii_alnum ('5'));
  r_assert (!r_unichar_is_ascii_alnum ('-'));

  /* hex_digit. */
  r_assert (r_unichar_is_ascii_hex_digit ('0'));
  r_assert (r_unichar_is_ascii_hex_digit ('9'));
  r_assert (r_unichar_is_ascii_hex_digit ('A'));
  r_assert (r_unichar_is_ascii_hex_digit ('F'));
  r_assert (r_unichar_is_ascii_hex_digit ('a'));
  r_assert (r_unichar_is_ascii_hex_digit ('f'));
  r_assert (!r_unichar_is_ascii_hex_digit ('G'));
  r_assert (!r_unichar_is_ascii_hex_digit ('g'));

  /* space. */
  r_assert (r_unichar_is_ascii_space (' '));
  r_assert (r_unichar_is_ascii_space ('\t'));
  r_assert (r_unichar_is_ascii_space ('\n'));
  r_assert (r_unichar_is_ascii_space ('\v'));
  r_assert (r_unichar_is_ascii_space ('\f'));
  r_assert (r_unichar_is_ascii_space ('\r'));
  r_assert (!r_unichar_is_ascii_space ('a'));
  r_assert (!r_unichar_is_ascii_space (0x00A0));  /* NBSP, not ASCII. */

  /* control. */
  r_assert (r_unichar_is_ascii_control (0));
  r_assert (r_unichar_is_ascii_control (0x1F));
  r_assert (r_unichar_is_ascii_control (0x7F));
  r_assert (!r_unichar_is_ascii_control (' '));
  r_assert (!r_unichar_is_ascii_control ('a'));

  /* print. */
  r_assert (r_unichar_is_ascii_print (' '));
  r_assert (r_unichar_is_ascii_print ('a'));
  r_assert (r_unichar_is_ascii_print ('~'));
  r_assert (!r_unichar_is_ascii_print (0x7F));
  r_assert (!r_unichar_is_ascii_print (0x1F));
  r_assert (!r_unichar_is_ascii_print (0x80));

  /* punct. */
  r_assert (r_unichar_is_ascii_punct ('!'));
  r_assert (r_unichar_is_ascii_punct ('/'));
  r_assert (r_unichar_is_ascii_punct (':'));
  r_assert (r_unichar_is_ascii_punct ('~'));
  r_assert (!r_unichar_is_ascii_punct ('a'));
  r_assert (!r_unichar_is_ascii_punct ('0'));
  r_assert (!r_unichar_is_ascii_punct (' '));
  r_assert (!r_unichar_is_ascii_punct (0x7F));

  /* Every non-ASCII codepoint must answer FALSE to every class
   * except is_ascii itself (which it already fails). Spot-check
   * around the boundary. */
  for (i = 0x80; i <= 0x100; i++) {
    r_assert (!r_unichar_is_ascii (i));
    r_assert (!r_unichar_is_ascii_letter (i));
    r_assert (!r_unichar_is_ascii_digit (i));
    r_assert (!r_unichar_is_ascii_alnum (i));
    r_assert (!r_unichar_is_ascii_hex_digit (i));
    r_assert (!r_unichar_is_ascii_space (i));
    r_assert (!r_unichar_is_ascii_control (i));
    r_assert (!r_unichar_is_ascii_print (i));
    r_assert (!r_unichar_is_ascii_punct (i));
  }
}
RTEST_END;
