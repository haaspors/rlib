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

  /* Partial UTF-16, missing low surrogate */
  utf16[0] = 0x78; utf16[1] = 0x79; utf16[2] = 0xd801; utf16[3] = 0;
  r_assert_cmpptr ((utf8 = r_utf16_to_utf8_dup (utf16, 3, &res, &u8len, &utf16end)), ==, NULL);
  r_assert_cmpint (res, ==, R_UNICODE_INCOMPLETE_CODE_POINT);
  r_assert_cmpuint (u8len, ==, 2);
  r_assert_cmpptr (utf16end, ==, utf16 + 3);

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
