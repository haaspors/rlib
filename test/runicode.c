#include <rlib/rlib.h>

RTEST (runicode, utf16_to_utf8, RTEST_FAST)
{
  runichar2 utf16[64];
  rchar * utf8;
  rlong u16len, u8len;
  rboolean error;

  utf16[0] = 0x61; utf16[1] = 0x62; utf16[2] = 0x63;
  utf16[3] = 0x31; utf16[4] = 0x32; utf16[5] = 0x33;
  utf16[6] = 0x21; utf16[7] = 0x22; utf16[8] = 0x23; utf16[9] = 0;
  utf8 = r_utf16_to_utf8 (utf16, 9, &error, &u16len, &u8len);
  r_assert_cmpstr (utf8, ==, "abc123!\"#");
  r_assert (!error);
  r_assert_cmpint (u16len, ==, 9);
  r_assert_cmpint (u8len, ==, 9);
  r_free (utf8);

  /* 2byte UTF-8 */
  utf16[0] = 0x3b1; utf16[1] = 0x3b2; utf16[2] = 0x3b3; utf16[3] = 0;
  utf8 = r_utf16_to_utf8 (utf16, 3, &error, &u16len, &u8len);
  r_assert_cmpstr (utf8, ==, "\xCE\xB1\xCE\xB2\xCE\xB3");
  r_assert (!error);
  r_assert_cmpint (u16len, ==, 3);
  r_assert_cmpint (u8len, ==, 6);
  r_free (utf8);

  /* Maxium UTF-16: 0x10FFFF = 0xD8FF 0xDFFFF = 4byte UTF-8*/
  utf16[0] = 0xDBFF; utf16[1] = 0xDFFF; utf16[2] = 0;
  utf8 = r_utf16_to_utf8 (utf16, 4, &error, &u16len, &u8len);
  r_assert_cmpstr (utf8, ==, "\xF4\x8F\xBF\xBF");
  r_assert (!error);
  r_assert_cmpint (u16len, ==, 2);
  r_assert_cmpint (u8len, ==, 4);
  r_free (utf8);

  /* Partial UTF-16, missing low surrogate */
  utf16[0] = 0x78; utf16[1] = 0x79; utf16[2] = 0xd801; utf16[3] = 0;
  utf8 = r_utf16_to_utf8 (utf16, 3, &error, &u16len, &u8len);
  r_assert_cmpstr (utf8, ==, "xy");
  r_assert (error);
  r_assert_cmpint (u16len, ==, 3);
  r_assert_cmpint (u8len, ==, 2);
  r_free (utf8);

  /* Invalid UTF-16, missing high surrogate */
  utf16[0] = 0x79; utf16[1] = 0x7A; utf16[2] = 0xdc01; utf16[3] = 0;
  utf8 = r_utf16_to_utf8 (utf16, 3, &error, &u16len, &u8len);
  r_assert_cmpstr (utf8, ==, "yz");
  r_assert (error);
  r_assert_cmpint (u16len, ==, 2);
  r_assert_cmpint (u8len, ==, 2);
  r_free (utf8);
}
RTEST_END;

RTEST (runicode, utf8_to_utf16, RTEST_FAST)
{
  runichar2 utf16[64], * ptr;
  rlong u16len, u8len;
  rboolean error;

  ptr = r_utf8_to_utf16 ("abc123!\"#", 9, &error, &u8len, &u16len);
  r_assert (!error);
  r_assert_cmpint (u8len, ==, 9);
  r_assert_cmpint (u16len, ==, 9);
  utf16[0] = 0x61; utf16[1] = 0x62; utf16[2] = 0x63;
  utf16[3] = 0x31; utf16[4] = 0x32; utf16[5] = 0x33;
  utf16[6] = 0x21; utf16[7] = 0x22; utf16[8] = 0x23; utf16[9] = 0;
  r_assert_cmpmem (ptr, ==, utf16, sizeof (runichar2) * 9);
  r_free (ptr);

  ptr = r_utf8_to_utf16 ("\xCE\xB1\xCE\xB2\xCE\xB3", 6, &error, &u8len, &u16len);
  r_assert (!error);
  r_assert_cmpint (u8len, ==, 6);
  r_assert_cmpint (u16len, ==, 3);
  utf16[0] = 0x3b1; utf16[1] = 0x3b2; utf16[2] = 0x3b3; utf16[3] = 0;
  r_assert_cmpmem (ptr, ==, utf16, sizeof (runichar2) * 3);
  r_free (ptr);

  /* Error, partial utf8 codepoint (missing 0x80 in second byte) */
  ptr = r_utf8_to_utf16 ("\xCE\xB1\xCE\xB2\xCE\x33", 6, &error, &u8len, &u16len);
  r_assert (error);
  r_assert_cmpint (u8len, ==, 4);
  r_assert_cmpint (u16len, ==, 2);
  utf16[0] = 0x3b1; utf16[1] = 0x3b2; utf16[2] = 0;
  r_assert_cmpmem (ptr, ==, utf16, sizeof (runichar2) * 2);
  r_free (ptr);

  /* Error, invalid utf8 codepoint */
  ptr = r_utf8_to_utf16 ("\xCE\xB1\xFE\xB2\xCE\xC3", 6, &error, &u8len, &u16len);
  r_assert (error);
  r_assert_cmpint (u8len, ==, 2);
  r_assert_cmpint (u16len, ==, 1);
  utf16[0] = 0x3b1; utf16[1] = 0;
  r_assert_cmpuint (ptr[0], ==, utf16[0]);
  r_free (ptr);
}
RTEST_END;
