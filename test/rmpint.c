#include <rlib/rlib.h>

RTEST (rmpint, init_and_set, RTEST_FAST)
{
  rmpint a, b;

  /* These test only works when rmpint_digit is 32bit */
  r_assert_cmpuint (sizeof (rmpint_digit), ==, sizeof (ruint32));

  r_mpint_init (&a);
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_assert_cmpuint (r_mpint_digits_used (&a), ==, 0);
  r_assert_cmpuint (r_mpint_bytes_used (&a), ==, 0);
  r_assert_cmpuint (r_mpint_bits_used (&a), ==, 0);
  r_mpint_clear (&a);

  /* digits constraints */
  r_mpint_init_size (&a, 1);
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_mpint_clear (&a);

  /* init_copy and set */
  r_mpint_init (&a);
  r_mpint_set_u32 (&a, 0x42424242);
  r_assert_cmpuint (r_mpint_digits_used (&a), ==, 1);
  r_assert_cmpuint (r_mpint_bytes_used (&a), ==, 4);
  r_assert_cmpuint (r_mpint_bits_used (&a), ==, 31);
  r_mpint_init_copy (&b, &a);
  r_assert_cmpint (r_mpint_cmp (&a, &b), ==, 0);
  r_mpint_set_u32 (&a, 0x0000f00d);
  r_assert_cmpuint (r_mpint_digits_used (&a), ==, 1);
  r_assert_cmpuint (r_mpint_bytes_used (&a), ==, 2);
  r_assert_cmpuint (r_mpint_bits_used (&a), ==, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &b), <, 0);
  r_mpint_set (&a, &b);
  r_assert_cmpint (r_mpint_cmp (&a, &b), ==, 0);
  r_mpint_clear (&a);

  r_mpint_set (&b, &b);
  r_mpint_clear (&b);
}
RTEST_END;

RTEST (rmpint, init_binary, RTEST_FAST)
{
  static const ruint8 small[] = { 0xF0, 0xF1, 0xF2, 0xF3 };
  static const ruint8 big[] = { /* 1024 bits, 128 bytes */
    0xe6, 0x03, 0xbc, 0xf9, 0xfa, 0x9b, 0x40, 0x5c,
    0xd8, 0x51, 0xac, 0x0a, 0x3d, 0x33, 0xf9, 0x12,
    0x0c, 0x89, 0x57, 0xe7, 0x98, 0x25, 0xc2, 0xa5,
    0xbd, 0xae, 0x35, 0x00, 0x0c, 0x5e, 0x6b, 0x1d,
    0x30, 0x21, 0x62, 0x20, 0x0d, 0xd3, 0x56, 0x59,
    0xc2, 0xae, 0x13, 0x8e, 0xff, 0x1e, 0x6b, 0xb3,
    0x94, 0xa7, 0x45, 0xf0, 0xf8, 0x71, 0xb8, 0xaf,
    0x86, 0x13, 0x71, 0x10, 0x6f, 0xa0, 0xdb, 0x08,
    0x7c, 0x74, 0xac, 0x64, 0xdf, 0x7c, 0x8b, 0x41,
    0xf3, 0x36, 0x3f, 0x7a, 0x79, 0x1d, 0x83, 0x3d,
    0x68, 0x02, 0x90, 0x52, 0x3f, 0xc7, 0x4d, 0x0b,
    0x99, 0x26, 0x07, 0x44, 0x68, 0x1b, 0xfe, 0x8c,
    0xc7, 0x0b, 0x67, 0x7d, 0x15, 0xd1, 0x54, 0x6a,
    0x34, 0xf2, 0xf4, 0xd3, 0x61, 0xa4, 0x3f, 0xed,
    0x28, 0x55, 0x52, 0x39, 0x47, 0x14, 0x20, 0xe4,
    0x1a, 0x82, 0xe7, 0x4d, 0x57, 0x69, 0x82, 0xcf };
  static const ruint8 leading0[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x99, 0x26, 0x07, 0x44, 0x68, 0x1b, 0xfe, 0x8c,
    0xc7, 0x0b, 0x67, 0x7d, 0x15, 0xd1, 0x54, 0x6a,
    0x34, 0xf2, 0xf4, 0xd3, 0x61, 0xa4, 0x3f, 0xed,
    0x28, 0x55, 0x52, 0x39, 0x47, 0x14, 0x20, 0xe4,
    0x1a, 0x82, 0xe7, 0x4d, 0x57, 0x69, 0x82, 0xcf };
  rmpint a;

  r_mpint_init_binary (&a, small, sizeof (small));
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_assert_cmpuint (a.dig_used, ==, 1);
  r_assert_cmpuint (r_mpint_get_digit (&a, 0), ==, 0xF0F1F2F3);
  r_mpint_clear (&a);

  r_mpint_init_binary (&a, big, sizeof (big));
  r_assert_cmpuint (a.dig_alloc, >=, 1024 / (sizeof (rmpint_digit) * 8));
  r_assert_cmpuint (a.dig_used, ==, 1024 / (sizeof (rmpint_digit) * 8));
  r_assert_cmpuint (r_mpint_get_digit (&a,  0), ==, 0x576982cf);
  r_assert_cmpuint (r_mpint_get_digit (&a,  1), ==, 0x1a82e74d);
  r_assert_cmpuint (r_mpint_get_digit (&a, 31), ==, 0xe603bcf9);
  r_mpint_clear (&a);

  r_mpint_init_binary (&a, leading0, sizeof (leading0));
  r_assert_cmpuint (r_mpint_digits_used (&a), ==,
      (sizeof (leading0) - 8) / sizeof (rmpint_digit));
  r_mpint_clear (&a);
}
RTEST_END;

RTEST (rmpint, to_binary_new, RTEST_FAST)
{
  rmpint a;
  static const ruint8 bin[] = {
    0x68, 0x9A, 0x56, 0x95, 0x30, 0x44, 0x5C, 0x4F, 0x74, 0x32, 0x87, 0x02,
    0x9F, 0x4C, 0xF8, 0x6C, 0xAE, 0xCA, 0x9E, 0x61, 0x81, 0x21, 0x94, 0x0E,
    0x2F, 0x4A, 0x8D, 0x55, 0x1B, 0xA3, 0x95, 0x2D, 0x3E, 0xDB, 0xB6, 0x80,
    0x49, 0xAB, 0xD6, 0x13, 0x09, 0xBD, 0x8A, 0x82, 0xEB, 0xD0, 0xA7, 0x7E,
    0xDE, 0x3D, 0xA6, 0x9B, 0xF4, 0x4A, 0x18, 0x89, 0xAD, 0x4F, 0x91, 0x5D,
    0xC1, 0x00, 0x00, 0x00, 0x00
  };
  static const ruint8 leading0[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x99, 0x26, 0x07, 0x44, 0x68, 0x1b, 0xfe, 0x8c,
    0xc7, 0x0b, 0x67, 0x7d, 0x15, 0xd1, 0x54, 0x6a,
    0x34, 0xf2, 0xf4, 0xd3, 0x61, 0xa4, 0x3f, 0xed,
    0x28, 0x55, 0x52, 0x39, 0x47, 0x14, 0x20, 0xe4,
    0x1a, 0x82, 0xe7, 0x4d, 0x57, 0x69, 0x82, 0xcf };
  ruint8 * binptr;
  rsize size = 0;

  r_assert_cmpptr (r_mpint_to_binary_new (NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_mpint_to_binary_new (NULL, &size), ==, NULL);

  r_mpint_init (&a);
  r_assert_cmpptr (r_mpint_to_binary_new (&a, NULL), ==, NULL);
  r_assert_cmpptr ((binptr = r_mpint_to_binary_new (&a, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, 0);
  r_mpint_clear (&a);
  r_free (binptr);

  r_mpint_init_binary (&a, bin, sizeof (bin));
  r_assert_cmpptr ((binptr = r_mpint_to_binary_new (&a, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, sizeof (bin));
  r_assert_cmpmem (binptr, ==, bin, size);

  r_mpint_clear (&a);
  r_free (binptr);

  r_mpint_init_binary (&a, leading0, sizeof (leading0));
  r_assert_cmpptr ((binptr = r_mpint_to_binary_new (&a, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, sizeof (leading0) - 8);
  r_assert_cmpmem (binptr, ==, leading0 + 8, size);

  r_mpint_clear (&a);
  r_free (binptr);
}
RTEST_END;

RTEST (rmpint, to_binary_with_size, RTEST_FAST)
{
  rmpint a;
  ruint8 out[256];

  r_memset (out, 0, sizeof (out));
  r_assert (!r_mpint_to_binary_with_size (NULL, NULL, 0));
  r_mpint_init (&a);
  r_mpint_set_u32 (&a, 42);
  r_assert (!r_mpint_to_binary_with_size (&a, NULL, 0));
  r_assert (!r_mpint_to_binary_with_size (NULL, out, 0));
  r_assert (!r_mpint_to_binary_with_size (&a, out, 0));
  r_assert (r_mpint_to_binary_with_size (&a, out, 3));
  r_assert_cmpuint (out[0], ==, 0);
  r_assert_cmpuint (out[1], ==, 0);
  r_assert_cmpuint (out[2], ==, 42);

  r_mpint_clear (&a);
}
RTEST_END;

RTEST (rmpint, to_str, RTEST_FAST)
{
  rmpint a;
  rchar * str;

  r_assert_cmpptr (r_mpint_to_str (NULL), ==, NULL);

  r_mpint_init (&a);
  r_assert_cmpptr ((str = r_mpint_to_str (&a)), !=, NULL);
  r_assert_cmpstr (str, ==, "");
  r_mpint_clear (&a);
  r_free (str);

  r_mpint_init_str (&a, "0xfedcba98765432100123456789abcdef", NULL, 0);
  r_assert_cmpptr ((str = r_mpint_to_str (&a)), !=, NULL);
  r_assert_cmpstr (str, ==, "0xfedcba98765432100123456789abcdef");
  r_mpint_clear (&a);
  r_free (str);
}
RTEST_END;

RTEST (rmpint, init_str, RTEST_FAST)
{
  rmpint a;

  /* Small hexadecimal number */
  r_mpint_init_str (&a, "0x123456", NULL, 0);
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_assert_cmpuint (a.dig_used, ==, 1);
  r_assert_cmpuint (r_mpint_get_digit (&a, 0), ==, 0x123456);
  r_mpint_clear (&a);

  /* Big hexadecimal number */
  r_mpint_init_str (&a, "0xfedcba98765432100123456789abcdef", NULL, 0);
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_assert_cmpuint (a.dig_used, ==, 4);
  r_assert_cmpuint (r_mpint_get_digit (&a, 3), ==, 0xfedcba98);
  r_assert_cmpuint (r_mpint_get_digit (&a, 2), ==, 0x76543210);
  r_assert_cmpuint (r_mpint_get_digit (&a, 1), ==, 0x01234567);
  r_assert_cmpuint (r_mpint_get_digit (&a, 0), ==, 0x89abcdef);
  r_mpint_clear (&a);

  /* hexadecimal number with leading zeros */
  r_mpint_init_str (&a, "0x000000000000000099260744681bfe8cc70b677d15d1546a"
      "34f2f4d361a43fed28555239471420e41a82e74d576982cf", NULL, 0);
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_assert_cmpuint (a.dig_used, ==, 10);
  r_mpint_clear (&a);

  /* Small decimal number */
  r_mpint_init_str (&a, "-4294967295", NULL, 0);
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_assert_cmpuint (a.dig_used, ==, 1);
  r_assert_cmpuint (r_mpint_get_digit (&a, 0), ==, 0xffffffff);
  r_mpint_clear (&a);

  /* Big decimal number */
  r_mpint_init_str (&a,
      "1314413183426951221926094199371466960500662574317200"
      "6030529504645527800951523697620149903055663251854220"
      "067020503783524785523675819158836547734770656069477", NULL, 0);
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_assert_cmpuint (a.dig_used, ==, 16);
  r_assert_cmpuint (r_mpint_get_digit (&a, 15), ==, 0xfaf72d97);
  r_assert_cmpuint (r_mpint_get_digit (&a, 14), ==, 0x665c4766);
  r_assert_cmpuint (r_mpint_get_digit (&a, 13), ==, 0xb9bb3c33);
  r_assert_cmpuint (r_mpint_get_digit (&a, 12), ==, 0x75cc54e0);
  r_assert_cmpuint (r_mpint_get_digit (&a, 11), ==, 0x71121f90);
  r_assert_cmpuint (r_mpint_get_digit (&a, 10), ==, 0xb4aa944c);
  r_assert_cmpuint (r_mpint_get_digit (&a,  9), ==, 0xb88e4bee);
  r_assert_cmpuint (r_mpint_get_digit (&a,  8), ==, 0x64f9d3f8);
  r_assert_cmpuint (r_mpint_get_digit (&a,  7), ==, 0x71dfb9a7);
  r_assert_cmpuint (r_mpint_get_digit (&a,  6), ==, 0x0555dfce);
  r_assert_cmpuint (r_mpint_get_digit (&a,  5), ==, 0x39193d1b);
  r_assert_cmpuint (r_mpint_get_digit (&a,  4), ==, 0xebd5fa63);
  r_assert_cmpuint (r_mpint_get_digit (&a,  3), ==, 0x01522e01);
  r_assert_cmpuint (r_mpint_get_digit (&a,  2), ==, 0x7b05335f);
  r_assert_cmpuint (r_mpint_get_digit (&a,  1), ==, 0xf5816af9);
  r_assert_cmpuint (r_mpint_get_digit (&a,  0), ==, 0xc865c765);
  r_mpint_clear (&a);

  /* decimal number with leading zeros */
  r_mpint_init_str (&a, "0000000000000000"
      "1314413183426951221926094199371466960500662574317200", NULL, 10);
  r_assert_cmpuint (a.dig_alloc, >=, RMPINT_DEF_DIGITS);
  r_assert_cmpuint (a.dig_used, ==, 6);
  r_mpint_clear (&a);

  {
    rmpint b;
    static const ruint8 bin[] = {
      0x68, 0x9A, 0x56, 0x95, 0x30, 0x44, 0x5C, 0x4F, 0x74, 0x32, 0x87, 0x02,
      0x9F, 0x4C, 0xF8, 0x6C, 0xAE, 0xCA, 0x9E, 0x61, 0x81, 0x21, 0x94, 0x0E,
      0x2F, 0x4A, 0x8D, 0x55, 0x1B, 0xA3, 0x95, 0x2D, 0x3E, 0xDB, 0xB6, 0x80,
      0x49, 0xAB, 0xD6, 0x13, 0x09, 0xBD, 0x8A, 0x82, 0xEB, 0xD0, 0xA7, 0x7E,
      0xDE, 0x3D, 0xA6, 0x9B, 0xF4, 0x4A, 0x18, 0x89, 0xAD, 0x4F, 0x91, 0x5D,
      0xC1, 0x00, 0x00, 0x00, 0x00
    };
    r_mpint_init_binary (&b, bin, sizeof (bin));
    r_mpint_init_str (&a,
        "14024953728730578789345009768938286552406233692216360596743065811"
        "05058015625183421168010093796539719923247191572873565397777876666"
        "439544923672811350299508736", NULL, 0);
    r_assert_cmpuint (a.dig_used, ==, 17);
    r_assert_cmpint (r_mpint_cmp (&a, &b), ==, 0);
    r_mpint_clear (&b);
  }
  r_mpint_clear (&a);
}
RTEST_END;

RTEST (rmpint, cmp, RTEST_FAST)
{
  rmpint a, b;

  r_assert_cmpint (r_mpint_cmp (NULL, NULL), ==, 0);
  r_assert_cmpint (r_mpint_cmp (NULL, &b), <, 0);
  r_assert_cmpint (r_mpint_cmp (&a, NULL), >, 0);
  r_assert_cmpint (r_mpint_ucmp (NULL, NULL), ==, 0);
  r_assert_cmpint (r_mpint_ucmp (NULL, &b), <, 0);
  r_assert_cmpint (r_mpint_ucmp (&a, NULL), >, 0);

  r_mpint_init (&a);
  r_mpint_init (&b);

  r_assert_cmpint (r_mpint_cmp (&a, &b), ==, 0);
  r_assert_cmpint (r_mpint_ucmp (&a, &b), ==, 0);

  r_mpint_set_u32 (&a, 1);
  r_assert_cmpint (r_mpint_cmp (&a, &b), >, 0);
  r_assert_cmpint (r_mpint_ucmp (&a, &b), >, 0);

  r_mpint_set_i32 (&b, -1);
  r_assert_cmpint (r_mpint_cmp (&a, &b), >, 0);
  r_assert_cmpint (r_mpint_ucmp (&a, &b), ==, 0);

  r_mpint_set_i32 (&b, -2);
  r_assert_cmpint (r_mpint_cmp (&a, &b), >, 0);
  r_assert_cmpint (r_mpint_ucmp (&a, &b), <, 0);

  r_mpint_clear (&a);
  r_mpint_clear (&b);

  r_mpint_init_str (&a, "0xfedcba98765432100123456789abcdef", NULL, 0);
  r_mpint_init_copy (&b, &a);
  r_assert_cmpint (r_mpint_cmp (&a, &b), ==, 0);
  r_assert_cmpint (r_mpint_ucmp (&a, &b), ==, 0);

  b.sign = 1;
  r_assert (r_mpint_isneg (&b));
  r_assert_cmpint (r_mpint_cmp (&a, &b), >, 0);
  r_assert_cmpint (r_mpint_ucmp (&a, &b), ==, 0);

  r_mpint_clear (&b);
  r_mpint_init_str (&b, "0xedcba987542013589abcde", NULL, 0);
  r_assert_cmpint (r_mpint_cmp (&a, &b), >, 0);
  r_assert_cmpint (r_mpint_ucmp (&a, &b), >, 0);

  r_mpint_clear (&a);
  r_mpint_clear (&b);
}
RTEST_END;

RTEST (rmpint, cmp_x32, RTEST_FAST)
{
  rmpint a;

  r_assert_cmpint (r_mpint_cmp_i32 (NULL, 0), <, 0);
  r_assert_cmpint (r_mpint_ucmp_u32 (NULL, 0), <, 0);

  r_mpint_init (&a);
  r_assert_cmpint (r_mpint_cmp_i32 (&a, 0), ==, 0);
  r_assert_cmpint (r_mpint_ucmp_u32 (&a, 0), ==, 0);

  r_mpint_set_u32 (&a, 1);
  r_assert_cmpint (r_mpint_cmp_i32 (&a, 0), >, 0);
  r_assert_cmpint (r_mpint_cmp_i32 (&a, -1), >, 0);
  r_assert_cmpint (r_mpint_cmp_i32 (&a, 1), ==, 0);
  r_assert_cmpint (r_mpint_ucmp_u32 (&a, 0), >, 0);

  r_mpint_set_i32 (&a, -1);
  r_assert_cmpint (r_mpint_cmp_i32 (&a, 0), <, 0);
  r_assert_cmpint (r_mpint_cmp_i32 (&a, 1), <, 0);
  r_assert_cmpint (r_mpint_cmp_i32 (&a, -1), ==, 0);
  r_assert_cmpint (r_mpint_ucmp_u32 (&a, 0), >, 0);
  r_assert_cmpint (r_mpint_ucmp_u32 (&a, 1), ==, 0);

  r_mpint_clear (&a);

  r_mpint_init_str (&a, "0xfedcba98765432100123456789abcdef", NULL, 0);
  r_assert_cmpint (r_mpint_cmp_i32 (&a, 45653456), >, 0);
  r_assert_cmpint (r_mpint_ucmp_u32 (&a, 45653456), >, 0);

  a.sign = 1;
  r_assert (r_mpint_isneg (&a));
  r_assert_cmpint (r_mpint_cmp_i32 (&a, 45653456), <, 0);
  r_assert_cmpint (r_mpint_ucmp_u32 (&a, 45653456), >, 0);

  r_mpint_clear (&a);
}
RTEST_END;

RTEST (rmpint, add, RTEST_FAST)
{
  rmpint a, b, sum;

  r_mpint_init (&a);
  r_mpint_init (&b);
  r_mpint_init_str (&sum, "0x1aabbaaba", NULL, 16);

  r_assert (!r_mpint_add (NULL, &a, &b));
  r_assert (!r_mpint_add (&sum, NULL, &b));
  r_assert (!r_mpint_add (&sum, &a, NULL));

  r_assert (r_mpint_add_u32 (&a, &a, 0xbaadbaad));
  r_assert_cmpuint (r_mpint_get_digit (&a, 0), ==, 0xbaadbaad);
  r_assert (r_mpint_add_u32 (&b, &b, 0xf00df00d));
  r_assert_cmpuint (r_mpint_get_digit (&b, 0), ==, 0xf00df00d);

  r_assert_cmpuint (a.dig_used, ==, 1);
  r_assert (r_mpint_add (&a, &a, &b));
  r_assert_cmpuint (a.dig_used, ==, 2);
  r_assert_cmpint (r_mpint_cmp (&a, &sum), ==, 0);

  a.sign = 1;
  r_assert (r_mpint_add (&a, &a, &b));
  r_assert_cmpuint (a.dig_used, ==, 1);
  r_assert_cmpuint (r_mpint_get_digit (&a, 0), ==, 0xbaadbaad);

  r_mpint_clear (&a);
  r_mpint_clear (&b);
  r_mpint_clear (&sum);

  r_mpint_init_str (&a, "0xffffffffffffffff", NULL, 16);
  r_mpint_init_str (&sum, "0x10000000000000001", NULL, 16);
  r_assert_cmpuint (a.dig_used, ==, 2);
  r_assert (r_mpint_add_u32 (&a, &a, 2));
  r_assert_cmpuint (a.dig_used, ==, 3);
  r_assert_cmpint (r_mpint_cmp (&sum, &a), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&sum);

}
RTEST_END;

RTEST (rmpint, sub, RTEST_FAST)
{
  rmpint a, b, diff;

  r_assert (!r_mpint_sub (NULL, &a, &b));
  r_assert (!r_mpint_sub (&diff, NULL, &b));
  r_assert (!r_mpint_sub (&diff, &a, NULL));

  r_mpint_init_str (&a, "0xf00df00df00df00d", NULL, 16);
  r_mpint_init_str (&b, "0xbaadbaadbaadbaad", NULL, 16);
  r_assert_cmpuint (a.dig_used, ==, 2);
  r_assert_cmpuint (b.dig_used, ==, 2);

  r_assert (r_mpint_sub (&a, &a, &b));

  r_mpint_init_str (&diff, "0x3560356035603560", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &diff), ==, 0);
  r_mpint_clear (&diff);

  r_assert (r_mpint_sub_u32 (&a, &a, 1));
  r_mpint_init_str (&diff, "0x356035603560355f", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &diff), ==, 0);
  r_mpint_clear (&diff);

  r_mpint_clear (&a);
  r_mpint_clear (&b);
  r_mpint_clear (&diff);

  r_mpint_init_str (&a, "124835812584283582438528", NULL, 10);
  r_mpint_init_str (&b, "234845527586835683495634", NULL, 10);
  r_assert (r_mpint_sub (&a, &a, &b));

  r_mpint_init_str (&diff, "-110009715002552101057106", NULL, 10);
  r_assert_cmpuint (a.sign, ==, diff.sign);
  r_assert_cmpint (r_mpint_cmp (&a, &diff), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&b);
  r_mpint_clear (&diff);
}
RTEST_END;

RTEST (rmpint, mul, RTEST_FAST)
{
  rmpint a, b, product;

  r_assert (!r_mpint_mul (NULL, &a, &b));
  r_assert (!r_mpint_mul (&product, NULL, &b));
  r_assert (!r_mpint_mul (&product, &a, NULL));

  r_mpint_init_str (&a, "124835812584283582438528", NULL, 10);
  r_mpint_init_str (&b, "234845527586835683495634", NULL, 10);
  r_assert (r_mpint_mul (&a, &a, &b));
  r_mpint_init_str (&product, "29317132268087419237854977564655193492961386752",
      NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&a, &product), ==, 0);
  r_mpint_clear (&product);

  r_assert (r_mpint_mul (&b, &b, &b));
  r_mpint_init_str (&product, "55152421827539200050250857282023923061697061956",
      NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&b, &product), ==, 0);
  r_mpint_clear (&product);

  r_mpint_clear (&a);
  r_mpint_clear (&b);

  r_mpint_init_str (&a, "32988508445363273104", NULL, 10);
  r_mpint_init_str (&b, "11842699746565636369428991229064723401144829996871"
      "36371896483394424964980473856", NULL, 10);
  r_assert_cmpuint (r_mpint_digits_used (&a), ==, 3);
  r_assert_cmpuint (r_mpint_digits_used (&b), ==, 9);
  r_assert (r_mpint_mul (&a, &a, &b));
  r_mpint_init_str (&product, "39067300060548198941638232905149031772162646"
      "410671562516825380181480357066568272081261957059969024", NULL, 10);
  r_assert_cmpuint (r_mpint_digits_used (&product), ==, 11);
  r_assert_cmpuint (r_mpint_digits_used (&a), ==, r_mpint_digits_used (&product));
  r_assert_cmpint (r_mpint_cmp (&product, &a), ==, 0);
  r_mpint_clear (&product);
  r_mpint_clear (&a);
  r_mpint_clear (&b);

  r_mpint_init_str (&a, "11842699746565636369428991229064723401144829996871"
      "36371896483394424964980473856", NULL, 10);
  r_assert_cmpuint (r_mpint_digits_used (&a), ==, 9);
  r_assert (r_mpint_mul (&a, &a, &a));
  r_mpint_init_str (&product,
      "14024953728730578789345009768938286552406233692216360596743065811050"
      "58015625183421168010093796539719923247191572873565397777876666439544"
      "923672811350299508736", NULL, 10);
  r_assert_cmpuint (r_mpint_digits_used (&product), ==, 17);
  r_assert_cmpuint (r_mpint_digits_used (&a), ==, r_mpint_digits_used (&product));
  r_assert_cmpmem (product.data, ==, a.data, sizeof (rmpint_digit) * 17);
  r_assert_cmpint (r_mpint_cmp (&product, &a), ==, 0);
  r_mpint_clear (&product);
  r_mpint_clear (&a);
}
RTEST_END;

RTEST (rmpint, div, RTEST_FAST)
{
  rmpint n, d, q, r, cmp;

  r_assert (!r_mpint_div (NULL, NULL, &n, &d));
  r_assert (!r_mpint_div (&q, NULL, NULL, &d));
  r_assert (!r_mpint_div (&q, NULL, &n, NULL));
  r_assert (!r_mpint_div (NULL, &r, NULL, &d));
  r_assert (!r_mpint_div (NULL, &r, &n, NULL));

  r_assert (!r_mpint_div_i32 (&q, &r, &n, 0));
  r_assert (!r_mpint_div_u32 (&q, &r, &n, 0));

  r_mpint_init (&q);
  r_mpint_init (&r);
  r_mpint_init_str (&n, "234845527586835683495634", NULL, 10);
  r_mpint_init_str (&d, "1248358125842835824385", NULL, 10);

  r_assert (r_mpint_div (&q, &r, &n, &d));
  r_assert_cmpuint (q.sign, ==, 0);
  r_assert_cmpuint (q.dig_used, ==, 1);
  r_assert_cmpuint (r_mpint_get_digit (&q, 0), ==, 188);
  r_mpint_init_str (&cmp, "154199928382548511254", NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&r, &cmp), ==, 0);
  r_mpint_clear (&cmp);

  r_assert (r_mpint_div (&q, &r, &d, &n));
  r_assert (r_mpint_iszero (&q));
  r_mpint_init_copy (&cmp, &d);
  r_assert_cmpint (r_mpint_cmp (&r, &cmp), ==, 0);
  r_mpint_clear (&cmp);

  n.sign = 1;
  r_assert (r_mpint_div (&q, &r, &n, &d));
  r_assert_cmpuint (q.sign, !=, 0);
  r_assert_cmpuint (q.dig_used, ==, 1);
  r_assert_cmpuint (r_mpint_get_digit (&q, 0), ==, 188);
  r_mpint_init_str (&cmp, "-154199928382548511254", NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&r, &cmp), ==, 0);
  r_mpint_clear (&cmp);

  n.sign = 0;
  r_assert (r_mpint_div_u32 (&q, &r, &n, 5436258));
  r_mpint_init_str (&cmp, "43199849526427127", NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&q, &cmp), ==, 0);
  r_mpint_clear (&cmp);
  r_mpint_init_str (&cmp, "2924868", NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&r, &cmp), ==, 0);
  r_mpint_clear (&cmp);

  n.sign = 1;
  r_assert (r_mpint_div_i32 (&q, &r, &n, -5436258));
  r_mpint_init_str (&cmp, "43199849526427127", NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&q, &cmp), ==, 0);
  r_mpint_clear (&cmp);
  r_mpint_init_str (&cmp, "-2924868", NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&r, &cmp), ==, 0);
  r_mpint_clear (&cmp);

  r_mpint_clear (&r);
  r_mpint_clear (&q);
  r_mpint_clear (&n);
  r_mpint_clear (&d);
}
RTEST_END;

RTEST (rmpint, shl, RTEST_FAST)
{
  rmpint a, res;

  r_assert (!r_mpint_shl (NULL, &a, 4));
  r_assert (!r_mpint_shl (&a, NULL, 4));

  r_mpint_init_str (&a, "0x3560356035603560", NULL, 16);
  r_assert (r_mpint_shl (&a, &a, sizeof (rmpint_digit) * 8));
  r_mpint_init_str (&res, "0x356035603560356000000000", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&res);

  r_mpint_init_str (&a, "0x3560356035603560", NULL, 16);
  r_assert (r_mpint_shl (&a, &a, 16));
  r_mpint_init_str (&res, "0x35603560356035600000", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&res);

  r_mpint_init_str (&a, "0x3560356035603560", NULL, 16);
  r_assert (r_mpint_shl (&a, &a, 48));
  r_mpint_init_str (&res, "0x3560356035603560000000000000", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&res);

  r_mpint_init (&a);
  r_assert (r_mpint_shl (&a, &a, 16));
  r_assert (r_mpint_iszero (&a));
  r_mpint_clear (&a);
}
RTEST_END;

RTEST (rmpint, shr, RTEST_FAST)
{
  rmpint a, res;

  r_assert (!r_mpint_shr (NULL, &a, 4));
  r_assert (!r_mpint_shr (&a, NULL, 4));

  r_mpint_init_str (&a, "0x3560356035603560", NULL, 16);
  r_assert (r_mpint_shr (&a, &a, sizeof (rmpint_digit) * 8));
  r_mpint_init_str (&res, "0x35603560", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&res);

  r_mpint_init_str (&a, "0x3560356035603560", NULL, 16);
  r_assert (r_mpint_shr (&a, &a, 16));
  r_mpint_init_str (&res, "0x356035603560", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&res);

  r_mpint_init_str (&a, "0x3560356035603560", NULL, 16);
  r_assert (r_mpint_shr (&a, &a, 48));
  r_mpint_init_str (&res, "0x3560", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&res);

  r_mpint_init_str (&a, "0x3560356035603560", NULL, 16);
  r_assert (r_mpint_shr (&a, &a, 80));
  r_assert (r_mpint_iszero (&a));
  r_mpint_clear (&a);
}
RTEST_END;

RTEST (rmpint, gcd, RTEST_FAST)
{
  rmpint a, b, res;

  r_assert (!r_mpint_gcd (NULL, &a, &b));
  r_assert (!r_mpint_gcd (&res, NULL, &b));
  r_assert (!r_mpint_gcd (&res, &a, NULL));

  r_mpint_init_str (&a, "3457247357828345792348577567", NULL, 10);
  r_mpint_init_str (&b, "9243587249656426", NULL, 10);
  r_assert (r_mpint_gcd (&a, &a, &b));

  r_mpint_init_str (&res, "17", NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&res);
  r_mpint_clear (&a);
  r_mpint_clear (&b);

  r_mpint_init_str (&a, "324958749843759385732954874325984357439658735983745", NULL, 10);
  r_mpint_init_str (&b, "2348249874968739", NULL, 10);
  r_assert (r_mpint_gcd (&a, &a, &b));

  r_mpint_init_str (&res, "1", NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&res);
  r_mpint_clear (&a);
  r_mpint_clear (&b);
}
RTEST_END;

RTEST (rmpint, lcm, RTEST_FAST)
{
  rmpint a, b, res;

  r_assert (!r_mpint_lcm (NULL, &a, &b));
  r_assert (!r_mpint_lcm (&res, NULL, &b));
  r_assert (!r_mpint_lcm (&res, &a, NULL));

  r_mpint_init_str (&a, "2385729485729457928345791354", NULL, 10);
  r_mpint_init_str (&b, "425824359872495723", NULL, 10);
  r_assert (r_mpint_lcm (&a, &a, &b));

  r_mpint_init_str (&res, "1015901731089684842289256111254935507415378942",
      NULL, 10);
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&res);

  r_mpint_clear (&a);
  r_mpint_clear (&b);
}
RTEST_END;

RTEST (rmpint, exp, RTEST_FAST)
{
  rmpint b, res;
  ruint16 e = 42;

  r_assert (!r_mpint_exp (NULL, &b, e));
  r_assert (!r_mpint_exp (&res, NULL, e));

  r_mpint_init_str (&b, "5743562348", NULL, 10);
  r_mpint_init (&res);

  r_assert (r_mpint_exp (&res, &b, 0));
  r_assert_cmpuint (res.sign, ==, 0);
  r_assert_cmpuint (res.dig_used, ==, 1);
  r_assert_cmpuint (r_mpint_get_digit (&res, 0), ==, 1);

  r_assert (r_mpint_exp (&res, &b, 1));
  r_assert_cmpint (r_mpint_cmp (&res, &b), ==, 0);
  r_mpint_clear (&res);

  r_mpint_init_str (&res,
      "7684511633251468012111941373117957534768313142611896481287772575946926"
      "3460592407893170235158810804665815408320793320253528501291755061559579"
      "7512324561371665369516872320432258126057797181660079137299773680498462"
      "5705937097166808855574101096405852870118263887064440536268245014411337"
      "0160519826963013677605433875409569605845334283650503173756058464363892"
      "922878014215374707435055836423525033085557552643374479048704", NULL, 10);
  r_assert (r_mpint_exp (&b, &b, e));
  r_assert_cmpint (r_mpint_digits_used (&b), ==, r_mpint_digits_used (&res));
  r_assert_cmpint (r_mpint_cmp (&b, &res), ==, 0);
  r_mpint_clear (&res);

  r_mpint_clear (&b);
}
RTEST_END;

RTEST (rmpint, invmod, RTEST_FAST)
{
  rmpint a, m, res;

  r_mpint_init (&a);
  r_mpint_init (&m);
  r_mpint_init (&res);

  r_assert (!r_mpint_invmod (NULL, &a, &m));
  r_assert (!r_mpint_invmod (&res, NULL, &m));
  r_assert (!r_mpint_invmod (&res, &a, NULL));

  /* Return 0 when no possible inverse exists. */
  r_mpint_set_u32 (&a, 32);
  r_mpint_set_u32 (&m, 1024);
  r_assert (r_mpint_invmod (&res, &a, &m));
  r_assert (r_mpint_iszero (&res));
  r_mpint_set_u32 (&a, 3311);
  r_mpint_set_u32 (&m, 1022);
  r_assert (r_mpint_invmod (&res, &a, &m));
  r_assert (r_mpint_iszero (&res));

  r_mpint_set_u32 (&a, 27);
  r_mpint_set_u32 (&m, 393);
  r_assert (r_mpint_invmod (&res, &a, &m));
  r_assert (r_mpint_iszero (&res));

  r_mpint_set_u32 (&a, 42);
  r_mpint_set_u32 (&m, 2017);
  r_mpint_set_u32 (&res, 1969);
  r_assert (r_mpint_invmod (&a, &a, &m));
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);

  r_mpint_set_u32 (&a, 27);
  r_mpint_set_u32 (&m, 392);
  r_mpint_set_u32 (&res, 363);
  r_assert (r_mpint_invmod (&a, &a, &m));
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&m);
  r_mpint_clear (&res);

  r_mpint_init_str (&a, "234535235234", NULL, 10);
  r_mpint_init_str (&m, "2345665654331", NULL, 10);
  r_mpint_init_str (&res, "146170270779", NULL, 10);
  r_assert_cmpuint (r_mpint_digits_used (&a), >, 1);
  r_assert_cmpuint (r_mpint_digits_used (&m), >, 1);
  r_assert (r_mpint_invmod (&a, &a, &m));
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&m);
  r_mpint_clear (&res);

#if 0
  /* FIXME: bigger integers with even modulo! */
  r_mpint_init_str (&a, "", NULL, 10);
  r_mpint_init_str (&m, "", NULL, 10);
  r_mpint_init_str (&res, "", NULL, 10);
  r_assert_cmpuint (r_mpint_digits_used (&a), >, 1);
  r_assert_cmpuint (r_mpint_digits_used (&m), >, 1);
  r_assert (r_mpint_invmod (&a, &a, &m));
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&m);
  r_mpint_clear (&res);
#endif

  r_mpint_init_str (&a, "324958749843759385732954874325984357439658735983745", NULL, 10);
  r_mpint_init_str (&m, "2348249874968739", NULL, 10);
  r_mpint_init_str (&res, "1741662881064902", NULL, 10);
  r_assert_cmpuint (r_mpint_digits_used (&a), >, 1);
  r_assert_cmpuint (r_mpint_digits_used (&m), >, 1);
  r_assert (r_mpint_invmod (&a, &a, &m));
  r_assert_cmpint (r_mpint_cmp (&a, &res), ==, 0);
  r_mpint_clear (&a);
  r_mpint_clear (&m);
  r_mpint_clear (&res);
}
RTEST_END;

RTEST (rmpint, expmod, RTEST_FAST)
{
  rmpint b, e, m, res;

  r_assert (!r_mpint_expmod (NULL, &b, &e, &m));
  r_assert (!r_mpint_expmod (&res, NULL, &e, &m));
  r_assert (!r_mpint_expmod (&res, &b, NULL, &m));
  r_assert (!r_mpint_expmod (&res, &b, &e, NULL));

  r_mpint_init_str (&b, "4", NULL, 10);
  r_mpint_init_str (&e, "13", NULL, 10);
  r_mpint_init_str (&m, "497", NULL, 10);
  r_mpint_init_str (&res, "445", NULL, 10);
  r_assert (r_mpint_expmod (&b, &b, &e, &m));
  r_assert_cmpuint (r_mpint_digits_used (&res), ==, r_mpint_digits_used (&b));
  r_assert_cmpint (r_mpint_cmp (&b, &res), ==, 0);
  r_mpint_clear (&res);
  r_mpint_clear (&b);
  r_mpint_clear (&e);
  r_mpint_clear (&m);

  r_mpint_init_str (&b, "4782572232345452435234534", NULL, 10);
  r_mpint_init_str (&e, "2345243524352435452983475", NULL, 10);
  r_mpint_init_str (&m, "42359872349587", NULL, 10);
  r_mpint_init_str (&res, "8454269506363", NULL, 10);
  r_assert (r_mpint_expmod (&b, &b, &e, &m));
  r_assert_cmpuint (r_mpint_digits_used (&res), ==, r_mpint_digits_used (&b));
  r_assert_cmpint (r_mpint_cmp (&b, &res), ==, 0);
  r_mpint_clear (&res);
  r_mpint_clear (&b);
  r_mpint_clear (&e);
  r_mpint_clear (&m);

#if 0
  /* TODO: expomod doesn't currently handle even moduli */
  r_mpint_init_str (&b,
      "2988348162058574136915891421498819466320163312926952423791023078876139",
      NULL, 10);
  r_mpint_init_str (&e,
      "2351399303373464486466122544523690094744975233415544072992656881240319",
      NULL, 10);
  r_mpint_init_str (&m, "10000000000000000000000000000000000000000", NULL, 10);
  r_mpint_init_str (&res, "1527229998585248450016808958343740453059", NULL, 10);
  r_assert (r_mpint_expmod (&b, &b, &e, &m));
  r_assert_cmpuint (r_mpint_digits_used (&res), ==, r_mpint_digits_used (&b));
  r_assert_cmpint (r_mpint_cmp (&b, &res), ==, 0);
  r_mpint_clear (&res);
  r_mpint_clear (&b);
  r_mpint_clear (&e);
  r_mpint_clear (&m);
#endif

  /* negative base */
  r_mpint_init_str (&b, "-84574752858235447723458223495", NULL, 10);
  r_mpint_init_str (&e, "574382584732592435987234524", NULL, 10);
  r_mpint_init_str (&m, "48542652439519305", NULL, 10);
  r_mpint_init_str (&res, "42956008133040925", NULL, 10);
  r_assert (r_mpint_expmod (&b, &b, &e, &m));
  r_assert_cmpuint (r_mpint_digits_used (&res), ==, r_mpint_digits_used (&b));
  r_assert_cmpint (r_mpint_cmp (&b, &res), ==, 0);
  r_mpint_clear (&res);
  r_mpint_clear (&b);
  r_mpint_clear (&e);
  r_mpint_clear (&m);

#if 0
  /* TODO: negative power -> do invmod first */
  r_mpint_init_str (&b, "754727543295928345872435", NULL, 10);
  r_mpint_init_str (&e, "-37574235838945234", NULL, 10);
  r_mpint_init_str (&m, "847857457824523895872343", NULL, 10);
  r_mpint_init_str (&res, "????????", NULL, 10);
  r_assert (r_mpint_expmod (&b, &b, &e, &m));
  r_assert_cmpuint (r_mpint_digits_used (&res), ==, r_mpint_digits_used (&b));
  r_assert_cmpint (r_mpint_cmp (&b, &res), ==, 0);
  r_mpint_clear (&res);
  r_mpint_clear (&b);
  r_mpint_clear (&e);
  r_mpint_clear (&m);
#endif
}
RTEST_END;

RTEST (rmpint, ctz, RTEST_FAST)
{
  rmpint a;
  r_mpint_init (&a);

  r_assert_cmpuint (r_mpint_ctz (&a), ==, 32);

  r_mpint_set_u32 (&a, 1);
  r_assert_cmpuint (r_mpint_ctz (&a), ==, 0);

  r_mpint_set_u32 (&a, 65537);
  r_assert_cmpuint (r_mpint_ctz (&a), ==, 0);

  r_mpint_sub_u32 (&a, &a, 1);
  r_assert_cmpuint (r_mpint_ctz (&a), ==, 16);

  r_mpint_shl (&a, &a, 2 * sizeof (rmpint_digit) * 8);
  r_assert_cmpuint (r_mpint_ctz (&a), ==, 16 + 2 * sizeof (rmpint_digit) * 8);

  r_mpint_clear (&a);
}
RTEST_END;

RTEST (rmpint, isprime, RTEST_FAST)
{
  rmpint a;

  r_mpint_init (&a);
  r_assert (!r_mpint_isprime (&a));

  r_mpint_set_u32 (&a, 1);
  r_assert (!r_mpint_isprime (&a));

  r_mpint_set_u32 (&a, 2);
  r_assert (r_mpint_isprime (&a));

  r_mpint_set_u32 (&a, 42);
  r_assert (!r_mpint_isprime (&a));

  r_mpint_set_u32 (&a, 1201);
  r_assert (r_mpint_isprime (&a));

  r_mpint_set_u32 (&a, 65537);
  r_assert (r_mpint_isprime (&a));

  r_assert (r_mpint_mul (&a, &a, &a));
  r_assert (!r_mpint_isprime (&a));
  r_mpint_clear (&a);

  /* Fibonacci prime */
  r_mpint_init_str (&a, "19134702400093278081449423917", NULL, 10);
  r_assert (r_mpint_isprime (&a));
  r_mpint_clear (&a);

  r_mpint_init_str (&a, "9134702400093278081449423917", NULL, 10);
  r_assert (!r_mpint_isprime (&a));
  r_mpint_clear (&a);

  r_mpint_init_str (&a, "22584751787583336797527561822649328254745329", NULL, 10);
  r_assert (r_mpint_isprime (&a));
  r_mpint_clear (&a);
}
RTEST_END;

