#include <rlib/rlib.h>

RTEST (rbitset, stack, RTEST_FAST)
{
  RBitset * bitset;

  r_assert (r_bitset_init_stack (bitset, 80));

  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);
  r_assert (!r_bitset_set_bit (bitset, 80, TRUE));
  r_assert ( r_bitset_set_bit (bitset, 0, TRUE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 1);
  r_assert ( r_bitset_is_bit_set (bitset, 0));
  r_assert ( r_bitset_set_bit (bitset, 0, FALSE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);

  r_assert (r_bitset_init_stack (bitset, sizeof (rbsword) * 8));
  r_assert_cmpuint (_R_BITSET_BITS_SIZE (bitset->bsize) / sizeof (rbsword), ==, 1);

}
RTEST_END;

RTEST (rbitset, heap, RTEST_FAST)
{
  RBitset * bitset;

  r_assert (r_bitset_init_heap (bitset, 80));

  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);
  r_assert (!r_bitset_set_bit (bitset, 80, TRUE));
  r_assert ( r_bitset_set_bit (bitset, 0, TRUE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 1);
  r_assert ( r_bitset_is_bit_set (bitset, 0));
  r_assert ( r_bitset_set_bit (bitset, 0, FALSE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);

  r_free (bitset);
}
RTEST_END;

RTEST (rbitset, copy, RTEST_FAST)
{
  RBitset * a, * b, * c;

  r_assert (!r_bitset_copy (NULL, NULL));

  r_assert (r_bitset_init_stack (a, 26));
  r_assert (r_bitset_init_stack (b, 64));
  r_assert (r_bitset_init_stack (c, 80));

  r_assert (!r_bitset_copy (NULL, NULL));
  r_assert (!r_bitset_copy (a, NULL));
  r_assert (!r_bitset_copy (NULL, b));

  r_assert (r_bitset_set_all (a, TRUE));
  r_assert (!r_bitset_copy (a, b));
  r_assert_cmpuint (r_bitset_popcount (b), ==, 0);
  r_assert (r_bitset_copy (b, a));
  r_assert_cmpuint (r_bitset_popcount (b), ==, a->bsize);

  r_assert (r_bitset_clear (c));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 0);
  r_assert (r_bitset_copy (c, a));
  r_assert_cmpuint (r_bitset_popcount (c), ==, a->bsize);
}
RTEST_END;

RTEST (rbitset, set_at, RTEST_FAST)
{
  RBitset * a, * b;
  rsize i, j;

  r_assert (!r_bitset_set_u8_at (NULL, 42, 0));
  r_assert (!r_bitset_set_u16_at (NULL, 42, 0));
  r_assert (!r_bitset_set_u32_at (NULL, 42, 0));
  r_assert (!r_bitset_set_u64_at (NULL, 42, 0));

  r_assert (r_bitset_init_stack (a, 26));
  r_assert (r_bitset_init_stack (b, 80));

  r_assert (!r_bitset_set_u8_at (a, 42, 20));
  r_assert (!r_bitset_set_u16_at (a, 42, 12));
  r_assert (!r_bitset_set_u32_at (a, 42, 0));
  r_assert (!r_bitset_set_u64_at (b, 42, 20));

  /* u8 */
  r_assert (r_bitset_clear (a));
  r_assert (r_bitset_set_u8_at (a, 0x9C, 2));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 4);
  r_assert (r_bitset_is_bit_set (a, 4));
  r_assert (r_bitset_is_bit_set (a, 5));
  r_assert (r_bitset_is_bit_set (a, 6));
  r_assert (r_bitset_is_bit_set (a, 9));

  r_assert (r_bitset_clear (b));
  r_assert (r_bitset_set_u8_at (b, 0x9C, 61));
  r_assert (r_bitset_is_bit_set (b, 63));
  r_assert (r_bitset_is_bit_set (b, 64));
  r_assert (r_bitset_is_bit_set (b, 65));
  r_assert (r_bitset_is_bit_set (b, 68));

  /* u16 */
  r_assert (r_bitset_clear (a));
  r_assert (r_bitset_set_u16_at (a, 0x09C0, 5));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 4);
  r_assert (r_bitset_is_bit_set (a, 11));
  r_assert (r_bitset_is_bit_set (a, 12));
  r_assert (r_bitset_is_bit_set (a, 13));
  r_assert (r_bitset_is_bit_set (a, 16));

  /* u32 */
  r_assert (r_bitset_clear (b));
  r_assert (r_bitset_set_u32_at (b, 0x09C009C0, 26));
  r_assert_cmpuint (r_bitset_popcount (b), ==, 8);
  r_assert (r_bitset_is_bit_set (b, 32));
  r_assert (r_bitset_is_bit_set (b, 33));
  r_assert (r_bitset_is_bit_set (b, 34));
  r_assert (r_bitset_is_bit_set (b, 37));
  r_assert (r_bitset_is_bit_set (b, 48));
  r_assert (r_bitset_is_bit_set (b, 49));
  r_assert (r_bitset_is_bit_set (b, 50));
  r_assert (r_bitset_is_bit_set (b, 53));

  /* u64 */
  r_assert (r_bitset_clear (b));
  r_assert (r_bitset_set_u64_at (b, RUINT64_CONSTANT (0x00FF00FF00FF00FF), 2));
  r_assert_cmpuint (r_bitset_popcount (b), ==, 32);
  for (i = 0; i < sizeof (ruint64); ) {
    for (j = 0; j < 8; j++, i++)
      r_assert (r_bitset_is_bit_set (b, i + 2));
    for (j = 0; j < 8; j++, i++)
      r_assert (!r_bitset_is_bit_set (b, i + 2));
  }
}
RTEST_END;

static void
bitset_counter (rsize bit, rpointer user)
{
  rsize * count = user;
  (*count)++;

  (void) bit;
}

static void
bitset_bitpos_acc (rsize bit, rpointer user)
{
  (*(rsize *)user) += bit;
}

RTEST (rbitset, foreach, RTEST_FAST)
{
  RBitset * bitset;
  rsize count = 0;

  r_assert (r_bitset_init_stack (bitset, 160));

  r_bitset_foreach (bitset, TRUE, bitset_counter, &count);
  r_assert_cmpuint (count, ==, 0);

  r_assert ( r_bitset_set_bit (bitset, 0, TRUE));
  r_assert ( r_bitset_set_bit (bitset, 126, TRUE));
  r_assert ( r_bitset_set_bit (bitset, 90, TRUE));
  r_assert ( r_bitset_set_bit (bitset, 66, TRUE));
  r_assert ( r_bitset_set_bit (bitset, 153, TRUE));
  r_assert ( r_bitset_set_bit (bitset, 54, TRUE));

  r_bitset_foreach (bitset, TRUE, bitset_counter, &count);
  r_assert_cmpuint (count, ==, 6);
  count = 0;
  r_bitset_foreach (bitset, FALSE, bitset_counter, &count);
  r_assert_cmpuint (count, ==, 154);

  count = 0;
  r_bitset_foreach (bitset, TRUE, bitset_bitpos_acc, &count);
  r_assert_cmpuint (count, ==, 489);
}
RTEST_END;

RTEST (rbitset, set_bits, RTEST_FAST)
{
  RBitset * bitset;
  rsize array[] = { 2, 55, 123, 99, 3, 160, 44, 103 };

  r_assert (r_bitset_init_stack (bitset, 176));

  r_assert (!r_bitset_set_bits (NULL, NULL, 0, TRUE));
  r_assert (!r_bitset_set_bits (bitset, NULL, 0, TRUE));
  r_assert ( r_bitset_set_bits (bitset, array, 0, TRUE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);

  r_assert ( r_bitset_set_bits (bitset, array, R_N_ELEMENTS (array), TRUE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, R_N_ELEMENTS (array));
}
RTEST_END;

RTEST (rbitset, set_all, RTEST_FAST)
{
  RBitset * bitset;

  r_assert (!r_bitset_set_all (NULL, TRUE));

  r_assert (r_bitset_init_stack (bitset, 76));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);

  r_assert (r_bitset_set_all (bitset, TRUE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 76);

  r_assert (r_bitset_clear (bitset));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);
}
RTEST_END;

RTEST (rbitset, or, RTEST_FAST)
{
  RBitset * a, * b, * c;

  r_assert (r_bitset_init_stack (a, 26));
  r_assert (r_bitset_init_stack (b, 66));
  r_assert (r_bitset_init_stack (c, 76));

  r_assert (!r_bitset_or (NULL, NULL, NULL));
  r_assert (!r_bitset_or (a, NULL, NULL));
  r_assert (!r_bitset_or (a, b, NULL));
  r_assert (!r_bitset_or (a, b, c));          /* a is too small */

  r_assert_cmpuint (r_bitset_popcount (c), ==, 0);
  r_assert (r_bitset_or (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 0);
  r_assert (r_bitset_set_all (b, TRUE));
  r_assert (r_bitset_or (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 66);
  r_assert (r_bitset_clear (c));
  r_assert (r_bitset_set_all (a, TRUE));
  r_assert (r_bitset_set_all (b, TRUE));
  r_assert (r_bitset_or (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 66);
}
RTEST_END;

RTEST (rbitset, and, RTEST_FAST)
{
  RBitset * a, * b, * c;

  r_assert (r_bitset_init_stack (a, 26));
  r_assert (r_bitset_init_stack (b, 66));
  r_assert (r_bitset_init_stack (c, 76));

  r_assert (!r_bitset_and (NULL, NULL, NULL));
  r_assert (!r_bitset_and (a, NULL, NULL));
  r_assert (!r_bitset_and (a, b, NULL));
  r_assert (!r_bitset_and (a, b, c));         /* a is too small */

  r_assert_cmpuint (r_bitset_popcount (c), ==, 0);
  r_assert (r_bitset_and (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 0);
  r_assert (r_bitset_set_all (b, TRUE));
  r_assert (r_bitset_and (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 0);
  r_assert (r_bitset_clear (c));
  r_assert (r_bitset_set_all (a, TRUE));
  r_assert (r_bitset_set_all (b, TRUE));
  r_assert (r_bitset_and (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 26);
}
RTEST_END;

RTEST (rbitset, xor, RTEST_FAST)
{
  RBitset * a, * b, * c;

  r_assert (r_bitset_init_stack (a, 26));
  r_assert (r_bitset_init_stack (b, 66));
  r_assert (r_bitset_init_stack (c, 76));

  r_assert (!r_bitset_xor (NULL, NULL, NULL));
  r_assert (!r_bitset_xor (a, NULL, NULL));
  r_assert (!r_bitset_xor (a, b, NULL));
  r_assert (!r_bitset_xor (a, b, c));         /* a is too small */

  r_assert_cmpuint (r_bitset_popcount (c), ==, 0);
  r_assert (r_bitset_xor (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 0);
  r_assert (r_bitset_set_all (a, TRUE));
  r_assert (r_bitset_xor (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 26);
  r_assert (r_bitset_clear (c));
  r_assert (r_bitset_set_all (a, TRUE));
  r_assert (r_bitset_set_all (b, TRUE));
  r_assert (r_bitset_xor (c, a, b));
  r_assert_cmpuint (r_bitset_popcount (c), ==, 40);
}
RTEST_END;

RTEST (rbitset, not, RTEST_FAST)
{
  RBitset * a, * b;

  r_assert (r_bitset_init_stack (a, 26));
  r_assert (r_bitset_init_stack (b, 66));

  r_assert (!r_bitset_not (NULL, NULL));
  r_assert (!r_bitset_not (a, NULL));
  r_assert (!r_bitset_not (a, b));          /* a is too small */

  r_assert (r_bitset_inv (a));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 26);
  r_assert (r_bitset_not (b, a));
  r_assert_cmpuint (r_bitset_popcount (b), ==, 0);

  r_assert (r_bitset_set_bit (a, 13, FALSE));
  r_assert (r_bitset_not (b, a));
  r_assert_cmpuint (r_bitset_popcount (b), ==, 1);
  r_assert (r_bitset_is_bit_set (b, 13));
}
RTEST_END;

RTEST (rbitset, shl, RTEST_FAST)
{
  RBitset * a;

  r_assert (r_bitset_init_stack (a, 76));
  r_assert (r_bitset_set_all (a, TRUE));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 76);

  r_assert (!r_bitset_shl (NULL, 0));

  r_assert (r_bitset_shl (a, 76));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 0);
  r_assert (r_bitset_set_all (a, TRUE));

  r_assert (r_bitset_shl (a, 0));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 76);
  r_assert (r_bitset_shl (a, 1));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 75);
  r_assert (!r_bitset_is_bit_set (a, 0));
  r_assert ( r_bitset_is_bit_set (a, 75));

  r_assert (r_bitset_shl (a, 65));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 10);
}
RTEST_END;

RTEST (rbitset, shr, RTEST_FAST)
{
  RBitset * a;

  r_assert (r_bitset_init_stack (a, 76));
  r_assert (r_bitset_set_all (a, TRUE));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 76);

  r_assert (!r_bitset_shr (NULL, 0));

  r_assert (r_bitset_shr (a, 76));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 0);
  r_assert (r_bitset_set_all (a, TRUE));

  r_assert (r_bitset_shr (a, 0));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 76);
  r_assert (r_bitset_shr (a, 1));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 75);
  r_assert ( r_bitset_is_bit_set (a, 0));
  r_assert (!r_bitset_is_bit_set (a, 75));

  r_assert (r_bitset_shr (a, 65));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 10);
}
RTEST_END;

RTEST (rbitset, get_at, RTEST_FAST)
{
  RBitset * a;

  r_assert (r_bitset_init_stack (a, 76));
  r_assert (r_bitset_set_all (a, TRUE));

  r_assert_cmpuint (r_bitset_get_u8_at (NULL, 0), ==, 0);
  r_assert_cmpuint (r_bitset_get_u8_at (a, 76), ==, 0);
  r_assert_cmpuint (r_bitset_get_u8_at (a, 0), ==, RUINT8_MAX);
  r_assert_cmpuint (r_bitset_get_u8_at (a, 70), ==, 0x3f);
  r_assert_cmpuint (r_bitset_get_u8_at (a, 61), ==, RUINT8_MAX);

  r_assert_cmpuint (r_bitset_get_u16_at (NULL, 0), ==, 0);
  r_assert_cmpuint (r_bitset_get_u16_at (a, 76), ==, 0);
  r_assert_cmpuint (r_bitset_get_u16_at (a, 0), ==, RUINT16_MAX);
  r_assert_cmpuint (r_bitset_get_u16_at (a, 63), ==, 0x1fff);
  r_assert_cmpuint (r_bitset_get_u16_at (a, 55), ==, RUINT16_MAX);

  r_assert_cmpuint (r_bitset_get_u32_at (NULL, 0), ==, 0);
  r_assert_cmpuint (r_bitset_get_u32_at (a, 76), ==, 0);
  r_assert_cmpuint (r_bitset_get_u32_at (a, 0), ==, RUINT32_MAX);
  r_assert_cmpuint (r_bitset_get_u32_at (a, 50), ==, 0x3ffffff);
  r_assert_cmpuint (r_bitset_get_u32_at (a, 35), ==, RUINT32_MAX);

  r_assert_cmpuint (r_bitset_get_u64_at (NULL, 0), ==, 0);
  r_assert_cmpuint (r_bitset_get_u64_at (a, 76), ==, 0);
  r_assert_cmpuint (r_bitset_get_u64_at (a, 0), ==, RUINT64_MAX);
  r_assert_cmpuint (r_bitset_get_u64_at (a, 20), ==, RUINT64_CONSTANT (0xffffffffffffff));
  r_assert_cmpuint (r_bitset_get_u64_at (a, 5), ==, RUINT64_MAX);
}
RTEST_END;

RTEST (rbitset, count_zeroes, RTEST_FAST)
{
  RBitset * a, * b;

  r_assert (r_bitset_init_stack (a, 76));

  r_assert_cmpuint (r_bitset_clz (NULL), ==, 0);

  r_assert_cmpuint (r_bitset_clz (a), ==, 76);
  r_assert_cmpuint (r_bitset_ctz (a), ==, 76);

  r_assert (r_bitset_set_all (a, TRUE));
  r_assert_cmpuint (r_bitset_clz (a), ==, 0);
  r_assert_cmpuint (r_bitset_ctz (a), ==, 0);

  r_assert (r_bitset_set_all (a, FALSE));
  r_assert (r_bitset_set_bit (a, 33, TRUE));
  r_assert_cmpuint (r_bitset_ctz (a), ==, 33);
  r_assert_cmpuint (r_bitset_clz (a), ==, 76 - 1 - 33);

  r_assert (r_bitset_init_stack (b, 64));

  r_assert_cmpuint (r_bitset_clz (b), ==, 64);
  r_assert_cmpuint (r_bitset_ctz (b), ==, 64);

  r_assert (r_bitset_set_all (b, TRUE));
  r_assert_cmpuint (r_bitset_clz (b), ==, 0);
  r_assert_cmpuint (r_bitset_ctz (b), ==, 0);

  r_assert (r_bitset_set_all (b, FALSE));
  r_assert (r_bitset_set_bit (b, 33, TRUE));
  r_assert_cmpuint (r_bitset_ctz (b), ==, 33);
  r_assert_cmpuint (r_bitset_clz (b), ==, 64 - 1 - 33);
}
RTEST_END;

RTEST (rbitset, set_n_bits_at, RTEST_FAST)
{
  RBitset * a;
  int i;

  r_assert (r_bitset_init_stack (a, 76));

  r_assert (!r_bitset_set_n_bits_at (NULL, 0, 0, TRUE));
  r_assert (!r_bitset_set_n_bits_at (a, 4, 73, TRUE));
  r_assert (r_bitset_set_n_bits_at (a, 0, 0, FALSE));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 0);

  r_assert (r_bitset_set_n_bits_at (a, 4, 72, TRUE));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 4);

  r_assert (r_bitset_clear (a));
  r_assert (r_bitset_set_n_bits_at (a, 5, 0, TRUE));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 5);
  for (i = 0; i < 5; i++)
    r_assert (r_bitset_is_bit_set (a, i));
  r_assert (!r_bitset_is_bit_set (a, 6));
}
RTEST_END;

RTEST (rbitset, set_from_human_readable, RTEST_FAST)
{
  RBitset * a;
  int i;
  rsize bits;

  r_assert (r_bitset_init_stack (a, 76));

  r_assert (!r_bitset_set_from_human_readable (NULL, NULL, NULL));
  r_assert (!r_bitset_set_from_human_readable (a, NULL, NULL));
  r_assert (!r_bitset_set_from_human_readable (a, "-1", NULL));
  r_assert (!r_bitset_set_from_human_readable (a, "77", NULL));

  r_assert (!r_bitset_set_from_human_readable (a, "7,77", NULL));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 1);

  r_assert (r_bitset_clear (a));
  r_assert (r_bitset_set_from_human_readable (a, "7,7", NULL));
  r_assert_cmpuint (r_bitset_popcount (a), ==, 1);

  r_assert (r_bitset_clear (a));
  r_assert (r_bitset_set_from_human_readable (a, "0,2,4,8,9,11,44,55,23,75", &bits));
  r_assert_cmpuint (bits, ==, 10);
  r_assert_cmpuint (r_bitset_popcount (a), ==, 10);
  r_assert (r_bitset_is_bit_set (a, 0));
  r_assert (r_bitset_is_bit_set (a, 2));
  r_assert (r_bitset_is_bit_set (a, 4));
  r_assert (r_bitset_is_bit_set (a, 8));
  r_assert (r_bitset_is_bit_set (a, 9));
  r_assert (r_bitset_is_bit_set (a, 11));
  r_assert (r_bitset_is_bit_set (a, 23));
  r_assert (r_bitset_is_bit_set (a, 44));
  r_assert (r_bitset_is_bit_set (a, 55));
  r_assert (r_bitset_is_bit_set (a, 75));

  r_assert (r_bitset_clear (a));
  r_assert (r_bitset_set_from_human_readable (a, "0-3,8-11,16-19", &bits));
  r_assert_cmpuint (bits, ==, 3*4);
  r_assert_cmpuint (r_bitset_popcount (a), ==, 3*4);
  for (i = 0; i < 20; i++)
    r_assert (r_bitset_is_bit_set (a, i) == ((i / 4) % 2 ? FALSE : TRUE));

  r_assert (r_bitset_clear (a));
  r_assert (r_bitset_set_from_human_readable (a, "  4, 0 -\r\n3,  8\t,\n\r\n\t16-19", &bits));
  r_assert_cmpuint (bits, ==, 10);
  r_assert_cmpuint (r_bitset_popcount (a), ==, 10);
}
RTEST_END;

RTEST (rbitset, set_from_human_readable_file, RTEST_FAST | RTEST_SYSTEM)
{
  RBitset * a;
  int i;
  rsize bits;
  rchar * tmpfile;

  r_assert (r_bitset_init_stack (a, 76));

  r_assert (!r_bitset_set_from_human_readable_file (NULL, NULL, NULL));
  r_assert (!r_bitset_set_from_human_readable_file (a, NULL, NULL));
  r_assert (!r_bitset_set_from_human_readable_file (a, NULL, &bits));

  r_assert_cmpptr ((tmpfile = r_fs_path_new_tmpname_full (NULL, "rbitset", NULL)), !=, NULL);
  r_file_write_all (tmpfile, "0,4-10,16", 9);
  r_assert (r_fs_test_exists (tmpfile));

  r_assert (r_bitset_set_from_human_readable_file (a, tmpfile, &bits));
  r_assert_cmpuint (bits, ==, 9);
  r_assert_cmpuint (r_bitset_popcount (a), ==, bits);

  r_assert (r_bitset_is_bit_set (a, 0));
  r_assert (r_bitset_is_bit_set (a, 16));
  for (i = 4; i <= 10; i++)
    r_assert (r_bitset_is_bit_set (a, i));

  r_free (tmpfile);

  r_assert_cmpptr ((tmpfile = r_fs_path_new_tmpname_full (NULL, "rbitset", NULL)), !=, NULL);
  r_file_write_all (tmpfile, "0, 4 -  10,  16", 15);
  r_assert (r_fs_test_exists (tmpfile));

  r_assert (r_bitset_set_from_human_readable_file (a, tmpfile, &bits));
  r_assert_cmpuint (bits, ==, 9);
  r_assert_cmpuint (r_bitset_popcount (a), ==, bits);

  r_free (tmpfile);
}
RTEST_END;

RTEST (rbitset, to_human_readable, RTEST_FAST)
{
  RBitset * a;
  rchar * hr;

  r_assert (r_bitset_init_stack (a, 76));

  r_assert_cmpptr (r_bitset_to_human_readable (NULL), ==, NULL);

  r_assert_cmpptr ((hr = r_bitset_to_human_readable (a)), !=, NULL);
  r_assert_cmpstr (hr, ==, ""); r_free (hr);

  r_assert (r_bitset_set_bit (a, 0, TRUE));
  r_assert_cmpptr ((hr = r_bitset_to_human_readable (a)), !=, NULL);
  r_assert_cmpstr (hr, ==, "0"); r_free (hr);

  r_assert (r_bitset_set_n_bits_at (a, 5, 10, TRUE));
  r_assert (r_bitset_set_bit (a, 70, TRUE));
  r_assert_cmpptr ((hr = r_bitset_to_human_readable (a)), !=, NULL);
  r_assert_cmpstr (hr, ==, "0,10-14,70"); r_free (hr);

  r_assert (r_bitset_set_n_bits_at (a, 5, 71, TRUE));
  r_assert_cmpptr ((hr = r_bitset_to_human_readable (a)), !=, NULL);
  r_assert_cmpstr (hr, ==, "0,10-14,70-75"); r_free (hr);
}
RTEST_END;

