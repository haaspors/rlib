#include <rlib/rlib.h>

RTEST (rbitset, stack, RTEST_FAST)
{
  RBitset * bitset;

  r_assert_cmpptr (r_bitset_init_stack (bitset, 80), !=, NULL);

  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);
  r_assert (!r_bitset_set_bit (bitset, 80, TRUE));
  r_assert ( r_bitset_set_bit (bitset, 0, TRUE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 1);
  r_assert ( r_bitset_is_bit_set (bitset, 0));
  r_assert ( r_bitset_set_bit (bitset, 0, FALSE));
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 0);

  r_assert_cmpptr (r_bitset_init_stack (bitset, sizeof (rbsword) * 8), !=, NULL);
  r_assert_cmpuint (_R_BITSET_BITS_SIZE (bitset->bsize) / sizeof (rbsword), ==, 1);

}
RTEST_END;

RTEST (rbitset, heap, RTEST_FAST)
{
  RBitset * bitset;

  r_assert_cmpptr (r_bitset_init_heap (bitset, 80), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (a, 26), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (b, 64), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (c, 80), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (bitset, 160), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (bitset, 176), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (bitset, 76), !=, NULL);
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

  r_assert_cmpptr (r_bitset_init_stack (a, 26), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (b, 66), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (c, 76), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (a, 26), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (b, 66), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (c, 76), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (a, 26), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (b, 66), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (c, 76), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (a, 26), !=, NULL);
  r_assert_cmpptr (r_bitset_init_stack (b, 66), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (a, 76), !=, NULL);
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

  r_assert_cmpptr (r_bitset_init_stack (a, 76), !=, NULL);
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

RTEST (rbitset, count_zeroes, RTEST_FAST)
{
  RBitset * a, * b;

  r_assert_cmpptr (r_bitset_init_stack (a, 76), !=, NULL);

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

  r_assert_cmpptr (r_bitset_init_stack (b, 64), !=, NULL);

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

