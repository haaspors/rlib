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

