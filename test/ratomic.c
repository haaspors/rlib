#include <rlib/rlib.h>

RTEST (ratomic, int_load_store_exchange, R_TEST_TYPE_FAST)
{
  raint a = 0;

  r_assert_cmpint (r_atomic_int_load (&a), ==, 0);
  r_atomic_int_store (&a, 42);
  r_assert_cmpint (r_atomic_int_load (&a), ==, 42);
  r_assert_cmpint (r_atomic_int_exchange (&a, 7), ==, 42);
  r_assert_cmpint (r_atomic_int_load (&a), ==, 7);
}
RTEST_END;

RTEST (ratomic, int_cmp_xchg, R_TEST_TYPE_FAST)
{
  raint a = 10;
  int old;

  /* Success: *a matches old, gets replaced, returns TRUE. */
  old = 10;
  r_assert (r_atomic_int_cmp_xchg_strong (&a, &old, 20));
  r_assert_cmpint (r_atomic_int_load (&a), ==, 20);

  /* Failure: *a no longer matches old. Must return FALSE *and* write
   * the observed value back into old (the C11 semantic the MSVC path
   * has to emulate, otherwise retry loops spin forever). */
  old = 10;
  r_assert (!r_atomic_int_cmp_xchg_strong (&a, &old, 30));
  r_assert_cmpint (old, ==, 20);
  r_assert_cmpint (r_atomic_int_load (&a), ==, 20);

  /* A retry against the written-back value now succeeds. */
  r_assert (r_atomic_int_cmp_xchg_strong (&a, &old, 30));
  r_assert_cmpint (r_atomic_int_load (&a), ==, 30);

  /* Weak variant: same contract on the failure writeback (it may fail
   * spuriously, so only the failure-path writeback is asserted). */
  old = 0;
  r_assert (!r_atomic_int_cmp_xchg_weak (&a, &old, 99));
  r_assert_cmpint (old, ==, 30);
}
RTEST_END;

RTEST (ratomic, int_fetch_ops, R_TEST_TYPE_FAST)
{
  raint a = 0;

  r_assert_cmpint (r_atomic_int_fetch_add (&a, 5), ==, 0);
  r_assert_cmpint (r_atomic_int_fetch_add (&a, 3), ==, 5);
  r_assert_cmpint (r_atomic_int_fetch_sub (&a, 2), ==, 8);
  r_assert_cmpint (r_atomic_int_load (&a), ==, 6);

  r_atomic_int_store (&a, 0x0f);
  r_assert_cmpint (r_atomic_int_fetch_and (&a, 0x09), ==, 0x0f);
  r_assert_cmpint (r_atomic_int_load (&a), ==, 0x09);
  r_assert_cmpint (r_atomic_int_fetch_or (&a, 0x06), ==, 0x09);
  r_assert_cmpint (r_atomic_int_load (&a), ==, 0x0f);
  r_assert_cmpint (r_atomic_int_fetch_xor (&a, 0x0a), ==, 0x0f);
  r_assert_cmpint (r_atomic_int_load (&a), ==, 0x05);
}
RTEST_END;

RTEST (ratomic, uint_ops, R_TEST_TYPE_FAST)
{
  rauint a = 0;
  ruint old;

  r_atomic_uint_store (&a, 100);
  r_assert_cmpuint (r_atomic_uint_load (&a), ==, 100);
  r_assert_cmpuint (r_atomic_uint_exchange (&a, 5), ==, 100);

  r_assert_cmpuint (r_atomic_uint_fetch_add (&a, 10), ==, 5);
  r_assert_cmpuint (r_atomic_uint_fetch_sub (&a, 7), ==, 15);
  r_assert_cmpuint (r_atomic_uint_load (&a), ==, 8);

  old = 8;
  r_assert (r_atomic_uint_cmp_xchg_strong (&a, &old, 64));
  r_assert_cmpuint (r_atomic_uint_load (&a), ==, 64);
  old = 8;
  r_assert (!r_atomic_uint_cmp_xchg_strong (&a, &old, 1));
  r_assert_cmpuint (old, ==, 64);

  r_atomic_uint_store (&a, 0xf0);
  r_assert_cmpuint (r_atomic_uint_fetch_and (&a, 0xa0), ==, 0xf0);
  r_assert_cmpuint (r_atomic_uint_fetch_or  (&a, 0x0c), ==, 0xa0);
  r_assert_cmpuint (r_atomic_uint_fetch_xor (&a, 0xaa), ==, 0xac);
  r_assert_cmpuint (r_atomic_uint_load (&a), ==, 0x06);
}
RTEST_END;

RTEST (ratomic, ptr_ops, R_TEST_TYPE_FAST)
{
  raptr a = 0;
  rpointer old;

  r_assert_cmpptr (r_atomic_ptr_load (&a), ==, NULL);
  r_atomic_ptr_store (&a, RSIZE_TO_POINTER (0x1000));
  r_assert_cmpptr (r_atomic_ptr_load (&a), ==, RSIZE_TO_POINTER (0x1000));
  r_assert_cmpptr (r_atomic_ptr_exchange (&a, RSIZE_TO_POINTER (0x2000)), ==,
      RSIZE_TO_POINTER (0x1000));

  /* cmp_xchg success + failure-writeback, same as the int case. */
  old = RSIZE_TO_POINTER (0x2000);
  r_assert (r_atomic_ptr_cmp_xchg_strong (&a, &old, RSIZE_TO_POINTER (0x3000)));
  r_assert_cmpptr (r_atomic_ptr_load (&a), ==, RSIZE_TO_POINTER (0x3000));

  old = RSIZE_TO_POINTER (0x2000);
  r_assert (!r_atomic_ptr_cmp_xchg_strong (&a, &old, RSIZE_TO_POINTER (0x4000)));
  r_assert_cmpptr (old, ==, RSIZE_TO_POINTER (0x3000));
  r_assert_cmpptr (r_atomic_ptr_load (&a), ==, RSIZE_TO_POINTER (0x3000));
}
RTEST_END;
