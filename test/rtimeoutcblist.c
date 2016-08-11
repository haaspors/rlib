#include <rlib/rlib.h>

RTEST (rtimeoutcblist, single_insert_update, RTEST_FAST)
{
  RTimeoutCBList lst = R_TIMEOUT_CBLIST_INIT;

  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 0);

  r_assert (r_timeout_cblist_insert (&lst, 0, NULL, NULL, NULL, NULL, NULL));
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 1);

  r_assert_cmpuint (r_timeout_cblist_update (&lst, 0), ==, 1);
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 0);

  r_timeout_cblist_clear (&lst);
}
RTEST_END;

RTEST (rtimeoutcblist, notify, RTEST_FAST)
{
  RTimeoutCBList lst = R_TIMEOUT_CBLIST_INIT;

  r_assert (r_timeout_cblist_insert (&lst, 0, NULL, r_malloc (512), r_free, r_malloc (256), r_free));
  r_assert_cmpuint (r_timeout_cblist_update (&lst, 0), ==, 1);
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 0);

  r_assert (r_timeout_cblist_insert (&lst, 0, NULL, r_malloc (512), r_free, r_malloc (256), r_free));
  r_timeout_cblist_clear (&lst);
}
RTEST_END;

RTEST (rtimeoutcblist, insert_after, RTEST_FAST)
{
  RTimeoutCBList lst = R_TIMEOUT_CBLIST_INIT;

  r_assert (r_timeout_cblist_insert (&lst, 0, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 1, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 2, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 3, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 4, NULL, NULL, NULL, NULL, NULL));
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 5);

  r_assert_cmpuint (r_timeout_cblist_update (&lst, 2), ==, 3);
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 2);

  r_timeout_cblist_clear (&lst);
}
RTEST_END;

RTEST (rtimeoutcblist, insert_before, RTEST_FAST)
{
  RTimeoutCBList lst = R_TIMEOUT_CBLIST_INIT;

  r_assert (r_timeout_cblist_insert (&lst, 4, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 3, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 2, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 1, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 0, NULL, NULL, NULL, NULL, NULL));
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 5);

  r_assert_cmpuint (r_timeout_cblist_update (&lst, 2), ==, 3);
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 2);

  r_timeout_cblist_clear (&lst);
}
RTEST_END;

RTEST (rtimeoutcblist, insert_middle, RTEST_FAST)
{
  RTimeoutCBList lst = R_TIMEOUT_CBLIST_INIT;

  r_assert (r_timeout_cblist_insert (&lst, 4, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 0, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 2, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 1, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 3, NULL, NULL, NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 2, NULL, NULL, NULL, NULL, NULL));
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 6);

  r_assert_cmpuint (r_timeout_cblist_update (&lst, 2), ==, 4);
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 2);

  r_timeout_cblist_clear (&lst);
}
RTEST_END;

static void
increment_data (rpointer data, rpointer user)
{
  (void) user;
  (*((ruint *)data))++;
}

RTEST (rtimeoutcblist, cb, RTEST_FAST)
{
  RTimeoutCBList lst = R_TIMEOUT_CBLIST_INIT;
  ruint called[5] = { 0, 0, 0, 0, 0 };

  r_assert (r_timeout_cblist_insert (&lst, 4, increment_data, &called[4], NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 0, increment_data, &called[0], NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 2, increment_data, &called[2], NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 1, increment_data, &called[1], NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 3, increment_data, &called[3], NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 2, increment_data, &called[2], NULL, NULL, NULL));
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 6);

  r_assert_cmpuint (r_timeout_cblist_update (&lst, 2), ==, 4);
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 2);

  r_assert_cmpuint (called[0], ==, 1);
  r_assert_cmpuint (called[1], ==, 1);
  r_assert_cmpuint (called[2], ==, 2);
  r_assert_cmpuint (called[3], ==, 0);
  r_assert_cmpuint (called[4], ==, 0);

  r_assert (r_timeout_cblist_insert (&lst, 1, increment_data, &called[1], NULL, NULL, NULL));
  r_assert (r_timeout_cblist_insert (&lst, 3, increment_data, &called[3], NULL, NULL, NULL));
  r_assert_cmpuint (r_timeout_cblist_update (&lst, 2), ==, 1);

  r_assert (r_timeout_cblist_insert (&lst, 0, increment_data, &called[0], NULL, NULL, NULL));
  r_assert_cmpuint (r_timeout_cblist_update (&lst, 4), ==, 4);
  r_assert_cmpuint (r_timeout_cblist_len (&lst), ==, 0);

  r_assert_cmpuint (called[0], ==, 2);
  r_assert_cmpuint (called[1], ==, 2);
  r_assert_cmpuint (called[2], ==, 2);
  r_assert_cmpuint (called[3], ==, 2);
  r_assert_cmpuint (called[4], ==, 1);

  r_timeout_cblist_clear (&lst);
}
RTEST_END;

