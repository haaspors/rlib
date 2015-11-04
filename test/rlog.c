#include <rlib/rlib.h>

RTEST (rlog, register, RTEST_FAST)
{
  R_LOG_CATEGORY_DEFINE (tmp, "foobar", "foobar category", R_CLR_BG_RED);

  r_assert_cmpptr (r_log_category_find ("foobar"), ==, NULL);
  r_assert (!r_log_category_unregister (&tmp));
  r_assert (r_log_category_register (&tmp));
  r_assert_cmpptr (r_log_category_find ("foobar"), !=, NULL);

  r_assert (!r_log_category_register (&tmp));
  r_assert (r_log_category_unregister (&tmp));
}
RTEST_END;
