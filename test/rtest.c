#include <rlib/rlib.h>

static ruint
dummy_use__counter__func (void)
{
  /* Internally rtest is using __COUNTER__ */
  /* Usage of __COUNTER__ before tests could screw up test definitions */
  return __COUNTER__;
}

RTEST (rtest, use__COUNTER__, RTEST_FAST)
{
  dummy_use__counter__func ();
}
RTEST_END;

RTEST (rtest, asserts, RTEST_FAST)
{
  int dummy = 42;
  int foobar = 0;

  r_assert (TRUE);
  r_assert_cmpint (42, ==, 21*3 - 21);
  r_assert_cmpuint (42, <, 21*3);
  r_assert_cmphex (0x42, >, 21*3);
  r_assert_cmpptr (&dummy, !=, &foobar); /* Does the stack grow up or down? :P */
  r_assert_cmpfloat (3.14f, !=, 3.141592f);
  r_assert_cmpfloat (3.14, ==, 3.1400);

  r_assert_cmpstr ("Hello", !=, "Foobar");

  r_assert_cmpstrn ("Hello", !=, "Foobar", 3);
  r_assert_cmpstrn ("Hello", !=, "Foobar", 5);
  r_assert_cmpstrn ("Foo", ==, "Foobar", 3);
  r_assert_cmpstrn ("foo", !=, "Foobar", 3);

  r_assert_cmpstrsize ("Hello", 5, !=, "Foobar", 6);
  r_assert_cmpstrsize ("Hello", -1, !=, "Foobar", -1);
  r_assert_cmpstrsize ("Hello", -1, ==, "Hello", -1);
}
RTEST_END;

RTEST (rtest, assert_cmpbuf, RTEST_FAST)
{
  RBuffer * a, * b, * c;

  r_assert_cmpptr ((a = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS ("Hello"))), !=, NULL);
  r_assert_cmpptr ((b = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS ("Foobar"))), !=, NULL);
  r_assert_cmpptr ((c = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS ("Foo"))), !=, NULL);

  r_assert_cmpbuf (a, 0, ==, a, 0, 5);
  r_assert_cmpbuf (a, 0, !=, b, 0, 5);
  r_assert_cmpbuf (a, 0, ==, b, 0, 0);

  r_assert_cmpbufsize (a, 0, 5, ==, a, 0, 5);
  r_assert_cmpbufsize (a, 0, -1, ==, a, 0, -1);
  r_assert_cmpbufsize (a, 0, 3, !=, a, 0, 5);
  r_assert_cmpbufsize (a, 0, -1, !=, b, 0, -1);
  r_assert_cmpbufsize (b, 0, 3, ==, c, 0, 3);

  r_assert_cmpbufmem (b, 0, -1, ==, "Foobar", 6);
  r_assert_cmpbufmem (b, 0, -1, !=, "Hello", 5);

  r_buffer_unref (a);
  r_buffer_unref (b);
  r_buffer_unref (c);
}
RTEST_END;

RTEST (rtest, sym_spacing, RTEST_FAST)
{
  const RTest * test1 = &_RTEST_DATA_NAME (rtest, asserts);
  const RTest * test2 = &_RTEST_DATA_NAME (rtest, sym_spacing);
  rsize diff;

  r_assert_cmpuint (sizeof (RTest), ==, RLIB_SIZEOF_RTEST);
  r_assert_cmpptr (test1, !=, test2);

  diff = ((test1 > test2) ?
        ((ruint8*)test1 - (ruint8*)test2) : ((ruint8*)test2 - (ruint8*)test1));
  r_assert_cmpuint (diff % sizeof (RTest), ==, 0);
}
RTEST_END;

RTEST (rtest, assert_logs, RTEST_FAST)
{
  R_LOG_CATEGORY_DEFINE (tmpcat, "foobar", "foobar category", R_CLR_BG_RED);
  r_log_category_register (&tmpcat);

  r_assert_logs_cat (R_LOG_CAT_LEVEL (&tmpcat, R_LOG_LEVEL_TRACE, "foobar"), &tmpcat);
  r_assert_logs_level (R_LOG_CAT_LEVEL (&tmpcat, R_LOG_LEVEL_INFO, "foobar"), R_LOG_LEVEL_INFO);
  r_assert_logs_msg (R_LOG_CAT_LEVEL (&tmpcat, R_LOG_LEVEL_DEBUG, "foobar"), "foobar");
  r_assert_logs_full (R_LOG_CAT_LEVEL (&tmpcat, R_LOG_LEVEL_FIXME, "foobar"), &tmpcat, R_LOG_LEVEL_FIXME, "foobar");

  r_log_category_unregister (&tmpcat);
}
RTEST_END;

/********************************************************/
/* Main entry point and test runner                     */
/********************************************************/
RTEST_MAIN ("test build");
