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

/********************************************************/
/* Main entry point and test runner                     */
/********************************************************/
RTEST_MAIN ();
