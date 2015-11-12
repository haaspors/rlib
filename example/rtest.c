#include <rlib/rlib.h>
#include <signal.h>
#include <string.h>

/********************************************************/
/* Define a fixture for rtest suite                     */
/********************************************************/
RTEST_FIXTURE_STRUCT (rtest)
{
  int i;
  rpointer ptr;
  rchar * str;
};
RTEST_FIXTURE_SETUP (rtest)
{
  fixture->i = 0;
  fixture->ptr = NULL;
  fixture->str = r_strdup ("Hello");
}
RTEST_FIXTURE_TEARDOWN (rtest)
{
  r_free (fixture->ptr);
  r_free (fixture->str);
}
/********************************************************/

/********************************************************/
/* Some basic test definitions                          */
/********************************************************/
RTEST (rtest, fast, RTEST_FAST)
{
  r_assert (TRUE == TRUE);
}
RTEST_END;
RTEST (rtest, slow, RTEST_SLOW)
{
  r_assert (FALSE == FALSE);
}
RTEST_END;
RTEST_F (rtest, fixture, RTEST_FAST)
{
  /* Use fixture variable as a ptr to the fixture struct */
  r_assert_cmpint (fixture->i,    !=, 42);
  r_assert_cmpint (fixture->i,    ==, 0);
  r_assert_cmpstr (fixture->str,  !=, "foobar");
  r_assert_cmpstr (fixture->str,  ==, "Hello");
}
RTEST_END;
RTEST_LOOP (rtest, loop, RTEST_FAST, 0, 4)
{
  /* Use __i as the index */
  r_assert_cmpuint (__i, >=, 0);
  r_assert_cmpuint (__i, <, 4);
}
RTEST_END;
/********************************************************/

static rpointer
do_something_bad (rpointer data)
{
  switch (RPOINTER_TO_INT (data)) {
    case SIGABRT:
      r_assert_not_reached ();
      break;
    case SIGSEGV:
      *(int *)data = 42;
      break;
  }
  return NULL;
}

/********************************************************/
/* Asserts will make the test fail                      */
/* SIGSEGV or crashing will set the test state to ERROR */
/********************************************************/
RTEST (rtest, assert, RTEST_FAST)
{
  do_something_bad (RINT_TO_POINTER (SIGABRT));
}
RTEST_END;
RTEST(rtest, sigsegv, RTEST_FAST)
{
  do_something_bad (RINT_TO_POINTER (SIGSEGV));
}
RTEST_END;

RTEST (rtest, thread_success, RTEST_FAST)
{
  r_thread_join (r_thread_new ("dummy crasher", do_something_bad, NULL));
}
RTEST_END;
RTEST (rtest, thread_assert, RTEST_FAST)
{
  r_thread_join (r_thread_new ("dummy crasher", do_something_bad, RINT_TO_POINTER (SIGABRT)));
}
RTEST_END;
RTEST (rtest, thread_sigsegv, RTEST_FAST)
{
  r_thread_join (r_thread_new ("dummy crasher", do_something_bad, RINT_TO_POINTER (SIGSEGV)));
}
RTEST_END;
/********************************************************/

static void
_recurse_forever (int v)
{
  volatile int dummy[128];
  dummy[64] = v * 2;

  v = dummy[64] / 2;
  _recurse_forever (v+1);
}
/********************************************************/
/* Generate a stack overflow                            */
/********************************************************/
RTEST (rtest, stack_overflow, RTEST_FAST)
{
  _recurse_forever (0);
}
RTEST_END;

/********************************************************/
/* Generate a timeout                                   */
/********************************************************/
RTEST (rtest, timeout, RTEST_FAST)
{
  while (TRUE)
    r_thread_sleep (1);
}
RTEST_END;

/********************************************************/
/* Main entry point and test runner                     */
/********************************************************/
RTEST_MAIN ("1.0");
