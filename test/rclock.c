#include <rlib/rlib.h>

RTEST (rsystemclock, system, RTEST_FAST | RTEST_SYSTEM)
{
  RClock * clock;

  r_assert_cmpptr ((clock = r_system_clock_get ()), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpuint (r_clock_get_time (clock), >, 0);

  /* This should return the same singleton instance, but no need to test
   * explicitily for the same.... */
  r_assert_cmpptr ((clock = r_system_clock_get ()), !=, NULL);
  r_clock_unref (clock);
}
RTEST_END;

RTEST (rsystemclock, wait, RTEST_FAST | RTEST_SYSTEM)
{
  RClock * clock;
  RClockTime now, wait;

  r_assert_cmpptr ((clock = r_system_clock_get ()), !=, NULL);

  r_assert_cmpuint ((now = r_clock_get_time (clock)), >, 0);
  r_assert_cmpuint ((wait = r_clock_wait_relative (clock, 10 * R_USECOND)), !=, R_CLOCK_TIME_NONE);
  r_assert_cmpuint (wait, >, now);

  r_clock_unref (clock);
}
RTEST_END;


RTEST (rtestclock, update, RTEST_FAST)
{
  RClock * clock;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpuint (r_clock_get_time (clock), ==, 0);

  r_assert (r_test_clock_update_time (clock, 42));
  r_assert_cmpuint (r_clock_get_time (clock), ==, 42);

  r_assert (!r_test_clock_update_time (clock, 41));
  r_assert (r_test_clock_update_time (clock, 2*42));
  r_assert_cmpuint (r_clock_get_time (clock), ==, 2*42);

  r_clock_unref (clock);
}
RTEST_END;

RTEST (rtestclock, wait_update, RTEST_FAST)
{
  RClock * clock;

  r_assert_cmpptr ((clock = r_test_clock_new (TRUE)), !=, NULL);
  r_assert_cmpuint (r_clock_get_time (clock), ==, 0);

  r_assert_cmpuint (r_clock_wait_relative (clock, 42), ==, 42);
  r_assert_cmpuint (r_clock_get_time (clock), ==, 42);

  r_assert_cmpuint (r_clock_wait_relative (clock, 0), ==, 42);
  r_assert_cmpuint (r_clock_get_time (clock), ==, 42);

  r_clock_unref (clock);
}
RTEST_END;

static rpointer
update_time_func (rpointer data)
{
  RClock * clock = data;
  r_test_clock_update_time (clock, 42);
  return NULL;
}

RTEST (rtestclock, wait_no_update, RTEST_FAST)
{
  RClock * clock;
  RThread * thread;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpuint (r_clock_get_time (clock), ==, 0);

  r_assert_cmpptr ((thread = r_thread_new (NULL, update_time_func, clock)), !=, NULL);

  r_assert_cmpuint (r_clock_wait (clock, 32), ==, 42);
  r_assert_cmpuint (r_clock_get_time (clock), ==, 42);

  r_assert_cmpuint (r_clock_wait_relative (clock, 0), ==, 42);
  r_assert_cmpuint (r_clock_get_time (clock), ==, 42);

  r_assert_cmpptr (r_thread_join (thread), ==, NULL);
  r_thread_unref (thread);
  r_clock_unref (clock);
}
RTEST_END;

