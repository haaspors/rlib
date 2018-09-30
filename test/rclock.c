#include <rlib/rlib.h>

RTEST (rsystemclock, system, RTEST_FAST | RTEST_SYSTEM)
{
  RClock * clock;

  r_assert_cmpptr ((clock = r_system_clock_get ()), !=, NULL);
  r_assert (!r_clock_is_synthetic (clock));
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
  r_assert (r_clock_is_synthetic (clock));
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

static void
increment_data_rsize (rpointer data, rpointer user)
{
  (void) user;
  (*((rsize *)data))++;
}

RTEST (rclock, add_cancel_timeout, RTEST_FAST)
{
  RClock * clock;
  RClockEntry * entry[4];
  rsize count = 0;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpuint (r_clock_timeout_count (clock), ==, 0);

  r_assert_cmpptr ((entry[0] = r_clock_add_timeout_callback (clock, 0,
          increment_data_rsize, &count, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((entry[1] = r_clock_add_timeout_callback (clock, 1,
          increment_data_rsize, &count, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((entry[2] = r_clock_add_timeout_callback (clock, 2,
          increment_data_rsize, &count, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((entry[3] = r_clock_add_timeout_callback (clock, 3,
          increment_data_rsize, &count, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpuint (r_clock_timeout_count (clock), ==, 4);
  r_assert_cmpuint (count, ==, 0);

  r_assert (!r_clock_cancel_entry (NULL, NULL));
  r_assert (!r_clock_cancel_entry (clock, NULL));
  r_assert (r_clock_cancel_entry (clock, entry[1]));
  r_assert_cmpuint (r_clock_timeout_count (clock), ==, 3);

  r_clock_entry_unref (entry[3]);
  r_clock_entry_unref (entry[2]);
  r_clock_entry_unref (entry[1]);
  r_clock_entry_unref (entry[0]);
  r_clock_unref (clock);
}
RTEST_END;

RTEST (rtestclock, process_entries, RTEST_FAST)
{
  RClock * clock;
  RClockEntry * entry[4];
  rsize count = 0;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpuint (r_clock_timeout_count (clock), ==, 0);

  r_assert_cmpptr ((entry[0] = r_clock_add_timeout_callback (clock, 0,
          increment_data_rsize, &count, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((entry[1] = r_clock_add_timeout_callback (clock, 1,
          increment_data_rsize, &count, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((entry[2] = r_clock_add_timeout_callback (clock, 2,
          increment_data_rsize, &count, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((entry[3] = r_clock_add_timeout_callback (clock, 3,
          increment_data_rsize, &count, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpuint (r_clock_timeout_count (clock), ==, 4);
  r_assert_cmpuint (count, ==, 0);

  r_assert_cmpuint (r_clock_first_timeout (clock), ==, 0);
  r_assert (r_clock_cancel_entry (clock, entry[1]));
  r_assert_cmpuint (r_clock_timeout_count (clock), ==, 3);

  r_assert (r_test_clock_update_time (clock, 2));
  r_assert_cmpuint (r_clock_process_entries (clock, NULL), ==, 2);
  r_assert_cmpuint (r_clock_timeout_count (clock), ==, 1);
  r_assert_cmpuint (r_clock_first_timeout (clock), ==, 3);

  r_clock_entry_unref (entry[3]);
  r_clock_entry_unref (entry[2]);
  r_clock_entry_unref (entry[1]);
  r_clock_entry_unref (entry[0]);
  r_clock_unref (clock);
}
RTEST_END;

