#include <rlib/rlib.h>

RTEST (revloop, default, RTEST_FAST)
{
  REvLoop * loop;

  r_assert_cmpptr (r_ev_loop_default (), ==, NULL);

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr (r_ev_loop_default (), !=, NULL);

  r_ev_loop_unref (loop);
  r_assert_cmpptr (r_ev_loop_default (), ==, NULL);
}
RTEST_END;

/* Enable when epoll and ioctl backends are working!!! */
#if !defined (R_OS_WIN32)
static rboolean
prepare_cb (rpointer data, REvLoop * loop)
{
  (void) loop;
  (*((rsize *)data))++;
  return TRUE;
}

static rboolean
idle_cb (rpointer data, REvLoop * loop)
{
  (void) loop;
  return (*((rsize *)data))-- > 1;
}

RTEST (revloop, idle, RTEST_FAST)
{
  rsize count = 1;
  REvLoop * loop;

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);

  r_assert (r_ev_loop_add_idle (loop, idle_cb, &count, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (count, ==, 0);

  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (revloop, stop, RTEST_FAST)
{
  REvLoop * loop;
  rsize count = 1;

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);

  r_assert (r_ev_loop_add_idle (loop, idle_cb, &count, NULL));
  r_ev_loop_stop (loop);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 1);
  r_assert_cmpuint (count, ==, 1);

  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (revloop, prepare, RTEST_FAST)
{
  REvLoop * loop;
  rsize count = 1, it = 0;

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (it, ==, 0);

  r_assert (r_ev_loop_add_idle (loop, idle_cb, &count, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (count, ==, 0);
  r_assert_cmpuint (it, ==, 1);

  r_ev_loop_unref (loop);
}
RTEST_END;
#endif

static void
increment_rsize (rpointer data, REvLoop * loop)
{
  (void) loop;
  (*((rsize *)data))++;
}

RTEST (revloop, callback, RTEST_FAST)
{
  REvLoop * loop;
  rsize size = 0;

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);

  r_assert (r_ev_loop_add_callback (loop, FALSE, increment_rsize, &size, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (size, ==, 1);

  r_assert (r_ev_loop_add_callback (loop, TRUE, increment_rsize, &size, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (size, ==, 2);

  r_ev_loop_unref (loop);
}
RTEST_END;

/* Enable when epoll and ioctl backends are working!!! */
#if !defined (R_OS_WIN32)
RTEST (revloop, callback_at, RTEST_FAST)
{
  REvLoop * loop;
  rsize size = 0, it = 0;
  RClockTime deadline;

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));

  deadline = r_time_get_ts_monotonic () + R_MSECOND / 2;
  r_assert (r_ev_loop_add_callback_at (loop, NULL, deadline,
        increment_rsize, &size, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (size, ==, 1);
  r_assert_cmpuint (it, ==, 1);

  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (revloop, callback_later, RTEST_FAST)
{
  REvLoop * loop;
  rsize size = 0, it = 0;

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));

  r_assert (r_ev_loop_add_callback_later (loop, NULL, R_MSECOND / 2,
        increment_rsize, &size, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (size, ==, 1);
  r_assert_cmpuint (it, ==, 1);

  r_ev_loop_unref (loop);
}
RTEST_END;

static rboolean
update_clock_qmsec_func (rpointer data, REvLoop * loop)
{
  RClockTime ts;
  RClock * clock = data;
  (void) loop;

  ts = r_clock_get_time (clock);
  return r_test_clock_update_time (clock, ts + R_MSECOND / 4);
}

RTEST (revloop, timers, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  rsize size = 0, it = 0;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock)), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));
  r_assert (r_ev_loop_add_prepare (loop, update_clock_qmsec_func,
        r_clock_ref (clock), r_clock_unref));

  r_assert (r_ev_loop_add_callback_later (loop, NULL, R_MSECOND / 4,
        increment_rsize, &size, NULL));
  r_assert (r_ev_loop_add_callback_later (loop, NULL, R_MSECOND / 2,
        increment_rsize, &size, NULL));
  r_assert (r_ev_loop_add_callback_later (loop, NULL, (R_MSECOND / 4) * 3,
        increment_rsize, &size, NULL));
  r_assert (r_ev_loop_add_callback_later (loop, NULL, R_MSECOND,
        increment_rsize, &size, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (size, ==, 4);
  r_assert_cmpuint (it, ==, 4);

  r_ev_loop_unref (loop);
  r_clock_unref (clock);
}
RTEST_END;

RTEST (revloop, callback_later_cancel, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  rsize size = 0, it = 0;
  RClockEntry * entry;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock)), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));

  r_assert (r_ev_loop_add_callback_later (loop, &entry, R_MSECOND,
        increment_rsize, &size, NULL));
  r_assert (r_ev_loop_add_callback_later (loop, NULL, R_MSECOND / 2,
        increment_rsize, &size, NULL));
  r_test_clock_update_time (clock, R_MSECOND / 2);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), ==, 1);
  r_assert_cmpuint (size, ==, 1);

  r_assert (r_ev_loop_cancel_timer (loop, entry));
  r_clock_entry_unref (entry);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);

  r_assert_cmpuint (size, ==, 1);
  r_assert_cmpuint (it, ==, 1);

  r_ev_loop_unref (loop);
  r_clock_unref (clock);
}
RTEST_END;

#if defined (R_OS_UNIX)
static void
io_count_cb (rpointer data, REvIOEvents events, REvIO * evio)
{
  rsize * count = data;
  (void) evio;
  (void) events;

  (*count)++;
}

static rboolean
idle_stop_evio_cb (REvIO * evio)
{
  r_ev_io_stop (evio);
  return FALSE;
}

RTEST (revloop, evio_handle, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  REvIO * evio;
  int fd[2];
  rsize iocount = 0, it = 0;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock)), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));

  r_assert_cmpint (pipe (fd), ==, 0);

  r_assert_cmpptr ((evio = r_ev_loop_init_handle (loop, fd[0])), !=, NULL);
  r_assert (r_ev_io_start (evio, R_EV_IO_READABLE, io_count_cb, &iocount, NULL));
  r_assert_cmpint (write (fd[1], "test", 4), ==, 4);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT), ==, 1);
  r_assert_cmpuint (iocount, ==, 1);
  r_assert_cmpuint (it, ==, 1);

  r_assert (r_ev_loop_add_idle (loop, (REvFuncReturn)idle_stop_evio_cb,
        r_ev_io_ref (evio), r_ev_io_unref));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (iocount, ==, 1);
  r_assert_cmpuint (it, ==, 2);

  close (fd[0]);
  close (fd[1]);
  r_ev_loop_unref (loop);
  r_clock_unref (clock);
}
RTEST_END;
#endif
#endif

