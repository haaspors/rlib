#include <rlib/rev.h>
#include <rlib/ros.h>

RTEST (revloop, default, RTEST_FAST)
{
  REvLoop * loop;

  r_assert_cmpptr (r_ev_loop_default (), ==, NULL);

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr (r_ev_loop_default (), !=, NULL);
  r_assert_cmpuint (r_ev_loop_task_group_count (loop), >, 0);

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
check_for_current (rpointer data, REvLoop * loop)
{
  (void) data;
  r_assert_cmpptr (r_ev_loop_current (), ==, loop);
}

RTEST (revloop, current, RTEST_FAST)
{
  REvLoop * loop;

  r_assert_cmpptr (r_ev_loop_current (), ==, NULL);

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);

  r_assert (r_ev_loop_add_callback (loop, TRUE, check_for_current, NULL, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);

  r_assert_cmpptr (r_ev_loop_current (), ==, NULL);
  r_ev_loop_unref (loop);
}
RTEST_END;

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
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
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
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
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

typedef struct {
  REvIO * evio;
  rpointer ctx;
} RTestEvIOStartCtx;

static rboolean
idle_stop_evio_cb (rpointer data, REvLoop * loop)
{
  RTestEvIOStartCtx * ctx = data;
  (void) loop;
  r_ev_io_stop (ctx->evio, ctx->ctx);
  return FALSE;
}

RTEST (revloop, evio_handle, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  RTestEvIOStartCtx ctx;
  int fd[2];
  rsize iocount = 0, it = 0;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));

  r_assert_cmpint (pipe (fd), ==, 0);

  r_assert_cmpptr (r_ev_loop_create_ev_io (loop, R_IO_HANDLE_INVALID), ==, NULL);
  r_assert_cmpptr ((ctx.evio = r_ev_loop_create_ev_io (loop, fd[0])), !=, NULL);
  r_assert_cmpptr ((ctx.ctx = r_ev_io_start (ctx.evio, R_EV_IO_READABLE, io_count_cb, &iocount, NULL)), !=, NULL);
  r_assert_cmpint (write (fd[1], "test", 4), ==, 4);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT), ==, 1);
  r_assert_cmpuint (iocount, ==, 1);
  r_assert_cmpuint (it, ==, 1);

  r_assert (r_ev_loop_add_idle (loop, idle_stop_evio_cb, &ctx, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (iocount, ==, 1);
  r_assert_cmpuint (it, ==, 2);

  close (fd[0]);
  close (fd[1]);
  r_ev_io_unref (ctx.evio);
  r_assert_cmpuint (r_ref_refcount (loop), ==, 1);
  r_ev_loop_unref (loop);
  r_clock_unref (clock);
}
RTEST_END;
#endif

static void
register_thread_task (rpointer data, RTaskQueue * queue, RTask * task)
{
  (void) queue;
  (void) task;

  *((RThread **)data) = r_thread_current ();
}

static void
task_done (rpointer data, REvLoop * loop)
{
  (void) loop;

  r_assert_cmpptr (*(RThread **)data, !=, r_thread_current ());
}

RTEST (revloop, add_task, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  RThread * thread = NULL;
  RTask * task;
  rsize it = 0;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));

  r_assert_cmpptr ((task = r_ev_loop_add_task (loop, register_thread_task, task_done, &thread, NULL)), !=, NULL);

  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (it, ==, 1);
  r_assert_cmpptr (thread, !=, r_thread_current ());
  r_task_unref (task);

  thread = NULL;
  r_assert_cmpptr ((task = r_ev_loop_add_task (loop, register_thread_task, task_done, &thread, NULL)), !=, NULL);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (it, ==, 2);
  r_assert_cmpptr (thread, !=, r_thread_current ());
  r_task_unref (task);

  r_ev_loop_unref (loop);
  r_clock_unref (clock);
}
RTEST_END;

RTEST (revloop, add_task_with_taskgroup, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  RThread * thread[2] = { NULL, NULL };
  RTaskQueue * tq;
  RTask * task;
  rsize it = 0;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((tq = r_task_queue_new (2, 1)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, tq)), !=, NULL);
  r_assert (r_ev_loop_add_prepare (loop, prepare_cb, &it, NULL));

  r_assert_cmpptr ((task = r_ev_loop_add_task_with_taskgroup (loop, 0,
          register_thread_task, task_done, &thread[0], NULL)), !=, NULL);

  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (it, ==, 1);
  r_assert_cmpptr (thread[0], !=, r_thread_current ());
  r_task_unref (task);

  r_assert_cmpptr ((task = r_ev_loop_add_task_with_taskgroup (loop, 1,
          register_thread_task, task_done, &thread[1], NULL)), !=, NULL);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (it, ==, 2);
  r_assert_cmpptr (thread[1], !=, r_thread_current ());
  r_assert_cmpptr (thread[0], !=, thread[1]);
  r_task_unref (task);

  r_assert_cmpptr ((task = r_ev_loop_add_task_with_taskgroup (loop, 0,
          register_thread_task, task_done, &thread[1], NULL)), !=, NULL);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_assert_cmpuint (it, ==, 3);
  r_assert_cmpptr (thread[1], !=, r_thread_current ());
  r_assert_cmpptr (thread[0], ==, thread[1]);
  r_task_unref (task);

  r_ev_loop_unref (loop);
  r_clock_unref (clock);
  r_task_queue_unref (tq);
}
RTEST_END;
#endif

RTEST (revio, user, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  REvIO * evio;
  rpointer data;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  /* dummy fd/handle 42 */
  r_assert_cmpptr ((evio = r_ev_loop_create_ev_io (loop, 42)), !=, NULL);
  r_assert_cmpptr (r_ev_io_get_user (evio), ==, NULL);

  r_assert_cmpptr ((data = r_malloc (42)), !=, NULL);
  r_ev_io_set_user (evio, data, r_free);
  r_assert_cmpptr (r_ev_io_get_user (evio), ==, data);
  r_ev_io_unref (evio);
  r_ev_loop_unref (loop);
}
RTEST_END;

