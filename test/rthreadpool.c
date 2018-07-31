#include <rlib/rlib.h>
#include <rlib/ros.h>

#ifdef RLIB_HAVE_THREADS
RTEST_FIXTURE_STRUCT (rthreadpool)
{
  RCond startcond;
  RCond joincond;
  RMutex mutex;
  rboolean running;
};

RTEST_FIXTURE_SETUP (rthreadpool)
{
  r_mutex_init (&fixture->mutex);
  r_cond_init (&fixture->startcond);
  r_cond_init (&fixture->joincond);
  fixture->running = TRUE;
}

RTEST_FIXTURE_TEARDOWN (rthreadpool)
{
  r_cond_clear (&fixture->startcond);
  r_cond_clear (&fixture->joincond);
  r_mutex_clear (&fixture->mutex);
}

static rpointer
rthreadpool_test_wait_thread_func (rpointer common, rpointer spec)
{
  struct rthreadpool_data * fixture = common;
  (void) spec;

  r_mutex_lock (&fixture->mutex);
  /* Signal thread is started. */
  r_cond_signal (&fixture->startcond);

  while (fixture->running)
    r_cond_wait (&fixture->joincond, &fixture->mutex);
  r_mutex_unlock (&fixture->mutex);

  return RUINT_TO_POINTER (r_thread_get_id (r_thread_current ()));
}

static rpointer
rthreadpool_test_wait_thread_and_magic_func (rpointer common, rpointer spec)
{
  struct rthreadpool_data * fixture = common;
  rsize * magic = spec;

  r_mutex_lock (&fixture->mutex);
  /* Signal thread is started. */
  r_cond_signal (&fixture->startcond);

  *magic = 42;

  while (fixture->running)
    r_cond_wait (&fixture->joincond, &fixture->mutex);
  r_mutex_unlock (&fixture->mutex);

  return RUINT_TO_POINTER (r_thread_get_id (r_thread_current ()));
}

RTEST_F (rthreadpool, new, RTEST_FAST)
{
  RThreadPool * pool;

  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr (r_thread_pool_new (NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_thread_pool_new ("pool", NULL, NULL), ==, NULL);

  r_assert_cmpptr ((pool = r_thread_pool_new ("pool",
          rthreadpool_test_wait_thread_func, NULL)), !=, NULL);
  r_mutex_unlock (&fixture->mutex);
  r_thread_pool_unref (pool);
}
RTEST_END;

RTEST_F (rthreadpool, start_thread, RTEST_FAST)
{
  RThreadPool * pool;

  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr ((pool = r_thread_pool_new ("pool",
          rthreadpool_test_wait_thread_func, fixture)), !=, NULL);
  r_assert_cmpuint (r_thread_pool_running_threads (pool), ==, 0);

  r_assert (!r_thread_pool_start_thread (NULL, NULL, NULL, NULL));
  r_assert (r_thread_pool_start_thread (pool, "1", NULL, NULL));
  r_assert_cmpuint (r_thread_pool_running_threads (pool), <=, 1);
  r_cond_wait (&fixture->startcond, &fixture->mutex); /* Wait for thread to start. */
  r_assert_cmpuint (r_thread_pool_running_threads (pool), ==, 1);

  fixture->running = FALSE;
  r_cond_signal (&fixture->joincond);
  r_mutex_unlock (&fixture->mutex);
  r_thread_pool_join (pool);
  r_assert_cmpuint (r_thread_pool_running_threads (pool), ==, 0);
  r_thread_pool_unref (pool);
}
RTEST_END;

RTEST_F (rthreadpool, specific_user_data, RTEST_FAST)
{
  RThreadPool * pool;
  rsize magic = 0;

  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr ((pool = r_thread_pool_new ("pool",
          rthreadpool_test_wait_thread_and_magic_func, fixture)), !=, NULL);
  r_assert (r_thread_pool_start_thread (pool, "1", NULL, &magic));
  r_assert_cmpuint (magic, ==, 0);
  r_cond_wait (&fixture->startcond, &fixture->mutex); /* Wait for thread to start. */

  fixture->running = FALSE;
  r_cond_signal (&fixture->joincond);
  r_mutex_unlock (&fixture->mutex);
  r_thread_pool_join (pool);

  r_assert_cmpuint (magic, ==, 42);
  r_thread_pool_unref (pool);
}
RTEST_END;

RTEST_F (rthreadpool, start_thread_on_each_cpu, RTEST_FAST)
{
  RThreadPool * pool;
  rsize cpus;

  r_assert_cmpuint ((cpus = r_sys_cpu_allowed_count ()), >, 0);

  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr ((pool = r_thread_pool_new ("pool",
          rthreadpool_test_wait_thread_func, fixture)), !=, NULL);
  r_assert_cmpuint (r_thread_pool_running_threads (pool), ==, 0);

  r_assert (!r_thread_pool_start_thread_on_each_cpu (NULL, NULL, NULL));
  r_assert (r_thread_pool_start_thread_on_each_cpu (pool, NULL, NULL));
  r_assert_cmpuint (r_thread_pool_running_threads (pool), <=, cpus);

  /* Wait for threads to start. */
  while (r_thread_pool_running_threads (pool) < cpus)
    r_cond_wait (&fixture->startcond, &fixture->mutex);

  fixture->running = FALSE;
  r_cond_broadcast (&fixture->joincond);
  r_mutex_unlock (&fixture->mutex);
  r_thread_pool_join (pool);
  r_assert_cmpuint (r_thread_pool_running_threads (pool), ==, 0);
  r_thread_pool_unref (pool);

  if (cpus > 2) {
    RBitset * cpuset;
    rsize i;

    fixture->running = TRUE;

    r_assert (r_bitset_init_stack (cpuset, cpus));
    for (i = 0; i < cpus; i += 2) {
      if (!r_bitset_set_bit (cpuset, i, TRUE))
        break;
    }
    r_assert_cmpuint (r_bitset_popcount (cpuset), >=, 2);

    r_mutex_lock (&fixture->mutex);
    r_assert_cmpptr ((pool = r_thread_pool_new ("pool",
            rthreadpool_test_wait_thread_func, fixture)), !=, NULL);
    r_assert_cmpuint (r_thread_pool_running_threads (pool), ==, 0);

    r_assert (r_thread_pool_start_thread_on_each_cpu (pool, cpuset, NULL));
    r_assert_cmpuint (r_thread_pool_running_threads (pool), <=,
        r_bitset_popcount (cpuset));

    /* Wait for threads to start. */
    while (r_thread_pool_running_threads (pool) < r_bitset_popcount (cpuset))
      r_cond_wait (&fixture->startcond, &fixture->mutex);

    fixture->running = FALSE;
    r_cond_broadcast (&fixture->joincond);
    r_mutex_unlock (&fixture->mutex);
    r_thread_pool_join (pool);
    r_assert_cmpuint (r_thread_pool_running_threads (pool), ==, 0);
    r_thread_pool_unref (pool);
  }
}
RTEST_END;

#else
RTEST (rthreadpool, dummy, RTEST_FAST)
{
  r_assert (TRUE);
}
RTEST_END;
#endif

