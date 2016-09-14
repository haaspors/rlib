#include <rlib/rlib.h>

#ifdef RLIB_HAVE_THREADS
RTEST_FIXTURE_STRUCT (rthread)
{
  RCond cond;
  RMutex mutex;
  rboolean running;
};

RTEST_FIXTURE_SETUP (rthread)
{
  r_mutex_init (&fixture->mutex);
  r_cond_init (&fixture->cond);
  fixture->running = TRUE;
}

RTEST_FIXTURE_TEARDOWN (rthread)
{
  r_cond_clear (&fixture->cond);
  r_mutex_clear (&fixture->mutex);
}

static void
rthread_test_end_thread (struct rthread_data * fixture)
{
  fixture->running = FALSE;
  r_cond_signal (&fixture->cond); /* Signal the thread to end */
}

static rpointer
rthread_test_wait_thread_func (rpointer data)
{
  struct rthread_data * fixture = data;

  r_mutex_lock (&fixture->mutex);
  /* Signal thread is started. */
  r_cond_signal (&fixture->cond);

  while (fixture->running)
    r_cond_wait (&fixture->cond, &fixture->mutex);
  r_mutex_unlock (&fixture->mutex);

  return RUINT_TO_POINTER (r_thread_get_id (r_thread_current ()));
}

RTEST_F (rthread, new_join, RTEST_FAST)
{
  RThread * t;

  r_assert_cmpptr (r_thread_new (NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_thread_new ("rthread-test", NULL, NULL), ==, NULL);

  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr ((t = r_thread_new ("rthread-test",
          rthread_test_wait_thread_func, fixture)), !=, NULL);
  r_cond_wait (&fixture->cond, &fixture->mutex); /* Wait for thread to start. */
  rthread_test_end_thread (fixture);
  r_mutex_unlock (&fixture->mutex);
  r_assert_cmpptr (r_thread_join (t), ==, RUINT_TO_POINTER (r_thread_get_id (t)));
  r_thread_unref (t);
}
RTEST_END;

RTEST_F (rthread, new_with_affinity, RTEST_FAST | RTEST_SYSTEM)
{
  RThread * t;
  RBitset * cpuset;
  rsize first;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max_count ()));

  r_assert_cmpptr (r_thread_new_full (NULL, NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_thread_new_full ("rthread-test", NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr ((t = r_thread_new_full ("rthread-test", cpuset,
          rthread_test_wait_thread_func, fixture)), ==, NULL);

  r_assert (r_sys_cpuset_allowed (cpuset));
  r_assert_cmpuint (r_bitset_popcount (cpuset), >, 0);
  r_assert_cmpuint ((first = r_bitset_ctz (cpuset)), <, cpuset->bsize);
  r_assert (r_bitset_clear (cpuset));
  r_assert (r_bitset_set_bit (cpuset, first, TRUE));
  r_assert_cmpuint (r_bitset_popcount (cpuset), ==, 1);
  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr ((t = r_thread_new_full ("rthread-test", cpuset,
          rthread_test_wait_thread_func, fixture)), !=, NULL);
  r_cond_wait (&fixture->cond, &fixture->mutex); /* Wait for thread to start. */
#if defined (R_OS_LINUX)
  r_assert (r_thread_get_affinity (t, cpuset));
  r_assert_cmpuint (r_bitset_popcount (cpuset), ==, 1);
  r_assert (r_bitset_is_bit_set (cpuset, first));
#endif
  rthread_test_end_thread (fixture);
  r_mutex_unlock (&fixture->mutex);
  r_assert_cmpptr (r_thread_join (t), ==, RUINT_TO_POINTER (r_thread_get_id (t)));
  r_thread_unref (t);
}
RTEST_END;

RTEST_F (rthread, get_name, RTEST_FAST)
{
  RThread * t;

  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr ((t = r_thread_new ("rthread-test",
          rthread_test_wait_thread_func, fixture)), !=, NULL);
  r_cond_wait (&fixture->cond, &fixture->mutex); /* Wait for thread to start. */

  r_assert_cmpstr (r_thread_get_name (t), ==, "rthread-test");

  rthread_test_end_thread (fixture);
  r_mutex_unlock (&fixture->mutex);
  r_assert_cmpptr (r_thread_join (t), ==, RUINT_TO_POINTER (r_thread_get_id (t)));
  r_thread_unref (t);
}
RTEST_END;

#ifndef R_OS_DARWIN
RTEST_F (rthread, get_affinity, RTEST_FAST | RTEST_SYSTEM)
{
  RThread * t;
  RBitset * cpuset;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpu_max_count ()));

  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr ((t = r_thread_new ("rthread-test",
          rthread_test_wait_thread_func, fixture)), !=, NULL);
  r_cond_wait (&fixture->cond, &fixture->mutex); /* Wait for thread to start. */

  r_assert (r_thread_get_affinity (t, cpuset));
  r_assert_cmpuint (r_bitset_popcount (cpuset), >, 0);

  rthread_test_end_thread (fixture);
  r_mutex_unlock (&fixture->mutex);
  r_assert_cmpptr (r_thread_join (t), ==, RUINT_TO_POINTER (r_thread_get_id (t)));
  r_thread_unref (t);
}
RTEST_END;

RTEST_F (rthread, set_affinity, RTEST_FAST | RTEST_SYSTEM)
{
  RThread * t;
  RBitset * cpuset;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpu_max_count ()));

  r_mutex_lock (&fixture->mutex);
  r_assert_cmpptr ((t = r_thread_new ("rthread-test",
          rthread_test_wait_thread_func, fixture)), !=, NULL);
  r_cond_wait (&fixture->cond, &fixture->mutex); /* Wait for thread to start. */

  r_assert (r_thread_get_affinity (t, cpuset));
  r_assert_cmpuint (r_bitset_popcount (cpuset), >, 0);

  if (r_bitset_popcount (cpuset) > 1) {
    rsize first = r_bitset_ctz (cpuset);
    r_assert (r_bitset_clear (cpuset));
    r_assert (r_bitset_set_bit (cpuset, first, TRUE));
    r_assert_cmpuint (r_bitset_popcount (cpuset), ==, 1);
    r_assert (r_thread_set_affinity (t, cpuset));

    r_thread_yield ();
    r_thread_yield ();

    r_assert (r_bitset_clear (cpuset));
    r_assert (r_thread_get_affinity (t, cpuset));
    r_assert_cmpuint (r_bitset_popcount (cpuset), ==, 1);
  }

  rthread_test_end_thread (fixture);
  r_mutex_unlock (&fixture->mutex);
  r_assert_cmpptr (r_thread_join (t), ==, RUINT_TO_POINTER (r_thread_get_id (t)));
  r_thread_unref (t);
}
RTEST_END;
#endif

#else
RTEST (rthread, dummy, RTEST_FAST)
{
  r_assert (TRUE);
}
RTEST_END;
#endif

