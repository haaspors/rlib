#include <rlib/rlib.h>
#include <rlib/ros.h>

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

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()));

  r_assert_cmpptr (r_thread_new_full (NULL, NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_thread_new_full ("rthread-test", NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr ((t = r_thread_new_full ("rthread-test", cpuset,
          rthread_test_wait_thread_func, fixture)), ==, NULL);

  r_assert (r_sys_cpuset_allowed (cpuset));
  r_assert_cmpuint (r_bitset_popcount (cpuset), >, 0);
  r_assert_cmpuint ((first = r_bitset_ctz (cpuset)), <, cpuset->bits);
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

RTEST_STRESS (rthread, rwmutex_try, RTEST_FAST)
{
  RRWMutex mutex;
  r_rwmutex_init (&mutex);

  r_assert (r_rwmutex_tryrdlock (&mutex));
  r_assert (r_rwmutex_tryrdlock (&mutex));
  r_assert (!r_rwmutex_trywrlock (&mutex));
  r_rwmutex_rdunlock (&mutex);
  r_rwmutex_rdunlock (&mutex);

  r_assert (r_rwmutex_trywrlock (&mutex));
  r_assert (!r_rwmutex_tryrdlock (&mutex));
  r_rwmutex_wrunlock (&mutex);

  r_rwmutex_clear (&mutex);
}
RTEST_END;

typedef struct {
  RRWMutex mutex;
  rauint readers;
  rauint writers;
  rboolean running;
} RThreadsTestRWMutex;

static rpointer
rthread_test_rwmutex_reading (rpointer data)
{
  RThreadsTestRWMutex * test_ctx = data;
  ruint count = 0;

  for (; test_ctx->running; count++) {
    r_thread_yield();
    r_assert_cmpuint (r_atomic_uint_load (&test_ctx->writers), >=, 0);
    r_rwmutex_rdlock (&test_ctx->mutex);
    r_assert_cmpuint (r_atomic_uint_load (&test_ctx->writers), ==, 0);
    r_thread_yield();

    r_atomic_uint_fetch_add (&test_ctx->readers, 1);
    r_thread_yield();
    r_assert_cmpuint (r_atomic_uint_load (&test_ctx->readers), >, 0);
    r_atomic_uint_fetch_sub (&test_ctx->readers, 1);

    r_thread_yield();
    r_rwmutex_rdunlock (&test_ctx->mutex);
  }

  return RUINT_TO_POINTER (count);
}

static rpointer
rthread_test_rwmutex_writing (rpointer data)
{
  RThreadsTestRWMutex * test_ctx = data;
  ruint count = 0;

  for (; test_ctx->running; count++) {
    r_thread_yield();
    r_rwmutex_wrlock (&test_ctx->mutex);
    r_assert_cmpuint (r_atomic_uint_load (&test_ctx->readers), ==, 0);
    r_assert_cmpuint (r_atomic_uint_load (&test_ctx->writers), ==, 0);
    r_thread_yield();

    r_atomic_uint_fetch_add (&test_ctx->writers, 1);
    r_thread_yield();
    r_assert_cmpuint (r_atomic_uint_load (&test_ctx->writers), >, 0);
    r_atomic_uint_fetch_sub (&test_ctx->writers, 1);

    r_thread_yield();
    r_assert_cmpuint (r_atomic_uint_load (&test_ctx->readers), ==, 0);
    r_assert_cmpuint (r_atomic_uint_load (&test_ctx->writers), ==, 0);
    r_rwmutex_wrunlock (&test_ctx->mutex);
  }

  return RUINT_TO_POINTER (count);
}

RTEST_STRESS (rthread, rwmutex_stress, RTEST_FAST)
{
  RThreadsTestRWMutex test_ctx;
  RThread * trd[32];
  RThread * twr[8];
  int i;

  r_rwmutex_init (&test_ctx.mutex);
  r_atomic_uint_store (&test_ctx.readers, 0);
  r_atomic_uint_store (&test_ctx.writers, 0);
  test_ctx.running = TRUE;

  for (i = 0; i < R_N_ELEMENTS (trd); i++)
    trd[i] = r_thread_new ("rwmutex_reader", rthread_test_rwmutex_reading, &test_ctx);
  for (i = 0; i < R_N_ELEMENTS (twr); i++)
    twr[i] = r_thread_new ("rwmutex_writer", rthread_test_rwmutex_writing, &test_ctx);

  r_thread_usleep (R_USEC_PER_SEC / 2);
  test_ctx.running = FALSE;

  for (i = 0; i < R_N_ELEMENTS (twr); i++) {
    r_assert_cmpuint (RPOINTER_TO_UINT (r_thread_join (twr[i])), >, 0);
    r_thread_unref (twr[i]);
  }
  for (i = 0; i < R_N_ELEMENTS (trd); i++) {
    r_assert_cmpuint (RPOINTER_TO_UINT (r_thread_join (trd[i])), >, 0);
    r_thread_unref (trd[i]);
  }

  r_rwmutex_clear (&test_ctx.mutex);
}
RTEST_END;

#else
RTEST (rthread, dummy, RTEST_FAST)
{
  r_assert (TRUE);
}
RTEST_END;
#endif

