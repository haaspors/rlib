#include <rlib/rlib.h>

static void
simple_adder (rpointer data, RTaskQueue * tq, RTask * task)
{
  rauint * counter = data;
  (void) tq;
  (void) task;
  r_atomic_uint_fetch_add (counter, 1);
}

RTEST (rtaskqueue, simple, RTEST_FAST)
{
  RTaskQueue * tq;
  rauint counter;
  RTask * t;

  r_atomic_uint_store (&counter, 0);
  r_assert_cmpptr (r_task_queue_new_simple (0), ==, NULL);
  r_assert_cmpptr ((tq = r_task_queue_new_simple (1)), !=, NULL);
  r_assert_cmpuint (r_task_queue_group_count (tq), ==, 1);
  r_assert_cmpuint (r_task_queue_thread_count (tq), ==, 1);

  r_assert_cmpptr ((t = r_task_queue_add (tq, simple_adder, &counter, NULL)), !=, NULL);
  r_assert (r_task_wait (t));
  r_assert_cmpuint (r_atomic_uint_load (&counter), ==, 1);

  r_task_unref (t);
  r_task_queue_unref (tq);
}
RTEST_END;

static void
chain_adder (rpointer data, RTaskQueue * tq, RTask * task)
{
  RTask * t;

  (void) task;

  r_thread_yield ();
  r_assert_cmpptr ((t = r_task_queue_add (tq, simple_adder, data, NULL)), !=, NULL);
  r_task_unref (t);
  r_thread_yield ();
  r_assert_cmpptr ((t = r_task_queue_add (tq, simple_adder, data, NULL)), !=, NULL);
  r_task_unref (t);
  r_thread_yield ();
  r_assert_cmpptr ((t = r_task_queue_add (tq, simple_adder, data, NULL)), !=, NULL);
  r_task_unref (t);
  r_thread_yield ();
}

RTEST (rtaskqueue, chain, RTEST_FAST)
{
  RTaskQueue * tq;
  rauint counter;
  RTask * t[3];

  r_atomic_uint_store (&counter, 0);
  r_assert_cmpptr ((tq = r_task_queue_new_simple (1)), !=, NULL);

  r_assert_cmpptr ((t[0] = r_task_queue_add (tq, chain_adder, &counter, NULL)), !=, NULL);
  r_assert_cmpptr ((t[1] = r_task_queue_add (tq, chain_adder, &counter, NULL)), !=, NULL);
  r_assert_cmpptr ((t[2] = r_task_queue_add (tq, chain_adder, &counter, NULL)), !=, NULL);

  /* We can't use r_task_wait, as new tasks are added, and we should wait for them. */
  while (r_atomic_uint_load (&counter) < 9)
    r_thread_yield ();

  r_task_unref (t[0]);
  r_task_unref (t[1]);
  r_task_unref (t[2]);

  r_task_queue_unref (tq);
}
RTEST_END;


typedef struct {
  rauint * counter;
  rauint it;
} RTQTestCtx;

static void
chain_ctx (rpointer data, RTaskQueue * tq, RTask * task)
{
  RTQTestCtx * ctx = data;
  ruint old, new;

  r_thread_yield ();
  task = r_task_queue_add (tq, simple_adder, ctx->counter, NULL);

  r_thread_yield ();
  old = r_atomic_uint_load (&ctx->it);
  if (old > 0) {
    do {
      new = old - 1;
    } while (r_atomic_uint_cmp_xchg_weak (&ctx->it, &old, new));
    if (new > 0)
      r_task_unref (r_task_queue_add_full (tq, 0, chain_ctx, data, NULL, task, NULL));
  }

  r_task_unref (task);
}

RTEST (rtaskqueue, dep, RTEST_FAST)
{
  RTaskQueue * tq;
  rauint counter;
  RTask * t[3];
  RTQTestCtx ctx[3] = {
    { &counter, 4 },
    { &counter, 10 },
    { &counter, 6 },
  };

  r_atomic_uint_store (&counter, 0);
  r_assert_cmpptr ((tq = r_task_queue_new_simple (4)), !=, NULL);
  r_assert_cmpuint (r_task_queue_thread_count (tq), ==, 4);

  r_assert_cmpptr ((t[0] = r_task_queue_add_full (tq, 0, chain_ctx, &ctx[0], NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((t[1] = r_task_queue_add_full (tq, 0, chain_ctx, &ctx[1], NULL, t[0], NULL)), !=, NULL);
  r_assert_cmpptr ((t[2] = r_task_queue_add_full (tq, 0, chain_ctx, &ctx[2], NULL, t[1], NULL)), !=, NULL);

  /* We can't use r_task_wait, as new tasks are added, and we should wait for them. */
  while (r_atomic_uint_load (&counter) < 20)
    r_thread_yield ();

  r_task_unref (t[0]);
  r_task_unref (t[1]);
  r_task_unref (t[2]);
  r_task_queue_unref (tq);
}
RTEST_END;

RTEST (rtaskqueue, allocate_manually, RTEST_FAST)
{
  RTaskQueue * tq;
  rauint counter;
  RTask * t[3];
  RTQTestCtx ctx[3] = {
    { &counter, 10 },
    { &counter, 10 },
    { &counter, 10 },
  };

  r_atomic_uint_store (&counter, 0);
  r_assert_cmpptr ((tq = r_task_queue_new_simple (4)), !=, NULL);

  r_assert_cmpptr ((t[0] = r_task_queue_allocate (tq, chain_ctx, &ctx[0], NULL)), !=, NULL);
  r_assert_cmpptr ((t[1] = r_task_queue_allocate (tq, chain_ctx, &ctx[1], NULL)), !=, NULL);
  r_assert_cmpptr ((t[2] = r_task_queue_allocate (tq, chain_ctx, &ctx[2], NULL)), !=, NULL);

  r_assert (!r_task_add_dep (t[2], t[1], t[0], NULL));
  r_assert (!r_task_add_dep (t[1], t[0], NULL));

  r_assert (r_task_queue_add_task (tq, t[0]));
  r_assert (r_task_add_dep (t[1], t[0], NULL));
  r_assert (r_task_queue_add_task (tq, t[1]));
  r_assert (r_task_add_dep (t[2], t[1], t[0], NULL));
  r_assert (r_task_queue_add_task (tq, t[2]));

  /* We can't use r_task_wait, as new tasks are added, and we should wait for them. */
  while (r_atomic_uint_load (&counter) < 30)
    r_thread_yield ();

  r_task_unref (t[0]);
  r_task_unref (t[1]);
  r_task_unref (t[2]);
  r_task_queue_unref (tq);
}
RTEST_END;

RTEST (rtaskqueue, per_numa, RTEST_FAST)
{
  RTaskQueue * tq;
  rauint counter;
  RTask * t;

  r_atomic_uint_store (&counter, 0);
  r_assert_cmpptr (r_task_queue_new_simple (0), ==, NULL);
  r_assert_cmpptr ((tq = r_task_queue_new_per_numa_simple (2)), !=, NULL);
  r_assert_cmpuint (r_task_queue_group_count (tq), ==, r_sys_node_count ());
  r_assert_cmpuint (r_task_queue_thread_count (tq), ==, r_sys_node_count () * 2);

  r_assert_cmpptr ((t = r_task_queue_add (tq, simple_adder, &counter, NULL)), !=, NULL);
  r_assert (r_task_wait (t));
  r_assert_cmpuint (r_atomic_uint_load (&counter), ==, 1);

  r_task_unref (t);
  r_task_queue_unref (tq);
}
RTEST_END;

RTEST (rtaskqueue, per_numa_each_cpu, RTEST_FAST)
{
  RTaskQueue * tq;
  rauint counter;
  RTask * t;

  r_atomic_uint_store (&counter, 0);
  r_assert_cmpptr (r_task_queue_new_simple (0), ==, NULL);
  r_assert_cmpptr ((tq = r_task_queue_new_per_numa_each_cpu ()), !=, NULL);
  r_assert_cmpuint (r_task_queue_group_count (tq), ==, r_sys_node_count ());
  r_assert_cmpuint (r_task_queue_thread_count (tq), ==, r_sys_cpu_logical_count ());

  r_assert_cmpptr ((t = r_task_queue_add (tq, simple_adder, &counter, NULL)), !=, NULL);
  r_assert (r_task_wait (t));
  r_assert_cmpuint (r_atomic_uint_load (&counter), ==, 1);

  r_task_unref (t);
  r_task_queue_unref (tq);
}
RTEST_END;

RTEST (rtaskqueue, per_cpu, RTEST_FAST)
{
  RTaskQueue * tq;
  rauint counter;
  RTask * t;

  r_atomic_uint_store (&counter, 0);
  r_assert_cmpptr (r_task_queue_new_simple (0), ==, NULL);
  r_assert_cmpptr ((tq = r_task_queue_new_per_cpu_simple (2)), !=, NULL);
  r_assert_cmpuint (r_task_queue_group_count (tq), ==, (r_sys_cpu_logical_count () + 1) / 2);
  r_assert_cmpuint (r_task_queue_thread_count (tq), ==, r_sys_cpu_logical_count ());

  r_assert_cmpptr ((t = r_task_queue_add (tq, simple_adder, &counter, NULL)), !=, NULL);
  r_assert (r_task_wait (t));
  r_assert_cmpuint (r_atomic_uint_load (&counter), ==, 1);

  r_task_unref (t);
  r_task_queue_unref (tq);
}
RTEST_END;

