#include <rlib/rlib.h>

typedef struct {
  RRef ref;
  int val;
} RTestRef;

static inline RTestRef *
r_test_ref_new (int val)
{
  RTestRef * ret;

  if ((ret = r_mem_new (RTestRef)) != NULL) {
    r_ref_init (ret, r_free);
    ret->val = val;
  }

  return ret;
}

static void
r_test_ref_notify_cb (rpointer data, rpointer user)
{
  (void) user;
  *(rboolean *)data = TRUE;
}

RTEST (rref, ref, RTEST_FAST)
{
  RTestRef * ref;
  r_assert_cmpptr ((ref = r_test_ref_new (42)), !=, NULL);
  r_assert_cmpuint (r_ref_refcount (ref), ==, 1);
  r_assert_cmpptr (r_ref_ref (ref), !=, NULL);
  r_assert_cmpuint (r_ref_refcount (ref), ==, 2);
  r_ref_unref (ref);
  r_assert_cmpuint (r_ref_refcount (ref), ==, 1);
  r_ref_unref (ref);
}
RTEST_END;

RTEST (rref, weak_ref, RTEST_FAST)
{
  RTestRef * ref;
  rboolean weaknotified = FALSE;

  r_assert_cmpptr ((ref = r_test_ref_new (42)), !=, NULL);
  r_assert_cmpptr (r_atomic_ptr_load (&ref->ref.weaklst), ==, NULL);
  r_assert_cmpptr (r_ref_weak_ref (ref, r_test_ref_notify_cb, &weaknotified), !=, NULL);
  r_assert_cmpptr (r_atomic_ptr_load (&ref->ref.weaklst), !=, NULL);

  r_assert (!weaknotified);
  r_ref_unref (ref);
  r_assert (weaknotified);
}
RTEST_END;

RTEST (rref, weak_unref, RTEST_FAST)
{
  RTestRef * ref;
  rboolean weaknotified = FALSE;

  r_assert_cmpptr ((ref = r_test_ref_new (42)), !=, NULL);
  r_assert_cmpptr (r_atomic_ptr_load (&ref->ref.weaklst), ==, NULL);
  r_assert_cmpptr (r_ref_weak_ref (ref, r_test_ref_notify_cb, &weaknotified), !=, NULL);
  r_assert_cmpptr (r_atomic_ptr_load (&ref->ref.weaklst), !=, NULL);

  r_assert (!r_ref_weak_unref (ref, NULL, NULL));
  r_assert (!r_ref_weak_unref (ref, NULL, &weaknotified));
  r_assert (!r_ref_weak_unref (ref, r_test_ref_notify_cb, NULL));
  r_assert (r_ref_weak_unref (ref, r_test_ref_notify_cb, &weaknotified));
  r_assert_cmpptr (r_atomic_ptr_load (&ref->ref.weaklst), ==, NULL);
  r_ref_unref (ref);
  r_assert (!weaknotified);
}
RTEST_END;

#define LOOP_LENGTH   (R_SECOND / 5)

static rpointer
ref_unref_loop (rpointer data)
{
  RTestRef * ref = data;
  RClockTime now, start = r_time_get_ts_monotonic ();

  do {
    r_assert_cmpptr (r_ref_ref (ref), !=, NULL);
    r_thread_yield ();
    r_ref_unref (ref);
    r_thread_yield ();

    now = r_time_get_ts_monotonic ();
  } while (now - start < LOOP_LENGTH);

  return NULL;
}

static rpointer
weak_ref_unref_loop (rpointer data)
{
  RTestRef * ref = data;
  RClockTime now, start = r_time_get_ts_monotonic ();

  do {
    rboolean weaknotified = FALSE;
    r_assert_cmpptr (r_ref_weak_ref (ref, r_test_ref_notify_cb, &weaknotified), !=, NULL);
    r_thread_yield ();
    r_ref_weak_unref (ref, r_test_ref_notify_cb, &weaknotified);
    r_thread_yield ();
    r_assert (!weaknotified);

    now = r_time_get_ts_monotonic ();
  } while (now - start < LOOP_LENGTH);

  return NULL;
}

RTEST_STRESS (rref, ref_unref_stress, RTEST_FAST)
{
  RTestRef * ref;
  RThread * t[4];
  int i;

  r_assert_cmpptr ((ref = r_test_ref_new (42)), !=, NULL);

  for (i = 0; i < R_N_ELEMENTS (t); i++)
    r_assert_cmpptr ((t[i] = r_thread_new ("ref", ref_unref_loop, ref)), !=, NULL);

  for (i = 0; i < R_N_ELEMENTS (t); i++) {
    r_assert_cmpptr (r_thread_join (t[i]), ==, NULL);
    r_thread_unref (t[i]);
  }

  r_assert_cmpptr (r_atomic_ptr_load (&ref->ref.weaklst), ==, NULL);
  r_assert_cmpuint (r_ref_refcount (ref), ==, 1);
  r_ref_unref (ref);
}
RTEST_END;

RTEST_STRESS (rref, weak_stress, RTEST_FAST)
{
  RTestRef * ref;
  RThread * tref[4];
  RThread * tweak[1]; // TODO: Increase this! Currently weak refs are not thread safe
  int i;

  r_assert_cmpptr ((ref = r_test_ref_new (42)), !=, NULL);

  for (i = 0; i < R_N_ELEMENTS (tref); i++)
    r_assert_cmpptr ((tref[i] = r_thread_new ("ref", ref_unref_loop, ref)), !=, NULL);
  for (i = 0; i < R_N_ELEMENTS (tweak); i++)
    r_assert_cmpptr ((tweak[i] = r_thread_new ("weak", weak_ref_unref_loop, ref)), !=, NULL);

  for (i = 0; i < R_N_ELEMENTS (tweak); i++) {
    r_assert_cmpptr (r_thread_join (tweak[i]), ==, NULL);
    r_thread_unref (tweak[i]);
  }
  for (i = 0; i < R_N_ELEMENTS (tref); i++) {
    r_assert_cmpptr (r_thread_join (tref[i]), ==, NULL);
    r_thread_unref (tref[i]);
  }

  r_assert_cmpptr (r_atomic_ptr_load (&ref->ref.weaklst), ==, NULL);
  r_assert_cmpuint (r_ref_refcount (ref), ==, 1);
  r_ref_unref (ref);
}
RTEST_END;

