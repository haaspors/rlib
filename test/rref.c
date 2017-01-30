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

  r_ref_weak_unref (ref, r_test_ref_notify_cb, &weaknotified);
  r_assert_cmpptr (r_atomic_ptr_load (&ref->ref.weaklst), ==, NULL);
  r_ref_unref (ref);
  r_assert (!weaknotified);
}
RTEST_END;

