#include <rlib/rlib.h>

RTEST (rqueuering, basics, RTEST_FAST)
{
  RQueueRing * q;
  rpointer item;

  r_assert_cmpptr (r_queue_ring_new (0), ==, NULL);
  r_assert_cmpptr (r_queue_ring_new (RSIZE_MAX), ==, NULL);

  r_assert_cmpptr ((q = r_queue_ring_new (4)), !=, NULL);

  r_assert (r_queue_ring_is_empty (q));
  r_assert_cmpuint (r_queue_ring_size (q), ==, 0);

  r_assert (r_queue_ring_push (q, RUINT_TO_POINTER (42)));
  r_assert_cmpuint (r_queue_ring_size (q), ==, 1);

  r_assert_cmpptr ((item = r_queue_ring_pop (q)), ==, RUINT_TO_POINTER (42));
  r_assert_cmpuint (r_queue_ring_size (q), ==, 0);

  r_queue_ring_unref (q);
}
RTEST_END;

RTEST (rqueuering, wrap, RTEST_FAST)
{
  RQueueRing * q;
  rpointer item;

  r_assert_cmpptr ((q = r_queue_ring_new (4)), !=, NULL);

  r_assert (r_queue_ring_push (q, RUINT_TO_POINTER (42)));
  r_assert (r_queue_ring_push (q, RUINT_TO_POINTER (42)));
  r_assert (r_queue_ring_push (q, RUINT_TO_POINTER (42)));
  r_assert (r_queue_ring_push (q, RUINT_TO_POINTER (42)));
  r_assert_cmpuint (r_queue_ring_size (q), ==, 4);

  r_assert_cmpptr ((item = r_queue_ring_pop (q)), ==, RUINT_TO_POINTER (42));
  r_assert (r_queue_ring_push (q, RUINT_TO_POINTER (42)));
  r_assert_cmpuint (r_queue_ring_size (q), ==, 4);

  r_assert_cmpptr ((item = r_queue_ring_pop (q)), ==, RUINT_TO_POINTER (42));
  r_assert (r_queue_ring_push (q, RUINT_TO_POINTER (42)));
  r_assert_cmpuint (r_queue_ring_size (q), ==, 4);

  r_assert (!r_queue_ring_push (q, RUINT_TO_POINTER (42)));
  r_assert_cmpuint (r_queue_ring_size (q), ==, 4);

  r_queue_ring_unref (q);
}
RTEST_END;

RTEST (rqueuering, clear, RTEST_FAST)
{
  RQueueRing * q;

  r_assert_cmpptr ((q = r_queue_ring_new (4)), !=, NULL);
  r_assert (r_queue_ring_push (q, r_malloc (42)));
  r_assert (r_queue_ring_push (q, r_malloc (42)));
  r_assert (r_queue_ring_push (q, r_malloc (42)));
  r_assert (r_queue_ring_push (q, r_malloc (42)));
  r_assert_cmpuint (r_queue_ring_size (q), ==, 4);

  r_queue_ring_clear (q, r_free);
  r_assert_cmpuint (r_queue_ring_size (q), ==, 0);

  r_queue_ring_unref (q);
}
RTEST_END;

