#include <rlib/rlib.h>

RTEST (rqueuelist, stack, RTEST_FAST)
{
  RQueueList q = R_QUEUE_LIST_INIT;
  rpointer item;

  r_assert (r_queue_list_is_empty (&q));
  r_assert_cmpuint (r_queue_list_size (&q), ==, 0);

  r_queue_list_push (&q, RUINT_TO_POINTER (42));
  r_assert_cmpuint (r_queue_list_size (&q), ==, 1);
  r_assert (!r_queue_list_is_empty (&q));

  r_assert_cmpptr ((item = r_queue_list_pop (&q)), ==, RUINT_TO_POINTER (42));
  r_assert_cmpuint (r_queue_list_size (&q), ==, 0);
}
RTEST_END;

RTEST (rqueuelist, heap, RTEST_FAST)
{
  RQueueList * q;
  rpointer item;

  r_assert_cmpptr ((q = r_queue_list_new ()), !=, NULL);

  r_assert (r_queue_list_is_empty (q));
  r_assert_cmpuint (r_queue_list_size (q), ==, 0);

  r_queue_list_push (q, RUINT_TO_POINTER (42));
  r_assert_cmpuint (r_queue_list_size (q), ==, 1);

  r_assert_cmpptr ((item = r_queue_list_pop (q)), ==, RUINT_TO_POINTER (42));
  r_assert_cmpuint (r_queue_list_size (q), ==, 0);

  r_queue_list_free (q, NULL);
}
RTEST_END;

RTEST (rqueuelist, clear, RTEST_FAST)
{
  RQueueList q = R_QUEUE_LIST_INIT;
  r_assert_cmpuint (r_queue_list_size (&q), ==, 0);

  r_queue_list_push (&q, r_malloc (42));
  r_queue_list_push (&q, r_malloc (42));
  r_queue_list_push (&q, r_malloc (42));
  r_queue_list_push (&q, r_malloc (42));
  r_assert_cmpuint (r_queue_list_size (&q), ==, 4);

  r_queue_list_clear (&q, r_free);
  r_assert_cmpuint (r_queue_list_size (&q), ==, 0);
}
RTEST_END;

RTEST (rqueuelist, free, RTEST_FAST)
{
  RQueueList * q;

  r_assert_cmpptr ((q = r_queue_list_new ()), !=, NULL);
  r_assert_cmpuint (r_queue_list_size (q), ==, 0);

  r_queue_list_push (q, r_malloc (42));
  r_queue_list_push (q, r_malloc (42));
  r_queue_list_push (q, r_malloc (42));
  r_queue_list_push (q, r_malloc (42));
  r_assert_cmpuint (r_queue_list_size (q), ==, 4);

  r_queue_list_free (q, r_free);
}
RTEST_END;

RTEST (rqueuelist, peek, RTEST_FAST)
{
  RQueueList q = R_QUEUE_LIST_INIT;
  rpointer items[4];
  r_assert_cmpuint (r_queue_list_size (&q), ==, 0);

  r_assert_cmpptr (r_queue_list_peek (&q), ==, NULL);

  r_queue_list_push (&q, (items[0] = r_malloc (42)));
  r_queue_list_push (&q, (items[1] = r_malloc (42)));
  r_queue_list_push (&q, (items[2] = r_malloc (42)));
  r_queue_list_push (&q, (items[3] = r_malloc (42)));
  r_assert_cmpuint (r_queue_list_size (&q), ==, 4);

  r_assert_cmpptr (r_queue_list_peek (&q), ==, items[0]);
  r_assert_cmpuint (r_queue_list_size (&q), ==, 4);

  r_free (r_queue_list_pop (&q));
  r_assert_cmpptr (r_queue_list_peek (&q), ==, items[1]);
  r_assert_cmpuint (r_queue_list_size (&q), ==, 3);

  r_queue_list_clear (&q, r_free);
}
RTEST_END;

