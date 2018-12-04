#include <rlib/rlib.h>

RTEST (rcbqueue, basics, RTEST_FAST)
{
  RCBQueue q;
  RCBList * item;

  r_cbqueue_init (&q);

  r_assert (r_cbqueue_is_empty (&q));
  r_assert_cmpuint (r_cbqueue_size (&q), ==, 0);

  r_cbqueue_push (&q, NULL, RUINT_TO_POINTER (42), NULL, NULL, NULL);
  r_assert_cmpuint (r_cbqueue_size (&q), ==, 1);

  r_assert_cmpptr ((item = r_cbqueue_pop (&q)), !=, NULL);
  r_assert_cmpuint (r_cbqueue_size (&q), ==, 0);
  r_assert_cmpptr (item->next, ==, NULL);
  r_assert_cmpptr (item->prev, ==, NULL);
  r_assert_cmpptr (item->data.cb, ==, NULL);
  r_assert_cmpptr (item->data.data, ==, RUINT_TO_POINTER (42));
  r_assert_cmpptr (item->data.datanotify, ==, NULL);
  r_assert_cmpptr (item->data.user, ==, NULL);
  r_assert_cmpptr (item->data.usernotify, ==, NULL);
  r_cblist_free1 (item);

  r_cbqueue_clear (&q);
}
RTEST_END;

RTEST (rcbqueue, merge, RTEST_FAST)
{
  RCBQueue q0, q1;

  r_cbqueue_init (&q0);
  r_cbqueue_init (&q1);

  r_assert (r_cbqueue_is_empty (&q0));
  r_assert (r_cbqueue_is_empty (&q1));

  r_cbqueue_push (&q0, NULL, RUINT_TO_POINTER (42), NULL, NULL, NULL);
  r_assert_cmpuint (r_cbqueue_size (&q0), ==, 1);

  r_cbqueue_push (&q1, NULL, RUINT_TO_POINTER (42), NULL, NULL, NULL);
  r_cbqueue_push (&q1, NULL, RUINT_TO_POINTER (42), NULL, NULL, NULL);
  r_cbqueue_push (&q1, NULL, RUINT_TO_POINTER (42), NULL, NULL, NULL);
  r_assert_cmpuint (r_cbqueue_size (&q1), ==, 3);

  r_cbqueue_merge (&q0, &q1);
  r_assert_cmpuint (r_cbqueue_size (&q0), ==, 4);
  r_assert (r_cbqueue_is_empty (&q1));

  r_cbqueue_clear (&q0);
  r_cbqueue_clear (&q1);
}
RTEST_END;
