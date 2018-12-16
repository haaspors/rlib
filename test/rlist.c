#include <rlib/rlib.h>

#define PTR_CAFEBABE    RINT_TO_POINTER (0xCAFEBABE)
#define PTR_DEADBEEF    RINT_TO_POINTER (0xDEADBEEF)
#define PTR_BAADFOOD    RINT_TO_POINTER (0xBAADF00D)

RTEST (rlist, prepend, RTEST_FAST)
{
  RList * head = NULL;

  r_assert_cmpptr ((head = r_list_prepend (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_list_prepend (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpuint (r_list_len (head), ==, 2);
  r_assert_cmpptr (r_list_first (head)->data, ==, PTR_DEADBEEF);
  r_assert_cmpptr (r_list_last (head)->data,  ==, PTR_CAFEBABE);

  r_assert_cmpptr ((head = r_list_prepend (r_list_last (head), PTR_BAADFOOD)), !=, NULL);
  r_assert_cmpuint (r_list_len (head), ==, 3);
  r_assert_cmpptr (r_list_first (head)->data, ==, PTR_BAADFOOD);
  r_assert_cmpptr (head->next->data,  ==, PTR_DEADBEEF);
  r_assert_cmpptr (r_list_last (head)->data,  ==, PTR_CAFEBABE);

  r_list_destroy (head);
}
RTEST_END;

RTEST (rlist, contains, RTEST_FAST)
{
  RList * head = NULL;

  r_assert (!r_list_contains (head, NULL));
  r_assert (!r_list_contains (head, PTR_CAFEBABE));

  r_assert_cmpptr ((head = r_list_prepend (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_list_prepend (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_list_prepend (head, PTR_BAADFOOD)), !=, NULL);
  r_assert (r_list_contains (head, PTR_CAFEBABE));
  r_assert (r_list_contains (head, PTR_DEADBEEF));
  r_assert (r_list_contains (head, PTR_BAADFOOD));
  r_assert (!r_list_contains (head, NULL));

  /* slist will not find this element, but list will! */
  r_assert (r_list_contains (head->next, PTR_BAADFOOD));

  r_list_destroy (head);
}
RTEST_END;

RTEST (rlist, append, RTEST_FAST)
{
  RList * head = NULL;

  r_assert_cmpptr ((head = r_list_append (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_list_append (head, PTR_DEADBEEF)), !=, NULL);

  r_assert_cmpuint (r_list_len (head), ==, 2);
  r_assert_cmpptr (head->data, ==, PTR_CAFEBABE);
  r_assert_cmpptr (head->next->data, ==, PTR_DEADBEEF);
  r_assert_cmpptr (head->next->prev, ==, head);

  r_list_destroy (head);
}
RTEST_END;

RTEST (rlist, remove, RTEST_FAST)
{
  RList * head = NULL;

  r_assert_cmpptr ((head = r_list_prepend (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_list_prepend (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_list_prepend (head, PTR_BAADFOOD)), !=, NULL);

  r_assert_cmpuint (r_list_len (head), ==, 3);

  r_assert_cmpptr ((head = r_list_remove (head, NULL)), !=, NULL);
  r_assert_cmpuint (r_list_len (head), ==, 3);
  r_assert_cmpptr ((head = r_list_remove (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpuint (r_list_len (head), ==, 2);

  r_list_destroy (head);
}
RTEST_END;

RTEST (rlist, insert_before, RTEST_FAST)
{
  RList * head = NULL;

  r_assert_cmpptr ((head = r_list_insert_before (head, head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_list_insert_before (head, head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_list_insert_before (head, head->next,
          PTR_BAADFOOD)), !=, NULL);
  r_assert_cmpuint (r_list_len (head), ==, 3);
  r_assert_cmpptr (head->data, ==, PTR_DEADBEEF);
  r_assert_cmpptr (head->next->data, ==, PTR_BAADFOOD);

  r_list_destroy (head);
}
RTEST_END;

RTEST (rlist, insert_after, RTEST_FAST)
{
  RList * head = NULL;

  r_assert_cmpptr ((head = r_list_insert_after (head, head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_list_insert_after (head, head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_list_insert_after (head, r_list_last (head),
          PTR_BAADFOOD)), !=, NULL);
  r_assert_cmpuint (r_list_len (head), ==, 3);
  r_assert_cmpptr (head->data, ==, PTR_CAFEBABE);
  r_assert_cmpptr (head->next->data, ==, PTR_DEADBEEF);
  r_assert_cmpptr (r_list_last (head)->data, ==, PTR_BAADFOOD);

  r_list_destroy (head);
}
RTEST_END;

RTEST (rlist, nth, RTEST_FAST)
{
  RList * head = NULL;

  r_assert_cmpptr ((head = r_list_append (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_list_append (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_list_append (head, PTR_BAADFOOD)), !=, NULL);

  r_assert_cmpuint (r_list_len (head), ==, 3);
  r_assert_cmpptr (r_list_first (head)->data, ==, PTR_CAFEBABE);
  r_assert_cmpptr (head->next->data,          ==, PTR_DEADBEEF);
  r_assert_cmpptr (r_list_last (head)->data,  ==, PTR_BAADFOOD);

  r_assert_cmpptr (r_list_nth (head, 0), ==, r_list_first (head));
  r_assert_cmpptr (r_list_nth (head, 1), ==, head->next);
  r_assert_cmpptr (r_list_nth (head, 2), ==, r_list_last (head));
  r_assert_cmpptr (r_list_nth (head, 3), ==, NULL);

  r_list_destroy (head);
}
RTEST_END;

static void
list_count (rpointer item, rpointer user)
{
  rsize * count = user;
  (void)item;
  (*count)++;
}

RTEST (rlist, foreach, RTEST_FAST)
{
  RList * head = NULL;
  rsize count = 0;

  r_assert_cmpptr ((head = r_list_append (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_list_append (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_list_append (head, PTR_BAADFOOD)), !=, NULL);

  r_list_foreach (head, list_count, &count);
  r_assert_cmpuint (count, ==, 3);

  r_list_destroy (head);
}
RTEST_END;

