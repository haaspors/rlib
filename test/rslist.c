#include <rlib/rlib.h>

#define PTR_CAFEBABE    RINT_TO_POINTER (0xCAFEBABE)
#define PTR_DEADBEEF    RINT_TO_POINTER (0xDEADBEEF)
#define PTR_BAADFOOD    RINT_TO_POINTER (0xBAADF00D)

RTEST (rslist, add, RTEST_FAST)
{
  RSList * head = NULL;

  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpuint (r_slist_len (head), ==, 2);
  r_assert_cmpptr (r_slist_data (head), ==, PTR_DEADBEEF);
  r_assert_cmpptr (r_slist_data (r_slist_next (head)), ==, PTR_CAFEBABE);

  r_assert_cmpptr ((head = r_slist_insert_after (head, PTR_BAADFOOD)), !=, NULL);
  r_assert_cmpuint (r_slist_len (head), ==, 3);
  r_assert_cmpptr (r_slist_data (r_slist_next (head)), ==, PTR_BAADFOOD);
  r_slist_destroy (head);
  head = NULL;

  r_assert_cmpptr ((head = r_slist_insert_after (head, PTR_BAADFOOD)), !=, NULL);
  r_assert_cmpuint (r_slist_len (head), ==, 1);
  r_assert_cmpptr (r_slist_data (head), ==, PTR_BAADFOOD);
  r_slist_destroy (head);
}
RTEST_END;

RTEST (rslist, remove, RTEST_FAST)
{
  RSList * head = NULL;

  r_assert_cmpptr (r_slist_remove (head, PTR_DEADBEEF), ==, NULL);

  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_BAADFOOD)), !=, NULL);
  r_assert_cmpuint (r_slist_len (head), ==, 3);

  r_assert_cmpptr (r_slist_remove (head, NULL), !=, NULL);
  r_assert_cmpptr (r_slist_remove (head, PTR_DEADBEEF), !=, NULL);
  r_assert_cmpuint (r_slist_len (head), ==, 2);
  r_assert_cmpptr (r_slist_data (head), ==, PTR_BAADFOOD);
  r_assert_cmpptr (r_slist_data (r_slist_next (head)), ==, PTR_CAFEBABE);

  r_slist_destroy (head);
}
RTEST_END;

RTEST (rslist, nth, RTEST_FAST)
{
  RSList * head = NULL;

  r_assert_cmpptr (r_slist_nth (head, 0), ==, NULL);
  r_assert_cmpptr (r_slist_nth (head, 42), ==, NULL);

  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_BAADFOOD)), !=, NULL);

  r_assert_cmpptr (r_slist_data (r_slist_nth (head, 0)), ==, PTR_BAADFOOD);
  r_assert_cmpptr (r_slist_data (r_slist_nth (head, 1)), ==, PTR_DEADBEEF);
  r_assert_cmpptr (r_slist_data (r_slist_nth (head, 2)), ==, PTR_CAFEBABE);
  r_assert_cmpptr (r_slist_nth (head, 3), ==, NULL);

  r_slist_destroy (head);
}
RTEST_END;

RTEST (rslist, contains, RTEST_FAST)
{
  RSList * head = NULL;

  r_assert (!r_slist_contains (head, NULL));
  r_assert (!r_slist_contains (head, PTR_CAFEBABE));

  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_CAFEBABE)), !=, NULL);
  r_assert (!r_slist_contains (head, PTR_DEADBEEF));
  r_assert ( r_slist_contains (head, PTR_CAFEBABE));

  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpptr ((head = r_slist_prepend (head, PTR_BAADFOOD)), !=, NULL);
  r_assert (r_slist_contains (head, PTR_DEADBEEF));
  r_assert (r_slist_contains (head, PTR_CAFEBABE));
  r_assert (r_slist_contains (head, PTR_BAADFOOD));
  r_assert (!r_slist_contains (head, NULL));

  r_slist_destroy (head);
}
RTEST_END;

