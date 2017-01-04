#include <rlib/rlib.h>

RTEST (rhashset, insert_1_remove, RTEST_FAST)
{
  RHashSet * hs;
  rpointer p;

  r_assert_cmpptr ((hs = r_hash_set_new (NULL, NULL)), !=, NULL);
  r_assert_cmpuint (r_hash_set_current_alloc_size (hs), ==, 1 << 3);

  r_assert_cmpuint (r_hash_set_size (hs), ==, 0);
  r_assert (!r_hash_set_contains (hs, RUINT_TO_POINTER (0)));
  r_assert (r_hash_set_insert (hs, RUINT_TO_POINTER (0)));
  r_assert_cmpuint (r_hash_set_size (hs), ==, 1);

  r_assert (r_hash_set_contains (hs, RUINT_TO_POINTER (0)));
  r_assert (!r_hash_set_contains (hs, RUINT_TO_POINTER (42)));
  r_assert (r_hash_set_contains_full (hs, RUINT_TO_POINTER (0), &p));
  r_assert_cmpuint (RPOINTER_TO_UINT (p), ==, 0);

  r_assert (!r_hash_set_remove (hs, RUINT_TO_POINTER (1)));
  r_assert (!r_hash_set_remove (hs, RUINT_TO_POINTER (42)));
  r_assert (r_hash_set_remove (hs, RUINT_TO_POINTER (0)));
  r_assert_cmpuint (r_hash_set_size (hs), ==, 0);

  r_hash_set_unref (hs);
}
RTEST_END;

RTEST (rhashset, insert_resize_remove_all, RTEST_FAST)
{
  RHashSet * hs;
  rsize allocsize, i;

  r_assert_cmpptr ((hs = r_hash_set_new (NULL, NULL)), !=, NULL);
  r_assert_cmpuint ((allocsize = r_hash_set_current_alloc_size (hs)), >, 3);
  r_assert_cmpuint (r_hash_set_size (hs), ==, 0);

  for (i = 0; i < allocsize + 1; i++)
    r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (i)));

  r_assert_cmpuint (r_hash_set_size (hs), ==, allocsize + 1);
  r_assert_cmpuint (r_hash_set_current_alloc_size (hs), ==, allocsize * 2);

  for (i = 0; i < allocsize + 1; i++)
    r_assert (r_hash_set_contains (hs, RUINT_TO_POINTER (i)));

  r_hash_set_remove_all (hs);
  r_assert_cmpuint (r_hash_set_size (hs), ==, 0);
  r_assert_cmpuint (r_hash_set_current_alloc_size (hs), ==, allocsize * 2);
  r_hash_set_unref (hs);
}
RTEST_END;

RTEST (rhashset, str, RTEST_FAST)
{
  RHashSet * hs;

  r_assert_cmpptr ((hs = r_hash_set_new (r_str_hash, r_str_equal)), !=, NULL);

  r_assert (r_hash_set_insert (hs, "foobar"));
  r_assert (r_hash_set_insert (hs, "foo"));
  r_assert (r_hash_set_insert (hs, "bar"));
  r_assert_cmpuint (r_hash_set_size (hs), ==, 3);
  r_assert (r_hash_set_contains (hs, "bar"));
  r_assert (r_hash_set_insert (hs, "bar"));
  r_assert_cmpuint (r_hash_set_size (hs), ==, 3);

  r_hash_set_unref (hs);
}
RTEST_END;

static void
sum_uints (rpointer item, rpointer user)
{
  ruint * sum = user;
  *sum += RPOINTER_TO_UINT (item);
}

RTEST (rhashset, foreach, RTEST_FAST)
{
  RHashSet * hs;
  ruint sum = 0;

  r_assert_cmpptr ((hs = r_hash_set_new (NULL, NULL)), !=, NULL);

  r_assert (r_hash_set_insert (hs, RUINT_TO_POINTER (8)));
  r_assert (r_hash_set_insert (hs, RUINT_TO_POINTER (42)));
  r_assert (r_hash_set_insert (hs, RUINT_TO_POINTER (16)));
  r_assert (r_hash_set_insert (hs, RUINT_TO_POINTER (8)));

  r_hash_set_foreach (hs, sum_uints, &sum);
  r_assert_cmpuint (sum, ==, 8 + 42 + 16);

  r_assert (r_hash_set_remove (hs, RUINT_TO_POINTER (42)));
  sum = 0;
  r_hash_set_foreach (hs, sum_uints, &sum);
  r_assert_cmpuint (sum, ==, 8 + 16);

  r_hash_set_unref (hs);
}
RTEST_END;

