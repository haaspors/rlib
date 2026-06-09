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


/* A removal must not truncate the open-addressing probe chain of another item
 * that collided past it. With the default (identity) hash and the initial
 * 8-bucket table, 7/14/21/28 all start at bucket 0 (mod 7) and form one chain;
 * removing 14 must leave the items probed past it findable. */
RTEST (rhashset, remove_middle_of_collision_chain, RTEST_FAST)
{
  RHashSet * hs;

  r_assert_cmpptr ((hs = r_hash_set_new (NULL, NULL)), !=, NULL);
  r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (7)));
  r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (14)));
  r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (21)));
  r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (28)));

  r_assert (r_hash_set_remove (hs, RSIZE_TO_POINTER (14)));

  r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (21)));
  r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (28)));
  r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (7)));
  r_assert (!r_hash_set_contains (hs, RSIZE_TO_POINTER (14)));

  r_hash_set_unref (hs);
}
RTEST_END;

/* Same invariant via the exact stranding sequence found in the field. */
RTEST (rhashset, remove_preserves_probe_chain, RTEST_FAST)
{
  RHashSet * hs;
  static const rsize items[8] = { 3, 1000, 1001, 1002, 1003, 1004, 1005, 1006 };
  rsize i;

  r_assert_cmpptr ((hs = r_hash_set_new (NULL, NULL)), !=, NULL);
  for (i = 0; i < 8; i++)
    r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (items[i])));

  r_assert (r_hash_set_remove (hs, RSIZE_TO_POINTER (1000)));
  r_assert (r_hash_set_remove (hs, RSIZE_TO_POINTER (1002)));
  r_assert (r_hash_set_remove (hs, RSIZE_TO_POINTER (1004)));
  r_assert (r_hash_set_remove (hs, RSIZE_TO_POINTER (1006)));

  r_assert_cmpuint (r_hash_set_size (hs), ==, 4);
  r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (3)));
  r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (1001)));
  r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (1003)));
  r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (1005)));

  r_hash_set_unref (hs);
}
RTEST_END;

/* Insert across several resizes; after each insert look up an item never
 * inserted. A table that fills completely (no EMPTY bucket) makes the
 * open-addressing probe for an absent item loop forever -- this would hang. */
RTEST (rhashset, lookup_absent_never_loops, RTEST_FAST)
{
  RHashSet * hs;
  rsize i;
  const rsize n = 1000;

  r_assert_cmpptr ((hs = r_hash_set_new (NULL, NULL)), !=, NULL);
  for (i = 0; i < n; i++) {
    r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (i + 1)));
    r_assert (!r_hash_set_contains (hs, RSIZE_TO_POINTER (n + i + 1)));
  }
  r_assert_cmpuint (r_hash_set_size (hs), ==, n);
  for (i = 0; i < n; i++)
    r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (i + 1)));

  r_hash_set_unref (hs);
}
RTEST_END;

/* remove_all must actually empty the set even with no destroy-notify -- not
 * just zero the count while leaving findable "ghost" items behind. */
RTEST (rhashset, remove_all_clears_without_notify, RTEST_FAST)
{
  RHashSet * hs;
  rsize i;

  r_assert_cmpptr ((hs = r_hash_set_new (NULL, NULL)), !=, NULL);
  for (i = 1; i <= 5; i++)
    r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (i)));

  r_hash_set_remove_all (hs);

  r_assert_cmpuint (r_hash_set_size (hs), ==, 0);
  for (i = 1; i <= 5; i++)
    r_assert (!r_hash_set_contains (hs, RSIZE_TO_POINTER (i)));

  r_hash_set_unref (hs);
}
RTEST_END;

/* Sequential integer items must spread across the bucket array, not pile into a
 * contiguous home range that degrades unsuccessful lookups. */
RTEST (rhashset, sequential_items_stay_well_distributed, RTEST_FAST)
{
  RHashSet * hs;
  rsize i;
  const rsize n = 5000;

  r_assert_cmpptr ((hs = r_hash_set_new (NULL, NULL)), !=, NULL);
  for (i = 0; i < n; i++)
    r_assert (r_hash_set_insert (hs, RSIZE_TO_POINTER (i + 1)));

  r_assert_cmpuint (r_hash_set_max_probe (hs), <=, 48);

  for (i = 0; i < n; i++)
    r_assert (r_hash_set_contains (hs, RSIZE_TO_POINTER (i + 1)));

  r_hash_set_unref (hs);
}
RTEST_END;
