#include <rlib/rlib.h>

RTEST (rhashtable, insert_1_remove, RTEST_FAST)
{
  RHashTable * ht;
  rpointer p;

  r_assert_cmpptr ((ht = r_hash_table_new (NULL, NULL)), !=, NULL);
  r_assert_cmpuint (r_hash_table_current_alloc_size (ht), ==, 1 << 3);

  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);
  r_assert_cmpint (r_hash_table_contains (ht, RUINT_TO_POINTER (0)), ==, R_HASH_TABLE_NOT_FOUND);
  r_assert_cmpint (r_hash_table_insert (ht,
        RUINT_TO_POINTER (0), RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_contains (ht, RUINT_TO_POINTER (0)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht,
          RUINT_TO_POINTER (0))), ==, 42);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 1);

  r_assert_cmpint (r_hash_table_lookup_full (ht, RUINT_TO_POINTER (0),
        NULL, &p), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (RPOINTER_TO_UINT (p), ==, 42);

  r_assert_cmpint (r_hash_table_remove (ht, RUINT_TO_POINTER (1)), ==, R_HASH_TABLE_NOT_FOUND);
  r_assert_cmpint (r_hash_table_remove (ht, RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_NOT_FOUND);
  r_assert_cmpint (r_hash_table_remove (ht, RUINT_TO_POINTER (0)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);

  r_hash_table_unref (ht);
}
RTEST_END;

RTEST (rhashtable, insert_resize_remove_all, RTEST_FAST)
{
  RHashTable * ht;
  rsize allocsize, i;

  r_assert_cmpptr ((ht = r_hash_table_new (NULL, NULL)), !=, NULL);
  r_assert_cmpuint ((allocsize = r_hash_table_current_alloc_size (ht)), >, 3);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);

  for (i = 0; i < allocsize + 1; i++) {
    r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (i),
          RUINT_TO_POINTER (42 + i)), ==, R_HASH_TABLE_OK);
  }

  r_assert_cmpuint (r_hash_table_size (ht), ==, allocsize + 1);
  r_assert_cmpuint (r_hash_table_current_alloc_size (ht), ==, allocsize * 2);

  for (i = 0; i < allocsize + 1; i++) {
    r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht,
            RUINT_TO_POINTER (i))), ==, 42 + i);
  }

  r_hash_table_remove_all (ht);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);
  r_assert_cmpuint (r_hash_table_current_alloc_size (ht), ==, allocsize * 2);
  r_hash_table_unref (ht);
}
RTEST_END;

RTEST (rhashtable, notify, RTEST_FAST)
{
  RHashTable * ht;
  RBuffer * buf;

  r_assert_cmpptr ((ht = r_hash_table_new_full (NULL, NULL, NULL, r_buffer_unref)), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert_cmpuint (r_ref_refcount (buf), ==, 1);

  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (0),
        r_buffer_ref (buf)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 1);
  r_assert_cmpuint (r_ref_refcount (buf), ==, 2);

  r_hash_table_unref (ht);
  r_assert_cmpuint (r_ref_refcount (buf), ==, 1);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rhashtable, replace, RTEST_FAST)
{
  RHashTable * ht;
  RBuffer * buf;

  r_assert_cmpptr ((ht = r_hash_table_new_full (NULL, NULL, NULL, r_buffer_unref)), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);

  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (0), NULL), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 1);

  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (0),
        r_buffer_ref (buf)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 1);

  /* Do it again... */
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (0),
        r_buffer_ref (buf)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 1);

  r_hash_table_unref (ht);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rhashtable, steal, RTEST_FAST)
{
  RHashTable * ht;
  RBuffer * buf, * steal;

  r_assert_cmpptr ((ht = r_hash_table_new_full (NULL, NULL, NULL, r_buffer_unref)), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert_cmpuint (r_ref_refcount (buf), ==, 1);

  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (0),
        r_buffer_ref (buf)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 1);
  r_assert_cmpuint (r_ref_refcount (buf), ==, 2);

  r_assert_cmpint (r_hash_table_steal (ht, RSIZE_TO_POINTER (1),
        NULL, (rpointer *)&steal), ==, R_HASH_TABLE_NOT_FOUND);
  r_assert_cmpint (r_hash_table_steal (ht, RSIZE_TO_POINTER (0),
        NULL, (rpointer *)&steal), ==, R_HASH_TABLE_OK);
  r_assert_cmpptr (buf, ==, steal);

  r_hash_table_unref (ht);
  r_assert_cmpuint (r_ref_refcount (buf), ==, 2);
  r_buffer_unref (buf);
  r_buffer_unref (steal);
}
RTEST_END;

RTEST (rhashtable, str, RTEST_FAST)
{
  RHashTable * ht;

  r_assert_cmpptr ((ht = r_hash_table_new (r_str_hash, r_str_equal)), !=, NULL);

  r_assert_cmpint (r_hash_table_insert (ht,
        "foobar", RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht,
        "foo", RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht,
        "bar", RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 3);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, "bar")), ==, 42);
  r_assert_cmpint (r_hash_table_insert (ht,
        "bar", RUINT_TO_POINTER (0)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 3);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, "foo")), ==, 42);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, "bar")), ==, 0);

  r_hash_table_unref (ht);
}
RTEST_END;

RTEST (rhashtable, remove_with_func, RTEST_FAST)
{
  RHashTable * ht;

  r_assert_cmpptr ((ht = r_hash_table_new (NULL, NULL)), !=, NULL);

  r_assert_cmpint (r_hash_table_remove_all_values (ht, RUINT_TO_POINTER (0)),
      ==, R_HASH_TABLE_OK);

  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (0),
        RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (1),
        RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (2),
        RUINT_TO_POINTER (22)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (3),
        RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (4),
        RUINT_TO_POINTER (22)), ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 5);

  r_assert_cmpint (r_hash_table_remove_all_values (ht, RUINT_TO_POINTER (0)),
      ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 5);

  r_assert_cmpint (r_hash_table_remove_all_values (ht, RUINT_TO_POINTER (42)),
      ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 2);

  r_assert_cmpint (r_hash_table_remove_all_values (ht, RUINT_TO_POINTER (22)),
      ==, R_HASH_TABLE_OK);
  r_assert_cmpuint (r_hash_table_size (ht), ==, 0);

  r_hash_table_unref (ht);
}
RTEST_END;

static void
sum_value_uints (rpointer key, rpointer value, rpointer user)
{
  ruint * sum = user;

  (void) key;
  *sum += RPOINTER_TO_UINT (value);
}

RTEST (rhashtable, foreach, RTEST_FAST)
{
  RHashTable * ht;
  ruint sum = 0;

  r_assert_cmpptr ((ht = r_hash_table_new (r_str_hash, r_str_equal)), !=, NULL);

  r_assert_cmpint (r_hash_table_insert (ht,
        "foobar", RUINT_TO_POINTER (8)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht,
        "foo", RUINT_TO_POINTER (42)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht,
        "bar", RUINT_TO_POINTER (16)), ==, R_HASH_TABLE_OK);

  r_hash_table_foreach (ht, sum_value_uints, &sum);
  r_assert_cmpuint (sum, ==, 8 + 42 + 16);

  r_assert_cmpint (r_hash_table_remove (ht, "foo"), ==, R_HASH_TABLE_OK);
  sum = 0;
  r_hash_table_foreach (ht, sum_value_uints, &sum);
  r_assert_cmpuint (sum, ==, 8 + 16);

  r_hash_table_unref (ht);
}
RTEST_END;


RTEST (rhashtable, lookup_absent_never_loops, RTEST_FAST)
{
  RHashTable * ht;
  rsize i;
  const rsize n = 1000;

  r_assert_cmpptr ((ht = r_hash_table_new (NULL, NULL)), !=, NULL);

  /* Insert many entries, crossing several resizes; after every insert look up
   * a key that was never inserted. Before the load-factor fix a fully
   * populated table had no empty bucket, so the open-addressing probe for an
   * absent key never terminated -- this test would hang. */
  for (i = 0; i < n; i++) {
    r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (i + 1),
          RUINT_TO_POINTER (i + 1)), ==, R_HASH_TABLE_OK);
    r_assert_cmpint (r_hash_table_contains (ht, RSIZE_TO_POINTER (n + i + 1)),
        ==, R_HASH_TABLE_NOT_FOUND);
    r_assert_cmpptr (r_hash_table_lookup (ht, RSIZE_TO_POINTER (n + i + 1)),
        ==, NULL);
  }

  r_assert_cmpuint (r_hash_table_size (ht), ==, n);
  /* Every inserted key still resolves (probe integrity across the resizes). */
  for (i = 0; i < n; i++)
    r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht,
            RSIZE_TO_POINTER (i + 1))), ==, i + 1);
  /* And keys never inserted are absent (and the lookups terminate). */
  for (i = 0; i < n; i++)
    r_assert_cmpint (r_hash_table_contains (ht, RSIZE_TO_POINTER (n + i + 1)),
        ==, R_HASH_TABLE_NOT_FOUND);

  r_hash_table_unref (ht);
}
RTEST_END;

RTEST (rhashtable, lookup_absent_str_keys, RTEST_FAST)
{
  RHashTable * ht;
  rsize i;
  const rsize n = 500;

  /* As above but with string keys: more collisions / longer probe chains
   * exercise the absent-key probe-termination path harder. */
  r_assert_cmpptr ((ht = r_hash_table_new_full (r_str_hash, r_str_equal,
          r_free, NULL)), !=, NULL);

  for (i = 0; i < n; i++) {
    rchar * absent = r_strprintf ("absent-%"RSIZE_FMT, i);
    r_assert_cmpint (r_hash_table_insert (ht,
          r_strprintf ("key-%"RSIZE_FMT, i), RUINT_TO_POINTER (i + 1)),
        ==, R_HASH_TABLE_OK);
    r_assert_cmpint (r_hash_table_contains (ht, absent), ==, R_HASH_TABLE_NOT_FOUND);
    r_free (absent);
  }

  r_assert_cmpuint (r_hash_table_size (ht), ==, n);
  for (i = 0; i < n; i++) {
    rchar * present = r_strprintf ("key-%"RSIZE_FMT, i);
    rchar * absent = r_strprintf ("absent-%"RSIZE_FMT, i);
    r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, present)), ==, i + 1);
    r_assert_cmpint (r_hash_table_contains (ht, absent), ==, R_HASH_TABLE_NOT_FOUND);
    r_free (present);
    r_free (absent);
  }

  r_hash_table_unref (ht);
}
RTEST_END;

/* A removal must not truncate the open-addressing probe chain of another key
 * that collided past it. Replays the exact insert/remove sequence (handle
 * values from a stranded pollset) that left a still-present key unfindable. */
RTEST (rhashtable, remove_preserves_probe_chain, RTEST_FAST)
{
  RHashTable * ht;
  static const rsize keys[8] = { 3, 1000, 1001, 1002, 1003, 1004, 1005, 1006 };
  rsize i;

  r_assert_cmpptr ((ht = r_hash_table_new (NULL, NULL)), !=, NULL);
  for (i = 0; i < 8; i++)
    r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (keys[i]),
          RUINT_TO_POINTER (keys[i])), ==, R_HASH_TABLE_OK);

  r_assert_cmpint (r_hash_table_remove (ht, RSIZE_TO_POINTER (1000)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_remove (ht, RSIZE_TO_POINTER (1002)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_remove (ht, RSIZE_TO_POINTER (1004)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_remove (ht, RSIZE_TO_POINTER (1006)), ==, R_HASH_TABLE_OK);

  r_assert_cmpuint (r_hash_table_size (ht), ==, 4);
  /* every key not removed must still resolve */
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, RSIZE_TO_POINTER (3))), ==, 3);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, RSIZE_TO_POINTER (1001))), ==, 1001);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, RSIZE_TO_POINTER (1003))), ==, 1003);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, RSIZE_TO_POINTER (1005))), ==, 1005);

  r_hash_table_unref (ht);
}
RTEST_END;

/* Minimal collision chain: with the default (identity) hash and the initial
 * 8-bucket table, keys 7/14/21/28 all start at bucket 0 (mod 7) and form one
 * probe chain. Removing a key in the middle must not make the keys probed past
 * it unfindable -- the deletion has to leave the chain traversable. */
RTEST (rhashtable, remove_middle_of_collision_chain, RTEST_FAST)
{
  RHashTable * ht;

  r_assert_cmpptr ((ht = r_hash_table_new (NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (7),  RUINT_TO_POINTER (7)),  ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (14), RUINT_TO_POINTER (14)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (21), RUINT_TO_POINTER (21)), ==, R_HASH_TABLE_OK);
  r_assert_cmpint (r_hash_table_insert (ht, RSIZE_TO_POINTER (28), RUINT_TO_POINTER (28)), ==, R_HASH_TABLE_OK);

  r_assert_cmpint (r_hash_table_remove (ht, RSIZE_TO_POINTER (14)), ==, R_HASH_TABLE_OK);

  /* 21 and 28 sit past 14's bucket on the probe chain -- still findable */
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, RSIZE_TO_POINTER (21))), ==, 21);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, RSIZE_TO_POINTER (28))), ==, 28);
  r_assert_cmpuint (RPOINTER_TO_UINT (r_hash_table_lookup (ht, RSIZE_TO_POINTER (7))),  ==, 7);
  r_assert_cmpint (r_hash_table_contains (ht, RSIZE_TO_POINTER (14)), ==, R_HASH_TABLE_NOT_FOUND);

  r_hash_table_unref (ht);
}
RTEST_END;
