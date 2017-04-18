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

