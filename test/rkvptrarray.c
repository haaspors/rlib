#include <rlib/rlib.h>

RTEST (rkvptrarray, new_sized, RTEST_FAST)
{
  RKVPtrArray * array;

  r_assert_cmpptr ((array = r_kv_ptr_array_new_sized (4, NULL)), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_alloc_size (array), >=, 4);
  r_kv_ptr_array_unref (array);

  r_assert_cmpptr ((array = r_kv_ptr_array_new_sized (15, NULL)), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_alloc_size (array), ==, 16); /* power of 2 */
  r_kv_ptr_array_unref (array);
}
RTEST_END;

RTEST (rkvptrarray, add, RTEST_FAST)
{
  RKVPtrArray * array;

  r_assert_cmpptr ((array = r_kv_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_alloc_size (array), >, 0);

  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          RUINT_TO_POINTER (0), NULL, RUINT_TO_POINTER (0), NULL), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          RUINT_TO_POINTER (0), NULL, r_malloc (42), r_free), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 2);

  r_kv_ptr_array_unref (array);
}
RTEST_END;

RTEST (rkvptrarray, grow, RTEST_FAST)
{
  RKVPtrArray * array;
  rsize i, asize;

  r_assert_cmpptr ((array = r_kv_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint ((asize = r_kv_ptr_array_alloc_size (array)), >, 0);

  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);
  for (i = 0; i <= asize; i++)
    r_assert_cmpuint (r_kv_ptr_array_add (array,
          RUINT_TO_POINTER (0), NULL, r_malloc (42), r_free), ==, i);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, asize + 1);
  r_assert_cmpuint (r_kv_ptr_array_alloc_size (array), ==, asize << 1);

  r_kv_ptr_array_unref (array);
}
RTEST_END;

RTEST (rkvptrarray, init_and_grow, RTEST_FAST)
{
  RKVPtrArray array = R_KV_PTR_ARRAY_INIT;

  r_assert_cmpuint (r_kv_ptr_array_alloc_size (&array), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_size (&array), ==, 0);

  r_assert_cmpuint (r_kv_ptr_array_add (&array,
          RUINT_TO_POINTER (0), NULL, RUINT_TO_POINTER (0), NULL), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_add (&array,
          RUINT_TO_POINTER (42), NULL, RUINT_TO_POINTER (42), NULL), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_alloc_size (&array), >=, 4);
  r_assert_cmpuint (r_kv_ptr_array_size (&array), ==, 2);

  r_kv_ptr_array_clear (&array);
}
RTEST_END;

RTEST (rkvptrarray, remove_idx, RTEST_FAST)
{
  RKVPtrArray * array;
  rpointer data;

  r_assert_cmpptr ((array = r_kv_ptr_array_new_str ()), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);

  r_assert_cmpptr ((data = r_malloc (42)), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "bar", NULL, RUINT_TO_POINTER (22), NULL), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foobar", NULL, data, r_free), ==, 2);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "test", NULL, RUINT_TO_POINTER (32), NULL), ==, 3);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 4);

  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 2), ==, data);
  r_assert_cmpuint (r_kv_ptr_array_remove_idx (array, 2), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 3);
  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 3), ==, NULL);
  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 2), ==, RUINT_TO_POINTER (32));

  r_assert_cmpuint (r_kv_ptr_array_remove_idx (array, 0), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 2);
  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 0), ==, RUINT_TO_POINTER (22));
  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 1), ==, RUINT_TO_POINTER (32));

  r_kv_ptr_array_unref (array);
}
RTEST_END;

RTEST (rkvptrarray, remove_range, RTEST_FAST)
{
  RKVPtrArray * array;
  rpointer data[4];
  rsize i;

  r_assert_cmpptr ((array = r_kv_ptr_array_new_str ()), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "bar", NULL, RUINT_TO_POINTER (22), NULL), ==, 1);
  for (i = 0; i < R_N_ELEMENTS (data); i++) {
    r_assert_cmpptr ((data[i] = r_malloc (42)), !=, NULL);
    r_assert_cmpuint (r_kv_ptr_array_add (array, "test", NULL, data[i], r_free), ==, 2 + i);
  }

  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (32), NULL), ==, 2 + R_N_ELEMENTS (data));
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 2 + R_N_ELEMENTS (data) + 1);

  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 2), ==, data[0]);
  r_assert_cmpuint (r_kv_ptr_array_remove_range (array, 2, 2), ==, 2);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 5);
  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 2), ==, data[2]);
  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 3), ==, data[3]);

  r_assert_cmpuint (r_kv_ptr_array_remove_range (array, 2, -1), ==, 3);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 2);
  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 0), ==, RUINT_TO_POINTER (42));
  r_assert_cmpptr (r_kv_ptr_array_get_val (array, 1), ==, RUINT_TO_POINTER (22));

  r_kv_ptr_array_unref (array);
}
RTEST_END;

RTEST (rkvptrarray, remove_all, RTEST_FAST)
{
  RKVPtrArray * array;

  r_assert_cmpptr ((array = r_kv_ptr_array_new_str ()), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "bar", NULL, RUINT_TO_POINTER (22), NULL), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 2);

  r_kv_ptr_array_remove_all (array);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);
  r_kv_ptr_array_unref (array);
}
RTEST_END;

RTEST (rkvptrarray, remove_key_first, RTEST_FAST)
{
  RKVPtrArray * array;

  r_assert_cmpptr ((array = r_kv_ptr_array_new_str ()), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "bar", NULL, RUINT_TO_POINTER (22), NULL), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 2);

  r_assert_cmpuint (r_kv_ptr_array_remove_key_first (array, "foobar"), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_remove_key_first (array, "foo"), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 1);

  r_assert_cmpuint (r_kv_ptr_array_remove_key_first (array, "bar"), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);
  r_kv_ptr_array_unref (array);
}
RTEST_END;

RTEST (rkvptrarray, remove_key_all, RTEST_FAST)
{
  RKVPtrArray * array;

  r_assert_cmpptr ((array = r_kv_ptr_array_new_str ()), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (32), NULL), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "bar", NULL, RUINT_TO_POINTER (22), NULL), ==, 2);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (22), NULL), ==, 3);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 4);

  r_assert_cmpuint (r_kv_ptr_array_remove_key_all (array, "foobar"), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_remove_key_all (array, "foo"), ==, 3);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 1);

  r_kv_ptr_array_unref (array);
}
RTEST_END;

static void
rkvptrarray_str_concat (rpointer key, rpointer val, rpointer user)
{
  RString * str = user;
  rchar * strkey = key;
  r_string_append_printf (str, "/%s:%u", strkey, RPOINTER_TO_UINT (val));
}

RTEST (rkvptrarray, foreach, RTEST_FAST)
{
  RKVPtrArray * array;
  RString * str;
  rchar * tmp;

  r_assert_cmpptr ((array = r_kv_ptr_array_new_str ()), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foo", NULL, RUINT_TO_POINTER (22), NULL), ==, 0);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "bar", NULL, RUINT_TO_POINTER (32), NULL), ==, 1);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "foobar", NULL, RUINT_TO_POINTER (42), NULL), ==, 2);
  r_assert_cmpuint (r_kv_ptr_array_add (array,
          "test", NULL, RUINT_TO_POINTER (32), NULL), ==, 3);
  r_assert_cmpuint (r_kv_ptr_array_size (array), ==, 4);

  r_assert_cmpptr ((str = r_string_new_sized (128)), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_foreach (array, rkvptrarray_str_concat, str), ==, 4);
  r_assert_cmpstr ((tmp = r_string_free_keep (str)), ==, "/foo:22/bar:32/foobar:42/test:32"); r_free (tmp);

  r_assert_cmpptr ((str = r_string_new_sized (128)), !=, NULL);
  r_assert_cmpuint (r_kv_ptr_array_foreach_range (array, 1, 4, rkvptrarray_str_concat, str), ==, 0);
  r_assert_cmpuint (r_string_length (str), ==, 0);

  r_assert_cmpuint (r_kv_ptr_array_foreach_range (array, 1, 2, rkvptrarray_str_concat, str), ==, 2);
  r_assert_cmpstr ((tmp = r_string_free_keep (str)), ==, "/bar:32/foobar:42"); r_free (tmp);

  r_kv_ptr_array_unref (array);
}
RTEST_END;

