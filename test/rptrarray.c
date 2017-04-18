#include <rlib/rlib.h>

RTEST (rptrarray, add, RTEST_FAST)
{
  RPtrArray * array;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_alloc_size (array), >, 0);

  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (0), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 1);
  r_assert_cmpuint (r_ptr_array_add (array,
          r_malloc (42), r_free), ==, 1);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2);

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, grow, RTEST_FAST)
{
  RPtrArray * array;
  rsize i, asize;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint ((asize = r_ptr_array_alloc_size (array)), >, 0);

  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);
  for (i = 0; i <= asize; i++)
    r_assert_cmpuint (r_ptr_array_add (array, r_malloc (42), r_free), ==, i);
  r_assert_cmpuint (r_ptr_array_size (array), ==, asize + 1);
  r_assert_cmpuint (r_ptr_array_alloc_size (array), ==, asize << 1);

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, init, RTEST_FAST)
{
  RPtrArray array = R_PTR_ARRAY_INIT;

  r_assert_cmpuint (r_ptr_array_alloc_size (&array), ==, 0);
  r_assert_cmpuint (r_ptr_array_size (&array), ==, 0);

  r_assert_cmpuint (r_ptr_array_add (&array,
          RUINT_TO_POINTER (0), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (&array,
          RUINT_TO_POINTER (42), NULL), ==, 1);
  r_assert_cmpuint (r_ptr_array_alloc_size (&array), >=, 4);
  r_assert_cmpuint (r_ptr_array_size (&array), ==, 2);

  r_ptr_array_clear (&array);
}
RTEST_END;

RTEST (rptrarray, new_sized, RTEST_FAST)
{
  RPtrArray * array;

  r_assert_cmpptr ((array = r_ptr_array_new_sized (4)), !=, NULL);
  r_assert_cmpuint (r_ptr_array_alloc_size (array), >=, 4);
  r_ptr_array_unref (array);

  r_assert_cmpptr ((array = r_ptr_array_new_sized (15)), !=, NULL);
  r_assert_cmpuint (r_ptr_array_alloc_size (array), ==, 16); /* power of 2 */
  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, get, RTEST_FAST)
{
  RPtrArray * array;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 2);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 3);

  r_assert_cmpptr (r_ptr_array_get (array, 42), ==, NULL);
  r_assert_cmpptr (r_ptr_array_get (array, 0), ==, RUINT_TO_POINTER (42));
  r_assert_cmpptr (r_ptr_array_get (array, 1), ==, RUINT_TO_POINTER (22));
  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, RUINT_TO_POINTER (32));

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, clear_idx, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpptr ((data = r_malloc (42)), !=, NULL);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  r_assert_cmpuint (r_ptr_array_add (array,
          data, r_free), ==, 2);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 4);

  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data);
  r_assert_cmpuint (r_ptr_array_clear_idx (array, 2), ==, 2);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 4);
  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, NULL);

  r_assert_cmpuint (r_ptr_array_clear_idx (array, 3), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 4);

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, clear_range, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data[4];
  rsize i;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  for (i = 0; i < R_N_ELEMENTS (data); i++) {
    r_assert_cmpptr ((data[i] = r_malloc (42)), !=, NULL);
    r_assert_cmpuint (r_ptr_array_add (array, data[i], r_free), ==, 2 + i);
  }

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 2 + R_N_ELEMENTS (data));
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2 + R_N_ELEMENTS (data) + 1);

  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data[0]);
  r_assert_cmpuint (r_ptr_array_clear_range (array, 2, 2), ==, 2);
  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, NULL);
  r_assert_cmpptr (r_ptr_array_get (array, 3), ==, NULL);
  r_assert_cmpptr (r_ptr_array_get (array, 4), ==, data[2]);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2 + R_N_ELEMENTS (data) + 1);

  r_assert_cmpuint (r_ptr_array_clear_range (array, 2, -1), ==, 5);

  r_assert_cmpuint (r_ptr_array_size (array), ==, 2 + R_N_ELEMENTS (data) + 1);

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, remove_idx, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpptr ((data = r_malloc (42)), !=, NULL);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  r_assert_cmpuint (r_ptr_array_add (array,
          data, r_free), ==, 2);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 4);

  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data);
  r_assert_cmpuint (r_ptr_array_remove_idx (array, 2), ==, 2);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 3);
  r_assert_cmpptr (r_ptr_array_get (array, 3), ==, NULL);
  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, RUINT_TO_POINTER (32));

  r_assert_cmpuint (r_ptr_array_remove_idx (array, 0), ==, 0);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2);
  r_assert_cmpptr (r_ptr_array_get (array, 0), ==, RUINT_TO_POINTER (22));
  r_assert_cmpptr (r_ptr_array_get (array, 1), ==, RUINT_TO_POINTER (32));

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, remove_idx_fast, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpptr ((data = r_malloc (42)), !=, NULL);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  r_assert_cmpuint (r_ptr_array_add (array,
          data, r_free), ==, 2);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 4);

  r_assert_cmpptr (r_ptr_array_get (array, 1), ==, RUINT_TO_POINTER (22));
  r_assert_cmpuint (r_ptr_array_remove_idx_fast (array, 1), ==, 1);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 3);
  r_assert_cmpptr (r_ptr_array_get (array, 3), ==, NULL);
  r_assert_cmpptr (r_ptr_array_get (array, 1), ==, RUINT_TO_POINTER (32));

  r_assert_cmpuint (r_ptr_array_remove_idx_fast (array, 0), ==, 0);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2);
  r_assert_cmpptr (r_ptr_array_get (array, 0), ==, data);
  r_assert_cmpptr (r_ptr_array_get (array, 1), ==, RUINT_TO_POINTER (32));

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, remove_idx_clear, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpptr ((data = r_malloc (42)), !=, NULL);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  r_assert_cmpuint (r_ptr_array_add (array,
          data, r_free), ==, 2);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 4);

  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data);
  r_assert_cmpuint (r_ptr_array_remove_idx_clear (array, 2), ==, 2);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 4);
  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, NULL);

  r_assert_cmpuint (r_ptr_array_remove_idx_clear (array, 3), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 3);

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, remove_range, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data[4];
  rsize i;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  for (i = 0; i < R_N_ELEMENTS (data); i++) {
    r_assert_cmpptr ((data[i] = r_malloc (42)), !=, NULL);
    r_assert_cmpuint (r_ptr_array_add (array, data[i], r_free), ==, 2 + i);
  }

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 2 + R_N_ELEMENTS (data));
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2 + R_N_ELEMENTS (data) + 1);

  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data[0]);
  r_assert_cmpuint (r_ptr_array_remove_range (array, 2, 2), ==, 2);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 5);
  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data[2]);
  r_assert_cmpptr (r_ptr_array_get (array, 3), ==, data[3]);

  r_assert_cmpuint (r_ptr_array_remove_range (array, 2, -1), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2);
  r_assert_cmpptr (r_ptr_array_get (array, 0), ==, RUINT_TO_POINTER (42));
  r_assert_cmpptr (r_ptr_array_get (array, 1), ==, RUINT_TO_POINTER (22));

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, remove_range_fast, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data[4];
  rsize i;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  for (i = 0; i < R_N_ELEMENTS (data); i++) {
    r_assert_cmpptr ((data[i] = r_malloc (42)), !=, NULL);
    r_assert_cmpuint (r_ptr_array_add (array, data[i], r_free), ==, 2 + i);
  }

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 2 + R_N_ELEMENTS (data));
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2 + R_N_ELEMENTS (data) + 1);

  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data[0]);
  r_assert_cmpuint (r_ptr_array_remove_range_fast (array, 2, 2), ==, 2);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 5);
  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data[3]);
  r_assert_cmpptr (r_ptr_array_get (array, 3), ==, RUINT_TO_POINTER (32));

  r_assert_cmpuint (r_ptr_array_remove_range_fast (array, 2, -1), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2);
  r_assert_cmpptr (r_ptr_array_get (array, 0), ==, RUINT_TO_POINTER (42));
  r_assert_cmpptr (r_ptr_array_get (array, 1), ==, RUINT_TO_POINTER (22));

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, remove_range_clear, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data[4];
  rsize i;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 1);
  for (i = 0; i < R_N_ELEMENTS (data); i++) {
    r_assert_cmpptr ((data[i] = r_malloc (42)), !=, NULL);
    r_assert_cmpuint (r_ptr_array_add (array, data[i], r_free), ==, 2 + i);
  }

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 2 + R_N_ELEMENTS (data));
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2 + R_N_ELEMENTS (data) + 1);

  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, data[0]);
  r_assert_cmpuint (r_ptr_array_remove_range_clear (array, 2, 2), ==, 2);
  r_assert_cmpptr (r_ptr_array_get (array, 2), ==, NULL);
  r_assert_cmpptr (r_ptr_array_get (array, 3), ==, NULL);
  r_assert_cmpptr (r_ptr_array_get (array, 4), ==, data[2]);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 2 + R_N_ELEMENTS (data) + 1);

  r_assert_cmpuint (r_ptr_array_remove_range_clear (array, 2, -1), ==, 5);

  r_assert_cmpuint (r_ptr_array_size (array), ==, 2);

  r_ptr_array_unref (array);
}
RTEST_END;

RTEST (rptrarray, find, RTEST_FAST)
{
  RPtrArray * array;
  rpointer data[4];
  rsize i;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_ptr_array_find (array, NULL), ==, R_PTR_ARRAY_INVALID_IDX);
  r_assert_cmpuint (r_ptr_array_find (array, RUINT_TO_POINTER (22)), ==, R_PTR_ARRAY_INVALID_IDX);

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 1);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 2);
  for (i = 0; i < R_N_ELEMENTS (data); i++) {
    r_assert_cmpptr ((data[i] = r_malloc (42)), !=, NULL);
    r_assert_cmpuint (r_ptr_array_add (array, data[i], r_free), ==, 3 + i);
  }
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 3 + R_N_ELEMENTS (data));
  r_assert_cmpuint (r_ptr_array_size (array), ==, 3 + R_N_ELEMENTS (data) + 1);

  r_assert_cmpuint (r_ptr_array_find (array, NULL), ==, R_PTR_ARRAY_INVALID_IDX);
  r_assert_cmpuint (r_ptr_array_find (array, RUINT_TO_POINTER (32)), ==, 1);
  r_assert_cmpuint (r_ptr_array_find_range (array, RUINT_TO_POINTER (32), 2, -1), ==, 3 + R_N_ELEMENTS (data));
  r_assert_cmpuint (r_ptr_array_find (array, data[1]), ==, 4);
  r_assert_cmpuint (r_ptr_array_find_range (array, data[1], 5, -1), ==, R_PTR_ARRAY_INVALID_IDX);

  r_ptr_array_unref (array);
}
RTEST_END;

static void
rptrarray_str_concat (rpointer data, rpointer user)
{
  RString * str = user;
  r_string_append_printf (str, "/%u", RPOINTER_TO_UINT (data));
}

RTEST (rptrarray, foreach, RTEST_FAST)
{
  RPtrArray * array;
  RString * str;
  rchar * tmp;

  r_assert_cmpptr ((array = r_ptr_array_new ()), !=, NULL);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 0);

  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (22), NULL), ==, 0);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 1);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (42), NULL), ==, 2);
  r_assert_cmpuint (r_ptr_array_add (array,
          RUINT_TO_POINTER (32), NULL), ==, 3);
  r_assert_cmpuint (r_ptr_array_size (array), ==, 4);

  r_assert_cmpptr ((str = r_string_new_sized (128)), !=, NULL);
  r_assert_cmpuint (r_ptr_array_foreach (array, rptrarray_str_concat, str), ==, 4);
  r_assert_cmpstr ((tmp = r_string_free_keep (str)), ==, "/22/32/42/32"); r_free (tmp);

  r_assert_cmpptr ((str = r_string_new_sized (128)), !=, NULL);
  r_assert_cmpuint (r_ptr_array_foreach_range (array, 1, 4, rptrarray_str_concat, str), ==, 0);
  r_assert_cmpuint (r_string_length (str), ==, 0);

  r_assert_cmpuint (r_ptr_array_foreach_range (array, 1, 2, rptrarray_str_concat, str), ==, 2);
  r_assert_cmpstr ((tmp = r_string_free_keep (str)), ==, "/32/42"); r_free (tmp);

  r_ptr_array_unref (array);
}
RTEST_END;

