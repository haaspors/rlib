#include <rlib/rlib.h>

RTEST (rdictionary, new, RTEST_FAST)
{
  RDictionary * dict;

  r_assert_cmpptr ((dict = r_dictionary_new ()), !=, NULL);

  r_assert_cmpuint (r_dictionary_size (dict), ==, 0);
  r_assert_cmpuint (r_dictionary_current_alloc_size (dict), >, 0);

  r_dictionary_unref (dict);
}
RTEST_END;

RTEST (rdictionary, insert, RTEST_FAST)
{
  RDictionary * dict;

  r_assert_cmpptr ((dict = r_dictionary_new ()), !=, NULL);
  r_assert_cmpuint (r_dictionary_size (dict), ==, 0);

  r_assert (r_dictionary_insert (dict, "foo", NULL));
  r_assert (r_dictionary_insert (dict, "bar", NULL));
  r_assert_cmpuint (r_dictionary_size (dict), ==, 2);

  r_assert (r_dictionary_insert (dict, "foo", NULL));
  r_assert (r_dictionary_insert (dict, "test", NULL));
  r_assert_cmpuint (r_dictionary_size (dict), ==, 3);

  r_dictionary_unref (dict);
}
RTEST_END;

RTEST (rdictionary, insert_1_remove, RTEST_FAST)
{
  RDictionary * dict;

  r_assert_cmpptr ((dict = r_dictionary_new ()), !=, NULL);

  r_assert (!r_dictionary_remove (dict, "foo"));

  r_assert_cmpuint (r_dictionary_size (dict), ==, 0);
  r_assert (r_dictionary_insert (dict, "foo", NULL));
  r_assert_cmpuint (r_dictionary_size (dict), ==, 1);

  r_assert (r_dictionary_remove (dict, "foo"));
  r_assert_cmpuint (r_dictionary_size (dict), ==, 0);

  r_dictionary_unref (dict);
}
RTEST_END;

RTEST (rdictionary, replace, RTEST_FAST)
{
  RDictionary * dict;
  RBuffer * buf, * repbuf;

  r_assert_cmpptr ((dict = r_dictionary_new_full (r_buffer_unref)), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((repbuf = r_buffer_new ()), !=, NULL);

  r_assert_cmpuint (r_dictionary_size (dict), ==, 0);

  r_assert (r_dictionary_insert (dict, "foo", buf));
  r_assert_cmpuint (r_dictionary_size (dict), ==, 1);

  r_assert (r_dictionary_insert (dict, "foo", repbuf));
  r_assert_cmpuint (r_dictionary_size (dict), ==, 1);

  r_dictionary_unref (dict);
}
RTEST_END;

static void
accum_uint (const rchar * key, rpointer value, rpointer user)
{
  (void) key;
  *((ruint *)user) += RPOINTER_TO_UINT (value);
}

RTEST (rdictionary, foreach, RTEST_FAST)
{
  RDictionary * dict;
  ruint sum = 0;

  r_assert_cmpptr ((dict = r_dictionary_new ()), !=, NULL);

  r_assert (r_dictionary_insert (dict, "foobar", RUINT_TO_POINTER (8)));
  r_assert (r_dictionary_insert (dict, "foo", RUINT_TO_POINTER (42)));
  r_assert (r_dictionary_insert (dict, "bar", RUINT_TO_POINTER (16)));

  r_dictionary_foreach (dict, accum_uint, &sum);
  r_assert_cmpuint (sum, ==, 8 + 42 + 16);

  r_assert (r_dictionary_remove (dict, "foo"));
  sum = 0;
  r_dictionary_foreach (dict, accum_uint, &sum);
  r_assert_cmpuint (sum, ==, 8 + 16);

  r_dictionary_unref (dict);
}
RTEST_END;

