#include <rlib/rlib.h>

RTEST (rmem, cmp, RTEST_FAST)
{
  ruint8 foo[]    = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  ruint8 bar[]    = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  ruint8 badger[] = { 0, 1, 2, 3, 4, 5, 9, 8, 7, 6 };
  const rsize size = sizeof (foo);

  r_assert_cmpint (r_memcmp (foo,   bar,    size), ==, 0);
  r_assert_cmpint (r_memcmp (foo,   badger, size),  <, 0);
  r_assert_cmpint (r_memcmp (NULL,  foo,    size),  <, 0);
  r_assert_cmpint (r_memcmp (foo,   NULL,   size),  >, 0);
  r_assert_cmpint (r_memcmp (NULL,  NULL,   size), ==, 0);
}
RTEST_END;

RTEST (rmem, set, RTEST_FAST)
{
  ruint8 data[1024];

  r_memclear (data, 1024);
  r_assert_cmpuint (data[0],      ==,  0);
  r_assert_cmpuint (data[1024-1], ==,  0);

  r_memset (data, 42, 512);
  r_assert_cmpuint (data[0],      ==, 42);
  r_assert_cmpuint (data[512-1],  ==, 42);
  r_assert_cmpuint (data[512],    ==,  0);
}
RTEST_END;

RTEST (rmem, cpy, RTEST_FAST)
{
  ruint8 foo[]    = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  ruint8 dst[sizeof (foo)];
  r_memclear (dst, sizeof (dst));

  r_assert_cmpptr (r_memcpy (NULL, NULL, 42), ==, NULL);
  r_assert_cmpptr (r_memcpy (NULL,  foo, 42), ==, NULL);
  r_assert_cmpptr (r_memcpy ( dst, NULL, 42), ==, NULL);

  r_assert_cmpptr (r_memcpy (dst, foo, 0), ==, dst);
  r_assert_cmpmem (foo, !=, dst, sizeof (foo));
  r_assert_cmpptr (r_memcpy (dst, foo, sizeof (foo)), ==, dst);
  r_assert_cmpmem (foo, ==, dst, sizeof (foo));
}
RTEST_END;

RTEST (rmem, dup, RTEST_FAST)
{
  ruint8 foo[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  ruint8 * bar;

  r_assert_cmpptr (r_memdup (NULL, 42), ==, NULL);
  r_assert_cmpptr (r_memdup (foo, 0), ==, NULL);
  r_assert_cmpptr ((bar = r_memdup (foo, sizeof (foo))), !=, NULL);
  r_assert_cmpmem (foo, ==, bar, sizeof (foo));
  r_free (bar);
}
RTEST_END;

RTEST (rmem, move, RTEST_FAST)
{
  ruint8 foo[]    = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  ruint8 * dup = r_memdup (foo, sizeof (foo));

  r_assert_cmpptr (r_memmove (NULL, NULL, 42), ==, NULL);
  r_assert_cmpptr (r_memmove (NULL,  foo, 42), ==, NULL);
  r_assert_cmpptr (r_memmove ( foo, NULL, 42), ==, NULL);

  r_assert_cmpptr (r_memmove (foo, &foo[5], 0), ==, foo);
  r_assert_cmpmem (foo, ==, dup, sizeof (foo));
  r_assert_cmpptr (r_memmove (foo, &foo[5], 5), ==, foo);
  r_assert_cmpmem (foo, !=, dup, sizeof (foo));
  r_assert_cmpmem (&foo[0], ==, &foo[5], 5);
  r_free (dup);
}
RTEST_END;

