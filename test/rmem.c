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

RTEST (rmem, scan_byte, RTEST_FAST)
{
  const ruint8 foo[]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

  r_assert_cmpptr (r_mem_scan_byte (NULL, 0, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_byte (foo, 0, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_byte (foo, sizeof (foo), 0), ==, &foo[0]);
  r_assert_cmpptr (r_mem_scan_byte (foo, sizeof (foo), 8), ==, &foo[8]);
  r_assert_cmpptr (r_mem_scan_byte (foo, sizeof (foo), 0xff), ==, NULL);
  r_assert_cmpptr (r_mem_scan_byte (foo, sizeof (foo) - 2, 8), ==, NULL);
}
RTEST_END;

RTEST (rmem, scan_byte_any, RTEST_FAST)
{
  const ruint8 foo[]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  const ruint8 any[]  = { 0xff, 0x0f, 0xda, 8 };

  r_assert_cmpptr (r_mem_scan_byte_any (NULL, 0, NULL, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_byte_any (foo, 0, NULL, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_byte_any (foo, 0, any, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_byte_any (foo, sizeof (foo), any, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_byte_any (foo, sizeof (foo), any, sizeof (any)), ==, &foo[8]);
  r_assert_cmpptr (r_mem_scan_byte_any (foo, sizeof (foo), any, sizeof (any) - 1), ==, NULL);
  r_assert_cmpptr (r_mem_scan_byte_any (foo, sizeof (foo) - 2, any, sizeof (any)), ==, NULL);
}
RTEST_END;

RTEST (rmem, scan_data, RTEST_FAST)
{
  const ruint8 foo[]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  const ruint8 data[]  = { 7, 8 };

  r_assert_cmpptr (r_mem_scan_data (NULL, 0, NULL, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_data (foo, 0, NULL, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_data (foo, 0, data, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_data (foo, sizeof (foo), data, 0), ==, NULL);
  r_assert_cmpptr (r_mem_scan_data (foo, sizeof (foo), data, sizeof (data)), ==, &foo[7]);
  r_assert_cmpptr (r_mem_scan_data (data, sizeof (data), foo, sizeof (foo)), ==, NULL);
  r_assert_cmpptr (r_mem_scan_data (foo, sizeof (foo), data + 1, sizeof (data) - 1), ==, &foo[8]);
  r_assert_cmpptr (r_mem_scan_data (foo, sizeof (foo) - 2, data, sizeof (data)), ==, NULL);
}
RTEST_END;

