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

RTEST (rmem, scan_simple_pattern, RTEST_FAST)
{
  const ruint8 foo[]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  rpointer end;

  r_assert_cmpptr (r_mem_scan_simple_pattern (NULL, 0, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, 0, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "*", NULL), ==, foo);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "*", &end), ==, foo);
  r_assert_cmpptr (end, ==, foo + sizeof (foo));
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "06", &end), ==, &foo[6]);
  r_assert_cmpptr (end, ==, &foo[7]);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "??06??", &end), ==, &foo[5]);
  r_assert_cmpptr (end, ==, &foo[8]);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "01*06??", &end), ==, &foo[1]);
  r_assert_cmpptr (end, ==, &foo[8]);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "??**??", &end), ==, foo);
  r_assert_cmpptr (end, ==, foo + sizeof (foo));
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "00??*??*??07", &end), ==, foo);
  r_assert_cmpptr (end, ==, &foo[8]);

  /* pattern errors */
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "666", NULL), ==, NULL);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "-06", NULL), ==, NULL);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "06???", NULL), ==, NULL);
  r_assert_cmpptr (r_mem_scan_simple_pattern (foo, sizeof (foo), "06??m?", NULL), ==, NULL);
}
RTEST_END;

RTEST (rmem, scan_pattern, RTEST_FAST)
{
  RMemScanResult * res;
  const ruint8 foo[]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

  r_assert_cmpuint (r_mem_scan_pattern (NULL, 0, NULL, NULL), ==, R_MEM_SCAN_RESULT_INVAL);
  r_assert_cmpuint (r_mem_scan_pattern (foo, 0, NULL, NULL), ==, R_MEM_SCAN_RESULT_INVAL);
  r_assert_cmpuint (r_mem_scan_pattern (foo, sizeof (foo), NULL, NULL), ==, R_MEM_SCAN_RESULT_INVAL);
  r_assert_cmpuint (r_mem_scan_pattern (foo, sizeof (foo), "*", NULL), ==, R_MEM_SCAN_RESULT_INVAL);

  r_assert_cmpuint (r_mem_scan_pattern (foo, sizeof (foo), "*", &res), ==, R_MEM_SCAN_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 1);
  r_assert_cmpuint (res->token[0].size, ==, sizeof (foo));
  r_assert_cmpptr (res->token[0].ptr_data, ==, &foo[0]);
  r_free (res);

  r_assert_cmpuint (r_mem_scan_pattern (foo, sizeof (foo), "??", &res), ==, R_MEM_SCAN_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 1);
  r_assert_cmpuint (res->token[0].size, ==, 1);
  r_assert_cmpptr (res->token[0].ptr_data, ==, &foo[0]);
  r_free (res);

  r_assert_cmpuint (r_mem_scan_pattern (foo, sizeof (foo), "00??*??*??07", &res), ==, R_MEM_SCAN_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 7);
  r_assert_cmpuint (res->token[0].size, ==, 1);
  r_assert_cmpuint (res->token[1].size, ==, 1);
  r_assert_cmpuint (res->token[2].size, ==, 0);
  r_assert_cmpuint (res->token[3].size, ==, 1);
  r_assert_cmpuint (res->token[2].ptr_data, >=, res->token[1].ptr_data);
  r_assert_cmpuint (res->token[3].ptr_data, >, res->token[1].ptr_data);
  r_assert_cmpuint (res->token[3].ptr_data, <, res->token[5].ptr_data);
  r_assert_cmpuint (res->token[4].ptr_data, <=, res->token[5].ptr_data);
  r_assert_cmpuint (res->token[4].size, ==, 0);
  r_assert_cmpuint (res->token[5].size, ==, 1);
  r_assert_cmpuint (res->token[6].size, ==, 1);
  r_free (res);

}
RTEST_END;

