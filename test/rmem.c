#include <rlib/rlib.h>

RTEST (rmem, set_vtable_validation, RTEST_FAST)
{
  /* r_mem_set_vtable must reject a NULL vtable or one with any NULL
   * callback -- installing it would crash the very next allocation. */
  RMemVTable bad = { NULL, NULL, NULL, NULL };
  rboolean was_default;

  was_default = r_mem_using_system_default ();
  r_assert (was_default);

  r_mem_set_vtable (NULL);
  r_assert (r_mem_using_system_default ());

  r_mem_set_vtable (&bad);
  r_assert (r_mem_using_system_default ());

  /* Single NULL callback: still rejected wholesale (no partial swap). */
  bad.malloc = malloc;
  bad.calloc = calloc;
  bad.realloc = NULL;
  bad.free = free;
  r_mem_set_vtable (&bad);
  r_assert (r_mem_using_system_default ());
}
RTEST_END;

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

RTEST (rmem, agg, RTEST_FAST)
{
  ruint8 foo[]    = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  ruint8 * p;
  rsize size;

  r_assert_cmpptr ((p = r_memdup_agg (&size, NULL)), ==, NULL);
  r_assert_cmpptr ((p = r_memdup_agg (&size, foo, (rsize)5, foo + 4, (rsize)5, NULL)), !=, NULL);
  r_assert_cmpuint (size, ==, 5 + 5);
  r_assert_cmpmem (p + 0, ==, foo, 5);
  r_assert_cmpmem (p + 5, ==, foo + 4, 5);
  r_free (p);
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
  r_assert_cmpptr (r_mem_scan_data (foo, sizeof (foo) - 1, data, sizeof (data)), ==, &foo[7]);
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
  r_assert_cmpuint (res->token[0].chunk.size, ==, sizeof (foo));
  r_assert_cmpptr (res->token[0].chunk.data, ==, &foo[0]);
  r_free (res);

  r_assert_cmpuint (r_mem_scan_pattern (foo, sizeof (foo), "??", &res), ==, R_MEM_SCAN_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 1);
  r_assert_cmpuint (res->token[0].chunk.size, ==, 1);
  r_assert_cmpptr (res->token[0].chunk.data, ==, &foo[0]);
  r_free (res);

  r_assert_cmpuint (r_mem_scan_pattern (foo, sizeof (foo), "00??*??*??07", &res), ==, R_MEM_SCAN_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 7);
  r_assert_cmpuint (res->token[0].chunk.size, ==, 1);
  r_assert_cmpuint (res->token[1].chunk.size, ==, 1);
  r_assert_cmpuint (res->token[2].chunk.size, ==, 0);
  r_assert_cmpuint (res->token[3].chunk.size, ==, 1);
  r_assert_cmpuint (res->token[2].chunk.data, >=, res->token[1].chunk.data);
  r_assert_cmpuint (res->token[3].chunk.data, >, res->token[1].chunk.data);
  r_assert_cmpuint (res->token[3].chunk.data, <, res->token[5].chunk.data);
  r_assert_cmpuint (res->token[4].chunk.data, <=, res->token[5].chunk.data);
  r_assert_cmpuint (res->token[4].chunk.size, ==, 0);
  r_assert_cmpuint (res->token[5].chunk.size, ==, 1);
  r_assert_cmpuint (res->token[6].chunk.size, ==, 1);
  r_free (res);
}
RTEST_END;

RTEST (rmem, scan_pattern_str, RTEST_FAST)
{
  RMemScanResult * res;
  static const rchar * reqline = "GET /api/ HTTP/1.1\r\n";

  r_assert_cmpuint (r_mem_scan_pattern (reqline, r_strlen (reqline),
        "*20*20*0D0A", &res), ==, R_MEM_SCAN_RESULT_OK);
  r_assert_cmpuint (res->tokens, ==, 6);
  r_assert_cmpptr (res->token[0].chunk.data, ==, &reqline[0]);
  r_assert_cmpuint (res->token[0].chunk.size, ==, 3);
  r_assert_cmpuint (res->token[1].chunk.size, ==, 1);
  r_assert_cmpptr (res->token[2].chunk.data, ==, &reqline[4]);
  r_assert_cmpuint (res->token[2].chunk.size, ==, 5);
  r_assert_cmpuint (res->token[3].chunk.size, ==, 1);
  r_assert_cmpptr (res->token[4].chunk.data, ==, &reqline[10]);
  r_assert_cmpuint (res->token[4].chunk.size, ==, 8);
  r_assert_cmpptr (res->token[5].chunk.data, ==, &reqline[18]);
  r_assert_cmpuint (res->token[5].chunk.size, ==, 2);
  r_free (res);
}
RTEST_END;

RTEST (rmem, memclear_secure, RTEST_FAST)
{
  /* Basic correctness for the secure-wipe primitive - it's the same
   * surface area as memset(0) but with a compiler barrier that
   * keeps the writes from being elided. The "actually goes through
   * the compiler barrier" property is invisible to a C-level test
   * (we'd have to inspect machine code), so this just confirms the
   * functional zeroing across a few interesting sizes plus the
   * NULL / zero-length edge cases. */
  static const rsize sizes[] = { 1, 7, 15, 16, 17, 33, 64, 256 };
  ruint8 buf[256];
  rsize i, j;

  for (j = 0; j < R_N_ELEMENTS (sizes); j++) {
    rsize n = sizes[j];
    for (i = 0; i < n; i++)
      buf[i] = (ruint8) (0xa5u ^ (i & 0xff));
    /* Sentinel byte one past the requested size; must NOT be wiped. */
    if (n < sizeof (buf))
      buf[n] = 0x77;

    r_memclear_secure (buf, n);

    for (i = 0; i < n; i++)
      r_assert_cmpuint (buf[i], ==, 0);
    if (n < sizeof (buf))
      r_assert_cmpuint (buf[n], ==, 0x77);
  }

  /* No-op on NULL / zero-length, no crash. */
  r_memclear_secure (NULL, 16);
  r_memclear_secure (NULL, 0);
  r_memclear_secure (buf, 0);
}
RTEST_END;

