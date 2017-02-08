#include <rlib/rlib.h>

RTEST (rbuffer, new_empty, RTEST_FAST)
{
  RBuffer * buf;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 0);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 0);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 0);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 0);
  r_assert (!r_buffer_is_all_writable (buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, new_wrapped, RTEST_FAST)
{
  RBuffer * buf;
  rpointer data;

  r_assert_cmpptr ((buf = r_buffer_new_take (r_malloc (512), 512)), !=, NULL);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 512);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 0);
  r_assert (r_buffer_is_all_writable (buf));
  r_buffer_unref (buf);

  data = r_malloc (512);
  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_READONLY, data, 512,
          256, 64, data, r_free)), !=, NULL);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 64);
  r_assert (!r_buffer_is_all_writable (buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, new_dup, RTEST_FAST)
{
  RBuffer * buf;
  static const ruint8 testdata[] = {
    0x81, 0xca, 0x00, 0x05, 0xf3, 0xcb, 0x20, 0x01, 0x01, 0x0a, 0x6f, 0x75, 0x74, 0x43, 0x68, 0x61,
    0x81, 0xca, 0x00, 0x05, 0xf3, 0xcb, 0x20, 0x01, 0x01, 0x0a, 0x6f, 0x75, 0x74, 0x43, 0x68, 0x61,
  };

  r_assert_cmpptr ((buf = r_buffer_new_dup (testdata, sizeof (testdata))), !=, NULL);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, sizeof (testdata));
  r_assert_cmpuint (r_buffer_get_size (buf), ==, sizeof (testdata));
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 0);
  r_assert (r_buffer_is_all_writable (buf));

  r_assert_cmpint (r_buffer_memcmp (buf, 0, testdata, sizeof (testdata)), ==, 0);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, new_alloc, RTEST_FAST)
{
  RBuffer * buf;
  RMemAllocationParams params = { R_MEM_FLAG_NONE, 0xff, 64, 64 };

  r_assert_cmpptr ((buf = r_buffer_new_alloc (NULL, 512, &params)), !=, NULL);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512 + 64 + 64);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 512);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 64);
  r_assert (r_buffer_is_all_writable (buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, view, RTEST_FAST)
{
  RBuffer * buf, * view;

  r_assert_cmpptr ((buf = r_buffer_new_alloc (NULL, 512, NULL)), !=, NULL);
  r_assert_cmpuint (r_buffer_memset (buf, 0, 0, 1024), ==, 512);

  r_assert_cmpptr ((view = r_buffer_view (buf, 128, 256)), !=, NULL);
  r_assert_cmpint (r_buffer_cmp (buf, 128, view, 0, 256), ==, 0);

  r_assert_cmpuint (r_buffer_memset (buf, 0, 42, 1024), ==, 512);
  r_assert_cmpint (r_buffer_cmp (buf, 128, view, 0, 256), ==, 0);

  r_buffer_unref (view);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, copy, RTEST_FAST)
{
  RBuffer * buf, * copy;

  r_assert_cmpptr ((buf = r_buffer_new_alloc (NULL, 512, NULL)), !=, NULL);
  r_assert_cmpuint (r_buffer_memset (buf, 0, 0, 1024), ==, 512);

  r_assert_cmpptr ((copy = r_buffer_copy (buf, 128, 256)), !=, NULL);
  r_assert_cmpuint (r_buffer_memset (copy, 0, 0, 1024), ==, 256);
  r_assert_cmpint (r_buffer_cmp (buf, 128, copy, 0, 256), ==, 0);

  r_assert_cmpuint (r_buffer_memset (copy, 0, 42, 1024), ==, 256);
  r_assert_cmpint (r_buffer_cmp (buf, 128, copy, 0, 256), !=, 0);

  r_buffer_unref (copy);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_append, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (!r_buffer_mem_append (buf, NULL));

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 128);
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 2);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512 * 2);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 512);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 128);
  r_mem_unref (mem);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_prepend, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (!r_buffer_mem_prepend (buf, NULL));

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_prepend (buf, mem));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 128);
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_prepend (buf, mem));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 2);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512 * 2);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 512);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 0);
  r_mem_unref (mem);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_insert, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (!r_buffer_mem_insert (buf, NULL, 0));

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_insert (buf, mem, 1));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 128);
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_insert (buf, mem, 0));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 2);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512 * 2);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 256);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 128);
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_insert (buf, mem, 1));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 3);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512 * 3);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 256 + 512);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 128);
  r_mem_unref (mem);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_replace, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (!r_buffer_mem_replace (buf, 0, NULL));

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 2);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512 * 2);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 512);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 128);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (!r_buffer_mem_replace (buf, 2, mem));
  r_assert (r_buffer_mem_replace (buf, 0, mem));
  r_mem_unref (mem);

  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 2);
  r_assert_cmpuint (r_buffer_get_allocsize (buf), ==, 512 * 2);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 512 + 512);
  r_assert_cmpuint (r_buffer_get_offset (buf), ==, 0);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_replace_range, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (!r_buffer_mem_replace_range (buf, 0, 1, NULL));

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 5);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 2048);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (128), 128, 128, 0)), !=, NULL);
  r_assert (!r_buffer_mem_replace_range (buf, 2, 4, mem));
  r_assert (r_buffer_mem_replace_range (buf, 1, 3, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 3);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 128 + 512);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (128), 128, 128, 0)), !=, NULL);
  r_assert (r_buffer_mem_replace_all (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 128);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_peek, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((mem = r_buffer_mem_peek (buf, 0)), ==, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_buffer_mem_peek (buf, 2)), ==, NULL);

  r_assert_cmpptr ((mem = r_buffer_mem_peek (buf, 0)), !=, NULL);
  r_assert_cmpuint (mem->allocsize, ==, 512);
  r_assert_cmpuint (mem->size, ==, 256);
  r_assert_cmpuint (mem->offset, ==, 128);
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_buffer_mem_peek (buf, 1)), !=, NULL);
  r_assert_cmpuint (mem->allocsize, ==, 512);
  r_assert_cmpuint (mem->size, ==, 512);
  r_assert_cmpuint (mem->offset, ==, 0);
  r_mem_unref (mem);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_remove, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((mem = r_buffer_mem_remove (buf, 0)), ==, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_buffer_mem_remove (buf, 2)), ==, NULL);
  r_assert_cmpptr ((mem = r_buffer_mem_remove (buf, 0)), !=, NULL);
  r_assert_cmpuint (mem->allocsize, ==, 512);
  r_assert_cmpuint (mem->size, ==, 256);
  r_assert_cmpuint (mem->offset, ==, 128);
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_buffer_mem_remove (buf, 1)), ==, NULL);
  r_assert_cmpptr ((mem = r_buffer_mem_remove (buf, 0)), !=, NULL);
  r_assert_cmpuint (mem->allocsize, ==, 512);
  r_assert_cmpuint (mem->size, ==, 512);
  r_assert_cmpuint (mem->offset, ==, 0);
  r_mem_unref (mem);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_clear, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 0);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);

  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 2);
  r_buffer_mem_clear (buf);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 0);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, mem_find, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;
  ruint idx = 42, count = 42;
  rsize offset = RSIZE_MAX, size = RSIZE_MAX;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (!r_buffer_mem_find (buf, 0, 256, &idx, &count, &offset, &size));

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);

  r_assert (!r_buffer_mem_find (buf, 0, 2048+1, &idx, &count, &offset, &size));
  r_assert (r_buffer_mem_find (buf, 0, 256, NULL, NULL, NULL, NULL));

  r_assert (r_buffer_mem_find (buf, 0, 256, &idx, &count, &offset, &size));
  r_assert_cmpuint (idx, ==, 0);
  r_assert_cmpuint (count, ==, 1);
  r_assert_cmpuint (offset, ==, 0);
  r_assert_cmpuint (size, ==, 256);

  r_assert (r_buffer_mem_find (buf, 1, 256, &idx, &count, &offset, &size));
  r_assert_cmpuint (idx, ==, 0);
  r_assert_cmpuint (count, ==, 2);
  r_assert_cmpuint (offset, ==, 1); /* offset 1 into idx 0 */
  r_assert_cmpuint (size, ==, 1);   /* size 1 of idx 1 */

  r_assert (r_buffer_mem_find (buf, 256 + 42, 512, &idx, &count, &offset, &size));
  r_assert_cmpuint (idx, ==, 1);
  r_assert_cmpuint (count, ==, 2);
  r_assert_cmpuint (offset, ==, 42); /* offset 42 into idx 1 */
  r_assert_cmpuint (size, ==, 42); /* size 42 of idx 2 */

  r_assert (r_buffer_mem_find (buf, 0, -1, &idx, &count, &offset, &size));
  r_assert_cmpuint (idx, ==, 0);
  r_assert_cmpuint (count, ==, 4);
  r_assert_cmpuint (offset, ==, 0);
  r_assert_cmpuint (size, ==, 512);

  r_assert (r_buffer_mem_find (buf, 512, -1, &idx, &count, &offset, &size));
  r_assert_cmpuint (idx, ==, 1);
  r_assert_cmpuint (count, ==, 3);
  r_assert_cmpuint (offset, ==, 256);
  r_assert_cmpuint (size, ==, 512);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, append_mem_from_buffer, RTEST_FAST)
{
  RBuffer * buf1, * buf2;
  RMem * mem;

  r_assert_cmpptr ((buf1 = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((buf2 = r_buffer_new ()), !=, NULL);
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 0);
  r_assert_cmpuint (r_buffer_get_size (buf2), ==, 0);

  r_assert (r_buffer_append_mem_from_buffer (buf1, buf2));
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 0);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);

  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 0);
  r_assert (r_buffer_append_mem_from_buffer (buf1, buf2));
  r_buffer_unref (buf2);
  r_assert_cmpuint (r_buffer_mem_count (buf1), ==, 2);
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 768);

  r_buffer_unref (buf1);
}
RTEST_END;

RTEST (rbuffer, append_view, RTEST_FAST)
{
  RBuffer * buf1, * buf2;
  RMem * mem;

  r_assert_cmpptr ((buf1 = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((buf2 = r_buffer_new ()), !=, NULL);
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 0);
  r_assert_cmpuint (r_buffer_get_size (buf2), ==, 0);

  r_assert (r_buffer_append_view (buf1, buf2, 0, -1));
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 0);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);

  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 0);
  r_assert (r_buffer_append_view (buf1, buf2, 42, -1));
  r_assert_cmpuint (r_buffer_mem_count (buf1), ==, 3);
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 1280 - 42);

  r_buffer_mem_clear (buf1);
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 0);
  r_assert (r_buffer_append_view (buf1, buf2, 42, 512));
  r_assert_cmpuint (r_buffer_mem_count (buf1), ==, 2);
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 512);

  r_buffer_unref (buf2);
  r_buffer_unref (buf1);
}
RTEST_END;

RTEST (rbuffer, merge_take, RTEST_FAST)
{
  RBuffer * buf1, * buf2, * merged;
  RMem * mem;

  r_assert_cmpptr ((buf1 = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((buf2 = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf1, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf1, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf1, mem));
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);

  r_assert_cmpuint (r_buffer_mem_count (buf1), ==, 3);
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 1280);
  r_assert_cmpuint (r_buffer_mem_count (buf2), ==, 2);
  r_assert_cmpuint (r_buffer_get_size (buf2), ==, 768);

  r_assert_cmpptr ((merged = r_buffer_merge_take (buf1, buf2, NULL)), !=, NULL);
  r_assert_cmpuint (r_buffer_mem_count (merged), ==, 5);
  r_assert_cmpuint (r_buffer_get_size (merged), ==, 1280 + 768);

  r_buffer_unref (merged);
}
RTEST_END;

RTEST (rbuffer, resize, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (!r_buffer_resize (buf, 0, 256));

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);

  r_assert (!r_buffer_resize (buf, 1, 2048));

  r_assert (r_buffer_resize (buf, 768, 1024));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);
#if 0
#else
  r_assert_cmpptr ((mem = r_buffer_mem_peek (buf, 0)), !=, NULL);
  r_assert_cmpuint (mem->offset, ==, 512);
  r_assert_cmpuint (mem->size, ==, 0);
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_buffer_mem_peek (buf, 1)), !=, NULL);
  r_assert_cmpuint (mem->offset, ==, 256);
  r_assert_cmpuint (mem->size, ==, 256);
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_buffer_mem_peek (buf, 2)), !=, NULL);
  r_assert_cmpuint (mem->offset, ==, 0);
  r_assert_cmpuint (mem->size, ==, 512);
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_buffer_mem_peek (buf, 3)), !=, NULL);
  r_assert_cmpuint (mem->offset, ==, 0);
  r_assert_cmpuint (mem->size, ==, 256);
  r_mem_unref (mem);
#endif

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, shrink, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (!r_buffer_shrink (buf, 256));
  r_assert (r_buffer_shrink (buf, 0));

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);

  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 2);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 512);
  r_assert (!r_buffer_shrink (buf, 1024));
  r_assert (r_buffer_shrink (buf, 512));
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 256);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 2);

  r_assert (r_buffer_shrink (buf, 128));
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 128);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);

  r_assert (!r_buffer_shrink (buf, 512));
  r_assert (r_buffer_shrink (buf, 0));
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 0);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 0);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, map, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, r_malloc0 (512), 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, r_malloc0 (512), 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);

  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, ==, 3 * 512 + 256);
  r_assert (r_buffer_unmap (buf, &info));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);

  r_assert_cmpptr ((mem = r_buffer_mem_remove (buf, 0)), !=, NULL);
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 3);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, ==, 3 * 512);
  r_assert (r_buffer_unmap (buf, &info));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 1);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, map_range, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint8 * data[4] = { r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512) };

  r_memset (data[0], 0x22, 512);
  r_memset (data[1], 0x32, 512);
  r_memset (data[2], 0x42, 512);
  r_memset (data[3], 0xff, 512);

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[0], 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[1], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[2], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[3], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);

  r_assert (!r_buffer_map_mem_range (buf, 2, 3, &info, R_MEM_MAP_READ));
  r_assert (r_buffer_map_mem_range (buf, 1, 2, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, ==, 1024);
  r_assert_cmpptr (info.data, !=, data[1]);
  r_assert_cmpmem (info.data, ==, data[1], 512);
  r_assert_cmpmem (info.data + 512, ==, data[2], 512);
  r_assert (r_buffer_unmap (buf, &info));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);

  r_assert (r_buffer_map_mem_range (buf, 1, 2, &info, R_MEM_MAP_READ));
  r_assert (r_buffer_unmap (buf, &info));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, map_range_all, RTEST_FAST)
{
  RBuffer * buf;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint8 * data;

  r_assert_cmpptr ((data = r_malloc0 (1024)), !=, NULL);
  r_memset (data + 256, 0x22, 512);
  r_assert_cmpptr ((buf = r_buffer_new_take (data, 1024)), !=, NULL);

  r_assert (r_buffer_map_mem_range (buf, 0, 1, &info, R_MEM_MAP_READ));
  r_assert (r_buffer_unmap (buf, &info));

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, map_bytes, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint8 * data[4] = { r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512) };

  r_memset (data[0], 0x22, 512);
  r_memset (data[1], 0x32, 512);
  r_memset (data[2], 0x42, 512);
  r_memset (data[3], 0xff, 512);

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[0], 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[1], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[2], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[3], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 3 * 512 + 256);

  r_assert (r_buffer_map_byte_range (buf, 512, 512, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, ==, 512);
  r_assert_cmpmem (info.data, ==, data[1] + 256, 256);
  r_assert_cmpmem (info.data + 256, ==, data[2], 256);
  r_assert (r_buffer_unmap (buf, &info));
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, cmp, RTEST_FAST)
{
  RBuffer * buf1, * buf2;
  RMem * mem;
  ruint8 * data[] = {
    r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512),
    r_malloc0 (512), r_malloc0 (512),
  };

  r_memset (data[0], 0x22, 512);
  r_memset (data[1], 0x32, 512);
  r_memset (data[2], 0x42, 512);
  r_memset (data[3], 0xff, 512);
  r_memset (data[4], 0x22, 512);
  r_memset (data[5], 0xff, 512);

  r_assert_cmpptr ((buf1 = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((buf2 = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[0], 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf1, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[1], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf1, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[2], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf1, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[3], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf1, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf1), ==, 4);
  r_assert_cmpuint (r_buffer_get_size (buf1), ==, 3 * 512 + 256);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[4], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[5], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf2, mem));
  r_mem_unref (mem);

  r_assert_cmpint (r_buffer_cmp (buf1, 0, NULL, 0, 256), >, 0);
  r_assert_cmpint (r_buffer_cmp (NULL, 0, buf2, 0, 256), <, 0);
  r_assert_cmpint (r_buffer_cmp (buf1, 0, buf2, 0, 256), ==, 0);
  r_assert_cmpint (r_buffer_cmp (buf1, 512, buf2, 0, 512), !=, 0);
  r_assert_cmpint (r_buffer_cmp (buf1, 2 * 512 + 256, buf2, 512, 512), ==, 0);

  r_buffer_unref (buf1);
  r_buffer_unref (buf2);
}
RTEST_END;

RTEST (rbuffer, memcmp, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;
  ruint8 * data[4] = { r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512) };
  ruint8 * test = r_malloc (2048);

  r_memset (data[0], 0x22, 512);
  r_memset (data[1], 0x32, 512);
  r_memset (data[2], 0x42, 512);
  r_memset (data[3], 0xff, 512);

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[0], 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[1], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[2], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[3], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 3 * 512 + 256);

  r_assert_cmpint (r_buffer_memcmp (NULL, 0, NULL, 0), <, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 0, NULL, 0), >, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 0, data[0], 0), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 0, data[0], 256), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 0, data[1], 256), <, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 256, data[1], 512), ==, 0);

  r_memset (test +    0, 0x22, 256);
  r_memset (test +  256, 0x32, 512);
  r_memset (test +  768, 0x42, 512);
  r_memset (test + 1280, 0xff, 512);
  r_assert_cmpint (r_buffer_memcmp (buf, 256, test, 1792), >, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 0, test, 1792), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 128, test, 512), >, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 768, test, 512), >, 0);

  r_free (test);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, memset, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;
  ruint8 * data[4] = { r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512) };
  ruint8 * test = r_malloc0 (512);

  r_memset (data[0], 0x22, 512);
  r_memset (data[1], 0x32, 512);
  r_memset (data[2], 0x42, 512);
  r_memset (data[3], 0xff, 512);

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[0], 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[1], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[2], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[3], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 3 * 512 + 256);

  r_assert_cmpuint (r_buffer_memset (buf, 0, 0xff, 512), ==, 0);
  r_assert_cmpmem (data[1], !=, test, 512);
  r_assert_cmpuint (r_buffer_memset (buf, 256, 0x00, 512), ==, 512);
  r_assert_cmpmem (data[1], ==, test, 512);

  r_assert_cmpuint (r_buffer_memset (buf, 1024, 0x00, 1024), ==, 768);
  r_assert_cmpmem (data[3], ==, test, 512);

  r_free (test);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, fill, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;
  ruint8 * data[4] = { r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512) };
  ruint8 fill[512];

  r_memset (data[0], 0x22, 512);
  r_memset (data[1], 0x32, 512);
  r_memset (data[2], 0x42, 512);
  r_memset (data[3], 0xff, 512);

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[3], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[0], 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[1], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[2], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 3 * 512 + 256);

  r_memset (fill, 0xcc, 512);
  r_assert_cmpuint (r_buffer_fill (buf, 0, NULL, 512), ==, 0);
  r_assert_cmpuint (r_buffer_fill (buf, 0, fill, 0), ==, 0);
  r_assert_cmpuint (r_buffer_fill (buf, 0, fill, 512), ==, 0);
  r_assert_cmpuint (r_buffer_fill (buf, 512, fill, 512), ==, 512);
  r_assert_cmpmem (data[0] + 128, ==, &fill[  0], 256);
  r_assert_cmpmem (data[1],       ==, &fill[256], 256);

  r_assert_cmpuint (r_buffer_fill (buf, 1280, fill, 512), ==, 512);
  r_assert_cmpmem (data[2],       ==, fill, 512);
  r_memset (fill, 0xdd, 512);
  r_assert_cmpuint (r_buffer_fill (buf, 1536, fill, 512), ==, 256);
  r_memset (fill, 0xcc, 256);
  r_assert_cmpmem (data[2],       ==, fill, 512);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, extract, RTEST_FAST)
{
  RBuffer * buf;
  RMem * mem;
  ruint8 * data[4] = { r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512) };
  ruint8 extract[512];

  r_memset (data[0], 0x22, 512);
  r_memset (data[1], 0x32, 512);
  r_memset (data[2], 0x42, 512);
  r_memset (data[3], 0xff, 512);

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[0], 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[1], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[2], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[3], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 3 * 512 + 256);

  r_assert_cmpuint (r_buffer_extract (buf, 0, NULL, 512), ==, 0);
  r_assert_cmpuint (r_buffer_extract (buf, 0, extract, 0), ==, 0);
  r_assert_cmpuint (r_buffer_extract (buf, 0, extract, 512), ==, 512);
  r_assert_cmpmem (&extract[  0], ==, data[0], 256);
  r_assert_cmpmem (&extract[256], ==, data[1], 256);

  r_assert_cmpuint (r_buffer_extract (buf, 256, extract, 512), ==, 512);
  r_assert_cmpmem (&extract[  0], ==, data[1], 512);
  r_assert_cmpuint (r_buffer_extract (buf, 1280, extract, 512), ==, 512);
  r_assert_cmpmem (&extract[  0], ==, data[3], 512);
  r_assert_cmpuint (r_buffer_extract (buf, 1536, extract, 512), ==, 256);

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rbuffer, replace_byte_range, RTEST_FAST)
{
  RBuffer * buf, * from, * out;
  RMem * mem;
  ruint8 * data[5] = { r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512), r_malloc0 (512) };

  r_memset (data[0], 0x22, 512);
  r_memset (data[1], 0x32, 512);
  r_memset (data[2], 0x42, 512);
  r_memset (data[3], 0xff, 512);
  r_memset (data[4], 0x11, 512);

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_READONLY, data[0], 512, 256, 128)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[1], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[2], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpptr ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data[3], 512, 512, 0)), !=, NULL);
  r_assert (r_buffer_mem_append (buf, mem));
  r_mem_unref (mem);
  r_assert_cmpuint (r_buffer_mem_count (buf), ==, 4);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 256 + 3 * 512);

  r_assert_cmpint (r_buffer_memcmp (buf, 0, data[0], 256), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 256, data[1], 512), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 768, data[2], 512), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (buf, 1280, data[3], 512), ==, 0);

  r_assert_cmpptr ((from = r_buffer_new_take (data[4], 512)), !=, NULL);

  r_assert_cmpptr ((out = r_buffer_replace_byte_range (buf, 512, 512, from)), !=, NULL);
  r_buffer_unref (from);
  r_buffer_unref (buf);

  r_assert_cmpuint (r_buffer_get_size (out), ==, 256 + 256 + 512 + 256 + 512);
  r_assert_cmpint (r_buffer_memcmp (out, 0, data[0], 256), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (out, 256, data[1], 256), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (out, 512, data[4], 512), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (out, 1024, data[2], 256), ==, 0);
  r_assert_cmpint (r_buffer_memcmp (out, 1280, data[3], 512), ==, 0);

  r_buffer_unref (out);
}
RTEST_END;

