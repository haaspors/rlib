#include <rlib/rlib.h>

RTEST (rmemallocator, default, RTEST_FAST)
{
  RMemAllocator * a;

  r_assert_cmpptr ((a = r_mem_allocator_default ()), !=, NULL);
  r_assert_cmpstr (a->mem_type, ==, R_MEM_ALLOCATOR_SYSTEM);

  r_mem_allocator_unref (a);
}
RTEST_END;

RTEST (rmemallocator, alloc, RTEST_FAST)
{
  RMemAllocator * a;
  RMem * mem;

  r_assert_cmpptr ((a = r_mem_allocator_default ()), !=, NULL);

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (a, 0, 1024, 16, 16, 0x0f)), !=, NULL);
  r_assert (!r_mem_is_zero_prefixed (mem));
  r_assert (!r_mem_is_zero_padded (mem));
  r_assert (r_mem_is_writable (mem));
  r_assert (!r_mem_is_readonly (mem));
  r_assert_cmpuint (mem->allocsize, >=, 1024 + 16 + 16);
  r_assert_cmpuint (mem->size, ==, 1024);
  r_assert_cmpuint (mem->offset, ==, 16);
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (a,
          R_MEM_FLAG_ZERO_PREFIXED | R_MEM_FLAG_ZERO_PADDED,
          1024, 16, 16, 0x0f)), !=, NULL);
  r_assert (r_mem_is_zero_prefixed (mem));
  r_assert (r_mem_is_zero_padded (mem));
  r_assert (r_mem_is_writable (mem));
  r_assert (!r_mem_is_readonly (mem));
  r_assert_cmpuint (mem->allocsize, >=, 1024 + 16 + 16);
  r_assert_cmpuint (mem->size, ==, 1024);
  r_assert_cmpuint (mem->offset, ==, 16);
  r_mem_unref (mem);

  r_mem_allocator_unref (a);
}
RTEST_END;

RTEST (rmem, resize, RTEST_FAST)
{
  RMem * mem;

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (NULL, 0, 1024, 64, 64, 0xff)), !=, NULL);
  r_assert_cmpuint (mem->size, ==, 1024);
  r_assert_cmpuint (mem->offset, ==, 64);

  r_assert (!r_mem_resize (mem, 2048, 42));
  r_assert (!r_mem_resize (mem, mem->allocsize, 1));
  r_assert (!r_mem_resize (mem, 0, mem->allocsize + 1));

  r_assert (r_mem_resize (mem, 128, 512));
  r_assert_cmpuint (mem->size, ==, 512);
  r_assert_cmpuint (mem->offset, ==, 128);

  r_assert (r_mem_resize (mem, 0, 1024));
  r_assert_cmpuint (mem->size, ==, 1024);
  r_assert_cmpuint (mem->offset, ==, 0);

  r_assert (r_mem_resize (mem, 0, mem->allocsize));
  r_assert_cmpuint (mem->size, ==, mem->allocsize);
  r_assert_cmpuint (mem->offset, ==, 0);

  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (NULL,
          R_MEM_FLAG_ZERO_PREFIXED | R_MEM_FLAG_ZERO_PADDED,
          512, 256, 256, 0xff)), !=, NULL);
  r_assert_cmpuint (mem->size, ==, 512);
  r_assert_cmpuint (mem->offset, ==, 256);
  r_assert (r_mem_is_zero_prefixed (mem));
  r_assert (r_mem_is_zero_padded (mem));

  /* This should still guarantee zero prefix/padding ... */
  r_assert (r_mem_resize (mem, 0, 768));
  r_assert (r_mem_is_zero_prefixed (mem));
  r_assert (r_mem_is_zero_padded (mem));

  /* ... and this will clear zero prefix ... */
  r_assert (r_mem_resize (mem, 256, 512));
  r_assert (!r_mem_is_zero_prefixed (mem));
  r_assert (r_mem_is_zero_padded (mem));

  /* ... while this will clear padding as well */
  r_assert (r_mem_resize (mem, 256, 256));
  r_assert (!r_mem_is_zero_prefixed (mem));
  r_assert (!r_mem_is_zero_padded (mem));

  r_mem_unref (mem);
}
RTEST_END;

RTEST (rmem, map, RTEST_FAST)
{
  RMem * mem;
  RMemMapInfo info;
  ruint8 * zero256 = r_alloca0 (256);

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (NULL, 0, 1024, 16, 16, 0xff)), !=, NULL);
  r_assert (r_mem_map (mem, &info, R_MEM_MAP_READ));
  r_assert_cmpint (info.flags, ==, R_MEM_MAP_READ);
  r_assert_cmpptr (info.mem, ==, mem);
  r_assert_cmpuint (info.size, ==, 1024);
  r_assert_cmpuint (info.allocsize, ==, 1024 + 16 + 16);
  r_assert_cmpuint ((RPOINTER_TO_SIZE (info.data) - mem->offset) & 0xff, ==, 0);
  r_assert (r_mem_unmap (mem, &info));
  r_mem_unref (mem);

  r_memclear (&info, sizeof (RMemMapInfo));
  r_assert_cmpptr ((mem = r_mem_allocator_alloc (NULL, R_MEM_FLAG_READONLY,
          512, 0, 16, 0xff)), !=, NULL);
  r_assert (!r_mem_map (mem, &info, R_MEM_MAP_WRITE));
  r_assert (!r_mem_map (mem, &info, R_MEM_MAP_RW));
  r_assert (r_mem_map (mem, &info, R_MEM_MAP_READ));
  r_assert_cmpint (info.flags, ==, R_MEM_MAP_READ);
  r_assert_cmpptr (info.mem, ==, mem);
  r_assert_cmpuint (info.size, ==, 512);
  r_assert_cmpuint (info.allocsize, ==, 512 + 16);
  r_assert_cmpuint (RPOINTER_TO_SIZE (info.data) & 0xff, ==, 0);
  r_assert (r_mem_unmap (mem, &info));
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (NULL,
          R_MEM_FLAG_ZERO_PREFIXED | R_MEM_FLAG_ZERO_PADDED,
          512, 256, 256, 0xff)), !=, NULL);
  r_assert (r_mem_map (mem, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, ==, 512);
  r_assert_cmpuint (info.allocsize, ==, 1024);
  r_assert_cmpmem (info.data - mem->offset, ==, zero256, 256);
  r_assert_cmpmem (info.data + mem->size, ==, zero256, 256);
  r_assert (r_mem_unmap (mem, &info));
  r_mem_unref (mem);
}
RTEST_END;

RTEST (rmem, copy, RTEST_FAST)
{
  RMem * mem, * copy;
  RMemMapInfo infomem, infocopy;

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (NULL, 0, 1024, 16, 16, 0xff)), !=, NULL);
  r_assert (r_mem_map (mem, &infomem, R_MEM_MAP_WRITE));
  r_memset (infomem.data, 0x42, infomem.size);
  r_assert (r_mem_unmap (mem, &infomem));

  r_assert_cmpptr ((copy = r_mem_copy (mem, 0, -1)), !=, NULL);

  r_assert (r_mem_map (mem, &infomem, R_MEM_MAP_READ));
  r_assert (r_mem_map (copy, &infocopy, R_MEM_MAP_READ));

  r_assert_cmpptr (infomem.mem, ==, mem);
  r_assert_cmpuint (infomem.size, ==, 1024);
  r_assert_cmpptr (infocopy.mem, ==, copy);
  r_assert_cmpuint (infocopy.size, ==, 1024);
  r_assert_cmpptr (infomem.data, !=, infocopy.data);
  r_assert_cmpmem (infomem.data, ==, infocopy.data, infomem.size);
  r_assert_cmpuint (RPOINTER_TO_SIZE (infomem.data) & 0xff, ==, 16);
  r_assert_cmpuint (RPOINTER_TO_SIZE (infocopy.data) & 0xff, ==, 0);

  r_assert (r_mem_unmap (mem, &infomem));
  r_assert (r_mem_unmap (copy, &infocopy));

  r_mem_unref (copy);
  r_mem_unref (mem);
}
RTEST_END;

RTEST (rmem, view, RTEST_FAST)
{
  RMem * mem, * view;
  RMemMapInfo infomem, infoview;

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (NULL, R_MEM_FLAG_NO_VIEWS,
          1024, 16, 16, 0xff)), !=, NULL);
  r_assert_cmpptr (r_mem_view (mem, 512, -1), ==, NULL);
  r_mem_unref (mem);

  r_assert_cmpptr ((mem = r_mem_allocator_alloc (NULL, 0, 1024, 16, 16, 0xff)), !=, NULL);
  r_assert (r_mem_map (mem, &infomem, R_MEM_MAP_WRITE));
  r_memset (infomem.data, 0x42, infomem.size);
  r_memset (infomem.data + infomem.size / 3, 0x13, infomem.size / 3);
  r_assert (r_mem_unmap (mem, &infomem));

  r_assert_cmpptr (r_mem_view (mem, -17, 512), ==, NULL);
  r_assert_cmpptr (r_mem_view (mem, 0, 1025+16), ==, NULL);
  r_assert_cmpptr (r_mem_view (mem, 1024, 17), ==, NULL);

  r_assert_cmpptr ((view = r_mem_view (mem, 512, -1)), !=, NULL);
  r_assert_cmpptr (view->parent, ==, mem);
  r_assert_cmpuint (view->size, ==, 512);

  r_assert (r_mem_map (mem, &infomem, R_MEM_MAP_READ));
  r_assert (r_mem_map (view, &infoview, R_MEM_MAP_READ));

  r_assert_cmpptr (infomem.mem, ==, mem);
  r_assert_cmpptr (infoview.mem, ==, view);

  r_assert_cmpptr (infomem.data + 512, ==, infoview.data);

  r_assert (r_mem_unmap (mem, &infomem));
  r_assert (r_mem_unmap (view, &infoview));

  r_mem_unref (view);
  r_mem_unref (mem);
}
RTEST_END;

RTEST (rmem, wrapped, RTEST_FAST)
{
  RMem * mem;
  rsize allocsize = 42;
  rpointer data = r_malloc0 (allocsize);

  r_assert_cmpptr (r_mem_new_wrapped (R_MEM_FLAG_NONE, NULL, allocsize,
          24, 4, data, r_free), ==, NULL);
  r_assert_cmpptr (r_mem_new_wrapped (R_MEM_FLAG_NONE, data, 0,
          24, 4, data, r_free), ==, NULL);
  r_assert_cmpptr (r_mem_new_wrapped (R_MEM_FLAG_NONE, data, allocsize,
          24, 24, data, r_free), ==, NULL);
  /* This is really just the same as r_mem_new_take () */
  r_assert_cmpptr ((mem = r_mem_new_wrapped (R_MEM_FLAG_NONE, data, allocsize,
          24, 4, data, r_free)), !=, NULL);
  r_assert (!r_mem_is_zero_prefixed (mem));
  r_assert (!r_mem_is_zero_padded (mem));
  r_assert (r_mem_is_writable (mem));
  r_assert (!r_mem_is_readonly (mem));
  r_assert_cmpuint (mem->allocsize, ==, 42);
  r_assert_cmpuint (mem->size, ==, 24);
  r_assert_cmpuint (mem->offset, ==, 4);

  r_mem_unref (mem);
}
RTEST_END;

RTEST (rmem, merge, RTEST_FAST)
{
  RMem * a, * b, * c, * d, * merged;
  RMemAllocationParams params = { R_MEM_FLAG_NONE, 0, 64, 32 };
  RMemMapInfo info;
  ruint8 test[256];

  r_assert_cmpptr ((a = r_mem_allocator_alloc (NULL, R_MEM_FLAG_NONE, 256, 16, 16, 0xff)), !=, NULL);
  r_assert (r_mem_map (a, &info, R_MEM_MAP_WRITE));
  r_memset (info.data, 0x42, info.size);
  r_assert (r_mem_unmap (a, &info));

  r_assert_cmpptr ((b = r_mem_allocator_alloc (NULL, R_MEM_FLAG_NONE, 256, 0, 0, 0x0f)), !=, NULL);
  r_assert (r_mem_map (b, &info, R_MEM_MAP_WRITE));
  r_memset (info.data, 0x20, info.size);
  r_assert (r_mem_unmap (b, &info));

  r_assert_cmpptr ((c = r_mem_allocator_alloc (NULL, R_MEM_FLAG_NONE, 256, 0, 0, 0x0f)), !=, NULL);
  r_assert (r_mem_map (c, &info, R_MEM_MAP_WRITE));
  r_memset (info.data, 0x0, info.size);
  r_assert (r_mem_unmap (c, &info));

  r_assert_cmpptr ((d = r_mem_allocator_alloc (NULL, R_MEM_FLAG_NONE, 256, 0, 0, 0x0f)), !=, NULL);
  r_assert (r_mem_map (d, &info, R_MEM_MAP_WRITE));
  r_memset (info.data, 0xff, info.size);
  r_assert (r_mem_unmap (d, &info));

  r_assert_cmpptr ((merged = r_mem_merge (&params, a, b, c, d, NULL)), !=, NULL);
  r_assert_cmpuint (merged->size, ==, 1024);
  r_assert_cmpuint (merged->allocsize, >=, 1024 + 64 + 32);
  r_assert_cmpuint (merged->offset, ==, 64);

  r_mem_unref (a);
  r_mem_unref (b);

  r_assert (r_mem_map (merged, &info, R_MEM_MAP_WRITE));
  r_memset (test, 0x42, sizeof (test));
  r_assert_cmpmem (&info.data[0], ==, test, sizeof (test));
  r_memset (test, 0x20, sizeof (test));
  r_assert_cmpmem (&info.data[256], ==, test, sizeof (test));
  r_memset (test, 0x0, sizeof (test));
  r_assert_cmpmem (&info.data[512], ==, test, sizeof (test));
  r_memset (test, 0xff, sizeof (test));
  r_assert_cmpmem (&info.data[768], ==, test, sizeof (test));
  r_assert (r_mem_unmap (merged, &info));

  r_mem_unref (merged);
}
RTEST_END;

