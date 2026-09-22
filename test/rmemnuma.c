#include <rlib/ros.h>

RTEST (rmemnuma, page_size, RTEST_FAST)
{
  rsize pagesize = r_mem_numa_page_size ();

  r_assert_cmpuint (pagesize, >, 0);
  /* Page sizes are powers of two, and callers round sizes by this. */
  r_assert_cmpuint (pagesize & (pagesize - 1), ==, 0);
}
RTEST_END;

RTEST (rmemnuma, alloc_local, RTEST_FAST | RTEST_SYSTEM)
{
  rsize size = r_mem_numa_page_size () * 4;
  ruint8 * mem;
  rsize i;

  r_assert_cmpptr (r_mem_numa_alloc_local (0), ==, NULL);

  r_assert_cmpptr ((mem = r_mem_numa_alloc_local (size)), !=, NULL);
  for (i = 0; i < size; i++)
    r_assert_cmpuint (mem[i], ==, 0);
  r_memset (mem, 0x5a, size);
  r_assert_cmpuint (mem[size - 1], ==, 0x5a);
  r_mem_numa_free (mem, size);

  /* Releasing nothing is a no-op, as with r_free. */
  r_mem_numa_free (NULL, size);
  r_mem_numa_free (NULL, 0);
}
RTEST_END;

RTEST (rmemnuma, bad_args, RTEST_FAST | RTEST_SYSTEM)
{
  rsize size = r_mem_numa_page_size ();
  ruint node;
  rpointer mem;

  r_assert (!r_mem_numa_bind (NULL, size, 0));
  r_assert (!r_mem_numa_interleave (NULL, size, NULL));
  r_assert (!r_mem_numa_node_of (NULL, &node));

  r_assert_cmpptr ((mem = r_mem_numa_alloc_local (size)), !=, NULL);
  r_assert (!r_mem_numa_bind (mem, 0, 0));
  r_assert (!r_mem_numa_interleave (mem, 0, NULL));
  r_assert (!r_mem_numa_node_of (mem, NULL));
  /* No machine has this many nodes; the mask cannot even hold it. */
  r_assert (!r_mem_numa_bind (mem, size, 1 << 20));
  r_mem_numa_free (mem, size);
}
RTEST_END;

/* Android blocks the mempolicy syscalls and exposes no NUMA at all. */
#if !defined (R_OS_ANDROID)
RTEST (rmemnuma, alloc_onnode, RTEST_FAST | RTEST_SYSTEM)
{
  rsize size = r_mem_numa_page_size () * 4;
  RBitset * nodeset;
  ruint i;

  r_assert (r_bitset_init_stack (nodeset, r_sys_nodeset_max ()));
  r_assert (r_sys_nodeset_online (nodeset));
  r_assert_cmpuint (r_bitset_popcount (nodeset), >, 0);

  for (i = 0; i < nodeset->bits; i++) {
    ruint8 * mem;
    ruint node;

    if (!r_bitset_is_bit_set (nodeset, i))
      continue;

    r_assert_cmpptr ((mem = r_mem_numa_alloc_onnode (size, i)), !=, NULL);
#if defined (R_OS_LINUX)
    /* An online node is one mbind accepts, so a failure here is ours
     * and not the machine's. */
    if (r_mem_numa_available ())
      r_assert (r_mem_numa_bind (mem, size, i));
#endif
    r_memset (mem, 0xa5, size);

    /* Where the binding took, the page must have come from that node. */
    if (r_mem_numa_available () && r_mem_numa_node_of (mem, &node))
      r_assert_cmpuint (node, ==, i);

    r_mem_numa_free (mem, size);
  }
}
RTEST_END;

RTEST (rmemnuma, alloc_interleaved, RTEST_FAST | RTEST_SYSTEM)
{
  rsize size = r_mem_numa_page_size () * 4;
  RBitset * nodeset;
  ruint8 * mem;

  r_assert (r_bitset_init_stack (nodeset, r_sys_nodeset_max ()));
  r_assert (r_sys_nodeset_online (nodeset));

  /* An explicit nodeset, and NULL for "whatever this process may
   * allocate from" - which the kernel will not accept as an empty
   * mask, so it has to be filled in for us. */
  r_assert_cmpptr ((mem = r_mem_numa_alloc_interleaved (size, nodeset)), !=, NULL);
  r_memset (mem, 0x33, size);
  r_assert_cmpuint (mem[size - 1], ==, 0x33);
#if defined (R_OS_LINUX)
  if (r_mem_numa_available ()) {
    r_assert (r_mem_numa_interleave (mem, size, nodeset));
    r_assert (r_mem_numa_interleave (mem, size, NULL));

    r_bitset_clear (nodeset);
    r_assert (r_mem_numa_interleave (mem, size, nodeset));
    r_assert (r_sys_nodeset_online (nodeset));
  }
#endif
  r_mem_numa_free (mem, size);

  r_assert_cmpptr ((mem = r_mem_numa_alloc_interleaved (size, NULL)), !=, NULL);
  r_memset (mem, 0x33, size);
  r_assert_cmpuint (mem[size - 1], ==, 0x33);
  r_mem_numa_free (mem, size);
}
RTEST_END;

RTEST (rmemnuma, node_of, RTEST_FAST | RTEST_SYSTEM)
{
  rsize size = r_mem_numa_page_size ();
  ruint8 * mem;
  ruint node;

  r_assert_cmpptr ((mem = r_mem_numa_alloc_local (size)), !=, NULL);
  mem[0] = 1;

  if (r_mem_numa_node_of (mem, &node)) {
    RBitset * nodeset;

    r_assert (r_bitset_init_stack (nodeset, r_sys_nodeset_max ()));
    r_assert (r_sys_nodeset_online (nodeset));
    r_assert (r_bitset_is_bit_set (nodeset, node));
  }

  r_mem_numa_free (mem, size);
}
RTEST_END;
#endif /* !R_OS_ANDROID */
