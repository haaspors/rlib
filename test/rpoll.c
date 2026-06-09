#include <rlib/rlib.h>

RTEST (rpollset, init_clear, RTEST_FAST)
{
  RPollSet ps;

  r_poll_set_init (&ps, 0);
  r_assert_cmpptr (ps.handle_user, !=, NULL);
  r_assert_cmpptr (ps.handle_idx, !=, NULL);
  r_assert_cmpuint (ps.count, ==, 0);
  r_assert_cmpuint (ps.alloc, >, 0);
  r_assert_cmpptr (ps.handles, !=, 0);
  r_poll_set_clear (&ps);

  r_poll_set_init (&ps, 512);
  r_assert_cmpptr (ps.handle_user, !=, NULL);
  r_assert_cmpptr (ps.handle_idx, !=, NULL);
  r_assert_cmpuint (ps.count, ==, 0);
  r_assert_cmpuint (ps.alloc, ==, 512);
  r_assert_cmpptr (ps.handles, !=, 0);
  r_poll_set_clear (&ps);
}
RTEST_END;

RTEST (rpollset, add, RTEST_FAST)
{
  RPollSet ps;

  r_poll_set_init (&ps, 0);
  r_assert_cmpuint (ps.count, ==, 0);

  r_assert_cmpint (r_poll_set_add (NULL, (RIOHandle)1, 0, NULL), <, 0);
  r_assert_cmpint (r_poll_set_add (&ps, R_IO_HANDLE_INVALID, 0, NULL), <, 0);

  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)1, 0, NULL), ==, 0);
  r_assert_cmpuint (ps.count, ==, 1);
  r_assert_cmpuint (r_hash_table_size (ps.handle_user), ==, 1);
  r_assert_cmpuint (r_hash_table_size (ps.handle_idx), ==, 1);
  r_poll_set_clear (&ps);
}
RTEST_END;

RTEST (rpollset, add_remove_single, RTEST_FAST)
{
  RPollSet ps;

  r_poll_set_init (&ps, 0);
  r_assert_cmpuint (ps.count, ==, 0);

  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)1, 0, NULL), ==, 0);
  r_assert_cmpuint (ps.count, ==, 1);
  r_assert_cmpuint (r_hash_table_size (ps.handle_user), ==, 1);
  r_assert_cmpuint (r_hash_table_size (ps.handle_idx), ==, 1);

  r_assert (!r_poll_set_remove (NULL, (RIOHandle)1));
  r_assert (!r_poll_set_remove (&ps, R_IO_HANDLE_INVALID));
  r_assert (!r_poll_set_remove (&ps, (RIOHandle)2));

  r_assert (r_poll_set_remove (&ps, (RIOHandle)1));
  r_assert_cmpuint (ps.count, ==, 0);
  r_assert_cmpuint (r_hash_table_size (ps.handle_user), ==, 0);
  r_assert_cmpuint (r_hash_table_size (ps.handle_idx), ==, 0);

  r_assert (!r_poll_set_remove (&ps, (RIOHandle)1));
  r_poll_set_clear (&ps);
}
RTEST_END;

RTEST (rpollset, add_remove_multiple, RTEST_FAST)
{
  RPollSet ps;

  r_poll_set_init (&ps, 0);
  r_assert_cmpuint (ps.count, ==, 0);

  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)1, 0, NULL), ==, 0);
  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)2, 0, NULL), ==, 1);
  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)3, 0, NULL), ==, 2);
  r_assert_cmpuint (ps.count, ==, 3);
  r_assert_cmpuint (r_hash_table_size (ps.handle_user), ==, 3);
  r_assert_cmpuint (r_hash_table_size (ps.handle_idx), ==, 3);

  r_assert (r_poll_set_remove (&ps, (RIOHandle)1));
  r_assert (r_poll_set_remove (&ps, (RIOHandle)3));
  r_assert_cmpuint (ps.count, ==, 1);
  r_assert_cmpuint (r_hash_table_size (ps.handle_user), ==, 1);
  r_assert_cmpuint (r_hash_table_size (ps.handle_idx), ==, 1);

  r_assert (r_poll_set_remove (&ps, (RIOHandle)2));
  r_assert_cmpuint (ps.count, ==, 0);
  r_assert_cmpuint (r_hash_table_size (ps.handle_user), ==, 0);
  r_assert_cmpuint (r_hash_table_size (ps.handle_idx), ==, 0);
  r_poll_set_clear (&ps);
}
RTEST_END;

RTEST (rpollset, find, RTEST_FAST)
{
  RPollSet ps;

  r_poll_set_init (&ps, 0);
  r_assert_cmpuint (ps.count, ==, 0);

  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)1, 0, NULL), ==, 0);
  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)2, 0, NULL), ==, 1);
  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)3, 0, NULL), ==, 2);
  r_assert_cmpuint (ps.count, ==, 3);

  r_assert_cmpint (r_poll_set_find (NULL, (RIOHandle)1), <, 0);
  r_assert_cmpint (r_poll_set_find (&ps, R_IO_HANDLE_INVALID), <, 0);

  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle)3), ==, 2);
  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle)2), ==, 1);
  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle)1), ==, 0);

  r_assert (r_poll_set_remove (&ps, (RIOHandle)1));

  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle)3), ==, 0);
  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle)2), ==, 1);
  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle)1), <, 0);

  r_poll_set_clear (&ps);
}
RTEST_END;

RTEST (rpollset, get_user, RTEST_FAST)
{
  RPollSet ps;

  r_poll_set_init (&ps, 0);
  r_assert_cmpuint (ps.count, ==, 0);

  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)1, 0, (rpointer)1), ==, 0);
  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)2, 0, (rpointer)2), ==, 1);
  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)3, 0, (rpointer)3), ==, 2);
  r_assert_cmpuint (ps.count, ==, 3);

  r_assert_cmpptr (r_poll_set_get_user (NULL, (RIOHandle)1), ==, NULL);
  r_assert_cmpptr (r_poll_set_get_user (&ps, R_IO_HANDLE_INVALID), ==, NULL);

  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)3), ==, (rpointer)3);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)2), ==, (rpointer)2);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)1), ==, (rpointer)1);

  r_assert (r_poll_set_remove (&ps, (RIOHandle)1));

  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)3), ==, (rpointer)3);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)2), ==, (rpointer)2);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)1), ==, NULL);

  r_poll_set_clear (&ps);
}
RTEST_END;

RTEST (rpollset, add_grows_past_initial_alloc, RTEST_FAST)
{
  RPollSet ps;
  const ruint n = 200;
  ruint i;

  /* r_poll_set_init picks a default alloc; we want to push enough
   * entries past it that the grow path runs and every slot still
   * lands inside the (re)allocated buffer. */
  r_poll_set_init (&ps, 0);

  for (i = 1; i <= n; i++)
    r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)(rsize)i, 0,
          (rpointer)(rsize)i), >=, 0);

  r_assert_cmpuint (ps.count, ==, n);
  r_assert_cmpuint (ps.alloc, >=, n);
  for (i = 1; i <= n; i++)
    r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)(rsize)i),
        ==, (rpointer)(rsize)i);

  r_poll_set_clear (&ps);
}
RTEST_END;

static rpointer
r_test_pollset_fail_realloc (rpointer ptr, rsize size)
{
  (void) ptr;
  (void) size;
  return NULL;
}

RTEST (rpollset, add_grow_oom_keeps_set_intact, RTEST_FAST)
{
  RPollSet ps;
  RMemVTable saved, hook;
  ruint i, fill;

  r_poll_set_init (&ps, 0);

  /* Fill exactly to capacity so the next add must grow the buffer. */
  fill = ps.alloc;
  for (i = 1; i <= fill; i++)
    r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)(rsize)i, 0,
          (rpointer)(rsize)i), >=, 0);
  r_assert_cmpuint (ps.count, ==, fill);
  r_assert_cmpuint (ps.alloc, ==, fill);

  /* Fail the grow's realloc: the add must report failure without
   * corrupting the set -- count/alloc unchanged and the buffer not nulled. */
  r_mem_get_vtable (&saved);
  hook = saved;
  hook.realloc = r_test_pollset_fail_realloc;
  r_mem_set_vtable (&hook);

  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)(rsize)(fill + 1), 0,
        (rpointer)(rsize)(fill + 1)), <, 0);

  r_mem_set_vtable (&saved);

  r_assert_cmpuint (ps.count, ==, fill);
  r_assert_cmpuint (ps.alloc, ==, fill);
  for (i = 1; i <= fill; i++)
    r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)(rsize)i),
        ==, (rpointer)(rsize)i);

  r_poll_set_clear (&ps);
}
RTEST_END;

/* Re-adding a handle already in the set must update its one slot in place, not
 * append a second. (A handle reappears when a closed fd's entry lingers and the
 * OS recycles its value into a new socket.) */
RTEST (rpollset, re_add_existing_updates_in_place, RTEST_FAST)
{
  RPollSet ps;

  r_poll_set_init (&ps, 0);

  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)1, R_IO_IN, (rpointer)0xA), ==, 0);
  r_assert_cmpuint (ps.count, ==, 1);

  /* Same handle again -> same slot, updated user + events, no growth. */
  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)1, R_IO_OUT, (rpointer)0xB), ==, 0);
  r_assert_cmpuint (ps.count, ==, 1);
  r_assert_cmpuint (r_hash_table_size (ps.handle_user), ==, 1);
  r_assert_cmpuint (r_hash_table_size (ps.handle_idx), ==, 1);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)1), ==, (rpointer)0xB);
  r_assert_cmpuint (ps.handles[0].events, ==, R_IO_OUT);

  /* A single remove fully evicts it: no orphaned second slot left behind. */
  r_assert (r_poll_set_remove (&ps, (RIOHandle)1));
  r_assert_cmpuint (ps.count, ==, 0);
  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle)1), <, 0);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)1), ==, NULL);

  r_poll_set_clear (&ps);
}
RTEST_END;

/* The #310 shape at the set level: a handle entered and never removed, its fd
 * value recycled into a new socket and re-added, then the original "pruned".
 * A blind append would leave a stale handles[] slot for that handle with no
 * hash entry -- unremovable, and poll() spins on the dead duplicate. With one
 * slot per handle there is no orphan. */
RTEST (rpollset, recycled_handle_leaves_no_orphan, RTEST_FAST)
{
  RPollSet ps;
  ruint i;
  rboolean stale;

  r_poll_set_init (&ps, 0);

  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)7, R_IO_IN, (rpointer)0xA), ==, 0);
  r_assert_cmpint (r_poll_set_add (&ps, (RIOHandle)8, R_IO_IN, (rpointer)0xB), ==, 1);
  /* fd 7 recycled into a new socket, re-added while the old entry still lingers */
  r_poll_set_add (&ps, (RIOHandle)7, R_IO_OUT, (rpointer)0xC);
  r_assert_cmpuint (ps.count, ==, 2);           /* two slots, not three */

  r_assert (r_poll_set_remove (&ps, (RIOHandle)7));
  r_assert_cmpuint (ps.count, ==, 1);
  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle)7), <, 0);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)7), ==, NULL);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle)8), ==, (rpointer)0xB);

  for (i = 0, stale = FALSE; i < ps.count; i++)
    if (ps.handles[i].handle == (RIOHandle)7)
      stale = TRUE;
  r_assert (!stale);                            /* no orphaned slot for 7 */

  r_poll_set_clear (&ps);
}
RTEST_END;

