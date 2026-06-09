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


/* A live pollset must stay internally consistent: handles[], handle_user and
 * handle_idx in lockstep, no handle in two live slots, and every removed handle
 * fully gone. The swap-compaction in r_poll_set_remove_idx is where this breaks
 * (a stranded/duplicated slot is the #310 dead-fd-in-pollset). Heavy handle
 * reuse mimics recycled fds. */
static void
r_test_pollset_assert_consistent (RPollSet * ps)
{
  ruint i, j;

  r_assert_cmpuint (r_hash_table_size (ps->handle_user), ==, ps->count);
  r_assert_cmpuint (r_hash_table_size (ps->handle_idx), ==, ps->count);

  for (i = 0; i < ps->count; i++) {
    RIOHandle h = ps->handles[i].handle;
    /* the maps point this handle back at exactly this slot */
    r_assert_cmpint (r_poll_set_find (ps, h), ==, (int) i);
    r_assert_cmpptr (r_poll_set_get_user (ps, h), !=, NULL);
    /* no other live slot holds the same handle */
    for (j = i + 1; j < ps->count; j++)
      r_assert_cmpint ((int) (ps->handles[j].handle == h), ==, 0);
  }
}

RTEST (rpollset, remove_compaction_stays_consistent, RTEST_FAST)
{
  RPollSet ps;
  ruint round, i;

  r_poll_set_init (&ps, 0);

  for (round = 0; round < 200; round++) {
    /* Reuse a small handle space so adds keep hitting recycled values. Users
     * are non-NULL (handle value) so get_user can flag a stranded slot. */
    ruint n = 6 + (round % 5);
    for (i = 0; i < n; i++) {
      RIOHandle h = (RIOHandle) (rsize) (1 + ((round * 7 + i * 3) % 11));
      r_poll_set_add (&ps, h, R_IO_IN, (rpointer) (rsize) h);
      r_test_pollset_assert_consistent (&ps);
    }
    /* Remove every live entry, alternating front/back to drive the
     * swap-compaction from both directions. */
    while (ps.count > 0) {
      ruint idx = (round & 1) ? 0 : ps.count - 1;
      RIOHandle dead = ps.handles[idx].handle;
      r_assert (r_poll_set_remove (&ps, dead));
      r_assert_cmpint (r_poll_set_find (&ps, dead), <, 0);
      r_assert_cmpptr (r_poll_set_get_user (&ps, dead), ==, NULL);
      r_test_pollset_assert_consistent (&ps);
    }
    r_assert_cmpuint (ps.count, ==, 0);
  }

  r_poll_set_clear (&ps);
}
RTEST_END;

/* Replays the exact add/remove sequence that strands a handle in the live set
 * (observed driving the http suite with non-recycling fds): eight handles are
 * added, then four are removed by handle. The set must stay internally
 * consistent -- a removed handle must not orphan another that probed past it in
 * the index map; the bug left a still-present handle unfindable, so the loop
 * could neither service nor remove its watcher and hung. */
RTEST (rpollset, remove_sequence_leaves_no_unfindable_handle, RTEST_FAST)
{
  RPollSet ps;
  const RIOHandle h[8] = {
    (RIOHandle) 0x3,   (RIOHandle) 0x3e8, (RIOHandle) 0x3e9, (RIOHandle) 0x3ea,
    (RIOHandle) 0x3eb, (RIOHandle) 0x3ec, (RIOHandle) 0x3ed, (RIOHandle) 0x3ee,
  };
  ruint i;

  r_poll_set_init (&ps, 0);
  for (i = 0; i < 8; i++)
    r_assert_cmpint (r_poll_set_add (&ps, h[i], R_IO_IN, (rpointer) (ruintptr) h[i]), >=, 0);

  r_assert (r_poll_set_remove (&ps, (RIOHandle) 0x3e8));
  r_assert (r_poll_set_remove (&ps, (RIOHandle) 0x3ea));
  r_assert (r_poll_set_remove (&ps, (RIOHandle) 0x3ec));
  r_assert (r_poll_set_remove (&ps, (RIOHandle) 0x3ee));

  r_test_pollset_assert_consistent (&ps);
  r_assert_cmpint (r_poll_set_find (&ps, (RIOHandle) 0x3ed), >=, 0);
  r_assert_cmpptr (r_poll_set_get_user (&ps, (RIOHandle) 0x3ed), ==, (rpointer) (ruintptr) 0x3ed);

  r_poll_set_clear (&ps);
}
RTEST_END;
