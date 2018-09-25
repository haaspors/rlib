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

