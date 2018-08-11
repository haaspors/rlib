#include <rlib/rlib.h>
#include <rlib/ros.h>

#define TESTPREFIX    "riotest"

RTEST (rio, open, RTEST_FAST | RTEST_SYSTEM)
{
  RIOHandle handle;

  r_assert_cmpint (r_io_open_file ("/foo/bar/badger", R_FILE_OPEN_EXISTING,
        R_FILE_READ, R_FILE_SHARE_EXCLUSIVE, R_FILE_FLAG_NONE, NULL), ==, R_IO_HANDLE_INVALID);
  rchar * path = r_proc_get_exe_path ();
  r_assert_cmpint ((handle = r_io_open_file (path, R_FILE_OPEN_EXISTING,
        R_FILE_READ, R_FILE_SHARE_EXCLUSIVE, R_FILE_FLAG_NONE, NULL)), !=, R_IO_HANDLE_INVALID);
  r_assert (r_io_close (handle));

  r_free (path);
}
RTEST_END;

RTEST (rio, open_tmp, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * tmp, * base;
  RIOHandle handle;

  r_assert_cmpint ((handle = r_io_open_tmp (NULL, TESTPREFIX, NULL)), !=, R_IO_HANDLE_INVALID);
  r_assert (r_io_close (handle));

  tmp = NULL;
  r_assert_cmpint ((handle = r_io_open_tmp (NULL, TESTPREFIX, &tmp)), !=, R_IO_HANDLE_INVALID);
  r_assert_cmpptr (tmp, !=, NULL);
  r_assert_cmpstr ((base = r_fs_path_basename (tmp)), !=, TESTPREFIX);
  r_assert (r_str_has_prefix (base, TESTPREFIX));
  r_free (base); r_free (tmp);
  r_assert (r_io_close (handle));
}
RTEST_END;

RTEST (rio, write_seek_read, RTEST_FAST | RTEST_SYSTEM)
{
  static const rchar testdata[] = "foobarbadger";
  rchar buffer[256];
  RIOHandle handle;

  r_assert_cmpint ((handle = r_io_open_tmp_full (NULL, TESTPREFIX, R_FILE_RDWR,
          R_FILE_SHARE_EXCLUSIVE, R_FILE_FLAG_NONE, NULL, NULL)), !=, R_IO_HANDLE_INVALID);

  r_assert_cmpint (r_io_write (handle, testdata, sizeof (testdata)), ==, sizeof (testdata));
  r_assert_cmpint (r_io_tell (handle), ==, sizeof (testdata));
  r_assert_cmpint (r_io_seek (handle, 0, R_SEEK_MODE_SET), ==, 0);
  r_assert_cmpint (r_io_tell (handle), ==, 0);
  r_assert_cmpint (r_io_read (handle, buffer, sizeof (testdata)), ==, sizeof (testdata));
  r_assert_cmpstr (buffer, ==, "foobarbadger");
  r_assert_cmpint (r_io_tell (handle), ==, sizeof (testdata));

  r_assert (r_io_flush (handle));
  r_assert_cmpuint (r_io_filesize (handle), ==, sizeof (testdata));

  r_assert (r_io_close (handle));
}
RTEST_END;

