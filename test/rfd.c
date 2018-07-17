#include <rlib/rlib.h>
#include <rlib/ros.h>

#define TESTPREFIX    "rfdtest"

RTEST (rfd, open, RTEST_FAST | RTEST_SYSTEM)
{
  int fd;
  rchar * path = r_proc_get_exe_path ();

  r_assert_cmpint (r_fd_open ("/foo/bar/badger", O_RDONLY, 0), <, 0);
  r_assert_cmpint ((fd = r_fd_open (path, O_RDONLY, 0)), >=, 0);
  r_assert (r_fd_close (fd));

  r_free (path);
}
RTEST_END;

RTEST (rfd, open_tmp, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * tmp, * base;
  int fd;

  r_assert_cmpint ((fd = r_fd_open_tmp (NULL, TESTPREFIX, NULL)), >=, 0);
  r_assert (r_fd_close (fd));

  tmp = NULL;
  r_assert_cmpint ((fd = r_fd_open_tmp (NULL, TESTPREFIX, &tmp)), >=, 0);
  r_assert_cmpptr (tmp, !=, NULL);
  r_assert_cmpstr ((base = r_fs_path_basename (tmp)), !=, TESTPREFIX);
  r_assert (r_str_has_prefix (base, TESTPREFIX));
  r_free (base); r_free (tmp);
  r_assert (r_fd_close (fd));
}
RTEST_END;

RTEST (rfd, write_seek_read, RTEST_FAST | RTEST_SYSTEM)
{
  static const rchar testdata[] = "foobarbadger";
  rchar buffer[256];
  int fd;

  r_assert_cmpint ((fd = r_fd_open_tmp_full (NULL, TESTPREFIX,
          O_RDWR, 0600, NULL)), >=, 0);

  r_assert_cmpint (r_fd_write (fd, testdata, sizeof (testdata)), ==, sizeof (testdata));
  r_assert_cmpint (r_fd_tell (fd), ==, sizeof (testdata));
  r_assert_cmpint (r_fd_seek (fd, 0, R_SEEK_MODE_SET), ==, 0);
  r_assert_cmpint (r_fd_tell (fd), ==, 0);
  r_assert_cmpint (r_fd_read (fd, buffer, sizeof (testdata)), ==, sizeof (testdata));
  r_assert_cmpstr (buffer, ==, "foobarbadger");
  r_assert_cmpint (r_fd_tell (fd), ==, sizeof (testdata));

  r_assert (r_fd_close (fd));
}
RTEST_END;

