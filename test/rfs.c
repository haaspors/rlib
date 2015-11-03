#include <rlib/rlib.h>

RTEST (rfs, basename, RTEST_FAST)
{
  rchar * tmp;

  r_assert_cmpptr (r_fs_path_basename (NULL), ==, NULL);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("")), ==, "."); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename (".")), ==, "."); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("/")), ==, "."); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("/.")), ==, "."); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("/dev/null")), ==, "null"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("tmp/temp")), ==, "temp"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("tmp")), ==, "tmp"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("/tmp")), ==, "tmp"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("/tmp/")), ==, "tmp"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_basename ("tmp/.")), ==, "."); r_free (tmp);
}
RTEST_END;

RTEST (rfs, dirname, RTEST_FAST)
{
  rchar * tmp;

  r_assert_cmpptr (r_fs_path_dirname (NULL), ==, NULL);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("")), ==, "."); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname (".")), ==, "."); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/")), ==, "/"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/.")), ==, "/"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/dev/null")), ==, "/dev"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("tmp/temp")), ==, "tmp"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("tmp")), ==, "."); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/tmp")), ==, "/"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/tmp/")), ==, "/"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("tmp/.")), ==, "tmp"); r_free (tmp);
}
RTEST_END;
