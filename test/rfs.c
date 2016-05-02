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

RTEST (rfs, path_build, RTEST_FAST)
{
  rchar * tmp;

  r_assert_cmpptr (r_fs_path_build (NULL), ==, NULL);
  r_assert_cmpstr ((tmp = r_fs_path_build ("", NULL)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_build (R_DIR_SEP_STR, NULL)), ==,
      R_DIR_SEP_STR); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_build ("foo", "bar", NULL)), ==,
      "foo"R_DIR_SEP_STR"bar"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_build ("foo/", "/bar", NULL)), ==,
      "foo"R_DIR_SEP_STR"bar"); r_free (tmp);
}
RTEST_END;

RTEST (rfs, get_tmp_dir, RTEST_FAST | RTEST_SYSTEM)
{
  const rchar * tmpdir;

  r_assert_cmpptr ((tmpdir = r_fs_get_tmp_dir ()), !=, NULL);
  r_assert_cmpptr (tmpdir, ==, r_fs_get_tmp_dir ());
#ifdef R_OS_UNIX
  /* FIXME: Change to is absolute path */
  r_assert_cmpint (*tmpdir, ==, R_DIR_SEP);
#endif
}
RTEST_END;

