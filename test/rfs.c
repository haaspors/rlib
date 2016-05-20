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

RTEST (rfs, test, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * exe;

  r_assert_cmpptr ((exe = r_proc_get_exe_path ()), !=, NULL);

  r_assert ( r_fs_test_exists (exe));
  r_assert ( r_fs_test_is_regular (exe));
  r_assert (!r_fs_test_is_directory (exe));
  r_assert (!r_fs_test_is_device (exe));
  r_assert (!r_fs_test_is_symlink (exe));

  r_assert ( r_fs_test_read_access (exe));
  r_assert ( r_fs_test_write_access (exe));
  r_assert ( r_fs_test_exec_access (exe));

  r_free (exe);

#ifdef R_OS_UNIX
  r_assert ( r_fs_test_exists ("/dev/random"));
  r_assert (!r_fs_test_is_regular ("/dev/random"));
  r_assert (!r_fs_test_is_directory ("/dev/random"));
  r_assert ( r_fs_test_is_device ("/dev/random"));
  r_assert (!r_fs_test_is_symlink ("/dev/random"));

  r_assert ( r_fs_test_read_access ("/dev/random"));
  r_assert ( r_fs_test_write_access ("/dev/random"));
  r_assert (!r_fs_test_exec_access ("/dev/random"));
#endif
}
RTEST_END;

