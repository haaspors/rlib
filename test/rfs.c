#include <rlib/rlib.h>
#include <rlib/ros.h>

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
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/")), ==, R_DIR_SEP_STR); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/.")), ==, R_DIR_SEP_STR); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/dev/null")), ==, "/dev"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("tmp/temp")), ==, "tmp"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("tmp")), ==, "."); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/tmp")), ==, R_DIR_SEP_STR); r_free (tmp);
  r_assert_cmpstr ((tmp = r_fs_path_dirname ("/tmp/")), ==, R_DIR_SEP_STR); r_free (tmp);
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

#ifdef RLIB_HAVE_FILES
RTEST (rfs, get_tmp_dir, RTEST_FAST | RTEST_SYSTEM)
{
  const rchar * tmpdir;

  r_assert_cmpptr ((tmpdir = r_fs_get_tmp_dir ()), !=, NULL);
  r_assert_cmpptr (tmpdir, ==, r_fs_get_tmp_dir ());
  r_assert (r_fs_path_is_absolute (tmpdir));
}
RTEST_END;

RTEST (rfs, path_is_absolute, RTEST_FAST)
{
  r_assert (!r_fs_path_is_absolute (NULL));
  r_assert (!r_fs_path_is_absolute (""));
  r_assert (!r_fs_path_is_absolute ("foo"));
  r_assert (!r_fs_path_is_absolute ("foo/bar"));
  r_assert (!r_fs_path_is_absolute ("./foo"));
  r_assert (!r_fs_path_is_absolute ("../foo"));

#ifdef R_OS_WIN32
  r_assert (r_fs_path_is_absolute ("C:\\foo"));
  r_assert (r_fs_path_is_absolute ("c:\\foo"));
  r_assert (r_fs_path_is_absolute ("C:/foo"));
  r_assert (r_fs_path_is_absolute ("\\\\server\\share"));
  r_assert (r_fs_path_is_absolute ("//server/share"));
  r_assert (!r_fs_path_is_absolute ("C:"));
  r_assert (!r_fs_path_is_absolute ("C:foo"));
#else
  r_assert (r_fs_path_is_absolute ("/"));
  r_assert (r_fs_path_is_absolute ("/foo"));
  r_assert (r_fs_path_is_absolute ("/foo/bar"));
#endif
}
RTEST_END;
#endif

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

RTEST (rfs, mkdir, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * tmpdir, * subdir;
  r_assert_cmpptr ((tmpdir = r_fs_path_new_tmpfile ()), !=, NULL);

  r_assert (!r_fs_test_exists (tmpdir));
  r_assert ( r_fs_mkdir (tmpdir, 0777));
  r_assert ( r_fs_test_exists (tmpdir));
  r_assert ( r_fs_test_is_directory (tmpdir));

  r_free (tmpdir);
  r_assert_cmpptr ((tmpdir = r_fs_path_new_tmpfile ()), !=, NULL);

  r_assert_cmpptr ((subdir = r_fs_path_build (tmpdir, "foo", "bar", NULL)), !=, NULL);
  r_assert (!r_fs_mkdir (subdir, 0777));
  r_assert (!r_fs_test_exists (tmpdir));
  r_assert (!r_fs_test_exists (subdir));
  r_assert ( r_fs_mkdir_full (subdir, 0777));
  r_assert ( r_fs_test_exists (tmpdir));
  r_assert ( r_fs_test_exists (subdir));
  r_free (tmpdir);
  r_free (subdir);
}
RTEST_END;

RTEST (rfs, is_symlink, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * link;
  r_assert_cmpptr ((link = r_fs_path_new_tmpfile ()), !=, NULL);

  /* A path that does not exist is not a symlink. */
  r_assert (!r_fs_test_is_symlink (link));

  /* Positive check: detect a symlink we create. r_fs_symlink returns FALSE
   * when the platform forbids it (e.g. unprivileged Windows), so the check is
   * skipped, not failed, there. */
  if (r_fs_symlink ("rlib-symlink-target", link)) {
    r_assert (r_fs_test_is_symlink (link));
    r_assert (r_fs_remove_symlink (link));
    r_assert (!r_fs_test_is_symlink (link));
  }

  r_free (link);
}
RTEST_END;

RTEST (rfs, dir_enumerate, RTEST_FAST | RTEST_SYSTEM)
{
  static const rchar * const expect[] = { "alpha", "beta", "gamma" };
  rboolean seen[R_N_ELEMENTS (expect)] = { FALSE };
  rchar * tmpdir, * p;
  RFsDir * dir;
  const rchar * name;
  ruint i, count = 0;

  /* Opening a path that does not exist fails. */
  r_assert_cmpptr ((tmpdir = r_fs_path_new_tmpfile ()), !=, NULL);
  r_assert_cmpptr (r_fs_dir_open (tmpdir), ==, NULL);

  r_assert (r_fs_mkdir (tmpdir, 0777));

  /* An empty directory yields no entries (". " / ".." are filtered). */
  r_assert_cmpptr ((dir = r_fs_dir_open (tmpdir)), !=, NULL);
  r_assert_cmpptr (r_fs_dir_read_next (dir), ==, NULL);
  r_fs_dir_close (dir);

  for (i = 0; i < R_N_ELEMENTS (expect); i++) {
    r_assert_cmpptr ((p = r_fs_path_build (tmpdir, expect[i], NULL)), !=, NULL);
    r_assert (r_file_write_all (p, expect[i], r_strlen (expect[i])));
    r_assert (r_fs_test_is_regular (p));
    r_free (p);
  }

  /* Enumeration returns exactly the created set, in any order, no duplicates. */
  r_assert_cmpptr ((dir = r_fs_dir_open (tmpdir)), !=, NULL);
  while ((name = r_fs_dir_read_next (dir)) != NULL) {
    r_assert_cmpstr (name, !=, ".");
    r_assert_cmpstr (name, !=, "..");
    for (i = 0; i < R_N_ELEMENTS (expect) && !r_str_equals (name, expect[i]); i++) ;
    r_assert_cmpuint (i, <, R_N_ELEMENTS (expect));   /* nothing unexpected */
    r_assert (!seen[i]);                              /* no duplicate */
    seen[i] = TRUE;
    count++;
  }
  r_fs_dir_close (dir);

  r_assert_cmpuint (count, ==, R_N_ELEMENTS (expect));
  for (i = 0; i < R_N_ELEMENTS (expect); i++)
    r_assert (seen[i]);

  /* Opening a regular file (not a directory) fails. */
  r_assert_cmpptr ((p = r_fs_path_build (tmpdir, expect[0], NULL)), !=, NULL);
  r_assert_cmpptr (r_fs_dir_open (p), ==, NULL);
  r_free (p);

  r_free (tmpdir);
}
RTEST_END;

