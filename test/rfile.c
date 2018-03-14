#include <rlib/rlib.h>
#include <rlib/ros.h>

#define TESTPREFIX    "rfiletest"

RTEST (rfile, open, RTEST_FAST | RTEST_SYSTEM)
{
  RFile * file;
  rchar * path = r_proc_get_exe_path ();

  r_assert_cmpptr (r_file_open ("/foo/bar/badger", "r"), ==, NULL);
  r_assert_cmpptr ((file = r_file_open (path, "r")), !=, NULL);
  r_file_unref (file);

  r_free (path);
}
RTEST_END;

RTEST (rfile, new_tmp, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * tmp, * base;
  RFile * file;

  r_assert_cmpptr ((file = r_file_new_tmp (NULL, TESTPREFIX, NULL)), !=, NULL);
  r_file_unref (file);

  tmp = NULL;
  r_assert_cmpptr ((file = r_file_new_tmp (NULL, TESTPREFIX, &tmp)), !=, NULL);
  r_assert_cmpptr (tmp, !=, NULL);
  r_assert_cmpstr ((base = r_fs_path_basename (tmp)), !=, TESTPREFIX);
  r_assert (r_str_has_prefix (base, TESTPREFIX));
  r_free (base); r_free (tmp);
  r_file_unref (file);
}
RTEST_END;

RTEST (rfile, write_seek_read, RTEST_FAST | RTEST_SYSTEM)
{
  static const rchar testdata[] = "foobarbadger";
  rchar buffer[256];
  RFile * file;
  rsize res;

  r_assert_cmpptr ((file = r_file_new_tmp_full (NULL, TESTPREFIX, "w+", NULL)), !=, NULL);

  r_assert_cmpint (r_file_write (file, testdata, sizeof (testdata), &res), ==, R_FILE_ERROR_OK);
  r_assert_cmpuint (res, ==, sizeof (testdata));
  r_assert_cmpint (r_file_tell (file), ==, sizeof (testdata));
  r_assert_cmpint (r_file_seek (file, 0, SEEK_SET), ==, 0);
  r_assert_cmpint (r_file_tell (file), ==, 0);
  r_assert_cmpint (r_file_read (file, buffer, sizeof (testdata), &res), ==, R_FILE_ERROR_OK);
  r_assert_cmpuint (res, ==, sizeof (testdata));
  r_assert_cmpstr (buffer, ==, "foobarbadger");
  r_assert_cmpint (r_file_tell (file), ==, sizeof (testdata));

  r_file_unref (file);
}
RTEST_END;

RTEST (rfile, write_read_all, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * file;
  ruint8 * out;
  rsize size;

  r_assert_cmpptr ((file = r_fs_path_new_tmpname_full (NULL, TESTPREFIX, "")), !=, NULL);

  r_assert (!r_file_read_all (NULL, NULL, NULL));
  r_assert (!r_file_read_all (file, NULL, NULL));
  r_assert (!r_file_read_all (file, &out, NULL));

  r_assert (r_file_write_all (file, "foobarstop", 10));
  r_assert (r_file_read_all (file, &out, &size));
  r_free (file);

  r_assert_cmpuint (size, ==, 10);
  r_assert_cmpmem (out, ==, "foobarstop", size);
  r_free (out);
}
RTEST_END;

RTEST (rfile, read_number, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * file;
  rchar tmp[256];
  int len;

  r_assert_cmpuint (r_file_read_uint (NULL, 42), ==, 42);
  r_assert_cmpint (r_file_read_int (NULL, 42), ==, 42);

  r_assert_cmpptr ((file = r_fs_path_new_tmpname_full (NULL, TESTPREFIX, "")), !=, NULL);
  r_assert (r_file_write_all (file, "14341542", 8));
  r_assert_cmpuint (r_file_read_uint (file, 42), ==, 14341542);
  r_free (file);

  r_assert_cmpptr ((file = r_fs_path_new_tmpname_full (NULL, TESTPREFIX, "")), !=, NULL);
  r_assert (r_file_write_all (file, "-14341542", 9));
  r_assert_cmpint (r_file_read_int (file, 42), ==, -14341542);
  r_free (file);

  r_assert_cmpptr ((file = r_fs_path_new_tmpname_full (NULL, TESTPREFIX, "")), !=, NULL);
  r_assert_cmpuint ((len = r_sprintf (tmp, "%u", RUINT_MAX)), ==, 10);
  r_assert (r_file_write_all (file, tmp, len));
  r_assert_cmpuint (r_file_read_uint (file, 42), ==, RUINT_MAX);
  r_assert_cmpint (r_file_read_int (file, 42), ==, -1);
  r_free (file);

  r_assert_cmpptr ((file = r_fs_path_new_tmpname_full (NULL, TESTPREFIX"max", "")), !=, NULL);
  r_assert_cmpuint ((len = r_sprintf (tmp, "0x%x", RUINT_MAX - 100)), ==, 10);
  r_assert (r_file_write_all (file, tmp, len));
  r_assert_cmpuint (r_file_read_uint (file, 42), ==, RUINT_MAX - 100);
  r_assert_cmpint (r_file_read_int (file, 42), ==, -101);
  r_free (file);
}
RTEST_END;

