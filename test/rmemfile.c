#include <rlib/rlib.h>

RTEST (rmemfile, read, RTEST_FAST | RTEST_SYSTEM)
{
  static const rchar testdata[] = "foobarfoobar";
  RMemFile * f, * f1;
  RIOHandle handle;
  rchar * tmpfile = NULL;

  r_assert_cmpptr ((f = r_mem_file_new ("/foo/bar/BADGER", R_MEM_PROT_READ, FALSE)), ==, NULL);

  /********/
  /* Generate tmp file to read from */
  /********/
  r_assert_cmpint ((handle = r_io_open_tmp (NULL, NULL, &tmpfile)), >=, 0);
  r_io_write (handle, testdata, sizeof (testdata)); /* This also writes the terminating zero */
  r_assert (r_io_close (handle));
  r_assert_cmpstr (tmpfile, !=, NULL);
  /********/

  r_assert_cmpptr ((f = r_mem_file_new (tmpfile, R_MEM_PROT_READ, FALSE)), !=, NULL);
  r_assert_cmpptr ((f1 = r_mem_file_ref (f)), !=, NULL);
  r_mem_file_unref (f1);

  r_assert_cmpuint (r_mem_file_get_size (f), ==, 6*2 + 1);
  r_assert_cmpstr ((rchar *)r_mem_file_get_mem (f), ==, "foobarfoobar");

  r_free (tmpfile);
  r_mem_file_unref (f);
}
RTEST_END;

