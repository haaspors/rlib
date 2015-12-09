#include <rlib/rlib.h>

RTEST (rmemfile, read, RTEST_FAST | RTEST_SYSTEM)
{
  static const rchar testdata[] = "foobarfoobar";
  RMemFile * f, * f1;
  int fd;
  rchar * tmpfile = NULL;

  r_assert_cmpptr ((f = r_mem_file_new ("/foo/bar/BADGER", R_MEM_PROT_READ, FALSE)), ==, NULL);

  /********/
  /* Generate tmp file to read from */
  /********/
  r_assert_cmpint ((fd = r_fd_open_tmp (NULL, NULL, &tmpfile)), >=, 0);
  r_fd_write (fd, testdata, sizeof (testdata)); /* This also writes the terminating zero */
  r_assert (r_fd_close (fd));
  r_assert_cmpptr (tmpfile, !=, NULL);
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

