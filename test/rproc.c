#include <rlib/rlib.h>

#define TEST_BINARY "rlibtest"

RTEST (rproc, get_exe, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * exe;

  r_assert_cmpptr ((exe = r_proc_get_exe_path ()), !=, NULL);
  r_assert (r_str_has_suffix (exe, TEST_BINARY));
  r_free (exe);

  r_assert_cmpstr ((exe = r_proc_get_exe_name ()), ==, TEST_BINARY);
  r_free (exe);
}
RTEST_END;

