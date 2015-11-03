#include <rlib/rlib.h>

RTEST (rproc, get_exe_path, RTEST_FAST | RTEST_SYSTEM)
{
  rchar * exename = r_proc_get_exe_path ();
  r_assert_cmpptr (exename, !=, NULL);

  r_assert (r_str_has_suffix (exename, "rlibtest"));
  r_free (exename);
}
RTEST_END;
