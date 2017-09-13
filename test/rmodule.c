#include <rlib/rlib.h>

#ifdef RLIB_HAVE_MODULE
RTEST (rmodule, self_open_close, RTEST_FAST)
{
  RMODULE mod;

  r_assert_cmpptr ((mod = r_module_open (NULL, TRUE, NULL)), !=, NULL);
  r_module_close (mod);
}
RTEST_END;
#endif

