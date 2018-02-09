#include <rlib/rlib.h>

#ifdef RLIB_HAVE_MODULE
RTEST (rmodule, self_open_close, RTEST_FAST)
{
  RMODULE mod;

  r_assert_cmpptr ((mod = r_module_open (NULL, TRUE, NULL)), !=, NULL);
  r_module_close (mod);
}
RTEST_END;

#ifdef __ELF__
RTEST (rmodule, find_section, RTEST_FAST)
{
  RMODULE mod;
  rpointer sec;
  ruint32 magic = _RTEST_MAGIC;
  rsize size;

  r_assert_cmpptr ((mod = r_module_open (NULL, TRUE, NULL)), !=, NULL);
  r_assert_cmpptr ((sec = r_module_find_section (mod, ".rtest", -1, &size)), !=, NULL);
  r_assert_cmpuint (size % RLIB_SIZEOF_RTEST, ==, 0);
  r_assert_cmpmem (sec, ==, &magic, sizeof (ruint32));
  r_module_close (mod);
}
RTEST_END;
#endif
#endif

