#include <rlib/rlib.h>

int
main (int argc, char ** argv)
{
  RMODULE mod = NULL;
  RModuleError err;
  rchar * str;
  rpointer s;
  rsize size = 0;

  (void) argc;
  (void) argv;

  if ((mod = r_module_open (NULL, TRUE, &err)) == NULL) {
    r_print ("Couldn't open self MODULE\n");
    return 11;
  }

  s = r_module_find_section (mod, ".data", -1, &size);
  str = r_str_mem_dump_dup ((const ruint8 *)s, size, 16);
  r_print (".data %p [%"RSIZE_FMT"]\n%s\n", s, size, str);
  r_free (str);

  r_module_close (mod);

  return 0;
}

