#include <rlib/rlib.h>
#include <stdlib.h>
#include <string.h>

static rboolean
do_print (const rchar * str, rsize size, rpointer data)
{
  return memcmp (str, data, size) == 0;
}

int
main (int argc, char **argv)
{
  (void)argc;

  r_print ("%s\n", *argv);
  r_override_print_handler (do_print, *argv, NULL, NULL);

  return r_print ("%s", *argv) - strlen(*argv);
}
