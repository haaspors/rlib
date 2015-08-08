#include <rlib/rlib.h>

int
main (int argc, char ** argv)
{
  rchar * str = r_malloc0 (10);

  str[0] = 'H';
  str[1] = 'i';
  str[2] = ' ';
  str[3] = argc + '0';
  str[4] = ' ';
  str[5] = argv[0][0];
  str[6] = argv[0][1];
  str[7] = argv[0][2];
  r_print ("%s\n", argv[0]);
  r_print ("%s\n", str);
  r_free (str);

  return 0;
}
