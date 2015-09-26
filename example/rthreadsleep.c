#include <rlib/rlib.h>

int
main (int argc, char ** argv)
{
  (void)argc;
  (void)argv;

  r_print ("Sleep for 1s\n");
  r_thread_sleep (1);

  r_print ("Sleep for %d us (1s)\n", R_USEC_PER_SEC);
  r_thread_usleep (R_USEC_PER_SEC);

  return 0;
}

