#include <rlib/rlib.h>

static void
_print_core_id (rsize bit, rpointer user)
{
  (void) user;
  r_print (" %"RSIZE_FMT, bit);
}

int
main (int argc, char ** argv)
{
  RBitset * cpuset;

  (void) argc;
  (void) argv;

  if (!r_bitset_init_stack (cpuset, 256)) {
    r_printerr ("r_bitset_init_stack failed\n");
    return 1;
  }

  if (!r_thread_get_affinity (r_thread_current (), cpuset)) {
    r_printerr ("r_thread_get_affinity failed\n");
    return 1;
  }

  r_print ("Running thread may be scheduled on %"RSIZE_FMT" different cores\nCores:",
      r_bitset_popcount (cpuset));
  r_bitset_foreach (cpuset, TRUE, _print_core_id, NULL);

  r_print ("\n");
  return 0;
}

