#include <rlib/rlib.h>

RTEST_BENCH (rbench, system, RTEST_FAST | RTEST_SYSTEM)
{
  RBitset * cpuset;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max_count ()));

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  r_print ("\tCPU:\n");
  r_print ("\t\tPackages: %4u\n", r_sys_cpu_packages ());
  r_print ("\t\tMAX:      %4u\n", r_sys_cpu_max_count ());
  r_print ("\t\tPyhsical: %4u\n", r_sys_cpu_physical_count ());
  r_print ("\t\tLogical:  %4u\n", r_sys_cpu_logical_count ());
  if (r_sys_cpuset_online (cpuset)) {
    rchar * online;
    r_print ("\t\tOnline:   %s\n", (online = r_bitset_to_human_readable (cpuset)));
    r_free (online);
  }
}
RTEST_END;

/********************************************************/
/* Main entry point and test runner                     */
/********************************************************/
RTEST_MAIN ("test benchmark");
