#include <rlib/rlib.h>

RTEST_BENCH (rbench, system, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  r_print ("\tCPU:\n");
  r_print ("\t\tPackages: %4u\n", r_sys_cpu_packages ());
  r_print ("\t\tMAX:      %4u\n", r_sys_cpu_max_count ());
  r_print ("\t\tPyhsical: %4u\n", r_sys_cpu_physical_count ());
  r_print ("\t\tLogical:  %4u\n", r_sys_cpu_logical_count ());
}
RTEST_END;

/********************************************************/
/* Main entry point and test runner                     */
/********************************************************/
RTEST_MAIN ("test benchmark");
