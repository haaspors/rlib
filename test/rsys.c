
#include <rlib/rlib.h>

RTEST (rsys, cpu, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpuint (r_sys_cpu_packages (), >, 0);
  r_assert_cmpuint (r_sys_cpu_physical_count (), >, 0);
  r_assert_cmpuint (r_sys_cpu_logical_count (), >, 0);
}
RTEST_END;

