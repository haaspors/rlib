
#include <rlib/rlib.h>

RTEST (rsys, cpu, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpuint (r_sys_cpu_packages (), >, 0);
  r_assert_cmpuint (r_sys_cpu_physical_count (), >, 0);
  r_assert_cmpuint (r_sys_cpu_logical_count (), >, 0);
}
RTEST_END;

RTEST (rsys, cpuset, RTEST_FAST | RTEST_SYSTEM)
{
  RBitset * cpuset;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max_count ()));
  r_assert (r_sys_cpuset_online (cpuset));
  r_assert_cmpuint (r_bitset_popcount (cpuset), ==, r_sys_cpu_logical_count ());
}
RTEST_END;

RTEST (rsys, node, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpuint (r_sys_node_count (), >, 0);
}
RTEST_END;

RTEST (rsys, topology, RTEST_FAST | RTEST_SYSTEM)
{
  RSysTopology * topo;
  RSysNode * node;
  RSysCpu * cpu;
  rsize i, j, nodecount = 0, cpucount, totcpucount = 0;
  RBitset * cpuset;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpu_max_count ()));

  r_assert_cmpptr ((topo = r_sys_topology_discover ()), !=, NULL);
  r_assert_cmpuint ((nodecount = r_sys_topology_node_count (topo)), ==,
      r_sys_node_count ());

  r_assert_cmpuint (r_sys_topology_node_count (NULL), ==, 0);
  r_assert_cmpptr (r_sys_topology_node (topo, nodecount), ==, NULL);

  for (i = 0; i < nodecount; i++) {
    r_assert_cmpptr ((node = r_sys_topology_node (topo, i)), !=, NULL);
    cpucount = r_sys_topology_node_cpu_count (node);
    totcpucount += cpucount;

    r_assert_cmpuint (r_sys_topology_node_cpu_count (NULL), ==, 0);
    r_assert (!r_sys_topology_node_cpuset (NULL, NULL));
    r_assert (!r_sys_topology_node_cpuset (node, NULL));

    r_bitset_clear (cpuset);
    r_assert (r_sys_topology_node_cpuset (node, cpuset));
    r_assert_cmpuint (cpucount, ==, r_bitset_popcount (cpuset));

    r_assert_cmpptr (r_sys_topology_node_cpu (NULL, 0), ==, NULL);
    r_assert_cmpptr (r_sys_topology_node_cpu (node, cpucount), ==, NULL);

    for (j = 0; j < cpucount; j++) {
      r_assert_cmpptr ((cpu = r_sys_topology_node_cpu (node, j)), !=, NULL);

      r_sys_cpu_unref (cpu);
    }

    r_sys_node_unref (node);
  }

  r_assert_cmpuint (totcpucount, ==, r_sys_cpu_logical_count ());
  r_sys_topology_unref (topo);
}
RTEST_END;

