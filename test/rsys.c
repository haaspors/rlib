#include <rlib/ros.h>

RTEST (rsys, cpu, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpuint (r_sys_cpu_packages (), >, 0);
  r_assert_cmpuint (r_sys_cpu_physical_count (), >, 0);
  r_assert_cmpuint (r_sys_cpu_logical_count (), >, 0);
  r_assert_cmpuint (r_sys_cpu_allowed_count (), >, 0);
  r_assert_cmpuint (r_sys_cpu_max_count (), >=, r_sys_cpu_logical_count ());
}
RTEST_END;

RTEST (rsys, cpuset, RTEST_FAST | RTEST_SYSTEM)
{
  RBitset * cpuset, * cpuset_allowed;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()));
  r_assert (r_bitset_init_stack (cpuset_allowed, r_sys_cpuset_max ()));

  r_assert (r_sys_cpuset_online (cpuset));
  r_assert (r_sys_cpuset_allowed (cpuset_allowed));

  r_assert_cmpuint (r_bitset_popcount (cpuset), ==, r_sys_cpu_logical_count ());
  r_assert_cmpuint (r_bitset_popcount (cpuset_allowed), <=, r_bitset_popcount (cpuset));
  r_assert_cmpuint (r_bitset_popcount (cpuset_allowed), ==, r_sys_cpu_allowed_count ());
}
RTEST_END;

/* NUMA topology: Android restricts /sys node access and exposes no real NUMA,
 * so node/nodeset/topology discovery doesn't work there. */
#if !defined (R_OS_ANDROID)
RTEST (rsys, cpuset_for_node, RTEST_FAST | RTEST_SYSTEM)
{
  RBitset * cpuset;
  ruint nodes, i;
  rsize cpus = 0;

  r_assert (!r_sys_cpuset_for_node (NULL, 0));

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()));

  r_assert_cmpuint ((nodes = r_sys_node_count_with_online_cpus ()), >, 0);
  r_assert (!r_sys_cpuset_for_node (cpuset, nodes));

  for (i = 0; i < nodes; i++) {
    r_assert (r_sys_cpuset_for_node (cpuset, i));
    cpus += r_bitset_popcount (cpuset);
  }

  r_assert_cmpuint (cpus, ==, r_sys_cpu_logical_count ());
}
RTEST_END;

RTEST (rsys, node_count, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpuint (r_sys_node_count (), >, 0);
  r_assert_cmpuint (r_sys_node_count_with_allowed_cpus (), >, 0);
}
RTEST_END;

RTEST (rsys, nodeset, RTEST_FAST | RTEST_SYSTEM)
{
  RBitset * possible, * online, * allowed;

  r_assert (r_bitset_init_stack (possible, r_sys_nodeset_max ()));
  r_assert (r_bitset_init_stack (online, r_sys_nodeset_max ()));
  r_assert (r_bitset_init_stack (allowed, r_sys_nodeset_max ()));

  r_assert (r_sys_nodeset_possible (possible));
  r_assert (r_sys_nodeset_online (online));
  r_assert (r_sys_nodeset_with_allowed_cpus (allowed));

  r_assert_cmpuint (r_bitset_popcount (online), ==, r_sys_node_count ());
  r_assert_cmpuint (r_bitset_popcount (allowed), ==, r_sys_node_count_with_allowed_cpus ());

  r_assert_cmpuint (r_bitset_popcount (online), <=, r_bitset_popcount (possible));
  r_assert_cmpuint (r_bitset_popcount (allowed), <=, r_bitset_popcount (online));
}
RTEST_END;

RTEST (rsys, nodeset_for_cpuset, RTEST_FAST | RTEST_SYSTEM)
{
  RBitset * nodeset, * cpuset;

  r_assert (r_bitset_init_stack (nodeset, r_sys_nodeset_max ()));
  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()));

  r_assert (!r_sys_nodeset_for_cpuset (NULL, NULL));

  r_assert (r_sys_nodeset_for_cpuset (nodeset, NULL));
  r_assert_cmpuint (r_bitset_popcount (nodeset), ==, r_sys_node_count_with_online_cpus ());

  r_assert (r_sys_nodeset_for_cpuset (nodeset, cpuset));
  r_assert_cmpuint (r_bitset_popcount (nodeset), ==, 0);
}
RTEST_END;

RTEST (rsys, topology, RTEST_FAST | RTEST_SYSTEM)
{
  RSysTopology * topo;
  RSysNode * node;
  RSysCpu * cpu;
  rsize i, j, nodecount, cpucount, totcpucount = 0;
  RBitset * cpuset;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()));

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

    r_assert_cmpuint (r_sys_topology_node_available_memory (NULL), ==, 0);
#if defined (R_OS_LINUX)
    /* Linux reports per-node MemFree via sysfs; an online node has some. */
    r_assert_cmpuint (r_sys_topology_node_available_memory (node), >, 0);
#endif

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
RTEST (rsys, topology_cpu, RTEST_FAST | RTEST_SYSTEM)
{
  RSysTopology * topo;
  RSysNode * node;
  RSysCpu * cpu;
  rsize i, j, nodecount, cpucount, cores = 0, cpus = 0;
  rsize namedcore = 0, namedpkg = 0;
  RBitset * cpuset, * siblings, * online;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()));
  r_assert (r_bitset_init_stack (siblings, r_sys_cpuset_max ()));
  r_assert (r_bitset_init_stack (online, r_sys_cpuset_max ()));
  r_assert (r_sys_cpuset_online (online));

  r_assert_cmpuint (r_sys_topology_cpu_id (NULL), ==, R_SYS_ID_UNKNOWN);
  r_assert_cmpuint (r_sys_topology_cpu_node_id (NULL), ==, R_SYS_ID_UNKNOWN);
  r_assert_cmpuint (r_sys_topology_cpu_core_id (NULL), ==, R_SYS_ID_UNKNOWN);
  r_assert_cmpuint (r_sys_topology_cpu_package_id (NULL), ==, R_SYS_ID_UNKNOWN);
  r_assert (!r_sys_topology_cpu_siblings (NULL, siblings));

  r_assert_cmpptr ((topo = r_sys_topology_discover ()), !=, NULL);
  for (i = 0, nodecount = r_sys_topology_node_count (topo); i < nodecount; i++) {
    r_assert_cmpptr ((node = r_sys_topology_node (topo, i)), !=, NULL);
    r_bitset_clear (cpuset);
    r_assert (r_sys_topology_node_cpuset (node, cpuset));
    cpucount = r_sys_topology_node_cpu_count (node);

    for (j = 0; j < cpucount; j++) {
      rsize id;

      r_assert_cmpptr ((cpu = r_sys_topology_node_cpu (node, j)), !=, NULL);
      r_assert (r_bitset_is_bit_set (cpuset, (id = r_sys_topology_cpu_id (cpu))));
      r_assert_cmpuint (r_sys_topology_cpu_node_id (cpu), ==, i);

      r_bitset_clear (siblings);
      r_assert (r_sys_topology_cpu_siblings (cpu, siblings));
      r_assert (r_bitset_is_bit_set (siblings, id));
      /* Siblings are online CPUs and nothing but. */
      r_assert (r_bitset_and (siblings, siblings, online));
      r_assert (r_bitset_is_bit_set (siblings, id));
      /* Count the lowest-numbered thread of each SMT group: the SMT
       * groups partition the logical CPUs, one group per core. */
      if (r_bitset_ctz (siblings) == id)
        cores++;

      /* sysfs reports an id it does not know as -1, so a platform may
       * legitimately name neither - but naming only some of the CPUs
       * means the read went wrong. */
      if (r_sys_topology_cpu_core_id (cpu) != R_SYS_ID_UNKNOWN) namedcore++;
      if (r_sys_topology_cpu_package_id (cpu) != R_SYS_ID_UNKNOWN) namedpkg++;
      cpus++;

      r_sys_cpu_unref (cpu);
    }

    r_sys_node_unref (node);
  }
  r_sys_topology_unref (topo);

  r_assert_cmpuint (cores, ==, r_sys_cpu_physical_count ());
  r_assert (namedcore == 0 || namedcore == cpus);
  r_assert (namedpkg == 0 || namedpkg == cpus);
}
RTEST_END;

RTEST (rsys, topology_cpu_cache, RTEST_FAST | RTEST_SYSTEM)
{
  RSysTopology * topo;
  RSysNode * node;
  RSysCpu * cpu;
  RSysCpuCache cache;
  rsize i, j, k, nodecount, cpucount, cachecount;
  RBitset * cpuset, * online;

  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()));
  r_assert (r_bitset_init_stack (online, r_sys_cpuset_max ()));
  r_assert (r_sys_cpuset_online (online));

  r_assert_cmpuint (r_sys_topology_cpu_cache_count (NULL), ==, 0);
  r_assert (!r_sys_topology_cpu_cache (NULL, 0, &cache));
  r_assert (!r_sys_topology_cpu_cache_cpuset (NULL, 0, cpuset));

  r_assert_cmpptr ((topo = r_sys_topology_discover ()), !=, NULL);
  for (i = 0, nodecount = r_sys_topology_node_count (topo); i < nodecount; i++) {
    r_assert_cmpptr ((node = r_sys_topology_node (topo, i)), !=, NULL);
    cpucount = r_sys_topology_node_cpu_count (node);

    for (j = 0; j < cpucount; j++) {
      ruint level = 0;

      r_assert_cmpptr ((cpu = r_sys_topology_node_cpu (node, j)), !=, NULL);
      cachecount = r_sys_topology_cpu_cache_count (cpu);
      r_assert (!r_sys_topology_cpu_cache (cpu, cachecount, &cache));
      r_assert (!r_sys_topology_cpu_cache_cpuset (cpu, cachecount, cpuset));
      r_assert (!r_sys_topology_cpu_cache (cpu, 0, NULL));
#if defined (R_OS_LINUX) || defined (R_OS_WIN32) || defined (R_OS_DARWIN)
      r_assert_cmpuint (cachecount, >, 0);
#endif

      for (k = 0; k < cachecount; k++) {
        r_assert (r_sys_topology_cpu_cache (cpu, k, &cache));
        r_assert_cmpuint (cache.level, >=, 1);
        /* Ordered from the core outwards. */
        r_assert_cmpuint (cache.level, >=, level);
        level = cache.level;
        r_assert_cmpuint (cache.size, >, 0);

        r_bitset_clear (cpuset);
        r_assert (r_sys_topology_cpu_cache_cpuset (cpu, k, cpuset));
        r_assert (r_bitset_is_bit_set (cpuset, r_sys_topology_cpu_id (cpu)));
        /* Nothing offline shares a cache with an online CPU. */
        r_assert (r_bitset_and (cpuset, cpuset, online));
        r_assert (r_bitset_is_bit_set (cpuset, r_sys_topology_cpu_id (cpu)));
      }

      r_sys_cpu_unref (cpu);
    }

    r_sys_node_unref (node);
  }
  r_sys_topology_unref (topo);
}
RTEST_END;
#endif /* !R_OS_ANDROID */

RTEST (rsys, topology_node_capabilities, RTEST_FAST | RTEST_SYSTEM)
{
  RSysTopology * topo;
  RSysNode * node;
  rsize i, nodecount;
  ruint nodes_with_cpu = 0, nodes_with_memory = 0;

  r_assert_cmpptr ((topo = r_sys_topology_discover ()), !=, NULL);
  for (i = 0, nodecount = r_sys_topology_node_count (topo); i < nodecount; i++) {
    r_assert_cmpptr ((node = r_sys_topology_node (topo, i)), !=, NULL);
    if (r_sys_topology_node_cpu_count (node) > 0) nodes_with_cpu++;
    if (r_sys_topology_node_available_memory (node) > 0) nodes_with_memory++;
    r_sys_node_unref (node);
  }
  r_sys_topology_unref (topo);

  r_assert_cmpuint (r_sys_node_count_with_online_cpus (), ==, nodes_with_cpu);
  /* FIXME: Read out available memory */
  /*r_assert_cmpuint (r_sys_node_count_with_memory (), ==, nodes_with_memory);*/
  (void) nodes_with_memory;
}
RTEST_END;

