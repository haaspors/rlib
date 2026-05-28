/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_SYS_H__
#define __R_SYS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/os/rsys.h
 * @brief CPU / NUMA-node counts and sets, plus a refcounted hardware
 * topology object.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rbitset.h>

/**
 * @defgroup r_sys System and hardware topology
 * @ingroup r_os
 *
 * @brief Query CPU and NUMA-node counts, build @ref RBitset masks of
 * the available CPUs / nodes, and walk a discovered hardware
 * topology.
 *
 * The stateless @c r_sys_cpu_* / @c r_sys_node_* / @c r_sys_*set_*
 * calls answer one-off questions ("how many logical CPUs?", "which
 * CPUs are online?"). For repeated structured access, discover an
 * @ref RSysTopology once and walk its nodes and CPUs.
 *
 * @{
 */

R_BEGIN_DECLS

/** @name CPU counts
 *  @{ */
/** @brief Number of physical CPU packages (sockets). */
R_API ruint r_sys_cpu_packages (void);
/** @brief Number of physical cores. */
R_API ruint r_sys_cpu_physical_count (void);
/** @brief Number of logical CPUs (hardware threads). */
R_API ruint r_sys_cpu_logical_count (void);
/** @brief Number of CPUs this process is allowed to run on. */
R_API ruint r_sys_cpu_allowed_count (void);
/** @brief Maximum possible CPU count the system can have. */
R_API ruint r_sys_cpu_max_count (void);
/** @} */

/** @name CPU sets
 *  @{ */
/** @brief Highest valid CPU index + 1 (sizing hint for a cpuset). */
R_API ruint r_sys_cpuset_max (void);
/** @brief Allocate a @ref RBitset sized to hold every possible CPU. */
R_API RBitset * r_sys_cpuset_new (void) R_ATTR_MALLOC;
/** @brief Fill @p cpuset with all CPUs the system could ever have. */
R_API rboolean r_sys_cpuset_possible (RBitset * cpuset);
/** @brief Fill @p cpuset with the physically-present CPUs. */
R_API rboolean r_sys_cpuset_present (RBitset * cpuset);
/** @brief Fill @p cpuset with the currently-online CPUs. */
R_API rboolean r_sys_cpuset_online (RBitset * cpuset);
/** @brief Fill @p cpuset with the CPUs this process may run on. */
R_API rboolean r_sys_cpuset_allowed (RBitset * cpuset);

/** @brief Fill @p cpuset with the CPUs belonging to NUMA @p node. */
R_API rboolean r_sys_cpuset_for_node (RBitset * cpuset, ruint node);
/** @} */

/** @name NUMA-node counts
 *  @{ */
/** @brief Total number of NUMA nodes. */
R_API ruint r_sys_node_count (void);
/** @brief Number of nodes that have at least one online CPU. */
R_API ruint r_sys_node_count_with_online_cpus (void);
/** @brief Number of nodes that have at least one allowed CPU. */
R_API ruint r_sys_node_count_with_allowed_cpus (void);
/** @} */

/** @name NUMA-node sets
 *  @{ */
/** @brief Highest valid node index + 1 (sizing hint for a nodeset). */
R_API ruint r_sys_nodeset_max (void);
/** @brief Allocate a @ref RBitset sized to hold every possible node. */
R_API RBitset * r_sys_nodeset_new (void) R_ATTR_MALLOC;
/** @brief Fill @p nodeset with all nodes the system could have. */
R_API rboolean r_sys_nodeset_possible (RBitset * nodeset);
/** @brief Fill @p nodeset with the currently-online nodes. */
R_API rboolean r_sys_nodeset_online (RBitset * nodeset);
/** @brief Fill @p nodeset with nodes that have online CPUs. */
R_API rboolean r_sys_nodeset_with_online_cpus (RBitset * nodeset);
/** @brief Fill @p nodeset with nodes that have allowed CPUs. */
R_API rboolean r_sys_nodeset_with_allowed_cpus (RBitset * nodeset);

/** @brief Fill @p nodeset with the nodes spanned by @p cpuset. */
R_API rboolean r_sys_nodeset_for_cpuset (RBitset * nodeset, const RBitset * cpuset);
/** @} */

/** @name Topology objects
 *
 * @ref RSysTopology / @ref RSysNode / @ref RSysCpu are refcounted;
 * use the @c _ref / @c _unref aliases. Nodes and CPUs are owned by
 * their parent topology.
 *  @{ */
/** @brief Opaque, refcounted hardware-topology snapshot. */
typedef struct RSysTopology  RSysTopology;
/** @brief Opaque, refcounted NUMA node within a topology. */
typedef struct RSysNode      RSysNode;
/** @brief Opaque, refcounted CPU within a topology node. */
typedef struct RSysCpu       RSysCpu;

/** @brief Discover the current hardware topology. */
R_API RSysTopology * r_sys_topology_discover (void);

/** @brief Number of NUMA nodes in @p topo. */
R_API rsize r_sys_topology_node_count (const RSysTopology * topo);
/** @brief Return the @p idx-th node of @p topo (borrowed). */
R_API RSysNode * r_sys_topology_node (RSysTopology * topo, rsize idx);

/** @brief Fill @p cpuset with the CPUs belonging to @p node. */
R_API rboolean r_sys_topology_node_cpuset (const RSysNode * node, RBitset * cpuset);
/** @brief Number of CPUs in @p node. */
R_API rsize r_sys_topology_node_cpu_count (const RSysNode * node);
/** @brief Return the @p idx-th CPU of @p node (borrowed). */
R_API RSysCpu * r_sys_topology_node_cpu (RSysNode * node, rsize idx);
/** @brief Bytes of memory local to @p node. */
R_API rsize r_sys_topology_node_available_memory (const RSysNode * node);

/** @brief Take a reference on a topology (alias for @ref r_ref_ref). */
#define r_sys_topology_ref    r_ref_ref
/** @brief Drop a reference on a topology (alias for @ref r_ref_unref). */
#define r_sys_topology_unref  r_ref_unref
/** @brief Take a reference on a node (alias for @ref r_ref_ref). */
#define r_sys_node_ref        r_ref_ref
/** @brief Drop a reference on a node (alias for @ref r_ref_unref). */
#define r_sys_node_unref      r_ref_unref
/** @brief Take a reference on a CPU (alias for @ref r_ref_ref). */
#define r_sys_cpu_ref         r_ref_ref
/** @brief Drop a reference on a CPU (alias for @ref r_ref_unref). */
#define r_sys_cpu_unref       r_ref_unref
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_SYS_H__ */

