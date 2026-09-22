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
#error "#include <rlib.h> only please."
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
 * use the @c _ref / @c _unref aliases. The @c r_sys_topology_node /
 * @c r_sys_topology_node_cpu accessors return a @b new reference that
 * the caller must @c _unref.
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
/** @brief Return the @p idx-th node of @p topo as a new reference
 *  (caller @c r_sys_node_unref's), or @c NULL if out of range. */
R_API RSysNode * r_sys_topology_node (RSysTopology * topo, rsize idx);

/** @brief Fill @p cpuset with the CPUs belonging to @p node. */
R_API rboolean r_sys_topology_node_cpuset (const RSysNode * node, RBitset * cpuset);
/** @brief Number of CPUs in @p node. */
R_API rsize r_sys_topology_node_cpu_count (const RSysNode * node);
/** @brief Return the @p idx-th CPU of @p node as a new reference
 *  (caller @c r_sys_cpu_unref's), or @c NULL if out of range. */
R_API RSysCpu * r_sys_topology_node_cpu (RSysNode * node, rsize idx);
/**
 * @brief Bytes of available (free) memory local to @p node, or 0 when
 * the platform does not expose it (e.g. non-NUMA macOS).
 */
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

/**
 * @brief Returned by the topology id accessors when the platform does
 * not name that part of the topology.
 *
 * Zero is a valid core, package and node id, so "unknown" needs a
 * sentinel of its own.
 */
#define R_SYS_ID_UNKNOWN  RSIZE_MAX

/** @brief What an @ref RSysCpuCache level holds. */
typedef enum {
  R_SYS_CPU_CACHE_UNIFIED = 0,    /**< Instructions and data. */
  R_SYS_CPU_CACHE_DATA,           /**< Data only. */
  R_SYS_CPU_CACHE_INSTRUCTION,    /**< Instructions only. */
  R_SYS_CPU_CACHE_TRACE           /**< Decoded-instruction trace cache. */
} RSysCpuCacheType;

/**
 * @brief One level of a CPU's cache hierarchy.
 *
 * Every field but @c level and @c type is 0 when the platform does not
 * report it - Darwin, for instance, gives sizes and the line size but
 * neither associativity nor set count.
 */
typedef struct {
  ruint level;                    /**< 1-based cache level (1 = L1). */
  RSysCpuCacheType type;          /**< What the level caches. */
  rsize size;                     /**< Total capacity in bytes. */
  rsize linesize;                 /**< Coherency line size in bytes. */
  rsize ways;                     /**< Ways per set (associativity). */
  rsize sets;                     /**< Number of sets. */
} RSysCpuCache;

/** @name CPU attributes
 *
 * Per-CPU detail for an @ref RSysCpu handed out by
 * @ref r_sys_topology_node_cpu. Core and package ids only mean
 * anything compared against each other ("same core?"); a platform
 * that does not name them gets enumeration ordinals instead, so
 * neither is safe to use as an array index.
 *  @{ */
/** @brief Logical CPU index, i.e. the bit this CPU occupies in a cpuset. */
R_API rsize r_sys_topology_cpu_id (const RSysCpu * cpu);
/** @brief Index of the NUMA node @p cpu belongs to. */
R_API rsize r_sys_topology_cpu_node_id (const RSysCpu * cpu);
/**
 * @brief Physical core id of @p cpu, or @ref R_SYS_ID_UNKNOWN.
 *
 * Only unique within a package: two CPUs are on the same physical core
 * iff their core @b and package ids match.
 */
R_API rsize r_sys_topology_cpu_core_id (const RSysCpu * cpu);
/** @brief Physical package (socket) id of @p cpu, or
 *  @ref R_SYS_ID_UNKNOWN. */
R_API rsize r_sys_topology_cpu_package_id (const RSysCpu * cpu);
/**
 * @brief Fill @p cpuset with the SMT thread siblings of @p cpu.
 *
 * The set includes @p cpu itself, so a machine without SMT (or a
 * platform that does not report siblings) yields a single bit.
 *
 * @param cpu    CPU to query.
 * @param cpuset Destination, sized by @ref r_sys_cpuset_max.
 * @return @c TRUE on success.
 */
R_API rboolean r_sys_topology_cpu_siblings (const RSysCpu * cpu, RBitset * cpuset);

/**
 * @brief Number of cache levels reported for @p cpu.
 *
 * 0 on a platform that exposes no cache topology. Split L1s count as
 * two levels, one @ref R_SYS_CPU_CACHE_DATA and one
 * @ref R_SYS_CPU_CACHE_INSTRUCTION.
 */
R_API rsize r_sys_topology_cpu_cache_count (const RSysCpu * cpu);
/**
 * @brief Copy the @p idx-th cache level of @p cpu into @p cache.
 *
 * Levels are ordered by increasing @c level, so index 0 is the
 * closest cache to the core.
 *
 * @param cpu   CPU to query.
 * @param idx   Cache index, below @ref r_sys_topology_cpu_cache_count.
 * @param cache Destination (must be non-NULL).
 * @return @c TRUE on success, @c FALSE if @p idx is out of range.
 */
R_API rboolean r_sys_topology_cpu_cache (const RSysCpu * cpu, rsize idx,
    RSysCpuCache * cache);
/**
 * @brief Fill @p cpuset with the CPUs sharing @p cpu's @p idx-th cache.
 *
 * Includes @p cpu itself. A private cache yields a single bit; an L3
 * shared across a package yields every CPU in it.
 *
 * @param cpu    CPU to query.
 * @param idx    Cache index, below @ref r_sys_topology_cpu_cache_count.
 * @param cpuset Destination, sized by @ref r_sys_cpuset_max.
 * @return @c TRUE on success, @c FALSE if @p idx is out of range.
 */
R_API rboolean r_sys_topology_cpu_cache_cpuset (const RSysCpu * cpu, rsize idx,
    RBitset * cpuset);
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_SYS_H__ */

