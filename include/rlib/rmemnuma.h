/* RLIB - Convenience library for useful things
 * Copyright (C) 2026  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
/**
 * @defgroup r_mem_numa NUMA-aware page allocation
 * @ingroup r_mem
 * @brief Allocate page-granular memory bound to a NUMA node, or
 * interleaved across a set of them.
 * @{
 */

/**
 * @file rlib/rmemnuma.h
 * @brief NUMA placement for whole-page allocations.
 *
 * Where a large buffer lands decides how fast the threads touching it
 * run, so these place it deliberately - bound to one node, or spread
 * across several to share their combined bandwidth - instead of
 * leaving it to the system's default policy.
 *
 * Whole pages straight from the OS, deliberately outside the
 * @c RMemVTable the @c r_malloc family routes through: placement is a
 * property of the mapping, so an allocator backend has no say in it.
 * Use this for buffers worth a mapping of their own. Release them with
 * @ref r_mem_numa_free and never with @c r_free.
 *
 * Where placement is not enforced (see @ref r_mem_numa_available) the
 * allocators still return usable memory, just wherever the system
 * would have put it. Node indices are the ones
 * @ref r_sys_topology_node_id reports, so the topology in
 * @c rlib/os/rsys.h and the allocations here agree on what "node 2"
 * means.
 */
#ifndef __R_MEM_NUMA_H__
#define __R_MEM_NUMA_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>

#include <rlib/data/rbitset.h>

R_BEGIN_DECLS

/**
 * @brief Whether this build and this machine actually place
 * allocations on the node they are asked for.
 *
 * @c FALSE means every call here still works, but the allocators fall
 * back to the system's default placement and the re-placement calls
 * fail outright.
 *
 * Placement being enforced does not imply a range can be re-placed
 * after the fact: win32 fixes it at allocation time, so
 * @ref r_mem_numa_bind and @ref r_mem_numa_interleave fail there
 * regardless.
 *
 * @return @c TRUE if the platform honours node placement.
 */
R_API rboolean r_mem_numa_available (void);

/**
 * @brief Granularity every allocation here is rounded up to.
 *
 * The system page size. The bytes between a requested size and the
 * page boundary are usable.
 *
 * @return Page size in bytes (never 0).
 */
R_API rsize r_mem_numa_page_size (void);

/**
 * @brief Allocate @p size bytes placed by the system's default policy.
 *
 * In practice that means first touch: each page lands on the node of
 * whichever CPU first writes to it, which is exactly what you want
 * when the thread that fills a buffer is also the one that reads it.
 * Unlike the other two allocators this needs no NUMA support, so it
 * is the portable way to get page-granular memory from this API.
 *
 * @param size Bytes required (rounded up to a page).
 * @return Zero-filled allocation, or @c NULL on failure.
 */
R_API rpointer r_mem_numa_alloc_local (rsize size) R_ATTR_MALLOC;

/**
 * @brief Allocate @p size bytes bound to NUMA node @p node.
 *
 * Every page comes from @p node's memory, whichever CPU touches it.
 * Where placement is not enforced (see @ref r_mem_numa_available) the
 * allocation still succeeds with default placement rather than
 * failing.
 *
 * @param size Bytes required (rounded up to a page).
 * @param node Node index, as reported by @ref r_sys_topology_node_id.
 * @return Zero-filled allocation, or @c NULL on failure.
 */
R_API rpointer r_mem_numa_alloc_onnode (rsize size, ruint node) R_ATTR_MALLOC;

/**
 * @brief Allocate @p size bytes spread page-by-page across @p nodeset.
 *
 * Trades the latency of a local binding for the combined bandwidth of
 * several nodes, which pays off for a buffer read by threads on all of
 * them. Falls back to default placement where interleaving is not
 * supported, which includes win32 - it can place an allocation on one
 * chosen node but not spread it over several.
 *
 * @param size    Bytes required (rounded up to a page).
 * @param nodeset Nodes to interleave over; @c NULL or empty means
 *                every node this process is allowed to allocate from.
 * @return Zero-filled allocation, or @c NULL on failure.
 */
R_API rpointer r_mem_numa_alloc_interleaved (rsize size,
    const RBitset * nodeset) R_ATTR_MALLOC;

/**
 * @brief Release an allocation from this API.
 *
 * @param ptr  Allocation from @ref r_mem_numa_alloc_local /
 *             @ref r_mem_numa_alloc_onnode /
 *             @ref r_mem_numa_alloc_interleaved. @c NULL is a no-op.
 * @param size The same @p size that was allocated - the mapping has
 *             to be unmapped at the length it was created with.
 */
R_API void r_mem_numa_free (rpointer ptr, rsize size);

/**
 * @brief Bind the pages spanning @p ptr to node @p node.
 *
 * Works on a whole allocation or on a page-aligned slice of one, so a
 * single mapping can be cut up per worker thread. Pages already
 * faulted in are left where they are; only pages touched from here on
 * follow the new binding.
 *
 * @param ptr  Start of the range (rounded down to a page boundary).
 * @param size Range length in bytes.
 * @param node Node index, as reported by @ref r_sys_topology_node_id.
 * @return @c TRUE on success, @c FALSE if @p node does not exist or
 *         the platform cannot re-place a live range (win32 among
 *         them - allocate with @ref r_mem_numa_alloc_onnode instead).
 */
R_API rboolean r_mem_numa_bind (rpointer ptr, rsize size, ruint node);

/**
 * @brief Interleave the pages spanning @p ptr across @p nodeset.
 *
 * The @ref r_mem_numa_bind notes on alignment and already-faulted
 * pages apply here too.
 *
 * @param ptr     Start of the range (rounded down to a page boundary).
 * @param size    Range length in bytes.
 * @param nodeset Nodes to interleave over; @c NULL or empty means
 *                every node this process is allowed to allocate from.
 * @return @c TRUE on success, @c FALSE if the platform cannot
 *         re-place a live range.
 */
R_API rboolean r_mem_numa_interleave (rpointer ptr, rsize size,
    const RBitset * nodeset);

/**
 * @brief Which node currently backs the page containing @p ptr.
 *
 * Reports where a page actually ended up, which is the only way to
 * confirm a first-touch policy did what you expected. Faults the page
 * in to answer, so the very call that asks is what decides the answer
 * for an untouched page.
 *
 * @param ptr  Address inside a mapped page.
 * @param node Receives the node index (must be non-NULL).
 * @return @c TRUE on success, @c FALSE if the platform cannot report
 *         it or @p ptr is not mapped.
 */
R_API rboolean r_mem_numa_node_of (rconstpointer ptr, ruint * node);

R_END_DECLS

/** @} */

#endif /* __R_MEM_NUMA_H__ */
