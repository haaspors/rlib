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

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rbitset.h>

R_BEGIN_DECLS

R_API ruint r_sys_cpu_packages (void);
R_API ruint r_sys_cpu_physical_count (void);
R_API ruint r_sys_cpu_logical_count (void);
R_API ruint r_sys_cpu_max_count (void);

R_API ruint r_sys_cpuset_max_count (void);
R_API rboolean r_sys_cpuset_possible (RBitset * cpuset);
R_API rboolean r_sys_cpuset_present (RBitset * cpuset);
R_API rboolean r_sys_cpuset_online (RBitset * cpuset);
R_API rboolean r_sys_cpuset_allowed (RBitset * cpuset);

R_API ruint r_sys_node_count (void);

/* Topology API */
typedef struct _RSysTopology  RSysTopology;
typedef struct _RSysNode      RSysNode;
typedef struct _RSysCpu       RSysCpu;

R_API RSysTopology * r_sys_topology_discover (void);

R_API rsize r_sys_topology_node_count (const RSysTopology * topo);
R_API RSysNode * r_sys_topology_node (RSysTopology * topo, rsize idx);

R_API rboolean r_sys_topology_node_cpuset (const RSysNode * node, RBitset * cpuset);
R_API rsize r_sys_topology_node_cpu_count (const RSysNode * node);
R_API RSysCpu * r_sys_topology_node_cpu (RSysNode * node, rsize idx);

#define r_sys_topology_ref    r_ref_ref
#define r_sys_topology_unref  r_ref_unref
#define r_sys_node_ref        r_ref_ref
#define r_sys_node_unref      r_ref_unref
#define r_sys_cpu_ref         r_ref_ref
#define r_sys_cpu_unref       r_ref_unref

R_END_DECLS

#endif /* __R_SYS_H__ */

