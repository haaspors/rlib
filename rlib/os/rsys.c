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

#include "config.h"
#include "rlib-private.h"

#include <rlib/file/rfile.h>
#include <rlib/os/rsys.h>

#include <rlib/rlog.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#ifdef R_OS_WIN32
#include <windows.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef R_OS_LINUX
#define R_SYSFS_CPU                   "/sys/devices/system/cpu"
#define R_SYSFS_CPU_FMT               "/sys/devices/system/cpu/cpu%u"

#define R_SYSFS_CPU_TOPO_PKG_ID       "/topology/physical_package_id"
#define R_SYSFS_CPU_TOPO_THR_SIB_LST  "/topology/thread_siblings_list"

#define R_SYSFS_NODE                  "/sys/devices/system/node"
#define R_SYSFS_NODE_FMT              "/sys/devices/system/node/node%u"

#include <rlib/rthreads.h>
#endif

#define R_LOG_CAT_DEFAULT &rlib_logcat

#if defined (R_OS_WIN32)
static PSYSTEM_LOGICAL_PROCESSOR_INFORMATION
r_sys_cpu_win32_get_logical_proc_info (ruint * count)
{
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION ret = NULL;
  DWORD retlen = 0;

  GetLogicalProcessorInformation (ret, &retlen);
  if (retlen == 0)
    return NULL;

  if ((ret = r_malloc (retlen)) != NULL) {
    if (GetLogicalProcessorInformation (ret, &retlen)) {
      *count = retlen / sizeof (SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    } else {
      r_free (ret);
      ret = NULL;
    }
  }

  return ret;
}
#endif

#if defined (R_OS_LINUX)
static rpointer
_max_cpu_func (rpointer data)
{
  ruint ret;
  (void) data;
  ret = r_file_read_uint (R_SYSFS_CPU "/kernel_max", RUINT_MAX);
  return RUINT_TO_POINTER (ret + 1);
}

static ROnce maxcpuonce = R_ONCE_INIT;
#define r_sys_cpu_linux_max_cpus() RPOINTER_TO_UINT (r_call_once (&maxcpuonce, _max_cpu_func, NULL))

static void
r_sys_cpu_linux_package_func (rsize bit, rpointer data)
{
  rchar tmp[256];
  RBitset * pack = data;

  r_snprintf (tmp, sizeof (tmp), R_SYSFS_CPU_FMT R_SYSFS_CPU_TOPO_PKG_ID,
      (ruint)bit);
  if (!r_bitset_set_bit (pack, r_file_read_uint (tmp, pack->bits), TRUE))
    R_LOG_WARNING ("Found weird package ID in %s", tmp);
}

static void
r_sys_cpu_linux_phys_func (rsize bit, rpointer data)
{
  rchar tmp[256];
  RBitset * phys = data;
  r_snprintf (tmp, sizeof (tmp), R_SYSFS_CPU_FMT R_SYSFS_CPU_TOPO_THR_SIB_LST,
      (ruint)bit);

  /* This reads the first number out of the human readable list file */
  if (!r_bitset_set_bit (phys, r_file_read_uint (tmp, phys->bits), TRUE))
    R_LOG_WARNING ("Found weird siblings ID in %s", tmp);
}
#endif

ruint
r_sys_cpu_packages (void)
{
  ruint ret = 0;

#if defined (R_OS_WIN32)
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION info;
  ruint i, count;

  if ((info = r_sys_cpu_win32_get_logical_proc_info (&count)) != NULL) {
    for (i = 0; i < count; i++) {
      if (info[i].Relationship == RelationProcessorPackage)
        ret++;
    }

    r_free (info);
  }
#elif defined (HAVE_SYSCTLBYNAME)
  ruint32 count;
  size_t size = sizeof (ruint32);

  if (sysctlbyname ("hw.packages", &count, &size, NULL, 0) == 0)
    ret = count;
#elif defined (R_OS_LINUX)
  RBitset * online, * packs;
  ruint max = r_sys_cpu_linux_max_cpus ();
  if (r_bitset_init_stack (online, max) && r_bitset_init_stack (packs, max)) {
    r_bitset_set_from_human_readable_file (online, R_SYSFS_CPU "/online", NULL);
    r_bitset_foreach (online, TRUE, r_sys_cpu_linux_package_func, packs);
    ret = r_bitset_popcount (packs);
  }
#endif

  return ret;
}

ruint
r_sys_cpu_physical_count (void)
{
  ruint ret = 0;

#if defined (R_OS_WIN32)
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION info;
  ruint i, count;

  if ((info = r_sys_cpu_win32_get_logical_proc_info (&count)) != NULL) {
    for (i = 0; i < count; i++) {
      if (info[i].Relationship == RelationProcessorCore)
        ret++;
    }

    r_free (info);
  }
#elif defined (HAVE_SYSCTLBYNAME)
  ruint32 count;
  size_t size = sizeof (ruint32);

  if (sysctlbyname ("hw.physicalcpu", &count, &size, NULL, 0) == 0)
    ret = count;
#elif defined (R_OS_LINUX)
  RBitset * online, * phys;
  ruint max = r_sys_cpu_linux_max_cpus ();
  if (r_bitset_init_stack (online, max) && r_bitset_init_stack (phys, max)) {
    r_bitset_set_from_human_readable_file (online, R_SYSFS_CPU "/online", NULL);
    r_bitset_foreach (online, TRUE, r_sys_cpu_linux_phys_func, phys);
    ret = r_bitset_popcount (phys);
  }
#endif

  return ret;
}

ruint
r_sys_cpu_logical_count (void)
{
  ruint ret = 0;

#if defined (R_OS_WIN32)
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION info;
  ruint i, count;

  if ((info = r_sys_cpu_win32_get_logical_proc_info (&count)) != NULL) {
    for (i = 0; i < count; i++) {
      if (info[i].Relationship == RelationProcessorCore) {
        ret += RSIZE_POPCOUNT (info[i].ProcessorMask);
      }
    }

    r_free (info);
  }
#elif defined (HAVE_SYSCTLBYNAME)
  ruint32 count;
  size_t size = sizeof (ruint32);

  if (sysctlbyname ("hw.logicalcpu", &count, &size, NULL, 0) == 0)
    ret = count;
#elif defined (R_OS_LINUX)
  RBitset * online;
  if (r_bitset_init_stack (online, r_sys_cpu_linux_max_cpus ())) {
    r_bitset_set_from_human_readable_file (online, R_SYSFS_CPU "/online", NULL);
    ret = r_bitset_popcount (online);
  }
#endif

  return ret;
}

ruint
r_sys_cpu_max_count (void)
{
  ruint ret;

#if defined (R_OS_WIN32)
  ret = sizeof (ULONGLONG) * 8;
#elif defined (HAVE_SYSCTLBYNAME)
  ret = 256;
#elif defined (R_OS_LINUX)
  ret = r_sys_cpu_linux_max_cpus ();
#else
  ret = 0;
#endif

  return ret;
}

ruint
r_sys_cpuset_max_count (void)
{
  ruint ret = r_sys_cpu_max_count ();
  return MAX (ret, 1024);
}

rboolean
r_sys_cpuset_possible (RBitset * cpuset)
{
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  r_bitset_clear (cpuset);
#if defined (R_OS_LINUX)
  return r_bitset_set_from_human_readable_file (cpuset, R_SYSFS_CPU "/possible", NULL);
#else
  return r_bitset_set_n_bits_at (cpuset, r_sys_cpu_logical_count (), 0, TRUE);
#endif
}

rboolean
r_sys_cpuset_present (RBitset * cpuset)
{
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  r_bitset_clear (cpuset);
#if defined (R_OS_LINUX)
  return r_bitset_set_from_human_readable_file (cpuset, R_SYSFS_CPU "/present", NULL);
#else
  return r_bitset_set_n_bits_at (cpuset, r_sys_cpu_logical_count (), 0, TRUE);
#endif
}

rboolean
r_sys_cpuset_online (RBitset * cpuset)
{
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  r_bitset_clear (cpuset);
#if defined (R_OS_LINUX)
  return r_bitset_set_from_human_readable_file (cpuset, R_SYSFS_CPU "/online", NULL);
#else
  return r_bitset_set_n_bits_at (cpuset, r_sys_cpu_logical_count (), 0, TRUE);
#endif
}

rboolean
r_sys_cpuset_allowed (RBitset * cpuset)
{
  rboolean ret = FALSE;

  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  r_bitset_clear (cpuset);
#if defined (R_OS_LINUX)
  if (r_bitset_set_from_human_readable_file (cpuset, R_SYSFS_CPU "/online", NULL)) {
    RFile * f;

    if ((f = r_file_open ("/proc/self/status", "r")) != NULL) {
      rchar buf[256];
      while (r_file_read_line (f, buf, sizeof (buf)) == R_FILE_ERROR_OK) {
        if (r_str_has_prefix (buf, "Cpus_allowed_list:")) {
          RBitset * bs;
          ret = r_bitset_init_stack (bs, cpuset->bits) &&
            r_bitset_set_from_human_readable (bs, buf + 18, NULL) &&
            r_bitset_and (cpuset, cpuset, bs);
          break;
        }
      }
      r_file_unref (f);
    }
  }
#else
  ret = r_bitset_set_n_bits_at (cpuset, r_sys_cpu_logical_count (), 0, TRUE);
#endif
  return ret;
}

ruint
r_sys_node_count (void)
{
  ruint ret = 0;

#if defined (R_OS_WIN32)
  ULONG hnn = 0;
  if (GetNumaHighestNodeNumber (&hnn))
    ret = ((ruint)hnn) + 1;
#elif defined (HAVE_SYSCTLBYNAME)
  size_t size = 0;

  if (sysctlbyname("hw.cacheconfig", NULL, &size, NULL, 0) == 0) {
    ruint64 * cc = r_alloca (size);
    if (sysctlbyname("hw.cacheconfig", cc, &size, NULL, 0) == 0)
      ret = r_sys_cpu_logical_count () / cc[0];
  }
#elif defined (R_OS_LINUX)
  RBitset * online;
  if (r_bitset_init_stack (online, r_sys_cpu_linux_max_cpus ())) {
    r_bitset_set_from_human_readable_file (online, R_SYSFS_NODE "/online", NULL);
    ret = r_bitset_popcount (online);
  }
#endif

  return ret;
}


struct _RSysTopology {
  RRef ref;

#if defined (HAVE_SYSCTLBYNAME)
  rsize     cachelvl;
  ruint64 * cachecfg;
#endif

  RBitset * nodeset;
  rsize nodecount;
  RSysNode ** nodes;
};
struct _RSysNode {
  RRef ref;

  rsize idx;
  rsize availablemem;

  RBitset * cpuset;
  rsize cpucount;
  RSysCpu ** cpus;
};
struct _RSysCpu {
  RRef ref;
  rsize idx;

  RSysNode * node;
};

static void
r_sys_topology_free (RSysTopology * topo)
{
  if (R_LIKELY (topo != NULL)) {
    rsize i;
#if defined (HAVE_SYSCTLBYNAME)
    r_free (topo->cachecfg);
#endif
    for (i = 0; i < topo->nodecount; i++)
      r_sys_node_unref (topo->nodes[i]);
    r_free (topo->nodes);
    r_free (topo->nodeset);
    r_free (topo);
  }
}

static void
r_sys_node_free (RSysNode * node)
{
  if (R_LIKELY (node != NULL)) {
    rsize i;
    for (i = 0; i < node->cpucount; i++)
      r_sys_cpu_unref (node->cpus[i]);
    r_free (node->cpus);
    r_free (node->cpuset);
    r_free (node);
  }
}

static void
r_sys_cpu_free (RSysCpu * cpu)
{
  if (R_LIKELY (cpu != NULL)) {
    r_free (cpu);
  }
}

static RSysCpu *
r_sys_cpu_discover (rsize idx, RSysNode * node)
{
  RSysCpu * ret;

  if ((ret = r_mem_new0 (RSysCpu)) != NULL) {
    r_ref_init (ret, r_sys_cpu_free);
    ret->idx = idx;
    ret->node = node;

    /* TODO! */
  }

  return ret;
}

static void
r_sys_topology_prepend_cpu (rsize bit, rpointer data)
{
  RSysNode * node = data;
  node->cpus[node->cpucount++] = r_sys_cpu_discover (bit, node);
}

static RSysNode *
r_sys_node_discover (rsize idx, RSysTopology * topo)
{
  RSysNode * ret;

  (void) topo;

  if ((ret = r_mem_new0 (RSysNode)) != NULL) {
    r_ref_init (ret, r_sys_node_free);
    ret->idx = idx;

#if defined (R_OS_WIN32)
    {
      ULONGLONG availmem = 0;
      GetNumaAvailableMemoryNode ((ruchar)idx, &availmem);
      ret->availablemem = (rsize)availmem;
    }
    if (r_bitset_init_heap (ret->cpuset, sizeof (ULONGLONG) * 8)) {
      ULONGLONG mask;
      if (idx < RUINT8_MAX && GetNumaNodeProcessorMask ((ruchar)idx, &mask))
        r_bitset_set_u64_at (ret->cpuset, mask, 0);
    }
#elif defined (HAVE_SYSCTLBYNAME)
    /* FIXME: Read out available memory */
    if (r_bitset_init_heap (ret->cpuset, r_sys_cpu_logical_count ())) {
      r_bitset_set_n_bits_at (ret->cpuset,
          topo->cachecfg[0], idx * topo->cachecfg[0], TRUE);
    }
#elif defined (R_OS_LINUX)
    /* FIXME: Read out available memory */
    if (r_bitset_init_heap (ret->cpuset, r_sys_cpu_linux_max_cpus ())) {
      rchar tmp[256];
      r_snprintf (tmp, sizeof (tmp), R_SYSFS_NODE_FMT "/cpulist", (ruint)idx);
      r_bitset_set_from_human_readable_file (ret->cpuset, tmp, NULL);
    }
#endif

    if (R_LIKELY (ret->cpuset != NULL)) {
      ret->cpus = r_mem_new_n (RSysCpu *, r_bitset_popcount (ret->cpuset));
      r_bitset_foreach (ret->cpuset, TRUE, r_sys_topology_prepend_cpu, ret);
    }
  }

  return ret;
}

static void
r_sys_topology_prepend_node (rsize bit, rpointer data)
{
  RSysTopology * topo = data;
  topo->nodes[topo->nodecount++] = r_sys_node_discover (bit, topo);
}

RSysTopology *
r_sys_topology_discover (void)
{
  RSysTopology * ret;

  if ((ret = r_mem_new0 (RSysTopology)) != NULL) {
    r_ref_init (ret, r_sys_topology_free);

    R_STMT_START {
#if defined (R_OS_WIN32)
      ULONG hnn = 0;
      if (GetNumaHighestNodeNumber (&hnn)) {
        if (r_bitset_init_heap (ret->nodeset, hnn + 1))
          r_bitset_set_all (ret->nodeset, TRUE);
      }
#elif defined (HAVE_SYSCTLBYNAME)
      size_t size = 0;
      if (sysctlbyname("hw.cacheconfig", NULL, &size, NULL, 0) == 0) {
        ret->cachecfg = r_malloc (size);
        ret->cachelvl = size / sizeof (ruint64);
        if (sysctlbyname("hw.cacheconfig", ret->cachecfg, &size, NULL, 0) == 0) {
          if (r_bitset_init_heap (ret->nodeset, r_sys_cpu_logical_count () / ret->cachecfg[0]))
            r_bitset_set_all (ret->nodeset, TRUE);
        }
      }
#elif defined (R_OS_LINUX)
      ruint max = r_sys_cpu_linux_max_cpus ();
      if (r_bitset_init_heap (ret->nodeset, max))
        r_bitset_set_from_human_readable_file (ret->nodeset, R_SYSFS_NODE "/online", NULL);
#endif
    } R_STMT_END;

    if (R_LIKELY (ret->nodeset != NULL)) {
      ret->nodes = r_mem_new_n (RSysNode *, r_bitset_popcount (ret->nodeset));
      r_bitset_foreach (ret->nodeset, TRUE, r_sys_topology_prepend_node, ret);
    }
  }

  return ret;
}

rsize
r_sys_topology_node_count (const RSysTopology * topo)
{
  if (R_UNLIKELY (topo == NULL)) return 0;
  return topo->nodecount;
}

RSysNode *
r_sys_topology_node (RSysTopology * topo, rsize idx)
{
  if (R_UNLIKELY (topo == NULL)) return NULL;
  return idx < topo->nodecount ? r_sys_node_ref (topo->nodes[idx]) : NULL;
}

rboolean
r_sys_topology_node_cpuset (const RSysNode * node, RBitset * cpuset)
{
  if (R_UNLIKELY (node == NULL)) return FALSE;
  return r_bitset_copy (cpuset, node->cpuset);
}

rsize
r_sys_topology_node_cpu_count (const RSysNode * node)
{
  if (R_UNLIKELY (node == NULL)) return 0;
  return node->cpucount;
}

RSysCpu *
r_sys_topology_node_cpu (RSysNode * node, rsize idx)
{
  if (R_UNLIKELY (node == NULL)) return NULL;
  return idx < node->cpucount ? r_sys_cpu_ref (node->cpus[idx]) : NULL;
}

