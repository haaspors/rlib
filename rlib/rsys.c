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

#include <rlib/rsys.h>
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
#define R_SYSFS_CPU_ONLINE            "/sys/devices/system/cpu/online"
#define R_SYSFS_CPU_MAX               "/sys/devices/system/cpu/kernel_max"
#define R_SYSFS_CPU_FMT               "/sys/devices/system/cpu/cpu%u"

#define R_SYSFS_CPU_TOPO_PKG_ID       "/topology/physical_package_id"
#define R_SYSFS_CPU_TOPO_THR_SIB_LST  "/topology/thread_siblings_list"

#define R_SYSFS_NODE_ONLINE           "/sys/devices/system/node/online"

#include <rlib/rfile.h>
#include <rlib/rbitset.h>
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
  ret = r_file_read_uint (R_SYSFS_CPU_MAX, RUINT_MAX);
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
  if (!r_bitset_set_bit (pack, r_file_read_uint (tmp, pack->bsize), TRUE))
    R_LOG_WARNING ("Found wierd package ID in %s", tmp);
}

static void
r_sys_cpu_linux_phys_func (rsize bit, rpointer data)
{
  rchar tmp[256];
  RBitset * phys = data;
  r_snprintf (tmp, sizeof (tmp), R_SYSFS_CPU_FMT R_SYSFS_CPU_TOPO_THR_SIB_LST,
      (ruint)bit);

  /* This reads the first number out of the human readable list file */
  if (!r_bitset_set_bit (phys, r_file_read_uint (tmp, phys->bsize), TRUE))
    R_LOG_WARNING ("Found wierd siblings ID in %s", tmp);
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
    r_bitset_set_from_human_readable_file (online, R_SYSFS_CPU_ONLINE, NULL);
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
    r_bitset_set_from_human_readable_file (online, R_SYSFS_CPU_ONLINE, NULL);
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
  ruint max = r_sys_cpu_linux_max_cpus ();
  if (r_bitset_init_stack (online, max)) {
    r_bitset_set_from_human_readable_file (online, R_SYSFS_CPU_ONLINE, NULL);
    ret = r_bitset_popcount (online);
  }
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
  ruint max = r_sys_cpu_linux_max_cpus ();
  if (r_bitset_init_stack (online, max)) {
    r_bitset_set_from_human_readable_file (online, R_SYSFS_NODE_ONLINE, NULL);
    ret = r_bitset_popcount (online);
  }
#endif

  return ret;
}

