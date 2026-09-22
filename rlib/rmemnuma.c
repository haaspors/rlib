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

#include "config.h"
#include <rlib/rmemnuma.h>

#include <rlib/rmem.h>

#if defined (HAVE_WINDOWS_H)
#include <windows.h>
#endif
#if defined (HAVE_QUERYWORKINGSETEX)
#include <psapi.h>
#endif
#if defined (HAVE_SYS_MMAN_H)
#include <sys/mman.h>
#endif
#if defined (HAVE_UNISTD_H)
#include <unistd.h>
#endif

/* No libc wraps mbind / get_mempolicy. */
#if defined (R_OS_LINUX) && defined (HAVE_SYS_SYSCALL_H) && \
    defined (HAVE_LINUX_MEMPOLICY_H)
#include <linux/mempolicy.h>
#include <sys/syscall.h>
#if defined (__NR_mbind) && defined (__NR_get_mempolicy)
#define R_MEM_NUMA_MEMPOLICY  1
#endif
#endif

#if defined (R_MEM_NUMA_MEMPOLICY)
#define R_MEM_NUMA_ULONG_BITS   (sizeof (unsigned long) * 8)
/* MAX_NUMNODES, the widest nodemask any kernel accepts. */
#define R_MEM_NUMA_MAX_NODES    1024
#define R_MEM_NUMA_MASK_LONGS \
    ((R_MEM_NUMA_MAX_NODES + R_MEM_NUMA_ULONG_BITS - 1) / R_MEM_NUMA_ULONG_BITS)

typedef struct {
  unsigned long mask[R_MEM_NUMA_MASK_LONGS];
} RMemNumaNodeMask;

static rboolean
r_mem_numa_nodemask_set (RMemNumaNodeMask * nm, ruint node)
{
  if (R_UNLIKELY (node >= R_MEM_NUMA_MAX_NODES))
    return FALSE;

  nm->mask[node / R_MEM_NUMA_ULONG_BITS] |=
      1UL << (node % R_MEM_NUMA_ULONG_BITS);
  return TRUE;
}

/* Returns the count, so an empty or out-of-range set stands out. */
static rsize
r_mem_numa_nodemask_from_bitset (RMemNumaNodeMask * nm,
    const RBitset * nodeset)
{
  rsize i, bits, ret = 0;

  if (nodeset == NULL)
    return 0;

  bits = MIN (nodeset->bits, (rsize)R_MEM_NUMA_MAX_NODES);
  for (i = 0; i < bits; i++) {
    if (r_bitset_is_bit_set (nodeset, i) &&
        r_mem_numa_nodemask_set (nm, (ruint)i))
      ret++;
  }

  return ret;
}

static rboolean
r_mem_numa_nodemask_allowed (RMemNumaNodeMask * nm)
{
  return syscall (__NR_get_mempolicy, NULL, nm->mask,
      (unsigned long)(R_MEM_NUMA_MAX_NODES + 1), NULL,
      MPOL_F_MEMS_ALLOWED) == 0;
}

/* The kernel takes the nodemask width as a bit count plus one. */
static rboolean
r_mem_numa_mbind (rpointer ptr, rsize size, int mode,
    const RMemNumaNodeMask * nm)
{
  return syscall (__NR_mbind, ptr, (unsigned long)size, mode, nm->mask,
      (unsigned long)(R_MEM_NUMA_MAX_NODES + 1), 0) == 0;
}
#endif

rboolean
r_mem_numa_available (void)
{
#if defined (R_MEM_NUMA_MEMPOLICY)
  int mode = 0;

  /* A kernel built without NUMA answers ENOSYS. */
  return syscall (__NR_get_mempolicy, &mode, NULL, 0UL, NULL, 0) == 0;
#elif defined (R_OS_WIN32)
  return TRUE;
#else
  return FALSE;
#endif
}

rsize
r_mem_numa_page_size (void)
{
  rsize ret = 0;

#if defined (R_OS_WIN32)
  SYSTEM_INFO si;

  GetSystemInfo (&si);
  ret = si.dwPageSize;
#elif defined (HAVE_SYSCONF)
  long v = sysconf (_SC_PAGESIZE);

  if (v > 0)
    ret = (rsize)v;
#endif

  /* Callers round sizes by this, so never hand back 0. */
  return ret > 0 ? ret : 4096;
}

rpointer
r_mem_numa_alloc_local (rsize size)
{
#if !defined (R_OS_WIN32) && defined (HAVE_MMAP)
  rpointer ret;
#endif

  if (R_UNLIKELY (size == 0)) return NULL;

#if defined (R_OS_WIN32)
  return VirtualAlloc (NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#elif defined (HAVE_MMAP)
  ret = mmap (NULL, size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return ret != MAP_FAILED ? ret : NULL;
#else
  /* No mapping API, so no placement; the rest of the contract holds. */
  return r_malloc0 (size);
#endif
}

rpointer
r_mem_numa_alloc_onnode (rsize size, ruint node)
{
#if defined (R_OS_WIN32)
  if (R_UNLIKELY (size == 0)) return NULL;

  return VirtualAllocExNuma (GetCurrentProcess (), NULL, size,
      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, (DWORD)node);
#else
  rpointer ret;

  if ((ret = r_mem_numa_alloc_local (size)) != NULL)
    r_mem_numa_bind (ret, size, node);

  return ret;
#endif
}

rpointer
r_mem_numa_alloc_interleaved (rsize size, const RBitset * nodeset)
{
  rpointer ret;

  if ((ret = r_mem_numa_alloc_local (size)) != NULL)
    r_mem_numa_interleave (ret, size, nodeset);

  return ret;
}

void
r_mem_numa_free (rpointer ptr, rsize size)
{
  if (ptr == NULL)
    return;

#if defined (R_OS_WIN32)
  (void) size;
  VirtualFree (ptr, 0, MEM_RELEASE);
#elif defined (HAVE_MMAP)
  munmap (ptr, size);
#else
  (void) size;
  r_free (ptr);
#endif
}

rboolean
r_mem_numa_bind (rpointer ptr, rsize size, ruint node)
{
#if defined (R_MEM_NUMA_MEMPOLICY)
  RMemNumaNodeMask nm = { { 0, } };

  if (R_UNLIKELY (ptr == NULL || size == 0)) return FALSE;
  if (!r_mem_numa_nodemask_set (&nm, node)) return FALSE;

  return r_mem_numa_mbind (ptr, size, MPOL_BIND, &nm);
#else
  (void) ptr;
  (void) size;
  (void) node;
  return FALSE;
#endif
}

rboolean
r_mem_numa_interleave (rpointer ptr, rsize size, const RBitset * nodeset)
{
#if defined (R_MEM_NUMA_MEMPOLICY)
  RMemNumaNodeMask nm = { { 0, } };

  if (R_UNLIKELY (ptr == NULL || size == 0)) return FALSE;

  /* MPOL_INTERLEAVE rejects an empty mask, so spell out what NULL means. */
  if (r_mem_numa_nodemask_from_bitset (&nm, nodeset) == 0 &&
      !r_mem_numa_nodemask_allowed (&nm))
    return FALSE;

  return r_mem_numa_mbind (ptr, size, MPOL_INTERLEAVE, &nm);
#else
  (void) ptr;
  (void) size;
  (void) nodeset;
  return FALSE;
#endif
}

rboolean
r_mem_numa_node_of (rconstpointer ptr, ruint * node)
{
#if defined (R_MEM_NUMA_MEMPOLICY)
  int n = -1;
#elif defined (HAVE_QUERYWORKINGSETEX)
  PSAPI_WORKING_SET_EX_INFORMATION wsi;
#endif

  if (R_UNLIKELY (ptr == NULL || node == NULL)) return FALSE;

#if defined (R_MEM_NUMA_MEMPOLICY)
  if (syscall (__NR_get_mempolicy, &n, NULL, 0UL, (rpointer)ptr,
          MPOL_F_NODE | MPOL_F_ADDR) != 0 || n < 0)
    return FALSE;

  *node = (ruint)n;
  return TRUE;
#elif defined (HAVE_QUERYWORKINGSETEX)
  r_memclear (&wsi, sizeof (wsi));
  wsi.VirtualAddress = (PVOID)ptr;
  if (!QueryWorkingSetEx (GetCurrentProcess (), &wsi, sizeof (wsi)) ||
      !wsi.VirtualAttributes.Valid)
    return FALSE;

  *node = (ruint)wsi.VirtualAttributes.Node;
  return TRUE;
#else
  return FALSE;
#endif
}
