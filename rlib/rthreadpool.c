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
#include <rlib/rthreadpool.h>

#include <rlib/rassert.h>
#include <rlib/rlist.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>
#include <rlib/rsys.h>


struct _RThreadPool
{
  RRef ref;
  rchar * prefix;
  RThreadFunc func;
  rpointer data;

  RMutex mutex;
  RSList * active, * joined;
  rauint counter, running;
};

static void
r_thread_pool_free (RThreadPool * pool)
{
  if (R_LIKELY (pool != NULL)) {
    r_mutex_lock (&pool->mutex);
    r_assert_cmpptr (pool->active, ==, NULL);
    r_slist_destroy_full (pool->joined, r_thread_unref);
    pool->joined = NULL;
    r_mutex_unlock (&pool->mutex);
    r_mutex_clear (&pool->mutex);

    r_free (pool->prefix);
    r_free (pool);
  }
}

RThreadPool *
r_thread_pool_new (const rchar * prefix, RThreadFunc func, rpointer data)
{
  RThreadPool * ret;

  if (R_UNLIKELY (func == NULL)) return NULL;

  if ((ret = r_mem_new (RThreadPool)) != NULL) {
    r_ref_init (ret, r_thread_pool_free);
    ret->prefix = r_strdup (prefix != NULL ? prefix : "rthreadpool");
    ret->func = func;
    ret->data = data;

    r_mutex_init (&ret->mutex);
    ret->active = ret->joined = NULL;
    r_atomic_uint_store (&ret->counter, 0);
    r_atomic_uint_store (&ret->running, 0);
  }

  return ret;
}

static rpointer
r_thread_pool_proxy (rpointer data)
{
  RThreadPool * pool = data;
  RThread * t = r_thread_current ();
  rpointer ret;

  r_mutex_lock (&pool->mutex);
  pool->active = r_slist_prepend (pool->active, t);
  r_mutex_unlock (&pool->mutex);

  r_atomic_uint_fetch_add (&pool->running, 1);
  ret = pool->func (pool->data);
  r_atomic_uint_fetch_sub (&pool->running, 1);

  r_mutex_lock (&pool->mutex);
  pool->active = r_slist_remove (pool->active, t);
  pool->joined = r_slist_prepend (pool->joined, t);
  r_mutex_unlock (&pool->mutex);

  return ret;
}

static RThread *
r_thread_pool_start_thread_internal (RThreadPool * pool,
    const rchar * fullname, const RBitset * affinity)
{
  RThread * ret;

  if (affinity != NULL)
    r_assert_cmpuint (r_bitset_popcount (affinity), >, 0);

  if ((ret = r_thread_new (fullname, r_thread_pool_proxy, pool)) != NULL) {
    if (affinity != NULL)
      r_thread_set_affinity (ret, affinity);
  }
  return ret;
}

rboolean
r_thread_pool_start_thread (RThreadPool * pool, const rchar * name, const RBitset * affinity)
{
  RThread * t;
  rchar * fullname;
  ruint n;

  if (R_UNLIKELY (pool == NULL)) return FALSE;

  n = r_atomic_uint_fetch_add (&pool->counter, 1);
  if (name == NULL) {
    rchar tmp[16];
    r_snprintf (tmp, sizeof (tmp), "%u", n);
    name = tmp;
  }

  fullname = r_strprintf ("%s-%s", pool->prefix, name);
  t = r_thread_pool_start_thread_internal (pool, fullname, affinity);
  r_free (fullname);

  return t != NULL;
}

rboolean
r_thread_pool_start_thread_on_cpu (RThreadPool * pool, rsize cpuidx)
{
  RThread * t;
  rchar * fullname;
  RBitset * cpuset;

  if (R_UNLIKELY (pool == NULL)) return FALSE;

  if (R_UNLIKELY (!r_bitset_init_stack (cpuset, cpuidx + 1) ||
        !r_bitset_set_bit (cpuset, cpuidx, TRUE)))
    return FALSE;

  r_atomic_uint_fetch_add (&pool->counter, 1);

  fullname = r_strprintf ("%s-%"RSIZE_FMT, pool->prefix, cpuidx);
  t = r_thread_pool_start_thread_internal (pool, fullname, cpuset);
  r_free (fullname);

  return t != NULL;
}

static void
r_thread_pool_start_thread_on_cpu_swapped (rsize cpu, rpointer pool)
{
  r_thread_pool_start_thread_on_cpu ((RThreadPool *)pool, cpu);
}

rboolean
r_thread_pool_start_thread_on_each_cpu (RThreadPool * pool, const RBitset * cpuset)
{
  if (R_UNLIKELY (pool == NULL)) return FALSE;

  if (cpuset != NULL) {
    r_bitset_foreach (cpuset, TRUE, r_thread_pool_start_thread_on_cpu_swapped, pool);
  } else {
    RBitset * bitset;
    if (R_UNLIKELY (!r_bitset_init_stack (bitset, r_sys_cpu_logical_count ())))
      return FALSE;
    r_bitset_set_all (bitset, TRUE);
    r_bitset_foreach (bitset, TRUE, r_thread_pool_start_thread_on_cpu_swapped, pool);
  }

  return TRUE;
}

void
r_thread_pool_join (RThreadPool * pool)
{
  RSList * copy;

  r_mutex_lock (&pool->mutex);
  copy = r_slist_copy (pool->active);
  r_mutex_unlock (&pool->mutex);

  r_slist_foreach (copy, (RFunc)r_thread_join, NULL);
  r_slist_destroy (copy);
}

ruint
r_thread_pool_running_threads (RThreadPool * pool)
{
  return r_atomic_uint_load (&pool->running);
}

