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
#ifndef __R_THREAD_POOL_H__
#define __R_THREAD_POOL_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/concurrency/rthreadpool.h
 * @brief Pool of worker threads sharing a common entry function;
 * each worker is spawned with optional CPU-affinity placement.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rbitset.h>

#include <rlib/concurrency/rthreads.h>

R_BEGIN_DECLS

/**
 * @defgroup r_threadpool Thread pool (RThreadPool)
 * @ingroup r_concurrency
 *
 * @brief Worker pool where every thread runs the same entry function
 * with a shared @c common argument plus a per-thread @c specific
 * argument.
 *
 * Workers are launched explicitly via one of the @c _start_thread_*
 * calls; the pool does not auto-size or auto-scale. @ref r_thread_pool_join
 * waits for all workers and tears the pool down.
 *
 * Use @ref r_taskqueue when you want a queue of pending jobs to be
 * pulled by a fixed set of consumers; use @ref r_threadpool when you
 * want N long-running parallel workers pinned to specific CPUs.
 *
 * @{
 */

/** @brief Opaque, refcounted thread-pool handle. */
typedef struct RThreadPool RThreadPool;
/**
 * @brief Worker entry-point signature.
 * @param common   Shared argument given at pool creation.
 * @param specific Per-thread argument supplied at @c _start_thread_*.
 * @return Discarded; the pool does not expose per-worker results.
 */
typedef rpointer (*RThreadPoolFunc) (rpointer common, rpointer specific);

/**
 * @brief Create a new pool that will spawn workers running @p func.
 *
 * @param prefix Used as the per-worker thread-name prefix for
 *               diagnostics; may be @c NULL.
 * @param func   Worker entry point shared by every thread in the pool.
 * @param data   @c common argument forwarded to every @p func call.
 */
R_API RThreadPool * r_thread_pool_new (const rchar * prefix,
    RThreadPoolFunc func, rpointer data);

/** @brief Take a reference on the pool (alias for @ref r_ref_ref). */
#define r_thread_pool_ref     r_ref_ref
/** @brief Drop a reference on the pool (alias for @ref r_ref_unref). */
#define r_thread_pool_unref   r_ref_unref

/**
 * @brief Spawn one worker with optional name and CPU-affinity mask.
 * @return @c TRUE on success, @c FALSE if thread creation failed.
 */
R_API rboolean  r_thread_pool_start_thread (RThreadPool * pool,
    const rchar * name, const RBitset * affinity, rpointer data);
/** @brief Spawn one worker pinned to a single CPU index. */
R_API rboolean  r_thread_pool_start_thread_on_cpu (RThreadPool * pool,
    rsize cpuidx, rpointer data);
/** @brief Spawn one worker whose affinity is the given @p cpuset. */
R_API rboolean  r_thread_pool_start_thread_on_cpuset (RThreadPool * pool,
    const RBitset * cpuset, rpointer data);
/**
 * @brief Spawn one worker per CPU set in @p cpuset, each pinned to
 * its respective CPU.
 */
R_API rboolean  r_thread_pool_start_thread_on_each_cpu (RThreadPool * pool,
    const RBitset * cpuset, rpointer data);

/**
 * @brief Wait for all workers to finish; the pool must not be used
 * for further @c _start_thread_* calls after this returns.
 */
R_API void      r_thread_pool_join (RThreadPool * pool);

/** @brief Return the number of workers currently running in @p pool. */
R_API ruint     r_thread_pool_running_threads (RThreadPool * pool);


R_END_DECLS

/** @} */

#endif /* __R_THREAD_POOL_H__ */

