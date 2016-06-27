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

#include <rlib/rtypes.h>

#include <rlib/rbitset.h>
#include <rlib/rref.h>
#include <rlib/rthreads.h>

R_BEGIN_DECLS

typedef struct _RThreadPool RThreadPool;
typedef rpointer (*RThreadPoolFunc) (rpointer common, rpointer specific);

R_API RThreadPool * r_thread_pool_new (const rchar * prefix,
    RThreadPoolFunc func, rpointer data);

#define r_thread_pool_ref     r_ref_ref
#define r_thread_pool_unref   r_ref_unref

R_API rboolean  r_thread_pool_start_thread (RThreadPool * pool,
    const rchar * name, const RBitset * affinity, rpointer data);
R_API rboolean  r_thread_pool_start_thread_on_cpu (RThreadPool * pool,
    rsize cpuidx, rpointer data);
R_API rboolean  r_thread_pool_start_thread_on_each_cpu (RThreadPool * pool,
    const RBitset * cpuset, rpointer data);

R_API void      r_thread_pool_join (RThreadPool * pool);

R_API ruint     r_thread_pool_running_threads (RThreadPool * pool);


R_END_DECLS

#endif /* __R_THREAD_POOL_H__ */

