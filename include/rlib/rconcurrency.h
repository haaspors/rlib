/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CONCURRENCY_H__
#define __R_CONCURRENCY_H__

/**
 * @defgroup r_concurrency Concurrency primitives
 *
 * @brief Atomics, threads, threadpools and task queues - the
 * concurrency-flavoured building blocks the rest of rlib uses for
 * thread-safe data structures, deferred work and parallel
 * execution.
 *
 * Four sub-areas:
 *
 *   - @c r_atomic — atomic operations (load / store / CAS / fetch-add
 *     across the integer widths plus pointer types).
 *   - @c r_threads — threads, mutexes, condition variables, TLS.
 *   - @c r_threadpool — fixed- and dynamic-size thread pools backed
 *     by @c r_threads + a queue of @c r_taskqueue jobs.
 *   - @c r_taskqueue — deferred-work queue with cancellation,
 *     priorities and per-task callbacks.
 *
 * Atomics underpin the refcount in @c r_ref and the hazard-pointer
 * machinery in @c r_hzrptr, so the dependency direction is
 * concurrency primitives -> data structures -> higher subsystems.
 */

#include <rlib/rlib.h>

#include <rlib/concurrency/ratomic.h>
#include <rlib/concurrency/rtaskqueue.h>
#include <rlib/concurrency/rthreadpool.h>
#include <rlib/concurrency/rthreads.h>

#endif /* __R_CONCURRENCY_H__ */
