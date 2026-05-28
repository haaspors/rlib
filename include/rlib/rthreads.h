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
#ifndef __R_THREAD_H__
#define __R_THREAD_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/ratomic.h>
#include <rlib/data/rbitset.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

/**
 * @defgroup r_once One-shot initialisation (ROnce)
 * @brief Run an init function exactly once across all threads, with
 * a cheap fast path on every subsequent call.
 * @{
 */

/**
 * @brief Lifecycle states of an @c ROnce.
 *
 * The states transition INIT -&gt; RUNNING -&gt; DONE exactly
 * once per @c ROnce instance, driven by the first @c r_call_once
 * caller. They are an implementation detail of @c r_call_once and
 * not intended for external use.
 */
typedef enum
{
  R_ONCE_STATE_INIT,    /**< Fresh, init function not yet started. */
  R_ONCE_STATE_RUNNING, /**< Init function executing in some thread. */
  R_ONCE_STATE_DONE     /**< Init function returned; @c ret is set. */
} ROnceState;

/**
 * @brief Static initialiser for an @c ROnce in INIT state.
 *
 * Use as @c { static ROnce o = R_ONCE_INIT; } at file or block scope.
 */
#define R_ONCE_INIT { R_ONCE_STATE_INIT, NULL }
/**
 * @brief One-shot initialisation guard.
 *
 * Pass the same @c ROnce instance to every @c r_call_once call; the
 * supplied init function is invoked at most once across all threads.
 * Subsequent calls return the cached pointer the init function
 * returned, on a fast path with no CAS.
 *
 * Storage must be either zero-initialised (static / global) or
 * explicitly seeded with @c R_ONCE_INIT before first use.
 */
typedef struct
{
  rauint state;     /**< Current @c ROnceState (atomic). */
  rpointer ret;     /**< Value returned by the init function. */
} ROnce;

#define R_TSS_INIT(notify) { (RDestroyNotify)(notify), { NULL } }
typedef struct
{
  RDestroyNotify  notify;
  union {
    rpointer      ptr;
    raptr         aptr;
    ruint         ui;
    ruint8        u8;
    ruint16       u16;
    ruint32       u32;
    ruint64       u64;
    ruint8        data[sizeof (rpointer) * 4];
  } impl;
} RTss;

typedef rpointer RMutex;
typedef rpointer RRMutex;
typedef rpointer RRWMutex;
typedef rpointer RCond;

typedef rpointer (*RThreadFunc) (rpointer data);
typedef struct RThread RThread;


/**
 * @brief Run @p f exactly once across all threads, return its result.
 *
 * The first caller to win the state transition runs @p f with @p a
 * and stores the returned pointer in @p once. All later callers,
 * across all threads, get the cached pointer back without re-running
 * @p f. Concurrent first-callers block until the running thread
 * finishes.
 *
 * The hot path (after init has settled) is a single atomic load and
 * a branch, so it is cheap enough to call on every entry to a
 * frequently-invoked function.
 *
 * @param once  Persistent @c ROnce instance, seeded with
 *              @c R_ONCE_INIT or zero-initialised.
 * @param f     Init function; called at most once per @p once.
 * @param a     Opaque argument forwarded to @p f.
 * @return The pointer @p f returned (cached after the first call).
 */
R_API rpointer  r_call_once         (ROnce * once, RThreadFunc f, rpointer a);

/** @} */ /* r_once group */

/* Thread spesific storage */
R_API rpointer r_tss_get            (RTss * tss);
R_API void     r_tss_set            (RTss * tss, rpointer data);

/* Non-recursive mutex */
R_API void      r_mutex_init        (RMutex * mutex);
R_API void      r_mutex_clear       (RMutex * mutex);
R_API void      r_mutex_lock        (RMutex * mutex);
R_API rboolean  r_mutex_trylock     (RMutex * mutex);
R_API void      r_mutex_unlock      (RMutex * mutex);

/* Recursive mutex */
R_API void      r_rmutex_init       (RRMutex * mutex);
R_API void      r_rmutex_clear      (RRMutex * mutex);
R_API void      r_rmutex_lock       (RRMutex * mutex);
R_API rboolean  r_rmutex_trylock    (RRMutex * mutex);
R_API void      r_rmutex_unlock     (RRMutex * mutex);

/* Read/Write mutex/lock */
R_API void      r_rwmutex_init      (RRWMutex * mutex);
R_API void      r_rwmutex_clear     (RRWMutex * mutex);
R_API void      r_rwmutex_rdlock    (RRWMutex * mutex);
R_API void      r_rwmutex_wrlock    (RRWMutex * mutex);
R_API rboolean  r_rwmutex_tryrdlock (RRWMutex * mutex);
R_API rboolean  r_rwmutex_trywrlock (RRWMutex * mutex);
R_API void      r_rwmutex_rdunlock  (RRWMutex * mutex);
R_API void      r_rwmutex_wrunlock  (RRWMutex * mutex);

/* Condition variable */
R_API void      r_cond_init         (RCond * cond);
R_API void      r_cond_clear        (RCond * cond);
R_API void      r_cond_wait         (RCond * cond, RMutex * mutex);
R_API void      r_cond_signal       (RCond * cond);
R_API void      r_cond_broadcast    (RCond * cond);

/* Threads */
#define r_thread_new(name, func, data)                                        \
  r_thread_new_full (name, NULL, func, data)
R_API RThread * r_thread_new_full   (const rchar * name,
    const RBitset * cpuset, RThreadFunc func, rpointer data);
#define r_thread_ref        r_ref_ref
#define r_thread_unref      r_ref_unref
R_API rpointer  r_thread_join       (RThread * thread);
/* RDestroyNotify-compatible "join then unref" helper for slist /
 * ptr-array destroy paths that should wait for the thread first.
 * Discards the thread's return value. */
static inline void r_thread_join_unref (rpointer thread)
{
  r_thread_join (thread);
  r_thread_unref (thread);
}
R_API int       r_thread_kill       (RThread * thread, int sig);
R_API const rchar * r_thread_get_name (const RThread * thread);
R_API ruint     r_thread_get_id     (const RThread * thread);
R_API rboolean  r_thread_get_affinity (const RThread * thread, RBitset * cpuset);
R_API rboolean  r_thread_set_affinity (RThread * thread, const RBitset * cpuset);

R_API RThread * r_thread_current    (void);
R_API void      r_thread_exit       (rpointer retval);
R_API void      r_thread_yield      (void);
R_API void      r_thread_sleep      (ruint sec);
R_API void      r_thread_usleep     (rulong microsec);

#ifdef R_OS_WIN32
R_API void      r_thread_win32_dll_thread_detach (void);
#endif

R_END_DECLS

#endif /* __R_THREAD_H__ */
