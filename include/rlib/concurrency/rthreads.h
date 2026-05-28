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

/**
 * @file rlib/concurrency/rthreads.h
 * @brief Threads, mutexes (plain, recursive, read/write), condition
 * variables, thread-specific storage and one-shot initialisation.
 */

#include <rlib/rtypes.h>
#include <rlib/concurrency/ratomic.h>
#include <rlib/data/rbitset.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

/**
 * @defgroup r_once One-shot initialisation
 * @ingroup r_concurrency
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

/**
 * @brief Static initialiser for an @ref RTss with destroy callback
 * @p notify; pass @c NULL to disable cleanup on @ref r_tss_set or
 * thread exit.
 */
#define R_TSS_INIT(notify) { (RDestroyNotify)(notify), { NULL } }
/**
 * @brief Thread-specific storage slot.
 *
 * Each thread sees its own value; @ref r_tss_get and @ref r_tss_set
 * read and write the calling thread's slot. The inline union lets
 * the slot hold a pointer, an atomic pointer, or up to 4 pointer
 * widths of inline bytes without a separate heap allocation.
 *
 * Declare with @ref R_TSS_INIT at file scope.
 */
typedef struct
{
  RDestroyNotify  notify;   /**< Destructor for the stored value, or @c NULL. */
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

/** @brief Opaque mutex handle; initialise with @ref r_mutex_init. */
typedef rpointer RMutex;
/** @brief Opaque recursive-mutex handle; initialise with @ref r_rmutex_init. */
typedef rpointer RRMutex;
/** @brief Opaque read/write-mutex handle; initialise with @ref r_rwmutex_init. */
typedef rpointer RRWMutex;
/** @brief Opaque condition-variable handle; initialise with @ref r_cond_init. */
typedef rpointer RCond;

/**
 * @brief Thread entry-point signature.
 * @param data Opaque argument passed to @ref r_thread_new_full.
 * @return Value the joiner receives from @ref r_thread_join.
 */
typedef rpointer (*RThreadFunc) (rpointer data);
/** @brief Opaque, refcounted thread handle returned by @ref r_thread_new_full. */
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

/**
 * @defgroup r_threads Threads, locks and condition variables
 * @ingroup r_concurrency
 * @brief OS-thread spawning, mutex / RW-mutex / condition-variable
 * primitives, and thread-specific storage.
 *
 * The pointer-typed @c RMutex / @c RRMutex / @c RRWMutex / @c RCond
 * carry an opaque OS handle; they must be initialised before use
 * with the matching @c _init call and torn down with @c _clear.
 *
 * @{
 */

/** @name Thread-specific storage (TSS)
 *  @{ */
/**
 * @brief Retrieve this thread's TSS value, or @c NULL if unset.
 * @param tss Persistent @ref RTss declared with @ref R_TSS_INIT.
 */
R_API rpointer r_tss_get            (RTss * tss);
/**
 * @brief Set this thread's TSS value, freeing the previous one via
 * the @c notify callback if any.
 */
R_API void     r_tss_set            (RTss * tss, rpointer data);
/** @} */

/** @name Non-recursive mutex
 *  @{ */
/** @brief Initialise a fresh @ref RMutex. */
R_API void      r_mutex_init        (RMutex * mutex);
/** @brief Release OS resources held by @p mutex; must be unlocked first. */
R_API void      r_mutex_clear       (RMutex * mutex);
/** @brief Acquire @p mutex, blocking until available. */
R_API void      r_mutex_lock        (RMutex * mutex);
/** @brief Try to acquire @p mutex without blocking; @c TRUE on success. */
R_API rboolean  r_mutex_trylock     (RMutex * mutex);
/** @brief Release @p mutex; the calling thread must currently hold it. */
R_API void      r_mutex_unlock      (RMutex * mutex);
/** @} */

/** @name Recursive mutex
 *
 * Identical contract to @ref RMutex except the owning thread can
 * lock the same mutex repeatedly; each @c _lock must be paired with
 * a matching @c _unlock.
 *  @{ */
/** @brief Initialise a fresh @ref RRMutex. */
R_API void      r_rmutex_init       (RRMutex * mutex);
/** @brief Release OS resources held by @p mutex. */
R_API void      r_rmutex_clear      (RRMutex * mutex);
/** @brief Acquire @p mutex (recursively for the owning thread). */
R_API void      r_rmutex_lock       (RRMutex * mutex);
/** @brief Try-lock variant; see @ref r_mutex_trylock. */
R_API rboolean  r_rmutex_trylock    (RRMutex * mutex);
/** @brief Release one nesting level of @p mutex. */
R_API void      r_rmutex_unlock     (RRMutex * mutex);
/** @} */

/** @name Read/write mutex
 *
 * Many concurrent readers OR a single writer; writers exclude both
 * readers and other writers.
 *  @{ */
/** @brief Initialise a fresh @ref RRWMutex. */
R_API void      r_rwmutex_init      (RRWMutex * mutex);
/** @brief Release OS resources held by @p mutex. */
R_API void      r_rwmutex_clear     (RRWMutex * mutex);
/** @brief Acquire a shared read lock; blocks until no writer holds the lock. */
R_API void      r_rwmutex_rdlock    (RRWMutex * mutex);
/** @brief Acquire an exclusive write lock; blocks until no reader or writer holds the lock. */
R_API void      r_rwmutex_wrlock    (RRWMutex * mutex);
/** @brief Try-lock variant of @ref r_rwmutex_rdlock. */
R_API rboolean  r_rwmutex_tryrdlock (RRWMutex * mutex);
/** @brief Try-lock variant of @ref r_rwmutex_wrlock. */
R_API rboolean  r_rwmutex_trywrlock (RRWMutex * mutex);
/** @brief Release a previously-acquired read lock. */
R_API void      r_rwmutex_rdunlock  (RRWMutex * mutex);
/** @brief Release a previously-acquired write lock. */
R_API void      r_rwmutex_wrunlock  (RRWMutex * mutex);
/** @} */

/** @name Condition variable
 *  @{ */
/** @brief Initialise a fresh @ref RCond. */
R_API void      r_cond_init         (RCond * cond);
/** @brief Release OS resources held by @p cond. */
R_API void      r_cond_clear        (RCond * cond);
/**
 * @brief Atomically release @p mutex and wait until signalled, then
 * reacquire @p mutex before returning.
 *
 * Spurious wake-ups are possible; callers must recheck their
 * predicate in a loop.
 */
R_API void      r_cond_wait         (RCond * cond, RMutex * mutex);
/** @brief Wake at least one thread waiting on @p cond. */
R_API void      r_cond_signal       (RCond * cond);
/** @brief Wake all threads waiting on @p cond. */
R_API void      r_cond_broadcast    (RCond * cond);
/** @} */

/** @name Threads
 *  @{ */
/**
 * @brief Convenience wrapper around @ref r_thread_new_full with no
 * CPU-affinity bitset.
 */
#define r_thread_new(name, func, data)                                        \
  r_thread_new_full (name, NULL, func, data)
/**
 * @brief Spawn a new thread running @p func(@p data).
 *
 * @param name    Optional human-readable name (for diagnostics and OS
 *                thread naming where available); may be @c NULL.
 * @param cpuset  Optional CPU-affinity mask; @c NULL leaves the OS
 *                default scheduling in place.
 * @param func    Entry point; its return value is returned by
 *                @ref r_thread_join.
 * @param data    Opaque argument forwarded to @p func.
 * @return New @ref RThread (refcounted), or @c NULL on failure.
 */
R_API RThread * r_thread_new_full   (const rchar * name,
    const RBitset * cpuset, RThreadFunc func, rpointer data);
/** @brief Take a reference on @p thread (alias for @ref r_ref_ref). */
#define r_thread_ref        r_ref_ref
/** @brief Drop a reference on @p thread (alias for @ref r_ref_unref). */
#define r_thread_unref      r_ref_unref
/**
 * @brief Wait for @p thread to terminate and return its result.
 *
 * Joining is one-shot per thread; calling twice on the same thread
 * is undefined.
 */
R_API rpointer  r_thread_join       (RThread * thread);
/**
 * @brief @c RDestroyNotify-compatible "join then unref" helper.
 *
 * Useful for @c RSList / @c RPtrArray destroy paths that should
 * wait for the thread first. Discards the thread's return value.
 */
static inline void r_thread_join_unref (rpointer thread)
{
  r_thread_join (thread);
  r_thread_unref (thread);
}
/**
 * @brief Send signal @p sig to @p thread (POSIX-style; thin wrapper
 * over @c pthread_kill on Unix).
 */
R_API int       r_thread_kill       (RThread * thread, int sig);
/** @brief Return the human-readable name @p thread was given at creation. */
R_API const rchar * r_thread_get_name (const RThread * thread);
/** @brief Return @p thread's OS-assigned numeric ID. */
R_API ruint     r_thread_get_id     (const RThread * thread);
/**
 * @brief Read @p thread's current CPU-affinity bitset into @p cpuset.
 * @return @c TRUE on success, @c FALSE if the OS does not support it.
 */
R_API rboolean  r_thread_get_affinity (const RThread * thread, RBitset * cpuset);
/**
 * @brief Set @p thread's CPU-affinity mask.
 * @return @c TRUE on success, @c FALSE if the OS does not support it.
 */
R_API rboolean  r_thread_set_affinity (RThread * thread, const RBitset * cpuset);

/**
 * @brief Return the calling thread's @ref RThread handle, or @c NULL
 * if the calling thread was not created by rlib.
 */
R_API RThread * r_thread_current    (void);
/** @brief Exit the calling thread, returning @p retval to its joiner. */
R_API void      r_thread_exit       (rpointer retval);
/** @brief Yield the calling thread's remaining quantum to the scheduler. */
R_API void      r_thread_yield      (void);
/** @brief Sleep the calling thread for @p sec whole seconds. */
R_API void      r_thread_sleep      (ruint sec);
/** @brief Sleep the calling thread for @p microsec microseconds. */
R_API void      r_thread_usleep     (rulong microsec);

#ifdef R_OS_WIN32
/**
 * @brief Win32 DLL @c DLL_THREAD_DETACH hook; must be called by the
 * host process's @c DllMain so per-thread state can be torn down.
 */
R_API void      r_thread_win32_dll_thread_detach (void);
#endif
/** @} */

/** @} */ /* r_threads group */

R_END_DECLS

#endif /* __R_THREAD_H__ */
