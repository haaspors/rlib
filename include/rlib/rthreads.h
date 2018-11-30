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

typedef enum
{
  R_ONCE_STATE_INIT,
  R_ONCE_STATE_RUNNING,
  R_ONCE_STATE_DONE
} ROnceState;

#define R_ONCE_INIT { R_ONCE_STATE_INIT, NULL }
typedef struct
{
  rauint state;
  rpointer ret;
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
typedef struct _RThread RThread;


/* Run once */
R_API rpointer  r_call_once         (ROnce * once, RThreadFunc f, rpointer a);

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
