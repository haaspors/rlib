/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/rthreads.h>

#include <rlib/os/rsys.h>

#include <rlib/data/rlist.h>

#include <rlib/rlog.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>
#include <rlib/rtime.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#define R_PTHREAD_KEY(tss)          (pthread_key_t)((tss)->impl.ui)
#endif
#ifdef HAVE_MACH_THREAD_POLICY_H
#include <mach/mach.h>
#endif
#ifdef HAVE_SCHED_H
#include <sched.h>
#endif
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#include <string.h>
#include <time.h>

#if defined (R_OS_WIN32)
#include <windows.h>
#include <process.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

/* TODO: Implement support for RCond on Windows XP! */

#if defined (R_OS_WIN32)
static RSList * g__r_tss_win32_dtors = NULL;
#endif

static RTss g__r_thread_self = R_TSS_INIT ((RDestroyNotify)r_thread_unref);

struct _RThread
{
  RRef ref;
  ruint thread_id;
  rchar * name;
  RThreadFunc func;
  rpointer data;
  rpointer retval;
  rboolean joined;
  rboolean is_rthread;
  rboolean is_root;
#if defined (R_OS_WIN32)
  HANDLE thread;
#elif defined (HAVE_PTHREAD_H)
  pthread_t thread;
  RMutex join_mutex;
#endif
};

#if defined (R_OS_WIN32)
#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
   DWORD dwType;
   LPCSTR szName;
   DWORD dwThreadID;
   DWORD dwFlags;
} THREADNAME_INFO;
#pragma pack(pop)
#endif

R_LOG_CATEGORY_DEFINE_STATIC (rthreadcat, "thread", "RLib threads",
    R_CLR_BG_YELLOW | R_CLR_FMT_BOLD);
#define R_LOG_CAT_DEFAULT &rthreadcat

/******************************************************************************/
/*  INIT/DEINIT                                                               */
/******************************************************************************/
void
r_thread_init (void)
{
  RThread * thread = r_thread_current ();

  r_log_category_register (&rthreadcat);

#ifdef HAVE_PTHREAD_GETNAME_NP
  static const int maxname = 24;
  rchar name[maxname + 1];
  if (pthread_getname_np (thread->thread, name, maxname) == 0 && name[0] != 0) {
    thread->name = r_strdup (name);
  } else
#endif
  {
    thread->name = r_strdup ("main/root");
  }

  thread->is_root = TRUE;
}

void
r_thread_deinit (void)
{
  RThread * thread = r_thread_current ();

  if (thread != NULL && thread->is_root) {
    r_tss_set (&g__r_thread_self, NULL);
    /* FIXME: Should this be necessary?? */
    r_thread_unref (thread);
  }

#if defined (R_OS_WIN32)
  r_slist_destroy (g__r_tss_win32_dtors);
  g__r_tss_win32_dtors = NULL;
#endif
}

#if defined (R_OS_WIN32)
void
r_thread_win32_dll_thread_detach (void)
{
  RSList * it;
  rboolean cont;

  do {
    cont = FALSE;
    for (it = g__r_tss_win32_dtors; it != NULL; it = it->next) {
      RTss * tss = it->data;
      rpointer v = r_tss_get (tss);
      if (v != NULL) {
        r_tss_set (tss, NULL);
        tss->notify (v);
        cont = TRUE;
      }
    }
  } while (cont);
}
#endif


/******************************************************************************/
/*  ROnce                                                                     */
/******************************************************************************/
rpointer
r_call_once (ROnce * once, RThreadFunc f, rpointer a)
{
  ruint old = R_ONCE_STATE_INIT;

  if (r_atomic_uint_cmp_xchg_strong (&once->state, &old, R_ONCE_STATE_RUNNING)) {
    once->ret = f (a);
    r_atomic_uint_store (&once->state, R_ONCE_STATE_DONE);
  } else if (old == R_ONCE_STATE_RUNNING) {
    /* Wait for once func to finish in other thread */
    do {
      r_thread_yield ();
    } while (r_atomic_uint_load (&once->state) != R_ONCE_STATE_DONE);
  }

  return once->ret;
}

/******************************************************************************/
/*  RTss - Thread spesific storage                                            */
/******************************************************************************/
#ifdef RLIB_HAVE_THREADS
static void
r_tss_ensure_allocated (RTss * tss)
{
#if defined (R_OS_WIN32)
  if (R_UNLIKELY (tss->impl.u32 == 0)) {
    ruint old = 0, tls;

    if ((tls = TlsAlloc ()) == TLS_OUT_OF_INDEXES)
      abort ();

    if (!r_atomic_uint_cmp_xchg_strong (&tss->impl.u32, &old, tls)) {
      TlsFree (tls);
    } else if (tss->notify != NULL) {
      RSList * dtor = r_slist_alloc (tss);
      dtor->next = r_atomic_ptr_exchange (&g__r_tss_win32_dtors, dtor);
    }
  }
#elif defined (HAVE_PTHREAD_H)
  if (R_UNLIKELY (tss->impl.ptr == NULL)) {
    pthread_key_t key;
    rpointer old = NULL;
    if (pthread_key_create (&key, tss->notify) != 0)
      abort ();

    if (!r_atomic_ptr_cmp_xchg_strong (&tss->impl.aptr, &old, (ruintptr)key))
      pthread_key_delete (key);
  }
#endif
}
#endif

rpointer
r_tss_get (RTss * tss)
{
#ifdef RLIB_HAVE_THREADS
  r_tss_ensure_allocated (tss);
#if defined (R_OS_WIN32)
  return TlsGetValue (tss->impl.u32);
#elif defined (HAVE_PTHREAD_H)
  return pthread_getspecific (R_PTHREAD_KEY (tss));
#else
#error Not implemented
#endif
#else
  return tss->impl.ptr;
#endif
}

void
r_tss_set (RTss * tss, rpointer data)
{
#ifdef RLIB_HAVE_THREADS
  r_tss_ensure_allocated (tss);
#if defined (R_OS_WIN32)
  TlsSetValue (tss->impl.u32, data);
#elif defined (HAVE_PTHREAD_H)
  pthread_setspecific (R_PTHREAD_KEY (tss), data);
#else
#error Not implemented
#endif
#else
  tss->impl.ptr = data;
#endif
}

/******************************************************************************/
/*  RMutex - Mutual exclusion primitive                                       */
/******************************************************************************/
void
r_mutex_init (RMutex * mutex)
{
#if defined (R_OS_WIN32)
  LPCRITICAL_SECTION cs = *mutex = r_mem_new (CRITICAL_SECTION);
  InitializeCriticalSection (cs);
#elif defined (HAVE_PTHREAD_H)
  pthread_mutex_t * ptm = *mutex = r_mem_new (pthread_mutex_t);
  pthread_mutex_init (ptm, NULL);
#else
  (void) mutex;
#endif
}

void
r_mutex_clear (RMutex * mutex)
{
#if defined (R_OS_WIN32)
  DeleteCriticalSection ((LPCRITICAL_SECTION)*mutex);
#elif defined (HAVE_PTHREAD_H)
  pthread_mutex_destroy ((pthread_mutex_t *)*mutex);
#endif
  r_free (*mutex);
}

void
r_mutex_lock (RMutex * mutex)
{
#if defined (R_OS_WIN32)
  LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)*mutex;
  EnterCriticalSection (cs);
  if (R_UNLIKELY (cs->RecursionCount > 1))
    abort ();
#elif defined (HAVE_PTHREAD_H)
  pthread_mutex_lock ((pthread_mutex_t *)*mutex);
#else
  (void) mutex;
#endif
}

rboolean
r_mutex_trylock (RMutex * mutex)
{
#if defined (R_OS_WIN32)
  return TryEnterCriticalSection ((LPCRITICAL_SECTION)*mutex);
#elif defined (HAVE_PTHREAD_H)
  return (pthread_mutex_trylock ((pthread_mutex_t *)*mutex) == 0);
#else
  (void) mutex;
  return TRUE;
#endif
}

void
r_mutex_unlock (RMutex * mutex)
{
#if defined (R_OS_WIN32)
  LeaveCriticalSection ((LPCRITICAL_SECTION)*mutex);
#elif defined (HAVE_PTHREAD_H)
  pthread_mutex_unlock ((pthread_mutex_t *)*mutex);
#else
  (void) mutex;
#endif
}

void
r_rmutex_init (RRMutex * mutex)
{
#if defined (R_OS_WIN32)
  LPCRITICAL_SECTION cs = *mutex = r_mem_new (CRITICAL_SECTION);
  InitializeCriticalSection (cs);
#elif defined (HAVE_PTHREAD_H)
  pthread_mutexattr_t attr;
  pthread_mutex_t * ptm = *mutex = r_mem_new (pthread_mutex_t);

  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (ptm, &attr);
  pthread_mutexattr_destroy (&attr);
#else
  (void) mutex;
#endif
}

void
r_rmutex_clear (RRMutex * mutex)
{
#if defined (R_OS_WIN32)
  DeleteCriticalSection ((LPCRITICAL_SECTION)*mutex);
#elif defined (HAVE_PTHREAD_H)
  pthread_mutex_destroy ((pthread_mutex_t *)*mutex);
#endif
  r_free (*mutex);
}

void
r_rmutex_lock (RRMutex * mutex)
{
#if defined (R_OS_WIN32)
  EnterCriticalSection ((LPCRITICAL_SECTION)*mutex);
#elif defined (HAVE_PTHREAD_H)
  pthread_mutex_lock ((pthread_mutex_t *)*mutex);
#else
  (void) mutex;
#endif
}

rboolean
r_rmutex_trylock (RRMutex * mutex)
{
#if defined (R_OS_WIN32)
  return TryEnterCriticalSection ((LPCRITICAL_SECTION)*mutex);
#elif defined (HAVE_PTHREAD_H)
  return (pthread_mutex_trylock ((pthread_mutex_t *)*mutex) == 0);
#else
  (void) mutex;
  return TRUE;
#endif
}

void
r_rmutex_unlock (RRMutex * mutex)
{
#if defined (R_OS_WIN32)
  LeaveCriticalSection ((LPCRITICAL_SECTION)*mutex);
#elif defined (HAVE_PTHREAD_H)
  pthread_mutex_unlock ((pthread_mutex_t *)*mutex);
#else
  (void) mutex;
#endif
}

/******************************************************************************/
/*  RCond - Condition variable primitive                                      */
/******************************************************************************/
void
r_cond_init (RCond * cond)
{
#if defined (R_OS_WIN32)
  PCONDITION_VARIABLE pc = *cond = r_mem_new (CONDITION_VARIABLE);
  InitializeConditionVariable (pc);
#elif defined (HAVE_PTHREAD_H)
  pthread_condattr_t attr;
  pthread_cond_t * pc;

  pthread_condattr_init (&attr);
  pc = *cond = r_mem_new (pthread_cond_t);

  pthread_cond_init (pc, &attr);
  pthread_condattr_destroy (&attr);
#else
  (void) cond;
#endif
}

void
r_cond_clear (RCond * cond)
{
#if defined (HAVE_PTHREAD_H)
  pthread_cond_destroy ((pthread_cond_t *)*cond);
#endif
  r_free (*cond);
}

void
r_cond_wait (RCond * cond, RMutex * mutex)
{
#if defined (R_OS_WIN32)
  SleepConditionVariableCS ((PCONDITION_VARIABLE)*cond,
      (LPCRITICAL_SECTION)*mutex, INFINITE);
#elif defined (HAVE_PTHREAD_H)
  pthread_cond_wait ((pthread_cond_t *)*cond, (pthread_mutex_t *)*mutex);
#else
  (void) cond;
  (void) mutex;
#endif
}

#if 0
rboolean
r_cond_wait_timed (RCond * cond, RMutex * mutex, rulong microsec)
{
  rboolean ret;
#if defined (R_OS_WIN32)
  if (!(ret = SleepConditionVariableCS ((PCONDITION_VARIABLE)*cond,
      (LPCRITICAL_SECTION)*mutex, microsec / 1000))) {
    /* GetLastError () should be ERROR_TIMEOUT */
  }
#elif defined (HAVE_PTHREAD_H)
  struct timespec expire;
  int waitret;
  clock_gettime (CLOCK_MONOTONIC, &expire)
  expire.tv_sec = microsec / R_USEC_PER_SEC;
  expire.tv_nsec = 1000 * (microsec % R_USEC_PER_SEC);
  waitret = pthread_cond_timedwait ((pthread_cond_t *)*cond,
      (pthread_mutex_t *)*mutex, &expire);

  if (!(ret = (waitret == 0))) {
    /* waitret should be ETIMEDOUT */
  }
#else
  (void) cond;
  ret = FALSE;
#endif
  return ret;
}
#endif

void
r_cond_signal (RCond * cond)
{
#if defined (R_OS_WIN32)
  WakeConditionVariable ((PCONDITION_VARIABLE)*cond);
#elif defined (HAVE_PTHREAD_H)
  pthread_cond_signal ((pthread_cond_t*)*cond);
#else
  (void) cond;
#endif
}

void
r_cond_broadcast (RCond * cond)
{
#if defined (R_OS_WIN32)
  WakeAllConditionVariable ((PCONDITION_VARIABLE)*cond);
#elif defined (HAVE_PTHREAD_H)
  pthread_cond_broadcast ((pthread_cond_t*)*cond);
#else
  (void) cond;
#endif
}

/******************************************************************************/
/*  RThread                                                                   */
/******************************************************************************/
static void
r_thread_free (RThread * thread)
{
  if (R_LIKELY (thread != NULL)) {
#ifdef RLIB_HAVE_THREADS
#if defined (R_OS_WIN32)
    CloseHandle ((HANDLE)thread->thread);
#elif defined (HAVE_PTHREAD_H)
    if (R_UNLIKELY (!thread->joined))
      pthread_detach (thread->thread);
    if (!thread->is_root)
      r_mutex_clear (&thread->join_mutex);
#endif
#endif
    r_free (thread->name);
    r_free (thread);
  }
}

#ifdef RLIB_HAVE_THREADS
#if defined (R_OS_WIN32)
static ruint __stdcall
#else
static rpointer
#endif
r_thread_trampoline (rpointer data)
{
  RThread * thread = data;

  r_tss_set (&g__r_thread_self, r_thread_ref (thread));
  if (thread->name != NULL) {
#if defined (R_OS_WIN32)
    THREADNAME_INFO info = { 0x1000, thread->name, -1, 0 };
    static const DWORD MS_VC_EXCEPTION = 0x406D1388;

    __try {
      RaiseException (MS_VC_EXCEPTION, 0,
          sizeof (THREADNAME_INFO) / sizeof (ULONG_PTR), (ULONG_PTR*)&info);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }
#elif defined (HAVE_PTHREAD_SETNAME_NP_WITH_TID)
    pthread_setname_np (thread->thread, thread->name);
#elif defined (HAVE_PTHREAD_SETNAME_NP_WITHOUT_TID)
    pthread_setname_np (thread->name);
#elif defined (HAVE_SYS_PRCTL_H) && defined (PR_SET_NAME)
    prctl (PR_SET_NAME, thread->name, 0, 0, 0, 0);
#else
#warning set thread name not supported
#endif
  }

#if defined (HAVE_PTHREAD_GETTHREADID_NP)
  thread->thread_id = (ruint)pthread_getthreadid_np ();
#elif defined (HAVE_PTHREAD_THREADID_NP)
  {
    __uint64_t ktid;
    pthread_threadid_np (NULL, &ktid);
    thread->thread_id = (ruint)ktid;
  }
#elif defined (HAVE_GETTID)
  thread->thread_id = (ruint)gettid ();
#endif

  R_LOG_INFO ("Thread %s [%u] starting", thread->name, thread->thread_id);
  thread->retval = thread->func (thread->data);
  R_LOG_TRACE ("Thread %s [%u] ending", thread->name, thread->thread_id);

#if defined (R_OS_WIN32)
  return 0;
#else
  return NULL;
#endif
}
#endif

RThread *
r_thread_new_full (const rchar * name,
    const RBitset * cpuset, RThreadFunc func, rpointer data)
{
  RThread * ret;

  if (R_UNLIKELY (func == NULL)) return NULL;
  if (cpuset != NULL && r_bitset_popcount (cpuset) == 0) return NULL;

  if ((ret = r_mem_new (RThread)) != NULL) {
    int err;
#if defined (HAVE_PTHREAD_H)
    pthread_attr_t attr;
#endif

    r_ref_init (ret, r_thread_free);
    ret->thread_id = 0;
    ret->name = r_strdup (name);
    ret->func = func;
    ret->data = data;
    ret->retval = NULL;
    ret->joined = FALSE;
    ret->is_rthread = TRUE;
    ret->is_root = FALSE;
#ifdef RLIB_HAVE_THREADS
#if defined (R_OS_WIN32)
    if ((ret->thread = (HANDLE)_beginthreadex (NULL, 0, r_thread_trampoline, ret,
        0, &ret->thread_id)) == NULL) {
      r_thread_unref (ret);
      ret = NULL;
    }
#elif defined (HAVE_PTHREAD_H)
    r_mutex_init (&ret->join_mutex);
    pthread_attr_init (&attr);
#ifdef HAVE_PTHREAD_ATTR_SETAFFINITY_NP
    if (cpuset != NULL) {
      rsize i, csetsize = CPU_ALLOC_SIZE (MAX (cpuset->bits, CPU_SETSIZE));
      cpu_set_t * cset = r_alloca0 (csetsize);

      for (i = 0; i < cpuset->bits; i++) {
        if (r_bitset_is_bit_set (cpuset, i))
          CPU_SET (i, cset);
      }
      if ((err = pthread_attr_setaffinity_np (&attr, csetsize, cset)) == 0) {
        cpuset = NULL;
      } else {
        rchar * str = r_bitset_to_human_readable (cpuset);
        R_LOG_ERROR ("pthread_attr_setaffinity_np error %u - %s for cpuset: [%s]",
            err, strerror (err), str);
        r_free (str);
      }
    }
#endif
    if ((err = pthread_create (&ret->thread, &attr, r_thread_trampoline, ret)) != 0) {
      rchar * str;

      if (cpuset != NULL)
        str = r_bitset_to_human_readable (cpuset);
      else
        str = r_strdup ("all");
      R_LOG_ERROR ("Error when creating new thread %u - %s with cpuset: [%s]",
          err, strerror (err), str);
      r_free (str);
      r_thread_unref (ret);
      ret = NULL;
    }
    pthread_attr_destroy (&attr);
#endif
#endif
  }

  if (ret != NULL && cpuset != NULL)
    r_thread_set_affinity (ret, cpuset);

  return ret;
}

#if RLIB_SIZEOF_VOID_P == 8
#define THR_FMT "%14p"
#else
#define THR_FMT "%10p"
#endif

rpointer
r_thread_join (RThread * thread)
{
#ifdef RLIB_HAVE_THREADS
  R_LOG_TRACE ("Trying to join thread %s [%u] "THR_FMT,
      thread->name, thread->thread_id, thread);
#if defined (R_OS_WIN32)
  if (!thread->joined) {
    WaitForSingleObject (thread->thread, INFINITE);
    thread->joined = TRUE;
  }
#elif defined (HAVE_PTHREAD_H)
  r_mutex_lock (&thread->join_mutex);
  if (!thread->joined) {
    if (pthread_join (thread->thread, NULL) != 0) {
      R_LOG_ERROR ("Error when join thread %s [%u] "THR_FMT,
          thread->name, thread->thread_id, thread);
    }
    thread->joined = TRUE;
  }
  r_mutex_unlock (&thread->join_mutex);
#endif
#endif

  return thread->retval;
}

int
r_thread_kill (RThread * thread, int sig)
{
#ifdef RLIB_HAVE_THREADS
#if defined (R_OS_WIN32)
  /* FIXME: Implement something that will look like a signal to the thread */
  (void)thread;
  (void)sig;
  return EINVAL;
#elif defined (HAVE_PTHREAD_H)
  return pthread_kill (thread->thread, sig);
#endif
#else
  (void)thread;
  (void)sig;
  return EINVAL;
#endif
}

RThread *
r_thread_current (void)
{
  RThread * thread = r_tss_get (&g__r_thread_self);

  if (R_UNLIKELY (thread == NULL)) {
    if ((thread = r_mem_new0 (RThread)) != NULL) {
      r_ref_init (thread, r_thread_free);
#ifdef RLIB_HAVE_THREADS
#if defined (R_OS_WIN32)
      thread->thread_id = GetCurrentThreadId ();
      thread->thread = OpenThread (THREAD_ALL_ACCESS, FALSE, thread->thread_id);
#elif defined (HAVE_PTHREAD_H)
      thread->thread = pthread_self ();
#endif
#endif

      r_tss_set (&g__r_thread_self, thread);
    }
  }

  return thread;
}

const rchar *
r_thread_get_name (const RThread * thread)
{
  return thread->name;
}

ruint
r_thread_get_id (const RThread * thread)
{
  return thread->thread_id;
}

rboolean
r_thread_get_affinity (const RThread * thread, RBitset * cpuset)
{
#ifdef RLIB_HAVE_THREADS
#if defined (R_OS_WIN32)
  DWORD_PTR mask, old;

  if (R_UNLIKELY (thread == NULL)) return FALSE;
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  r_bitset_clear (cpuset);
  for (mask = 1; mask > 0; mask <<= 1) {
    if ((old = SetThreadAffinityMask (thread->thread, mask)) != 0) {
      SetThreadAffinityMask (thread->thread, old);
#if RLIB_SIZEOF_VOID_P == 8
      return r_bitset_set_u64_at (cpuset, old, 0);
#elif RLIB_SIZEOF_VOID_P == 4
      return r_bitset_set_u32_at (cpuset, old, 0);
#else
#error "weird windows architecture!"
#endif
    } else if (GetLastError () != ERROR_INVALID_PARAMETER) {
      break;
    }
  }
#elif defined (HAVE_PTHREAD_GETAFFINITY_NP)
  rsize csetsize;
  cpu_set_t * cset;

  if (R_UNLIKELY (thread == NULL)) return FALSE;
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  r_bitset_clear (cpuset);
  csetsize = CPU_ALLOC_SIZE (MAX (cpuset->bits, CPU_SETSIZE));
  cset = r_alloca0 (csetsize);
  if (pthread_getaffinity_np (thread->thread, csetsize, cset) == 0) {
    rsize i = 0;
    for (; i < cpuset->bits; i++) {
      if (!r_bitset_set_bit (cpuset, i, CPU_ISSET (i, cset)))
        return FALSE;
    }
    return TRUE;
  }
#elif defined (HAVE_MACH_THREAD_POLICY_H)
  mach_port_t mach_thread;

  if (R_UNLIKELY (thread == NULL)) return FALSE;
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  /* FIXME: This is just bogus! OSX doesn't have proper API for affinity */
  r_bitset_clear (cpuset);
  if ((mach_thread = pthread_mach_thread_np (thread->thread)) != 0) {
    thread_affinity_policy_data_t data = { THREAD_AFFINITY_TAG_NULL };
    mach_msg_type_number_t count = THREAD_AFFINITY_POLICY_COUNT;
    boolean_t def = FALSE;

    if (thread_policy_get (mach_thread, THREAD_AFFINITY_POLICY,
          (thread_policy_t)&data, &count, &def) == KERN_SUCCESS) {
      if (data.affinity_tag == THREAD_AFFINITY_TAG_NULL)
        r_bitset_set_n_bits_at (cpuset, r_sys_cpu_logical_count (), 0, TRUE);
      return TRUE;
    }
  }
#endif
#endif
  return FALSE;
}

rboolean
r_thread_set_affinity (RThread * thread, const RBitset * cpuset)
{
#ifdef RLIB_HAVE_THREADS
#if defined (R_OS_WIN32)
  DWORD_PTR mask;

  if (R_UNLIKELY (thread == NULL)) return FALSE;
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

#if RLIB_SIZEOF_VOID_P == 8
  mask = r_bitset_get_u64_at (cpuset, 0);
#elif RLIB_SIZEOF_VOID_P == 4
  mask = r_bitset_get_u32_at (cpuset, 0);
#else
#error "weird windows architecture!"
#endif
  return SetThreadAffinityMask (thread->thread, mask) != 0;
#elif defined (HAVE_PTHREAD_SETAFFINITY_NP)
  rsize csetsize;
  cpu_set_t * cset;
  rsize i;

  if (R_UNLIKELY (thread == NULL)) return FALSE;
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  csetsize = CPU_ALLOC_SIZE (MAX (cpuset->bits, CPU_SETSIZE));
  cset = r_alloca0 (csetsize);
  for (i = 0; i < CPU_SETSIZE && i < cpuset->bits; i++) {
    if (r_bitset_is_bit_set (cpuset, i))
      CPU_SET (i, cset);
  }
  return pthread_setaffinity_np (thread->thread, csetsize, cset) == 0;
#elif defined (HAVE_MACH_THREAD_POLICY_H)
  mach_port_t mach_thread;

  if (R_UNLIKELY (thread == NULL)) return FALSE;
  if (R_UNLIKELY (cpuset == NULL)) return FALSE;

  /* FIXME: This is also bogus! OSX doesn't have proper API for affinity */
  if (r_bitset_popcount (cpuset) == r_sys_cpu_logical_count ()) {
    if ((mach_thread = pthread_mach_thread_np (thread->thread)) != 0) {
      thread_affinity_policy_data_t data = { THREAD_AFFINITY_TAG_NULL };

      thread_policy_set (mach_thread, THREAD_AFFINITY_POLICY,
          (thread_policy_t)&data, THREAD_AFFINITY_POLICY_COUNT);
    }
  }
  return TRUE;
#endif
#endif
  return FALSE;
}

void
r_thread_exit (rpointer retval)
{
  RThread * thread = r_thread_current ();
  if (R_UNLIKELY (!thread->is_rthread))
    abort ();
  thread->retval = retval;
#ifdef RLIB_HAVE_THREADS
#if defined (R_OS_WIN32)
  _endthreadex (0);
#elif defined (HAVE_PTHREAD_H)
  pthread_exit (NULL);
#endif
#endif
}

void
r_thread_yield (void)
{
#if defined (R_OS_WIN32)
  Sleep(0);
#elif defined (HAVE_SCHED_H)
  sched_yield ();
#else
  r_thread_sleep (0);
#endif
}
void
r_thread_sleep (ruint sec)
{
#if defined (R_OS_WIN32)
  Sleep (sec * 1000);
#elif defined (R_OS_UNIX)
  sleep (sec);
#else
  (void) sec;
#pragma message "sleep not supported"
#endif
}

void
r_thread_usleep (rulong microsec)
{
#if defined (R_OS_WIN32)
  Sleep (microsec / 1000);
#elif defined (R_OS_UNIX)
  struct timespec req, left;
  req.tv_sec = microsec / R_USEC_PER_SEC;
  req.tv_nsec = 1000 * (microsec % R_USEC_PER_SEC);
  while (nanosleep (&req, &left) == -1 && errno == EINTR)
    req = left;
#else
  (void) microsec;
#pragma message "nanosleep not supported"
#endif
}

