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
#include "rlib-internal.h"
#include <rlib/rthreads.h>
#include <rlib/ralloc.h>
#include <rlib/rlist.h>
#include <rlib/rstr.h>
#include <rlib/rtime.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#define R_PTHREAD_KEY(tss)          (pthread_key_t)((tss)->impl.ui)
#endif
#ifdef HAVE_SCHED_H
#include <sched.h>
#endif
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#include <time.h>

#ifdef R_OS_WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#endif

/* TODO: Implement support for RCond on Windows XP! */

#ifdef R_OS_WIN32
static RSList * g__r_tss_win32_dtors = NULL;
#endif

static RTss g__r_thread_self = R_TSS_INIT ((RDestroyNotify)r_thread_unref);

struct _RThread
{
  rauint ref_count;
  ruint thread_id;
  rchar * name;
  RThreadFunc func;
  rpointer data;
  rpointer retval;
  rboolean joined;
  rboolean is_rthread;
  rboolean is_root;
#ifdef R_OS_WIN32
  HANDLE thread;
#else
  pthread_t thread;
  RMutex join_mutex;
#endif
};

#ifdef R_OS_WIN32
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


/******************************************************************************/
/*  INIT/DEINIT                                                               */
/******************************************************************************/
void
r_thread_init (void)
{
  RThread * thread = r_thread_current ();

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
#ifdef R_OS_WIN32
  r_slist_destroy (g__r_tss_win32_dtors);
  g__r_tss_win32_dtors = NULL;
#endif
}

#ifdef R_OS_WIN32
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
static void
r_tss_ensure_allocated (RTss * tss)
{
#ifdef R_OS_WIN32
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
#else
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

rpointer
r_tss_get (RTss * tss)
{
  r_tss_ensure_allocated (tss);
#ifdef R_OS_WIN32
  return TlsGetValue (tss->impl.u32);
#else
  return pthread_getspecific (R_PTHREAD_KEY (tss));
#endif
}

void
r_tss_set (RTss * tss, rpointer data)
{
  r_tss_ensure_allocated (tss);
#ifdef R_OS_WIN32
//#error thread specific data destructor emulation not impl
  TlsSetValue (tss->impl.u32, data);
#else
  pthread_setspecific (R_PTHREAD_KEY (tss), data);
#endif
}

/******************************************************************************/
/*  RMutext - Mutual exclusion primitive                                      */
/******************************************************************************/
void
r_mutex_init (RMutex * mutex)
{
#ifdef R_OS_WIN32
  LPCRITICAL_SECTION cs = *mutex = r_malloc (sizeof (CRITICAL_SECTION));
  InitializeCriticalSection (cs);
#else
  pthread_mutex_t * ptm = *mutex = r_malloc (sizeof (pthread_mutex_t));
  pthread_mutex_init (ptm, NULL);
#endif
}

void
r_mutex_clear (RMutex * mutex)
{
#ifdef R_OS_WIN32
  DeleteCriticalSection ((LPCRITICAL_SECTION)*mutex);
#else
  pthread_mutex_destroy ((pthread_mutex_t *)*mutex);
#endif
  r_free (*mutex);
}

void
r_mutex_lock (RMutex * mutex)
{
#ifdef R_OS_WIN32
  LPCRITICAL_SECTION cs = (LPCRITICAL_SECTION)*mutex;
  EnterCriticalSection (cs);
  if (R_UNLIKELY (cs->RecursionCount > 1))
    abort ();
#else
  pthread_mutex_lock ((pthread_mutex_t *)*mutex);
#endif
}

rboolean
r_mutex_trylock (RMutex * mutex)
{
#ifdef R_OS_WIN32
  return TryEnterCriticalSection ((LPCRITICAL_SECTION)*mutex);
#else
  return (pthread_mutex_trylock ((pthread_mutex_t *)*mutex) == 0);
#endif
}

void
r_mutex_unlock (RMutex * mutex)
{
#ifdef R_OS_WIN32
  LeaveCriticalSection ((LPCRITICAL_SECTION)*mutex);
#else
  pthread_mutex_unlock ((pthread_mutex_t *)*mutex);
#endif
}

void
r_rmutex_init (RRMutex * mutex)
{
#ifdef R_OS_WIN32
  LPCRITICAL_SECTION cs = *mutex = r_malloc (sizeof (CRITICAL_SECTION));
  InitializeCriticalSection (cs);
#else
  pthread_mutexattr_t attr;
  pthread_mutex_t * ptm = *mutex = r_malloc (sizeof (pthread_mutex_t));

  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (ptm, &attr);
  pthread_mutexattr_destroy (&attr);
#endif
}

void
r_rmutex_clear (RRMutex * mutex)
{
#ifdef R_OS_WIN32
  DeleteCriticalSection ((LPCRITICAL_SECTION)*mutex);
#else
  pthread_mutex_destroy ((pthread_mutex_t *)*mutex);
#endif
  r_free (*mutex);
}

void
r_rmutex_lock (RRMutex * mutex)
{
#ifdef R_OS_WIN32
  EnterCriticalSection ((LPCRITICAL_SECTION)*mutex);
#else
  pthread_mutex_lock ((pthread_mutex_t *)*mutex);
#endif
}

rboolean
r_rmutex_trylock (RRMutex * mutex)
{
#ifdef R_OS_WIN32
  return TryEnterCriticalSection ((LPCRITICAL_SECTION)*mutex);
#else
  return (pthread_mutex_trylock ((pthread_mutex_t *)*mutex) == 0);
#endif
}

void
r_rmutex_unlock (RRMutex * mutex)
{
#ifdef R_OS_WIN32
  LeaveCriticalSection ((LPCRITICAL_SECTION)*mutex);
#else
  pthread_mutex_unlock ((pthread_mutex_t *)*mutex);
#endif
}

/******************************************************************************/
/*  RCond - Condition variable primitive                                      */
/******************************************************************************/
void
r_cond_init (RCond * cond)
{
#ifdef R_OS_WIN32
  PCONDITION_VARIABLE pc = *cond = r_malloc (sizeof (CONDITION_VARIABLE));
  InitializeConditionVariable (pc);
#else
  pthread_condattr_t attr;
  pthread_cond_t * pc;

  pthread_condattr_init (&attr);
  pc = *cond = r_malloc (sizeof (pthread_cond_t));

  pthread_cond_init (pc, &attr);
  pthread_condattr_destroy (&attr);
#endif
}

void
r_cond_clear (RCond * cond)
{
#ifdef R_OS_WIN32
#else
  pthread_cond_destroy ((pthread_cond_t *)*cond);
#endif
  r_free (*cond);
}

void
r_cond_wait (RCond * cond, RMutex * mutex)
{
#ifdef R_OS_WIN32
  SleepConditionVariableCS ((PCONDITION_VARIABLE)*cond,
      (LPCRITICAL_SECTION)*mutex, INFINITE);
#else
  pthread_cond_wait ((pthread_cond_t *)*cond, (pthread_mutex_t *)*mutex);
#endif
}

#if 0
rboolean
r_cond_wait_timed (RCond * cond, RMutex * mutex, rulong microsec)
{
  rboolean ret;
#ifdef R_OS_WIN32
  if (!(ret = SleepConditionVariableCS ((PCONDITION_VARIABLE)*cond,
      (LPCRITICAL_SECTION)*mutex, microsec / 1000))) {
    /* GetLastError () should be ERROR_TIMEOUT */
  }
#else
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
#endif
  return ret;
}
#endif

void
r_cond_signal (RCond * cond)
{
#ifdef R_OS_WIN32
  WakeConditionVariable ((PCONDITION_VARIABLE)*cond);
#else
  pthread_cond_signal ((pthread_cond_t*)*cond);
#endif
}

void
r_cond_broadcast (RCond * cond)
{
#ifdef R_OS_WIN32
  WakeAllConditionVariable ((PCONDITION_VARIABLE)*cond);
#else
  pthread_cond_broadcast ((pthread_cond_t*)*cond);
#endif
}

/******************************************************************************/
/*  RThread                                                                   */
/******************************************************************************/
#ifdef R_OS_WIN32
static ruint __stdcall
#else
static rpointer
#endif
r_thread_trampoline (rpointer data)
{
  RThread * thread = data;

  r_tss_set (&g__r_thread_self, r_thread_ref (thread));
  if (thread->name != NULL) {
#if defined(R_OS_WIN32)
    THREADNAME_INFO info = { 0x1000, thread->name, -1, 0 };
    static const DWORD MS_VC_EXCEPTION = 0x406D1388;

    __try {
      RaiseException (MS_VC_EXCEPTION, 0,
          sizeof (THREADNAME_INFO) / sizeof (ULONG_PTR), (ULONG_PTR*)&info);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }
#elif defined(HAVE_PTHREAD_SETNAME_NP_WITH_TID)
    pthread_setname_np (thread->thread, thread->name);
#elif defined(HAVE_PTHREAD_SETNAME_NP_WITHOUT_TID)
    pthread_setname_np (thread->name);
#elif defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_NAME)
    prctl (PR_SET_NAME, thread->name, 0, 0, 0, 0);
#else
#warning set thread name not supported
#endif
  }

#if defined(HAVE_PTHREAD_GETTHREADID_NP)
  thread->thread_id = (ruint)pthread_getthreadid_np ();
#elif defined(HAVE_PTHREAD_THREADID_NP)
  {
    __uint64_t ktid;
    pthread_threadid_np (NULL, &ktid);
    thread->thread_id = (ruint)ktid;
  }
#elif defined(HAVE_GETTID)
  thread->thread_id = (ruint)gettid ();
#endif

  thread->retval = thread->func (thread->data);

#ifdef R_OS_WIN32
  return 0;
#else
  return NULL;
#endif
}

RThread *
r_thread_new (const rchar * name, RThreadFunc func, rpointer data)
{
  RThread * ret = r_malloc (sizeof (RThread));
#ifndef R_OS_WIN32
  pthread_attr_t attr;
#endif

  ret->ref_count = 1;
  ret->thread_id = 0;
  ret->name = r_strdup (name);
  ret->func = func;
  ret->data = data;
  ret->retval = NULL;
  ret->joined = FALSE;
  ret->is_rthread = TRUE;
#ifdef R_OS_WIN32
  if ((ret->thread = (HANDLE)_beginthreadex (NULL, 0, r_thread_trampoline, ret,
      0, &ret->thread_id)) == NULL) {
    r_thread_unref (ret);
    ret = NULL;
  }
#else
  r_mutex_init (&ret->join_mutex);
  pthread_attr_init (&attr);
  if (pthread_create (&ret->thread, &attr, r_thread_trampoline, ret) != 0) {
    r_thread_unref (ret);
    ret = NULL;
  }
  pthread_attr_destroy (&attr);
#endif
  return ret;
}

static void
r_thread_free (RThread * thread)
{
  if (R_LIKELY (thread != NULL)) {
#ifdef R_OS_WIN32
    CloseHandle ((HANDLE)thread->thread);
#else
    if (R_UNLIKELY (!thread->joined))
      pthread_detach (thread->thread);
    r_mutex_clear (&thread->join_mutex);
#endif
    r_free (thread->name);
    r_free (thread);
  }
}

RThread *
r_thread_ref (RThread * thread)
{
  r_atomic_uint_fetch_add (&thread->ref_count, 1);
  return thread;
}

void
r_thread_unref (RThread * thread)
{
  if (r_atomic_uint_fetch_sub (&thread->ref_count, 1) == 1)
    r_thread_free (thread);
}

rpointer
r_thread_join (RThread * thread)
{
#ifdef R_OS_WIN32
  if (!thread->joined) {
    WaitForSingleObject (thread->thread, INFINITE);
    thread->joined = TRUE;
  }
#else
  r_mutex_lock (&thread->join_mutex);
  if (!thread->joined) {
    pthread_join (thread->thread, NULL);
    thread->joined = TRUE;
  }
  r_mutex_unlock (&thread->join_mutex);
#endif

  return thread->retval;
}

int
r_thread_kill (RThread * thread, int sig)
{
#ifdef R_OS_WIN32
  /* FIXME: Implement something that will look like a signal to the thread */
  (void)thread;
  (void)sig;
  return EINVAL;
#else
  return pthread_kill (thread->thread, sig);
#endif
}

RThread *
r_thread_current (void)
{
  RThread * thread = r_tss_get (&g__r_thread_self);

  if (R_UNLIKELY (!thread)) {
    thread = r_malloc0 (sizeof (RThread));
    thread->ref_count = 1;
#ifdef R_OS_WIN32
    thread->thread_id = GetCurrentThreadId ();
    thread->thread = OpenThread (THREAD_ALL_ACCESS, FALSE, thread->thread_id);
#else
    thread->thread = pthread_self ();
#endif

    r_tss_set (&g__r_thread_self, thread);
  }

  return thread;
}

const rchar *
r_thread_get_name (RThread * thread)
{
  return thread->name;
}

ruint
r_thread_get_id (RThread * thread)
{
  return thread->thread_id;
}

void
r_thread_exit (rpointer retval)
{
  RThread * thread = r_thread_current ();
  if (R_UNLIKELY (!thread->is_rthread))
    abort ();
  thread->retval = retval;
#ifdef R_OS_WIN32
  _endthreadex (0);
#else
  pthread_exit (NULL);
#endif
}

void
r_thread_yield (void)
{
#ifdef R_OS_WIN32
  Sleep(0);
#else
  sched_yield ();
#endif
}
void
r_thread_sleep (ruint sec)
{
#ifdef R_OS_WIN32
  Sleep (sec * 1000);
#else
  sleep (sec);
#endif
}

void
r_thread_usleep (rulong microsec)
{
#ifdef R_OS_WIN32
  Sleep (microsec / 1000);
#else
  struct timespec req, left;
  req.tv_sec = microsec / R_USEC_PER_SEC;
  req.tv_nsec = 1000 * (microsec % R_USEC_PER_SEC);
  while (nanosleep (&req, &left) == -1 && errno == EINTR)
    req = left;
#endif
}

