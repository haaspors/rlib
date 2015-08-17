/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_ATOMIC_H__
#define __R_ATOMIC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#if __has_extension(c_atomic)
#define USE_CLANG_ATOMICS         1
#elif R_GNUC_PREREQ(4, 7)
#define USE_GNUC_ATOMICS          1
#elif defined(__GNUC__)
#define USE_SYNC_ATOMICS          1
#elif defined(_MSC_VER)
#include <windows.h>
#define USE_MSC_ATOMICS           1
#endif


R_BEGIN_DECLS

#if defined(USE_CLANG_ATOMICS) || defined(USE_GNUC_ATOMICS)
typedef _Atomic(int)        raint;
typedef _Atomic(ruint)      rauint;
typedef _Atomic(ruintptr)   raptr;
#elif defined(USE_MSC_ATOMICS)
typedef int volatile        raint;
typedef ruint volatile      rauint;
typedef ruintptr volatile   raptr;
#else
typedef int                 raint;
typedef ruint               rauint;
typedef ruintptr            raptr;
#endif

R_API int       r_atomic_int_load             (raint * a);
R_API void      r_atomic_int_store            (raint * a, int val);
R_API int       r_atomic_int_exchange         (raint * a, int val);
R_API rboolean  r_atomic_int_cmp_xchg_weak    (raint * a, int * old, int val);
R_API rboolean  r_atomic_int_cmp_xchg_strong  (raint * a, int * old, int val);
R_API int       r_atomic_int_fetch_add        (raint * a, int val);
R_API int       r_atomic_int_fetch_sub        (raint * a, int val);
R_API int       r_atomic_int_fetch_and        (raint * a, int val);
R_API int       r_atomic_int_fetch_or         (raint * a, int val);
R_API int       r_atomic_int_fetch_xor        (raint * a, int val);

R_API ruint     r_atomic_uint_load            (rauint * a);
R_API void      r_atomic_uint_store           (rauint * a, ruint val);
R_API ruint     r_atomic_uint_exchange        (rauint * a, ruint val);
R_API rboolean  r_atomic_uint_cmp_xchg_weak   (rauint * a, ruint * old, ruint val);
R_API rboolean  r_atomic_uint_cmp_xchg_strong (rauint * a, ruint * old, ruint val);
R_API ruint     r_atomic_uint_fetch_add       (rauint * a, ruint val);
R_API ruint     r_atomic_uint_fetch_sub       (rauint * a, ruint val);
R_API ruint     r_atomic_uint_fetch_and       (rauint * a, ruint val);
R_API ruint     r_atomic_uint_fetch_or        (rauint * a, ruint val);
R_API ruint     r_atomic_uint_fetch_xor       (rauint * a, ruint val);

R_API rpointer  r_atomic_ptr_load             (raptr * a);
R_API void      r_atomic_ptr_store            (raptr * a, rpointer val);
R_API rpointer  r_atomic_ptr_exchange         (raptr * a, rpointer val);
R_API rboolean  r_atomic_ptr_cmp_xchg_weak    (raptr * a, rpointer * old, rpointer val);
R_API rboolean  r_atomic_ptr_cmp_xchg_strong  (raptr * a, rpointer * old, rpointer val);
R_API rpointer  r_atomic_ptr_fetch_add        (raptr * a, rpointer val);
R_API rpointer  r_atomic_ptr_fetch_sub        (raptr * a, rpointer val);
R_API rpointer  r_atomic_ptr_fetch_and        (raptr * a, rpointer val);
R_API rpointer  r_atomic_ptr_fetch_or         (raptr * a, rpointer val);
R_API rpointer  r_atomic_ptr_fetch_xor        (raptr * a, rpointer val);

R_END_DECLS

#if defined(USE_CLANG_ATOMICS)
#define r_atomic_int_load(a)                    __c11_atomic_load (a,     __ATOMIC_SEQ_CST)
#define r_atomic_int_store(a, v)                __c11_atomic_store (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_exchange(a, v)             __c11_atomic_exchange (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_cmp_xchg_weak(a, o, v)     __c11_atomic_compare_exchange_weak (a, o, v, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_int_cmp_xchg_strong(a, o, v)   __c11_atomic_compare_exchange_strong (a, o, v, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_add(a, v)            __c11_atomic_fetch_add (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_sub(a, v)            __c11_atomic_fetch_sub (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_and(a, v)            __c11_atomic_fetch_and (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_or(a, v)             __c11_atomic_fetch_or  (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_xor(a, v)            __c11_atomic_fetch_xor (a, v, __ATOMIC_SEQ_CST)

#define r_atomic_uint_load(a)                   __c11_atomic_load (a,     __ATOMIC_SEQ_CST)
#define r_atomic_uint_store(a, v)               __c11_atomic_store (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_exchange(a, v)            __c11_atomic_exchange (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_cmp_xchg_weak(a, o, v)    __c11_atomic_compare_exchange_weak (a, o, v, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_uint_cmp_xchg_strong(a, o, v)  __c11_atomic_compare_exchange_strong (a, o, v, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_add(a, v)           __c11_atomic_fetch_add (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_sub(a, v)           __c11_atomic_fetch_sub (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_and(a, v)           __c11_atomic_fetch_and (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_or(a, v)            __c11_atomic_fetch_or  (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_xor(a, v)           __c11_atomic_fetch_xor (a, v, __ATOMIC_SEQ_CST)

#define r_atomic_ptr_load(a)                    (rpointer)__c11_atomic_load (a,                   __ATOMIC_SEQ_CST)
#define r_atomic_ptr_store(a, v)                __c11_atomic_store (a,              (ruintptr)v,  __ATOMIC_SEQ_CST)
#define r_atomic_ptr_exchange(a, v)             (rpointer)__c11_atomic_exchange (a, (ruintptr)v,  __ATOMIC_SEQ_CST)
#define r_atomic_ptr_cmp_xchg_weak(a, o, v)     __c11_atomic_compare_exchange_weak (a, (ruintptr*)o, (ruintptr)v, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_cmp_xchg_strong(a, o, v)   __c11_atomic_compare_exchange_strong (a, (ruintptr*)o, (ruintptr)v, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_add(a, v)            (rpointer)__c11_atomic_fetch_add (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_sub(a, v)            (rpointer)__c11_atomic_fetch_sub (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_and(a, v)            (rpointer)__c11_atomic_fetch_and (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_or(a, v)             (rpointer)__c11_atomic_fetch_or  (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_xor(a, v)            (rpointer)__c11_atomic_fetch_xor (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#elif defined(USE_GNUC_ATOMICS)
#define r_atomic_int_load(a)                    __atomic_load_n (a,     __ATOMIC_SEQ_CST)
#define r_atomic_int_store(a, v)                __atomic_store_n (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_exchange(a, v)             __atomic_exchange_n (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_cmp_xchg_weak(a, o, v)     __atomic_compare_exchange_n (a, o, v, 1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_int_cmp_xchg_strong(a, o, v)   __atomic_compare_exchange_n (a, o, v, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_add(a, v)            __atomic_fetch_add (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_sub(a, v)            __atomic_fetch_sub (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_and(a, v)            __atomic_fetch_and (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_or(a, v)             __atomic_fetch_or  (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_int_fetch_xor(a, v)            __atomic_fetch_xor (a, v, __ATOMIC_SEQ_CST)

#define r_atomic_uint_load(a)                   __atomic_load_n (a,     __ATOMIC_SEQ_CST)
#define r_atomic_uint_store(a, v)               __atomic_store_n (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_exchange(a, v)            __atomic_exchange_n (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_cmp_xchg_weak(a, o, v)    __atomic_compare_exchange_n (a, o, v, 1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_uint_cmp_xchg_strong(a, o, v)  __atomic_compare_exchange_n (a, o, v, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_add(a, v)           __atomic_fetch_add (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_sub(a, v)           __atomic_fetch_sub (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_and(a, v)           __atomic_fetch_and (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_or(a, v)            __atomic_fetch_or  (a, v, __ATOMIC_SEQ_CST)
#define r_atomic_uint_fetch_xor(a, v)           __atomic_fetch_xor (a, v, __ATOMIC_SEQ_CST)

#define r_atomic_ptr_load(a)                    (rpointer)__atomic_load_n (a,     __ATOMIC_SEQ_CST)
#define r_atomic_ptr_store(a, v)                __atomic_store_n (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_exchange(a, v)             (rpointer)__atomic_exchange_n (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_cmp_xchg_weak(a, o, v)     __atomic_compare_exchange_n (a, (ruintptr*)o, (ruintptr)v, 1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_cmp_xchg_strong(a, o, v)   __atomic_compare_exchange_n (a, (ruintptr*)o, (ruintptr)v, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_add(a, v)            (rpointer)__atomic_fetch_add (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_sub(a, v)            (rpointer)__atomic_fetch_sub (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_and(a, v)            (rpointer)__atomic_fetch_and (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_or(a, v)             (rpointer)__atomic_fetch_or  (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#define r_atomic_ptr_fetch_xor(a, v)            (rpointer)__atomic_fetch_xor (a, (ruintptr)v, __ATOMIC_SEQ_CST)
#elif defined(USE_SYNC_ATOMICS)
#if __has_builtin(__sync_swap)
#define r_atomic_exchange(a, v)                 __sync_swap(a, v)
#else
#define r_atomic_exchange(a, v)                               \
__extension__ ({                                              \
  __typeof__(a) __a = (a);                                    \
  __typeof__(v) __v = (v);                                    \
  __sync_synchronize();                                       \
  __sync_lock_test_and_set(__a, __v);                         \
})
#endif
#define r_atomic_cmp_xchg(a, o, v)                            \
__extension__ ({                                              \
  __typeof__(o) __op = (o);                                   \
  __typeof__(*o) __o = *__op;                                 \
  ((*__op = __sync_val_compare_and_swap(a, __o, v)) == __o);  \
})

#define r_atomic_int_load(a)                    __sync_fetch_and_add(a, 0)
#define r_atomic_int_store(a, v)                r_atomic_exchange (a, v)
#define r_atomic_int_exchange(a, v)             r_atomic_exchange (a, v)
#define r_atomic_int_cmp_xchg_weak(a, o, v)     r_atomic_cmp_xchg (a, o, v)
#define r_atomic_int_cmp_xchg_strong(a, o, v)   r_atomic_cmp_xchg (a, o, v)
#define r_atomic_int_fetch_add(a, v)            __sync_fetch_and_add (a, v)
#define r_atomic_int_fetch_sub(a, v)            __sync_fetch_and_sub (a, v)
#define r_atomic_int_fetch_and(a, v)            __sync_fetch_and_and (a, v)
#define r_atomic_int_fetch_or(a, v)             __sync_fetch_and_or  (a, v)
#define r_atomic_int_fetch_xor(a, v)            __sync_fetch_and_xor (a, v)

#define r_atomic_uint_load(a)                   __sync_fetch_and_add(a, 0)
#define r_atomic_uint_store(a, v)               r_atomic_exchange (a, v)
#define r_atomic_uint_exchange(a, v)            r_atomic_exchange (a, v)
#define r_atomic_uint_cmp_xchg_weak(a, o, v)    r_atomic_cmp_xchg (a, o, v)
#define r_atomic_uint_cmp_xchg_strong(a, o, v)  r_atomic_cmp_xchg (a, o, v)
#define r_atomic_uint_fetch_add(a, v)           __sync_fetch_and_add (a, v)
#define r_atomic_uint_fetch_sub(a, v)           __sync_fetch_and_sub (a, v)
#define r_atomic_uint_fetch_and(a, v)           __sync_fetch_and_and (a, v)
#define r_atomic_uint_fetch_or(a, v)            __sync_fetch_and_or  (a, v)
#define r_atomic_uint_fetch_xor(a, v)           __sync_fetch_and_xor (a, v)

#define r_atomic_ptr_load(a)                    (rpointer)__sync_fetch_and_add(a, 0)
#define r_atomic_ptr_store(a, v)                r_atomic_exchange (a, (ruintptr)v)
#define r_atomic_ptr_exchange(a, v)             (rpointer)r_atomic_exchange (a, (ruintptr)v)
#define r_atomic_ptr_cmp_xchg_weak(a, o, v)     r_atomic_cmp_xchg (a, (ruintptr*)o, (ruintptr)v)
#define r_atomic_ptr_cmp_xchg_strong(a, o, v)   r_atomic_cmp_xchg (a, (ruintptr*)o, (ruintptr)v)
#define r_atomic_ptr_fetch_add(a, v)            (rpointer)__sync_fetch_and_add (a, (ruintptr)v)
#define r_atomic_ptr_fetch_sub(a, v)            (rpointer)__sync_fetch_and_sub (a, (ruintptr)v)
#define r_atomic_ptr_fetch_and(a, v)            (rpointer)__sync_fetch_and_and (a, (ruintptr)v)
#define r_atomic_ptr_fetch_or(a, v)             (rpointer)__sync_fetch_and_or  (a, (ruintptr)v)
#define r_atomic_ptr_fetch_xor(a, v)            (rpointer)__sync_fetch_and_xor (a, (ruintptr)v)
#elif USE_MSC_ATOMICS
#include <intrin.h>

/* TODO: Check if this works with MSC */
#define r_atomic_int_load(a)                    (MemoryBarrier(), *a)
#define r_atomic_int_store(a, v)                _InterlockedExchange ((long volatile *)a, (long)v)
#define r_atomic_int_exchange(a, v)             _InterlockedExchange ((long volatile *)a, (long)v)
#define r_atomic_int_cmp_xchg_weak(a, o, v)     (_InterlockedCompareExchange ((long volatile *)a, (long)v, *((long*)o)) == *((long*)o))
#define r_atomic_int_cmp_xchg_strong(a, o, v)   (_InterlockedCompareExchange ((long volatile *)a, (long)v, *((long*)o)) == *((long*)o))
#define r_atomic_int_fetch_add(a, v)            _InterlockedExchangeAdd ((long volatile *)a, (long)v)
#define r_atomic_int_fetch_sub(a, v)            _InterlockedExchangeAdd ((long volatile *)a, -((long)v))
#define r_atomic_int_fetch_and(a, v)            _InterlockedAnd ((long volatile *)a, (long)v)
#define r_atomic_int_fetch_or(a, v)             _InterlockedOr ((long volatile *)a, (long)v)
#define r_atomic_int_fetch_xor(a, v)            _InterlockedXor ((long volatile *)a, (long)v)

#define r_atomic_uint_load(a)                   (MemoryBarrier(), *a)
#define r_atomic_uint_store(a, v)               _InterlockedExchange ((long volatile *)a, (long)v)
#define r_atomic_uint_exchange(a, v)            _InterlockedExchange ((long volatile *)a, (long)v)
#define r_atomic_uint_cmp_xchg_weak(a, o, v)    (_InterlockedCompareExchange ((long volatile *)a, (long)v, *((long*)o)) == *((long*)o))
#define r_atomic_uint_cmp_xchg_strong(a, o, v)  (_InterlockedCompareExchange ((long volatile *)a, (long)v, *((long*)o)) == *((long*)o))
#define r_atomic_uint_fetch_add(a, v)           _InterlockedExchangeAdd ((long volatile *)a, (long)v)
#define r_atomic_uint_fetch_sub(a, v)           _InterlockedExchangeAdd ((long volatile *)a, -((long)v))
#define r_atomic_uint_fetch_and(a, v)           _InterlockedAnd ((long volatile *)a, (long)v)
#define r_atomic_uint_fetch_or(a, v)            _InterlockedOr ((long volatile *)a, (long)v)
#define r_atomic_uint_fetch_xor(a, v)           _InterlockedXor ((long volatile *)a, (long)v)

#define r_atomic_ptr_load(a)                    (rpointer)(MemoryBarrier(), *a)
#define r_atomic_ptr_store(a, v)                _InterlockedExchangePointer ((rpointer volatile)a, (rpointer)v)
#define r_atomic_ptr_exchange(a, v)             (rpointer)_InterlockedExchangePointer ((rpointer volatile)a, (rpointer)v)
#define r_atomic_ptr_cmp_xchg_weak(a, o, v)     (_InterlockedCompareExchangePointer ((rpointer volatile)a, (rpointer)v, *(o)) == *(o))
#define r_atomic_ptr_cmp_xchg_strong(a, o, v)   (_InterlockedCompareExchangePointer ((rpointer volatile)a, (rpointer)v, *(o)) == *(o))
#if RLIB_SIZEOF_VOID_P == 4
#define r_atomic_ptr_fetch_add(a, v)            (rpointer)_InterlockedExchangeAdd ((long volatile *)a, (long)v)
#define r_atomic_ptr_fetch_sub(a, v)            (rpointer)_InterlockedExchangeAdd ((long volatile *)a, -((long)v))
#define r_atomic_ptr_fetch_and(a, v)            (rpointer)_InterlockedAnd ((long volatile *)a, (long)v)
#define r_atomic_ptr_fetch_or(a, v)             (rpointer)_InterlockedOr ((long volatile *)a, (long)v)
#define r_atomic_ptr_fetch_xor(a, v)            (rpointer)_InterlockedXor ((long volatile *)a, (long)v)
#elif RLIB_SIZEOF_VOID_P == 8
#define r_atomic_ptr_fetch_add(a, v)            (rpointer)_InterlockedExchangeAdd64 ((_int64 volatile *)a, (_int64)v)
#define r_atomic_ptr_fetch_sub(a, v)            (rpointer)_InterlockedExchangeAdd64 ((_int64 volatile *)a, -((_int64)v))
#define r_atomic_ptr_fetch_and(a, v)            (rpointer)_InterlockedAnd64 ((_int64 volatile *)a, (_int64)v)
#define r_atomic_ptr_fetch_or(a, v)             (rpointer)_InterlockedOr64 ((_int64 volatile *)a, (_int64)v)
#define r_atomic_ptr_fetch_xor(a, v)            (rpointer)_InterlockedXor64 ((_int64 volatile *)a, (_int64)v)
#else
#error only x86 and x86_64 with MSC supported
#endif
#endif

#endif /* __R_ATOMIC_H__ */
