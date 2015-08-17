/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include <rlib/ratomic.h>

#if !defined(USE_CLANG_ATOMICS) && !defined(USE_GNUC_ATOMICS) && \
    !defined(USE_SYNC_ATOMICS) && !defined(USE_MSC_ATOMICS)
#error Must have compiler support for atomics when compiling rlib
#endif


int
(r_atomic_int_load) (raint * a)
{
  return r_atomic_int_load (a);
}

void
(r_atomic_int_store) (raint * a, int val)
{
  r_atomic_int_store (a, val);
}

int
(r_atomic_int_exchange) (raint * a, int val)
{
  return r_atomic_int_exchange (a, val);
}

rboolean
(r_atomic_int_cmp_xchg_weak) (raint * a, int * old, int val)
{
  return r_atomic_int_cmp_xchg_weak (a, old, val);
}

rboolean
(r_atomic_int_cmp_xchg_strong)  (raint * a, int * old, int val)
{
  return r_atomic_int_cmp_xchg_strong (a, old, val);
}

int
(r_atomic_int_fetch_add) (raint * a, int val)
{
  return r_atomic_int_fetch_add (a, val);
}

int
(r_atomic_int_fetch_sub) (raint * a, int val)
{
  return r_atomic_int_fetch_sub (a, val);
}

int
(r_atomic_int_fetch_and) (raint * a, int val)
{
  return r_atomic_int_fetch_and (a, val);
}

int
(r_atomic_int_fetch_or) (raint * a, int val)
{
  return r_atomic_int_fetch_or (a, val);
}

int
(r_atomic_int_fetch_xor) (raint * a, int val)
{
  return r_atomic_int_fetch_xor (a, val);
}

ruint
(r_atomic_uint_load) (rauint * a)
{
  return r_atomic_uint_load (a);
}

void
(r_atomic_uint_store) (rauint * a, ruint val)
{
  r_atomic_uint_store (a, val);
}

ruint
(r_atomic_uint_exchange) (rauint * a, ruint val)
{
  return r_atomic_uint_exchange (a, val);
}

rboolean
(r_atomic_uint_cmp_xchg_weak) (rauint * a, ruint * old, ruint val)
{
  return r_atomic_uint_cmp_xchg_weak (a, old, val);
}

rboolean
(r_atomic_uint_cmp_xchg_strong) (rauint * a, ruint * old, ruint val)
{
  return r_atomic_uint_cmp_xchg_strong (a, old, val);
}

ruint
(r_atomic_uint_fetch_add) (rauint * a, ruint val)
{
  return r_atomic_uint_fetch_add (a, val);
}

ruint
(r_atomic_uint_fetch_sub) (rauint * a, ruint val)
{
  return r_atomic_uint_fetch_sub (a, val);
}

ruint
(r_atomic_uint_fetch_and) (rauint * a, ruint val)
{
  return r_atomic_uint_fetch_and (a, val);
}

ruint
(r_atomic_uint_fetch_or) (rauint * a, ruint val)
{
  return r_atomic_uint_fetch_or (a, val);
}

ruint
(r_atomic_uint_fetch_xor) (rauint * a, ruint val)
{
  return r_atomic_uint_fetch_xor (a, val);
}

rpointer
(r_atomic_ptr_load) (raptr * a)
{
  return r_atomic_ptr_load (a);
}

void
(r_atomic_ptr_store) (raptr * a, rpointer val)
{
  r_atomic_ptr_store (a, val);
}

rpointer
(r_atomic_ptr_exchange) (raptr * a, rpointer val)
{
  return r_atomic_ptr_exchange (a, val);
}

rboolean
(r_atomic_ptr_cmp_xchg_weak) (raptr * a, rpointer * old, rpointer val)
{
  return r_atomic_ptr_cmp_xchg_weak (a, old, val);
}

rboolean
(r_atomic_ptr_cmp_xchg_strong)  (raptr * a, rpointer * old, rpointer val)
{
  return r_atomic_ptr_cmp_xchg_strong (a, old, val);
}

rpointer
(r_atomic_ptr_fetch_add) (raptr * a, rpointer val)
{
  return r_atomic_ptr_fetch_add (a, val);
}

rpointer
(r_atomic_ptr_fetch_sub) (raptr * a, rpointer val)
{
  return r_atomic_ptr_fetch_sub (a, val);
}

rpointer
(r_atomic_ptr_fetch_and) (raptr * a, rpointer val)
{
  return r_atomic_ptr_fetch_and (a, val);
}

rpointer
(r_atomic_ptr_fetch_or) (raptr * a, rpointer val)
{
  return r_atomic_ptr_fetch_or (a, val);
}

rpointer
(r_atomic_ptr_fetch_xor) (raptr * a, rpointer val)
{
  return r_atomic_ptr_fetch_xor (a, val);
}

