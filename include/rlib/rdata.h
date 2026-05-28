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
#ifndef __R_DATA_H__
#define __R_DATA_H__

/**
 * @defgroup r_data Data structures
 *
 * @brief Containers, strings, multi-precision integers and the
 * supporting primitives (hash functions, hazard pointers, callback
 * tuples) that the rest of rlib builds on.
 *
 * The data sub-tree groups into a few areas:
 *
 *   - **Numeric** — @c r_mpint, the multi-precision integer and
 *     its constant-time Montgomery-form @c RMpintFE companions.
 *   - **Text** — @c r_string, a refcounted growable byte string.
 *   - **Maps and sets** — @c r_hashtable, @c r_hashset and
 *     @c r_dictionary (a typedef alias for @c RHashTable). The
 *     hash itself is pluggable via @c r_hashfuncs.
 *   - **Sequences** — @c r_list (doubly-linked), @c r_queue
 *     (deque / ring buffer), @c r_ptrarray and the keyed
 *     @c r_kvptrarray.
 *   - **Specialised** — @c r_bitset, @c r_dirtree
 *     (path-component tree), @c r_timeoutcblist (timer-driven
 *     callbacks).
 *   - **Concurrency primitives** — @c r_hzrptr (hazard pointers
 *     for safe reclamation in lock-free data structures).
 *   - **Callback plumbing** — @c r_cbctx, the
 *     `(function, ctx, destroy-notify)` tuple that
 *     @c r_timeoutcblist and other callback collections key on.
 *
 * Refcounted data structures here derive from @c RRef (declared in
 * @c rlib/rref.h); the @c r_*_ref / @c r_*_unref macros each
 * delegates to @c r_ref_ref / @c r_ref_unref.
 */

#include <rlib/rlib.h>

#include <rlib/data/rbitset.h>
#include <rlib/data/rcbctx.h>
#include <rlib/data/rdictionary.h>
#include <rlib/data/rdirtree.h>
#include <rlib/data/rhashfuncs.h>
#include <rlib/data/rhashset.h>
#include <rlib/data/rhashtable.h>
#include <rlib/data/rhzrptr.h>
#include <rlib/data/rkvptrarray.h>
#include <rlib/data/rlist.h>
#include <rlib/data/rmpint.h>
#include <rlib/data/rptrarray.h>
#include <rlib/data/rqueue.h>
#include <rlib/data/rstring.h>
#include <rlib/data/rtimeoutcblist.h>

#endif /* __R_DATA_H__ */
