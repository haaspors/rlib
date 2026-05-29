/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_EV_RESOLVE_H__
#define __R_EV_RESOLVE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/ev/revresolve.h
 * @brief Event-loop asynchronous hostname / service resolution.
 */

#include <rlib/rtypes.h>

#include <rlib/ev/revloop.h>
#include <rlib/net/rresolve.h>
#include <rlib/rref.h>

/**
 * @defgroup r_evresolve Event-loop DNS resolution
 * @ingroup r_ev
 *
 * @brief Asynchronous counterpart to @ref r_resolve — resolve a host /
 * service on an @ref REvLoop and deliver the result via callback.
 *
 * Takes the same @ref RResolveAddrFlags / @ref RResolveHints as the
 * synchronous @ref r_resolve_sync; @ref REvResolveFunc fires on the
 * loop thread with the @ref RResolvedAddr list (owned by the resolver
 * for the duration of the callback) and a @ref RResolveResult.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted asynchronous resolve request. */
typedef struct REvResolve REvResolve;
/** @brief Completion callback delivering the resolved addresses and result code. */
typedef void (*REvResolveFunc) (rpointer data, RResolvedAddr * addr, RResolveResult res);

/**
 * @brief Begin resolving @p host / @p service on @p loop; @p flags
 * (@ref RResolveAddrFlags) and the optional @p hints constrain
 * resolution, and @p func is fired with the result.
 */
R_API REvResolve * r_ev_resolve_addr_new (const rchar * host, const rchar * service,
    RResolveAddrFlags flags, const RResolveHints * hints,
    REvLoop * loop, REvResolveFunc func, rpointer data, RDestroyNotify datanotify);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_ev_resolve_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_ev_resolve_unref r_ref_unref

R_END_DECLS

/** @} */

#endif /* __R_EV_RESOLVE_H__ */


