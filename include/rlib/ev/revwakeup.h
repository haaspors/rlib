/* RLIB - Convenience library for useful things
 * Copyright (C) 2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_EV_WAKEUP_H__
#define __R_EV_WAKEUP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/ev/revwakeup.h
 * @brief Event-loop wakeup source for waking a blocked loop from
 * another thread.
 */

#include <rlib/rtypes.h>

#include <rlib/ev/revloop.h>
#include <rlib/rref.h>

/**
 * @defgroup r_evwakeup Event-loop wakeup
 * @ingroup r_ev
 *
 * @brief A thread-safe nudge that wakes an @ref REvLoop blocked in
 * its poll.
 *
 * Create an @ref REvWakeup on the loop, then call
 * @ref r_ev_wakeup_signal from any thread to make the loop return
 * promptly from its current wait — the standard way to hand control
 * back to the loop thread after producing work elsewhere.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted event-loop wakeup source. */
typedef struct REvWakeup REvWakeup;

/** @brief Create a wakeup source on @p loop. */
R_API REvWakeup * r_ev_wakeup_new (REvLoop * loop);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_ev_wakeup_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_ev_wakeup_unref r_ref_unref

/** @brief Wake the loop from another thread; safe to call concurrently. */
R_API rboolean r_ev_wakeup_signal (REvWakeup * wakeup);

R_END_DECLS

/** @} */

#endif /* __R_EV_WAKEUP_H__ */



