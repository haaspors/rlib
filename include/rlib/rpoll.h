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
#ifndef __R_POLL_H__
#define __R_POLL_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rpoll.h
 * @brief Cross-platform poll-style multiplexer for @c RIOHandle plus
 * a self-resizing @ref RPollSet container.
 */

#include <rlib/rtypes.h>

#include <rlib/data/rhashtable.h>

/**
 * @defgroup r_poll Polling and poll sets
 *
 * @brief Synchronous IO-readiness multiplexer.
 *
 * @ref r_poll is a thin wrapper around @c poll() / @c WSAPoll() that
 * takes a flat @ref RPoll array. @ref RPollSet adds bookkeeping for
 * an arbitrary-size set with per-handle user data and constant-time
 * lookups (handle → index, handle → user pointer).
 *
 * This is the synchronous polling primitive; for high-throughput
 * event-driven I/O use @c r_evloop (ev/) which sits on @c epoll /
 * @c kqueue / IOCP.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Single poll descriptor; mirrors @c struct @c pollfd. */
typedef struct {
  RIOHandle handle;   /**< Handle to poll. */
  rushort events;     /**< Requested events bitmask (@c POLL* constants). */
  rushort revents;    /**< Returned events, filled by @ref r_poll. */
} RPoll;

/**
 * @brief Wait until any descriptor in @p handles becomes ready or
 * @p timeout elapses.
 *
 * @param handles Array of @p count descriptors to watch.
 * @param count   Number of descriptors.
 * @param timeout Maximum time to wait, or @c R_CLOCK_TIME_NONE for "wait forever".
 * @return Number of descriptors with non-zero @c revents, @c 0 on
 *         timeout, or @c -1 on error.
 */
R_API int r_poll (RPoll * handles, ruint count, RClockTime timeout);

/**
 * @brief Self-resizing collection of @ref RPoll entries with
 * per-handle user data and constant-time handle lookups.
 *
 * Internal fields are exposed so callers can pass @c set->handles /
 * @c set->count straight to @ref r_poll without an extra copy.
 */
typedef struct {
  RHashTable * handle_user;   /**< Internal: handle -> user pointer. */
  RHashTable * handle_idx;    /**< Internal: handle -> index in @c handles. */
  ruint count;                /**< Number of in-use entries. */
  ruint alloc;                /**< Capacity of the @c handles array. */
  RPoll * handles;            /**< Backing array of @c count active entries. */
} RPollSet;

/** @brief Initialise @p ps with an initial capacity of @p alloc entries. */
R_API void r_poll_set_init (RPollSet * ps, ruint alloc);
/** @brief Tear down @p ps; does not close the handles. */
R_API void r_poll_set_clear (RPollSet * ps);

/**
 * @brief Add @p handle with @p events watched and an opaque @p user
 * pointer for later lookup.
 * @return Index of the new entry, or @c -1 on failure.
 */
R_API int r_poll_set_add (RPollSet * ps, RIOHandle handle, rushort events, rpointer user);
/** @brief Remove @p handle from the set; safe if it isn't present. */
R_API rboolean r_poll_set_remove (RPollSet * ps, RIOHandle handle);

/** @brief Look up @p handle's index in the set, or @c -1 if absent. */
R_API int r_poll_set_find (RPollSet * ps, RIOHandle handle);
/** @brief Retrieve the @c user pointer that was associated with @p handle. */
R_API rpointer r_poll_set_get_user (RPollSet * ps, RIOHandle handle);

R_END_DECLS

/** @} */

#endif /* __R_POLL_H__ */


