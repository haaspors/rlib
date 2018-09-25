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

#include <rlib/rtypes.h>

#include <rlib/data/rhashtable.h>

R_BEGIN_DECLS

typedef struct {
  RIOHandle handle;
  rushort events;
  rushort revents;
} RPoll;

R_API int r_poll (RPoll * handles, ruint count, RClockTime timeout);

typedef struct {
  RHashTable * handle_user;
  RHashTable * handle_idx;
  ruint count;
  ruint alloc;
  RPoll * handles;
} RPollSet;

R_API void r_poll_set_init (RPollSet * ps, ruint alloc);
R_API void r_poll_set_clear (RPollSet * ps);

R_API int r_poll_set_add (RPollSet * ps, RIOHandle handle, rushort events, rpointer user);
R_API rboolean r_poll_set_remove (RPollSet * ps, RIOHandle handle);

R_API int r_poll_set_find (RPollSet * ps, RIOHandle handle);
R_API rpointer r_poll_set_get_user (RPollSet * ps, RIOHandle handle);

R_END_DECLS

#endif /* __R_POLL_H__ */


