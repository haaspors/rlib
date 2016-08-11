/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_TIMEOUT_CBLIST_H__
#define __R_TIMEOUT_CBLIST_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

typedef struct _RToCB RToCB;

typedef struct {
  RToCB * head;
  RToCB * tail;

  rsize size;
} RTimeoutCBList;

#define R_TIMEOUT_CBLIST_INIT { NULL, NULL, 0 }
#define r_timeout_cblist_init(lst) r_memset (lst, 0, sizeof (RTimeoutCBList))

R_API void r_timeout_cblist_clear (RTimeoutCBList * lst);
#define r_timeout_cblist_len(lst) (lst)->size

R_API rboolean r_timeout_cblist_insert (RTimeoutCBList * lst, RClockTime ts, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify);
R_API rsize r_timeout_cblist_update (RTimeoutCBList * lst, RClockTime ts);

R_END_DECLS

#endif /* __R_TIMEOUT_CBLIST_H__ */

