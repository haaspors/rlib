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

#include "config.h"
#include "rtimeoutcblist-private.h"

#include <rlib/rmem.h>

#define r_to_cb_internal_free(tocb)                                           \
  R_STMT_START {                                                              \
    (tocb)->next = (tocb)->prev = NULL;                                       \
    (tocb)->lst = NULL;                                                       \
    r_to_cb_unref (tocb);                                                     \
  } R_STMT_END

static void
r_to_cb_free (RToCB * cb)
{
  r_to_cb_deinit (cb);
  r_free (cb);
}

static RToCB *
r_to_cb_alloc (RClockTime ts, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  RToCB * ret;
  if ((ret = r_mem_new (RToCB)) != NULL) {
    r_ref_init (ret, r_to_cb_free);
    r_to_cb_init (ret, ts, cb, data, datanotify, user, usernotify);
  }
  return ret;
}

void
r_timeout_cblist_clear (RTimeoutCBList * lst)
{
  RToCB * it = lst->head;

  r_timeout_cblist_init (lst);

  while (it != NULL) {
    RToCB * cur = it;
    it = it->next;
    r_to_cb_internal_free (cur);
  }
}

rboolean
r_timeout_cblist_insert (RTimeoutCBList * lst,
    RToCB ** out, RClockTime ts, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  RToCB * tocb;

  if ((tocb = r_to_cb_alloc (ts, cb, data, datanotify, user, usernotify)) != NULL) {
    r_timeout_cblist_internal_insert (lst, tocb);
    if (out != NULL)
      *out = r_to_cb_ref (tocb);
    return TRUE;
  }

  if (out != NULL)
    *out = NULL;
  return FALSE;
}

rboolean
r_timeout_cblist_cancel (RTimeoutCBList * lst, RToCB * cb)
{
  RToCB * next, * prev;

  if (R_UNLIKELY (cb == NULL)) return FALSE;
  if (R_UNLIKELY (cb->lst != lst)) return FALSE;

  if (cb == lst->head)
    lst->head = cb->next;
  if (cb == lst->tail)
    lst->tail = cb->prev;

  prev = cb->prev;
  next = cb->next;
  if (prev != NULL)
    prev->next = cb->next;
  if (next != NULL)
    next->prev = cb->prev;

  r_to_cb_internal_free (cb);
  lst->size--;
  return TRUE;
}

RClockTime
r_timeout_cblist_first_timeout (RTimeoutCBList * lst)
{
  return (lst->head != NULL) ? lst->head->ts : R_CLOCK_TIME_NONE;
}

rsize
r_timeout_cblist_update (RTimeoutCBList * lst, RClockTime ts)
{
  rsize ret = 0;

  while (lst->head != NULL) {
    RToCB * cur = lst->head;

    if (ts < cur->ts)
      break;

    if (R_LIKELY (cur->cb != NULL))
      cur->cb (cur->data, cur->user);

    lst->head = lst->head->next;
    r_to_cb_internal_free (cur);
    ret++;
  }

  if (lst->head != NULL)
    lst->head->prev = NULL;
  else
    lst->tail = NULL;

  lst->size -= ret;
  return ret;
}

