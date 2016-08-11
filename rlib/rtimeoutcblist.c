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
#include <rlib/rtimeoutcblist.h>

#include <rlib/rmem.h>

struct _RToCB {
  RToCB * next;
  RToCB * prev;
  RClockTime ts;
  RFunc cb;
  rpointer data;
  RDestroyNotify datanotify;
  rpointer user;
  RDestroyNotify usernotify;
};

static RToCB *
r_to_cb_alloc (RClockTime ts, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  RToCB * ret;
  if ((ret = r_mem_new (RToCB)) != NULL) {
    ret->next = ret->prev = NULL;
    ret->ts = ts;
    ret->cb = cb;
    ret->data = data;
    ret->datanotify = datanotify;
    ret->user = user;
    ret->usernotify = usernotify;
  }
  return ret;
}

static void
r_to_cb_free (RToCB * cb)
{
  if (cb->datanotify != NULL)
    cb->datanotify (cb->data);
  if (cb->usernotify != NULL)
    cb->usernotify (cb->user);

  r_free (cb);
}

void
r_timeout_cblist_clear (RTimeoutCBList * lst)
{
  RToCB * it = lst->head;

  r_timeout_cblist_init (lst);

  while (it != NULL) {
    RToCB * cur = it;
    it = it->next;
    r_to_cb_free (cur);
  }
}

rboolean
r_timeout_cblist_insert (RTimeoutCBList * lst, RClockTime ts, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  RToCB * tocb, * it;

  if ((tocb = r_to_cb_alloc (ts, cb, data, datanotify, user, usernotify)) != NULL) {
    if (lst->head == NULL) {
      lst->head = lst->tail = tocb;
    } else if (ts >= lst->tail->ts) { /* last */
      tocb->prev = lst->tail;
      lst->tail->next = tocb;
      lst->tail = tocb;
    } else if (ts < lst->head->ts) { /* first */
      tocb->next = lst->head;
      lst->head->prev = tocb;
      lst->head = tocb;
    } else if (ts - lst->head->ts > lst->tail->ts - ts) { /* iterate backwards */
      for (it = lst->tail->prev; ts < it->ts; it = it->prev)
        ;

      /* insert after it */
      tocb->next = it->next;
      tocb->prev = it;
      it->next->prev = tocb;
      it->next = tocb;
    } else { /* iterate forwards */
      for (it = lst->head->next; ts >= it->ts; it = it->next)
        ;

      /* insert before it */
      tocb->prev = it->prev;
      tocb->next = it;
      it->prev->next = tocb;
      it->prev = tocb;
    }

    lst->size++;
    return TRUE;
  }

  return FALSE;
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
    r_to_cb_free (cur);
    ret++;
  }

  if (lst->head == NULL)
    lst->tail = NULL;

  lst->size -= ret;
  return ret;
}

