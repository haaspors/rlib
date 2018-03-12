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
#include <rlib/data/rtimeoutcblist.h>

struct _RToCB {
  RRef ref;
  RTimeoutCBList * lst;
  RToCB * next;
  RToCB * prev;
  RClockTime ts;
  RFunc cb;
  rpointer data;
  RDestroyNotify datanotify;
  rpointer user;
  RDestroyNotify usernotify;
};

static inline void
r_to_cb_init (RToCB * tocb, RClockTime ts, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  tocb->next = tocb->prev = NULL;
  tocb->ts = ts;
  tocb->cb = cb;
  tocb->data = data;
  tocb->datanotify = datanotify;
  tocb->user = user;
  tocb->usernotify = usernotify;
}

static inline void
r_to_cb_deinit (RToCB * tocb)
{
  if (tocb->datanotify != NULL)
    tocb->datanotify (tocb->data);
  if (tocb->usernotify != NULL)
    tocb->usernotify (tocb->user);
}

static inline void
r_timeout_cblist_internal_insert (RTimeoutCBList * lst, RToCB * tocb)
{
  RToCB * it;

  tocb->lst = lst;
  if (lst->head == NULL) {
    lst->head = lst->tail = tocb;
  } else if (tocb->ts >= lst->tail->ts) { /* last */
    tocb->prev = lst->tail;
    lst->tail->next = tocb;
    lst->tail = tocb;
  } else if (tocb->ts < lst->head->ts) { /* first */
    tocb->next = lst->head;
    lst->head->prev = tocb;
    lst->head = tocb;
  } else if (tocb->ts - lst->head->ts > lst->tail->ts - tocb->ts) { /* iterate backwards */
    for (it = lst->tail->prev; tocb->ts < it->ts; it = it->prev)
      ;

    /* insert after it */
    tocb->next = it->next;
    tocb->prev = it;
    it->next->prev = tocb;
    it->next = tocb;
  } else { /* iterate forwards */
    for (it = lst->head->next; tocb->ts >= it->ts; it = it->next)
      ;

    /* insert before it */
    tocb->prev = it->prev;
    tocb->next = it;
    it->prev->next = tocb;
    it->prev = tocb;
  }

  lst->size++;
}

