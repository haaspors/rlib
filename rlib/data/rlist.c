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

#include "config.h"
#include <rlib/data/rlist.h>

/******************************************************************************/
/* Doubly linked list                                                         */
/******************************************************************************/
#define r_list_data_equal   r_direct_equal
#define r_list_clear(lst)
R__LIST_IMPL (RList, r_list, rpointer,,)

/******************************************************************************/
/* Singly linked list                                                         */
/******************************************************************************/
#define r_slist_data_equal  r_direct_equal
#define r_slist_clear(lst)
R__SLIST_IMPL (RSList, r_slist, rpointer,,)

/******************************************************************************/
/* Free list (Singly linked list)                                             */
/******************************************************************************/
static inline
rboolean r_free_list_data_equal (rconstpointer a, rconstpointer b)
{
  const RFreePtrCtx * actx = a;
  const RFreePtrCtx * bctx = b;
  return actx->ptr == bctx->ptr && actx->notify == bctx->notify;
}
#define r_free_list_clear(lst)
R__SLIST_IMPL (RFreeList, r_free_list, RFreePtrCtx, &,)

/******************************************************************************/
/* Callback list (Doubly linked list)                                         */
/******************************************************************************/
static inline rboolean
r_cblist_data_equal (rconstpointer a, rconstpointer b)
{
  return r_memcmp (a, b, sizeof (RFuncCallbackCtx)) == 0;
}
static void
r_cblist_clear (RCBList * lst)
{
  r_func_callback_ctx_clear (&lst->data);
}
R__LIST_IMPL (RCBList, r_cblist, RFuncCallbackCtx, &,)

RCBList *
r_cblist_alloc_full (RFunc cb, rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify)
{
  RCBList * ret;
  if ((ret = r_mem_new (RCBList)) != NULL) {
    r_func_callback_ctx_init (&ret->data, cb, data, datanotify, user, usernotify);
    ret->next = ret->prev = NULL;
  }
  return ret;
}

RCBList *
r_cblist_prepend_full (RCBList * entry, RFunc cb, rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify)
{
  RCBList * ret = r_cblist_alloc_full (cb, data, datanotify, user, usernotify);
  if ((ret->next = entry) != NULL)
    ret->next->prev = ret;
  return ret;
}

RCBList *
r_cblist_append_full (RCBList * entry, RFunc cb, rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify)
{
  RCBList * lst = r_cblist_alloc_full (cb, data, datanotify, user, usernotify);

  if (entry != NULL) {
    RCBList * last = entry;
    while (last->next != NULL)
      last = last->next;
    last->next = lst;
    lst->prev = last;
  } else {
    entry = lst;
  }

  return entry;
}

rboolean
r_cblist_contains (RCBList * head, RFunc cb, rpointer data)
{
  if (head != NULL) {
    RCBList * it;
    for (it = head; it != NULL; it = it->next) {
      if (it->data.cb == cb && it->data.data == data)
        return TRUE;
    }
    for (it = head->prev; it != NULL; it = it->prev) {
      if (it->data.cb == cb && it->data.data == data)
        return TRUE;
    }
  }
  return FALSE;
}

rsize
r_cblist_call (RCBList * head)
{
  rsize ret = 0;
  for (; head != NULL; head = head->next) {
    if (R_LIKELY (head->data.cb != NULL)) {
      r_func_callback_ctx_call (&head->data);
      ret++;
    }
  }
  return ret;
}

/******************************************************************************/
/* Callback return list (Doubly linked list)                                  */
/******************************************************************************/
static inline rboolean
r_cbrlist_data_equal (rconstpointer a, rconstpointer b)
{
  return r_memcmp (a, b, sizeof (RFuncReturnCallbackCtx)) == 0;
}
static void
r_cbrlist_clear (RCBRList * lst)
{
  r_func_return_callback_ctx_clear (&lst->data);
}
R__LIST_IMPL (RCBRList, r_cbrlist, RFuncReturnCallbackCtx, &,)

RCBRList *
r_cbrlist_alloc_full (RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  RCBRList * ret;
  if ((ret = r_mem_new (RCBRList)) != NULL) {
    r_func_return_callback_ctx_init (&ret->data, cb, data, datanotify, user, usernotify);
    ret->next = ret->prev = NULL;
  }
  return ret;
}

RCBRList *
r_cbrlist_prepend_full (RCBRList * head, RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  RCBRList * ret = r_cbrlist_alloc_full (cb, data, datanotify, user, usernotify);
  if ((ret->next = head) != NULL)
    ret->next->prev = ret;
  return ret;
}

RCBRList *
r_cbrlist_append_full (RCBRList * entry, RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  RCBRList * n = r_cbrlist_alloc_full (cb, data, datanotify, user, usernotify);

  if (entry != NULL) {
    RCBRList * last = entry;
    while (last->next != NULL)
      last = last->next;
    last->next = n;
    n->prev = last;
  } else {
    entry = n;
  }

  return entry;
}

rboolean
r_cbrlist_contains (RCBRList * lst, RFuncReturn cb, rpointer data)
{
  if (lst != NULL) {
    RCBRList * it;

    for (it = lst; it != NULL; it = it->next) {
      if (it->data.cb == cb && it->data.data == data)
        return TRUE;
    }
    for (it = lst->prev; it != NULL; it = it->prev) {
      if (it->data.cb == cb && it->data.data == data)
        return TRUE;
    }
  }

  return FALSE;
}

RCBRList *
r_cbrlist_call (RCBRList * head)
{
  RCBRList * it, * next;

  for (it = head; it != NULL; it = next) {
    next = it->next;
    if (it->data.cb == NULL || !r_func_return_callback_ctx_call (&it->data)) {
      RCBRList * prev = it->prev;
      RCBRList * next = it->next;

      if (head == it)
        head = next;

      if (prev != NULL)
        prev->next = it->next;
      if (next != NULL)
        next->prev = it->prev;

      r_cbrlist_free1 (it);
    }
  }

  return head;
}

/******************************************************************************/
/* Callback list (Singly linked list)                                         */
/******************************************************************************/
static inline rboolean
r_cbslist_data_equal (rconstpointer a, rconstpointer b)
{
  return r_memcmp (a, b, sizeof (RFuncCallbackCtx)) == 0;
}
static void
r_cbslist_clear (RCBSList * lst)
{
  r_func_callback_ctx_clear (&lst->data);
}
R__SLIST_IMPL (RCBSList, r_cbslist, RFuncCallbackCtx, &,)

RCBSList *
r_cbslist_alloc_full (RFunc cb, rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify)
{
  RCBSList * ret;
  if ((ret = r_mem_new (RCBSList)) != NULL) {
    r_func_callback_ctx_init (&ret->data, cb, data, datanotify, user, usernotify);
    ret->next = NULL;
  }
  return ret;
}

RCBSList *
r_cbslist_prepend_full (RCBSList * head, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify)
{
  return r_cbslist_prepend_link (head,
      r_cbslist_alloc_full (cb, data, datanotify, user, usernotify));
}

RCBSList *
r_cbslist_append_full (RCBSList * entry, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify)
{
  return r_cbslist_append_link (entry,
      r_cbslist_alloc_full (cb, data, datanotify, user, usernotify));
}

rboolean
r_cbslist_contains (RCBSList * head, RFunc cb, rpointer data)
{
  if (head != NULL) {
    RCBSList * it;
    for (it = head; it != NULL; it = it->next) {
      if (it->data.cb == cb && it->data.data == data)
        return TRUE;
    }
  }
  return FALSE;
}

rsize
r_cbslist_call (RCBSList * head)
{
  rsize ret = 0;
  for (; head != NULL; head = head->next) {
    if (R_LIKELY (head->data.cb != NULL)) {
      r_func_callback_ctx_call (&head->data);
      ret++;
    }
  }
  return ret;
}
