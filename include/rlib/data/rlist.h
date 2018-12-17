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
#ifndef __R_LIST_H__
#define __R_LIST_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/data/rlist-internal.h>
#include <rlib/data/rcbctx.h>
#include <rlib/data/rhashfuncs.h>

#include <rlib/rmem.h>

R_BEGIN_DECLS

/******************************************************************************/
/* Doubly linked list                                                         */
/******************************************************************************/
R__LIST_DECL (RList, r_list, rpointer, R_API)
#define r_list_prepend      r_list_prepend_copy
#define r_list_append       r_list_append_copy
#define r_list_contains     r_list_contains_full

/******************************************************************************/
/* Singly linked list                                                         */
/******************************************************************************/
R__SLIST_DECL (RSList, r_slist, rpointer, R_API)
#define r_slist_prepend       r_slist_prepend_copy
#define r_slist_append        r_slist_append_copy
#define r_slist_contains      r_slist_contains_full

/******************************************************************************/
/* Free list (Singly linked list)                                             */
/******************************************************************************/
typedef struct {
  rpointer ptr;
  RDestroyNotify notify;
} RFreePtrCtx;

R__SLIST_DECL (RFreeList, r_free_list, RFreePtrCtx, R_API)

static inline RFreeList * r_free_list_alloc (rpointer ptr, RDestroyNotify notify)
{
  RFreeList * ret;
  if ((ret = r_free_list_alloc0 ()) != NULL) {
    ret->data.ptr = ptr;
    ret->data.notify = notify;
  }
  return ret;
}
static inline RFreeList * r_free_list_prepend (RFreeList * lst,
    rpointer ptr, RDestroyNotify notify)
{
  return r_free_list_prepend_link (lst, r_free_list_alloc (ptr, notify));
}

/******************************************************************************/
/* Callback list (Doubly linked list)                                         */
/******************************************************************************/
R__LIST_DECL (RCBList, r_cblist, RFuncCallbackCtx, R_API)

R_API RCBList * r_cblist_alloc_full (RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_MALLOC;
#define r_cblist_alloc(cb, data, user)                                        \
  r_cblist_alloc_full (cb, data, NULL, user, NULL)
R_API RCBList * r_cblist_prepend_full (RCBList * head, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
#define r_cblist_prepend(head, cb, data, user)                                \
  r_cblist_prepend_full (head, cb, data, NULL, user, NULL)
R_API RCBList * r_cblist_append_full (RCBList * entry, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
#define r_cblist_append(head, cb, data, user)                                 \
  r_cblist_append_full (head, cb, data, NULL, user, NULL)
R_API rboolean r_cblist_contains (RCBList * head, RFunc cb, rpointer data);
R_API rsize r_cblist_call (RCBList * head);

/******************************************************************************/
/* Callback return list (Doubly linked list)                                  */
/******************************************************************************/
R__LIST_DECL (RCBRList, r_cbrlist, RFuncReturnCallbackCtx, R_API)

R_API RCBRList * r_cbrlist_alloc_full (RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_MALLOC;
#define r_cbrlist_alloc(cb, data, user)                                       \
  r_cbrlist_alloc_full (cb, data, NULL, user, NULL)
R_API RCBRList * r_cbrlist_prepend_full (RCBRList * head, RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
#define r_cbrlist_prepend(head, cb, data, user)                               \
  r_cbrlist_prepend_full (head, cb, data, NULL, user, NULL)
R_API RCBRList * r_cbrlist_append_full (RCBRList * entry, RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
#define r_cbrlist_append(head, cb, data, user)                                \
  r_cbrlist_append_full (head, cb, data, NULL, user, NULL)
R_API rboolean r_cbrlist_contains (RCBRList * head, RFuncReturn cb, rpointer data);
R_API RCBRList * r_cbrlist_call (RCBRList * head) R_ATTR_WARN_UNUSED_RESULT;

/******************************************************************************/
/* Callback list (Singly linked list)                                         */
/******************************************************************************/
R__SLIST_DECL (RCBSList, r_cbslist, RFuncCallbackCtx, R_API)

R_API RCBSList * r_cbslist_alloc_full (RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_MALLOC;
#define r_cbslist_alloc(cb, data, user)                                       \
  r_cbslist_alloc_full (cb, data, NULL, user, NULL)
R_API RCBSList * r_cbslist_prepend_full (RCBSList * head, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
#define r_cbslist_prepend(head, cb, data, user)                               \
  r_cbslist_prepend_full (head, cb, data, NULL, user, NULL)
R_API RCBSList * r_cbslist_append_full (RCBSList * entry, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
#define r_cbslist_append(head, cb, data, user)                                \
  r_cbslist_append_full (head, cb, data, NULL, user, NULL)
R_API rboolean r_cbslist_contains (RCBSList * head, RFunc cb, rpointer data);
R_API rsize r_cbslist_call (RCBSList * head);


R_END_DECLS

#endif /* __R_LIST_H__ */
