/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include <rlib/rtypes.h>
#include <rlib/rmem.h>

R_BEGIN_DECLS

/******************************************************************************/
/* Free list (Singly linked list)                                             */
/******************************************************************************/
typedef struct _RFreeList RFreeList;

struct _RFreeList {
  rpointer ptr;
  RDestroyNotify notify;
  RFreeList * next;
};

static inline RFreeList * r_free_list_alloc (rpointer ptr, RDestroyNotify notify)
{
  RFreeList * ret;
  if ((ret = r_mem_new (RFreeList)) != NULL) {
    ret->ptr = ptr;
    ret->notify = notify;
    ret->next = NULL;
  }
  return ret;
}
static inline RFreeList * r_free_list_prepend (RFreeList * entry,
    rpointer ptr, RDestroyNotify notify)
{
  RFreeList * ret = r_free_list_alloc (ptr, notify);
  ret->next = entry;
  return ret;
}

static inline void r_free_list_free1 (RFreeList * entry)
{
  if (R_LIKELY (entry != NULL)) {
    if (entry->notify != NULL)
      entry->notify (entry->ptr);
    r_free (entry);
  }
}

static inline void r_free_list_destroy (RFreeList * head)
{
  RFreeList * next;
  while (head != NULL) {
    next = head->next;
    r_free_list_free1 (head);
    head = next;
  }
}

static inline rsize r_free_list_len (RFreeList * head)
{
  rsize ret = 0;

  while (head != NULL) {
    head = head->next;
    ret++;
  }

  return ret;
}

static inline rboolean r_free_list_contains (RFreeList * head, rpointer ptr)
{
  for (; head != NULL; head = head->next) {
    if (head->ptr == ptr)
      return TRUE;
  }

  return FALSE;
}

static inline void r_free_list_foreach (RFreeList * head,
    RFunc func, rpointer user)
{
  RFreeList * it;

  for (it = head; it != NULL; it = it->next)
    func (it->ptr, user);
}

static inline rsize r_free_list_foreach_remove (RFreeList ** head,
    RFuncReturn func, rpointer user)
{
  rsize ret = 0;
  RFreeList * it, * prev;

  for (it = *head, prev = NULL; it != NULL; prev = it, it = it->next) {
    if (func (it->ptr, user)) {
      if (prev != NULL)
        prev->next = it->next;
      else
        head = &it->next;

      r_free_list_free1 (it);
      ret++;
    }
  }

  return ret;
}


/******************************************************************************/
/* Singly linked list                                                         */
/******************************************************************************/
typedef struct _RSList RSList;

struct _RSList {
  rpointer data;
  RSList * next;
};

#define r_slist_data(lst)  (lst)->data
#define r_slist_next(lst)  (lst)->next

static inline RSList * r_slist_alloc (rpointer data)
{
  RSList * ret;
  if ((ret = r_mem_new (RSList)) != NULL) {
    ret->data = data;
    ret->next = NULL;
  }
  return ret;
}

static inline RSList * r_slist_prepend (RSList * head, rpointer data)
{
  RSList * ret = r_slist_alloc (data);
  ret->next = head;
  return ret;
}

static inline RSList * r_slist_insert_after (RSList * entry, rpointer data)
{
  RSList * ret = r_slist_alloc (data);
  if (entry != NULL) {
    ret->next = entry->next;
    entry->next = ret;
    ret = entry;
  }

  return ret;
}

#define r_slist_free1(entry) r_free (entry)
static inline void r_slist_free1_full (RSList * entry, RDestroyNotify notify)
{
  if (R_LIKELY (entry != NULL)) {
    if (notify != NULL)
      notify (entry->data);
    r_free (entry);
  }
}

#define r_slist_destroy(head) r_slist_destroy_full (head, NULL)
static inline void r_slist_destroy_full (RSList * head, RDestroyNotify notify)
{
  RSList * next;
  while (head != NULL) {
    next = head->next;
    r_slist_free1_full (head, notify);
    head = next;
  }
}

static inline rsize r_slist_len (RSList * head)
{
  rsize ret = 0;

  while (head != NULL) {
    head = r_slist_next (head);
    ret++;
  }

  return ret;
}

static inline rboolean r_slist_contains (RSList * head, rpointer data)
{
  for (; head != NULL; head = head->next) {
    if (head->data == data)
      return TRUE;
  }

  return FALSE;
}

static inline RSList * r_slist_remove (RSList * head, rpointer data)
{
  RSList * ret = head, * prev;

  for (prev = NULL; head != NULL; head = head->next) {
    if (head->data == data) {
      if (ret == head)
        ret = head->next;
      if (prev != NULL)
        prev->next = head->next;
      r_slist_free1 (head);
      break;
    }

    prev = head;
  }

  return ret;
}

static inline void r_slist_foreach (RSList * head,
    RFunc func, rpointer user)
{
  RSList * it;

  for (it = head; it != NULL; it = r_slist_next (it))
    func (r_slist_data (it), user);
}

R_END_DECLS

#endif /* __R_LIST_H__ */
