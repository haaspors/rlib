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
/* Doubly linked list                                                         */
/******************************************************************************/
typedef struct _RList RList;

#define r_list_data(lst)  (lst)->data
#define r_list_next(lst)  (lst)->next
#define r_list_prev(lst)  (lst)->prev

static inline RList * r_list_alloc (rpointer data);
static inline RList * r_list_prepend (RList * lst, rpointer data);
static inline RList * r_list_append (RList * lst, rpointer data);
static inline RList * r_list_insert_after (RList * head, RList * entry, rpointer data);
static inline RList * r_list_insert_before (RList * head, RList * entry, rpointer data);
static inline RList * r_list_remove (RList * head, rpointer data);
static inline RList * r_list_remove_link (RList * head, RList * entry);
static inline RList * r_list_destroy_link (RList * head, RList * entry);

#define r_list_free1(entry) r_free (entry)
static inline void r_list_free1_full (RList * entry, RDestroyNotify notify);
#define r_list_destroy(lst) r_list_destroy_full (lst, NULL)
static inline void r_list_destroy_full (RList * lst, RDestroyNotify notify);

static inline rsize r_list_len (RList * head);
static inline rboolean r_list_contains (RList * lst, rpointer data);
static inline RList * r_list_first (RList * lst);
static inline RList * r_list_last (RList * lst);
static inline RList * r_list_nth (RList * lst, rsize n);
static inline void r_list_foreach (RList * head, RFunc func, rpointer user);

/******************************************************************************/
/* Free list (Singly linked list)                                             */
/******************************************************************************/
typedef struct _RFreeList RFreeList;

static inline RFreeList * r_free_list_alloc (rpointer ptr, RDestroyNotify notify);
static inline RFreeList * r_free_list_prepend (RFreeList * entry,
    rpointer ptr, RDestroyNotify notify);
static inline void r_free_list_free1 (RFreeList * entry);
static inline void r_free_list_destroy (RFreeList * head);
static inline rsize r_free_list_len (RFreeList * head);
static inline rboolean r_free_list_contains (RFreeList * head, rpointer ptr);
static inline void r_free_list_foreach (RFreeList * head,
    RFunc func, rpointer user);
static inline rsize r_free_list_foreach_remove (RFreeList ** head,
    RFuncReturn func, rpointer user);

/******************************************************************************/
/* Singly linked list                                                         */
/******************************************************************************/
typedef struct _RSList RSList;

#define r_slist_data(lst)  (lst)->data
#define r_slist_next(lst)  (lst)->next

static inline RSList * r_slist_alloc (rpointer data);
static inline RSList * r_slist_prepend (RSList * head, rpointer data);
static inline RSList * r_slist_append (RSList * head, rpointer data);
static inline RSList * r_slist_insert_after (RSList * entry, rpointer data);
static inline RSList * r_slist_remove (RSList * head, rpointer data);

#define r_slist_free1(entry) r_free (entry)
static inline void r_slist_free1_full (RSList * entry, RDestroyNotify notify);
#define r_slist_destroy(head) r_slist_destroy_full (head, NULL)
static inline void r_slist_destroy_full (RSList * head, RDestroyNotify notify);

static inline rsize r_slist_len (RSList * head);
static inline rboolean r_slist_contains (RSList * head, rpointer data);
static inline RSList * r_slist_last (RSList * head);
static inline RSList * r_slist_nth (RSList * head, rsize n);
static inline void r_slist_foreach (RSList * head, RFunc func, rpointer user);



/******************************************************************************/
/* Doubly linked list                                                         */
/******************************************************************************/
struct _RList {
  rpointer data;
  RList * next;
  RList * prev;
};

static inline RList * r_list_alloc (rpointer data)
{
  RList * ret;
  if ((ret = r_mem_new (RList)) != NULL) {
    ret->data = data;
    ret->next = ret->prev = NULL;
  }
  return ret;
}

static inline RList * r_list_prepend (RList * lst, rpointer data)
{
  RList * ret = r_list_alloc (data);
  if ((ret->next = r_list_first (lst)) != NULL)
    ret->next->prev = ret;
  return ret;
}

static inline RList * r_list_append (RList * lst, rpointer data)
{
  RList * n = r_list_alloc (data);

  if (lst != NULL) {
    RList * last = r_list_last (lst);
    last->next = n;
    n->prev = last;
  } else {
    lst = n;
  }

  return lst;
}

static inline RList * r_list_insert_after (RList * head, RList * entry, rpointer data)
{
  RList * n = r_list_alloc (data);

  if (R_UNLIKELY (head == NULL))
    return n;
  if (entry == NULL)
    entry = head;

  n->next = entry->next;
  n->prev = entry;
  if (entry->next != NULL)
    entry->next->prev = n;
  entry->next = n;

  return head;
}

static inline RList * r_list_insert_before (RList * head, RList * entry, rpointer data)
{
  if (R_UNLIKELY (head == NULL)) {
    head = r_list_alloc (data);
  } else if (entry != NULL && entry != head) {
    RList * n = r_list_alloc (data);

    n->prev = entry->prev;
    n->next = entry;
    entry->prev->next = n;
    entry->prev = n;
  } else {
    head = r_list_prepend (head, data);
  }

  return head;
}

static inline RList * r_list_remove (RList * head, rpointer data)
{
  RList * cur;
  for (cur = head; cur != NULL; cur = r_list_next (cur)) {
    if (r_list_data (cur) == data)
      return r_list_destroy_link (head, cur);
  }

  return head;
}

static inline RList * r_list_remove_link (RList * head, RList * entry)
{
  if (entry != NULL) {
    RList * prev = r_list_prev (entry);
    RList * next = r_list_next (entry);

    if (head == entry)
      head = r_list_next (head);

    if (prev != NULL)
      prev->next = entry->next;
    if (next != NULL)
      next->prev = entry->prev;
  }

  return head;
}

static inline RList * r_list_destroy_link (RList * head, RList * entry)
{
  head = r_list_remove_link (head, entry);
  r_list_free1 (entry);

  return head;
}

static inline void r_list_free1_full (RList * entry, RDestroyNotify notify)
{
  if (R_LIKELY (entry != NULL)) {
    if (notify != NULL)
      notify (r_list_data (entry));
    r_free (entry);
  }
}

static inline void r_list_destroy_full (RList * lst, RDestroyNotify notify)
{
  if (lst != NULL) {
    RList * cur, * next;

    for (cur = r_list_next (lst); cur != NULL; cur = next) {
      next = r_list_next (cur);
      r_list_free1_full (cur, notify);
    }
    for (cur = r_list_prev (lst); cur != NULL; cur = next) {
      next = r_list_prev (cur);
      r_list_free1_full (cur, notify);
    }

    r_list_free1_full (lst, notify);
  }
}

static inline rsize r_list_len (RList * lst)
{
  rsize ret;

  if (lst != NULL) {
    RList * cur;
    ret = 1;
    for (cur = r_list_next (lst); cur != NULL; cur = r_list_next (cur))
      ret++;
    for (cur = r_list_prev (lst); cur != NULL; cur = r_list_prev (cur))
      ret++;
  } else {
    ret = 0;
  }

  return ret;
}

static inline rboolean r_list_contains (RList * lst, rpointer data)
{
  if (lst != NULL) {
    RList * it;

    for (it = lst; it != NULL; it = r_list_next (it)) {
      if (r_list_data (it) == data)
        return TRUE;
    }
    for (it = r_list_prev (lst); it != NULL; it = r_list_prev (it)) {
      if (r_list_data (it) == data)
        return TRUE;
    }
  }

  return FALSE;
}

static inline RList * r_list_first (RList * lst)
{
  if (R_LIKELY (lst != NULL)) {
    while (r_list_prev (lst) != NULL)
      lst = r_list_prev (lst);
  }
  return lst;
}

static inline RList * r_list_last (RList * lst)
{
  if (R_LIKELY (lst != NULL)) {
    while (r_list_next (lst) != NULL)
      lst = r_list_next (lst);
  }
  return lst;
}

static inline RList * r_list_nth (RList * lst, rsize n)
{
  while (n-- > 0 && lst != NULL)
    lst = r_list_next (lst);
  return lst;
}

static inline void r_list_foreach (RList * head, RFunc func, rpointer user)
{
  RList * it;

  for (it = head; it != NULL; it = r_list_next (it))
    func (r_list_data (it), user);
}


/******************************************************************************/
/* Free list (Singly linked list)                                             */
/******************************************************************************/
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
struct _RSList {
  rpointer data;
  RSList * next;
};

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

static inline RSList * r_slist_append (RSList * head, rpointer data)
{
  RSList * n = r_slist_alloc (data);

  if (head != NULL)
    r_slist_last (head)->next = n;
  else
    head = n;

  return head;
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

static inline void r_slist_free1_full (RSList * entry, RDestroyNotify notify)
{
  if (R_LIKELY (entry != NULL)) {
    if (notify != NULL)
      notify (entry->data);
    r_free (entry);
  }
}

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

static inline RSList * r_slist_last (RSList * head)
{
  if (R_LIKELY (head != NULL)) {
    while (r_slist_next (head) != NULL)
      head = r_slist_next (head);
  }
  return head;
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

static inline RSList * r_slist_nth (RSList * head, rsize n)
{
  while (n-- > 0 && head != NULL)
    head = r_slist_next (head);
  return head;
}

static inline void r_slist_foreach (RSList * head, RFunc func, rpointer user)
{
  RSList * it;

  for (it = head; it != NULL; it = r_slist_next (it))
    func (r_slist_data (it), user);
}

R_END_DECLS

#endif /* __R_LIST_H__ */
