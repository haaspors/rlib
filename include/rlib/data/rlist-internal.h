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
#ifndef __R_LIST_INTERNAL_H__
#define __R_LIST_INTERNAL_H__

#include <rlib/rtypes.h>
#include <rlib/rmem.h>

R_BEGIN_DECLS

/******************************************************************************/
/* Doubly linked list                                                         */
/*----------------------------------------------------------------------------*/
/* R__LIST_DECL (RList, r_list, rpointer, static inline)                      */
/* R__LIST_IMPL (RList, r_list, rpointer, r_direct_equal, &, static inline)   */
/******************************************************************************/
#define R__LIST_DECL(RTYPE, RTYPE_LOW, RDATA, FUNCSPECS)                      \
typedef struct _##RTYPE RTYPE;                                                \
FUNCSPECS RTYPE * RTYPE_LOW##_first (RTYPE * lst);                            \
FUNCSPECS RTYPE * RTYPE_LOW##_last (RTYPE * lst);                             \
FUNCSPECS RTYPE * RTYPE_LOW##_nth (RTYPE * lst, rsize n);                     \
FUNCSPECS rsize RTYPE_LOW##_len (RTYPE * lst);                                \
FUNCSPECS rboolean RTYPE_LOW##_contains_full (RTYPE * lst, RDATA data);       \
FUNCSPECS void RTYPE_LOW##_foreach (RTYPE * lst, RFunc func, rpointer user);  \
FUNCSPECS RTYPE * RTYPE_LOW##_alloc0 (void) R_ATTR_MALLOC;                    \
FUNCSPECS RTYPE * RTYPE_LOW##_alloc_copy (RDATA data) R_ATTR_MALLOC;          \
FUNCSPECS RTYPE * RTYPE_LOW##_prepend_link (RTYPE * lst, RTYPE * entry) R_ATTR_WARN_UNUSED_RESULT;  \
FUNCSPECS RTYPE * RTYPE_LOW##_append_link (RTYPE * lst, RTYPE * entry) R_ATTR_WARN_UNUSED_RESULT;   \
FUNCSPECS RTYPE * RTYPE_LOW##_prepend_copy (RTYPE * lst, RDATA data) R_ATTR_WARN_UNUSED_RESULT;     \
FUNCSPECS RTYPE * RTYPE_LOW##_append_copy (RTYPE * lst, RDATA data) R_ATTR_WARN_UNUSED_RESULT;      \
FUNCSPECS RTYPE * RTYPE_LOW##_insert_after (RTYPE * head, RTYPE * entry, RDATA data) R_ATTR_WARN_UNUSED_RESULT; \
FUNCSPECS RTYPE * RTYPE_LOW##_insert_before (RTYPE * head, RTYPE * entry, RDATA data) R_ATTR_WARN_UNUSED_RESULT;\
FUNCSPECS void RTYPE_LOW##_free1 (RTYPE * lst);                               \
FUNCSPECS void RTYPE_LOW##_free1_full (RTYPE * lst, RDestroyNotify notify);   \
FUNCSPECS RTYPE * RTYPE_LOW##_remove (RTYPE * head, RDATA data) R_ATTR_WARN_UNUSED_RESULT;          \
FUNCSPECS RTYPE * RTYPE_LOW##_remove_link (RTYPE * head, RTYPE * entry) R_ATTR_WARN_UNUSED_RESULT;  \
FUNCSPECS RTYPE * RTYPE_LOW##_destroy_link (RTYPE * head, RTYPE * entry) R_ATTR_WARN_UNUSED_RESULT; \
FUNCSPECS void RTYPE_LOW##_destroy (RTYPE * head);                            \
FUNCSPECS void RTYPE_LOW##_destroy_full (RTYPE * head, RDestroyNotify notify);\
struct _##RTYPE {                                                             \
  RDATA data;                                                                 \
  RTYPE * next;                                                               \
  RTYPE * prev;                                                               \
};

#define R__LIST_IMPL(RTYPE, RTYPE_LOW, RDATA, RREF, FUNCSPECS)                \
FUNCSPECS RTYPE * RTYPE_LOW##_first (RTYPE * lst)                             \
{                                                                             \
  if (lst != NULL) while (lst->prev != NULL) lst = lst->prev;                 \
  return lst;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_last (RTYPE * lst)                              \
{                                                                             \
  if (lst != NULL) while (lst->next != NULL) lst = lst->next;                 \
  return lst;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_nth (RTYPE * lst, rsize n)                      \
{                                                                             \
  while (n-- > 0 && lst != NULL) lst = lst->next;                             \
  return lst;                                                                 \
}                                                                             \
FUNCSPECS rsize RTYPE_LOW##_len (RTYPE * lst)                                 \
{                                                                             \
  rsize ret = 0;                                                              \
  if (lst != NULL) {                                                          \
    RTYPE * it;                                                               \
    for (it = lst->next; it != NULL; it = it->next) ret++;                    \
    for (it = lst->prev; it != NULL; it = it->prev) ret++;                    \
    ret++;                                                                    \
  }                                                                           \
  return ret;                                                                 \
}                                                                             \
FUNCSPECS rboolean RTYPE_LOW##_contains_full (RTYPE * lst, RDATA data)        \
{                                                                             \
  if (lst != NULL) {                                                          \
    RTYPE * it;                                                               \
    for (it = lst; it != NULL; it = it->next) {                               \
      if (RTYPE_LOW##_data_equal (&it->data, &data))                          \
        return TRUE;                                                          \
    }                                                                         \
    for (it = lst->prev; it != NULL; it = it->prev) {                         \
      if (RTYPE_LOW##_data_equal (&it->data, &data))                          \
        return TRUE;                                                          \
    }                                                                         \
  }                                                                           \
  return FALSE;                                                               \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_foreach (RTYPE * lst, RFunc func, rpointer user)   \
{                                                                             \
  for (; lst != NULL; lst = lst->next)                                        \
    func (RREF lst->data, user);                                              \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_alloc0 (void)                                   \
{                                                                             \
  return r_mem_new0 (RTYPE);                                                  \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_alloc_copy (RDATA data)                         \
{                                                                             \
  RTYPE * ret;                                                                \
  if ((ret = r_mem_new (RTYPE)) != NULL) {                                    \
    ret->data = data;                                                         \
    ret->next = ret->prev = NULL;                                             \
  }                                                                           \
  return ret;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_prepend_link (RTYPE * lst, RTYPE * entry)       \
{                                                                             \
  if ((entry->next = RTYPE_LOW##_first (lst)) != NULL)                        \
    entry->next->prev = entry;                                                \
  return entry;                                                               \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_append_link (RTYPE * lst, RTYPE * entry)        \
{                                                                             \
  if (lst != NULL) {                                                          \
    RTYPE * last = RTYPE_LOW##_last (lst);                                    \
    last->next = entry;                                                       \
    entry->prev = last;                                                       \
    entry = lst;                                                              \
  }                                                                           \
  return entry;                                                               \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_prepend_copy (RTYPE * lst, RDATA data)          \
{                                                                             \
  return RTYPE_LOW##_prepend_link (lst, RTYPE_LOW##_alloc_copy (data));       \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_append_copy (RTYPE * lst, RDATA data)           \
{                                                                             \
  return RTYPE_LOW##_append_link (lst, RTYPE_LOW##_alloc_copy (data));        \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_insert_after (RTYPE * head, RTYPE * entry, RDATA data) \
{                                                                             \
  RTYPE * lst = RTYPE_LOW##_alloc_copy (data);                                \
  if (R_UNLIKELY (head == NULL)) return lst;                                  \
  if (entry == NULL) entry = head;                                            \
  lst->next = entry->next;                                                    \
  lst->prev = entry;                                                          \
  if (entry->next != NULL) entry->next->prev = lst;                           \
  entry->next = lst;                                                          \
  return head;                                                                \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_insert_before (RTYPE * head, RTYPE * entry, RDATA data) \
{                                                                             \
  RTYPE * lst = RTYPE_LOW##_alloc_copy (data);                                \
  if (head != NULL && entry != NULL && entry != head) {                       \
    lst->prev = entry->prev;                                                  \
    lst->next = entry;                                                        \
    entry->prev->next = lst;                                                  \
    entry->prev = lst;                                                        \
  } else {                                                                    \
    head = RTYPE_LOW##_prepend_link (head, lst);                              \
  }                                                                           \
  return head;                                                                \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_free1 (RTYPE * lst)                                \
{                                                                             \
  RTYPE_LOW##_clear (lst);                                                    \
  r_free (lst);                                                               \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_free1_full (RTYPE * lst, RDestroyNotify notify)    \
{                                                                             \
  if (lst != NULL) {                                                          \
    if (notify != NULL) notify (RREF lst->data);                              \
    RTYPE_LOW##_free1 (lst);                                                  \
  }                                                                           \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_remove (RTYPE * head, RDATA data)               \
{                                                                             \
  RTYPE * it;                                                                 \
  for (it = head; it != NULL; it = it->next) {                                \
    if (RTYPE_LOW##_data_equal (&it->data, &data))                            \
      return RTYPE_LOW##_destroy_link (head, it);                             \
  }                                                                           \
  return head;                                                                \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_remove_link (RTYPE * head, RTYPE * entry)       \
{                                                                             \
  if (entry != NULL) {                                                        \
    RTYPE * next = entry->next;                                               \
    RTYPE * prev = entry->prev;                                               \
    if (head == entry) head = head->next;                                     \
    if (prev != NULL)  prev->next = entry->next;                              \
    if (next != NULL)  next->prev = entry->prev;                              \
  }                                                                           \
  return head;                                                                \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_destroy_link (RTYPE * head, RTYPE * entry)      \
{                                                                             \
  head = RTYPE_LOW##_remove_link (head, entry);                               \
  RTYPE_LOW##_free1 (entry);                                                  \
  return head;                                                                \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_destroy (RTYPE * head)                             \
{                                                                             \
  if (head != NULL) {                                                         \
    RTYPE * it, * next;                                                       \
    for (it = head->next; it != NULL; it = next) {                            \
      next = it->next;                                                        \
      RTYPE_LOW##_free1 (it);                                                 \
    }                                                                         \
    for (it = head->prev; it != NULL; it = next) {                            \
      next = it->prev;                                                        \
      RTYPE_LOW##_free1 (it);                                                 \
    }                                                                         \
    RTYPE_LOW##_free1 (head);                                                 \
  }                                                                           \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_destroy_full (RTYPE * head, RDestroyNotify notify) \
{                                                                             \
  if (head != NULL) {                                                         \
    RTYPE * it, * next;                                                       \
    for (it = head->next; it != NULL; it = next) {                            \
      next = it->next;                                                        \
      RTYPE_LOW##_free1_full (it, notify);                                    \
    }                                                                         \
    for (it = head->prev; it != NULL; it = next) {                            \
      next = it->prev;                                                        \
      RTYPE_LOW##_free1_full (it, notify);                                    \
    }                                                                         \
    RTYPE_LOW##_free1_full (head, notify);                                    \
  }                                                                           \
}                                                                             \

/******************************************************************************/
/* Singly linked list                                                         */
/******************************************************************************/
#define R__SLIST_DECL(RTYPE, RTYPE_LOW, RDATA, FUNCSPECS)                     \
typedef struct _##RTYPE RTYPE;                                                \
FUNCSPECS RTYPE * RTYPE_LOW##_last (RTYPE * lst);                             \
FUNCSPECS RTYPE * RTYPE_LOW##_nth (RTYPE * lst, rsize n);                     \
FUNCSPECS RTYPE * RTYPE_LOW##_copy (RTYPE * lst);                             \
FUNCSPECS RTYPE * RTYPE_LOW##_merge (RTYPE * a, RTYPE * b);                   \
FUNCSPECS rsize RTYPE_LOW##_len (RTYPE * lst);                                \
FUNCSPECS rboolean RTYPE_LOW##_contains_full (RTYPE * lst, RDATA data);       \
FUNCSPECS void RTYPE_LOW##_foreach (RTYPE * lst, RFunc func, rpointer user);  \
FUNCSPECS rsize RTYPE_LOW##_foreach_remove (RTYPE ** head,                    \
    RFuncReturn func, rpointer user);                                         \
FUNCSPECS RTYPE * RTYPE_LOW##_alloc0 (void) R_ATTR_MALLOC;                    \
FUNCSPECS RTYPE * RTYPE_LOW##_alloc_copy (RDATA data) R_ATTR_MALLOC;          \
FUNCSPECS RTYPE * RTYPE_LOW##_prepend_link (RTYPE * lst, RTYPE * entry) R_ATTR_WARN_UNUSED_RESULT;  \
FUNCSPECS RTYPE * RTYPE_LOW##_append_link (RTYPE * lst, RTYPE * entry) R_ATTR_WARN_UNUSED_RESULT;   \
FUNCSPECS RTYPE * RTYPE_LOW##_prepend_copy (RTYPE * lst, RDATA data) R_ATTR_WARN_UNUSED_RESULT;     \
FUNCSPECS RTYPE * RTYPE_LOW##_append_copy (RTYPE * lst, RDATA data) R_ATTR_WARN_UNUSED_RESULT;      \
FUNCSPECS RTYPE * RTYPE_LOW##_insert_after (RTYPE * head, RTYPE * entry, RDATA data) R_ATTR_WARN_UNUSED_RESULT; \
FUNCSPECS void RTYPE_LOW##_free1 (RTYPE * lst);                               \
FUNCSPECS void RTYPE_LOW##_free1_full (RTYPE * lst, RDestroyNotify notify);   \
FUNCSPECS RTYPE * RTYPE_LOW##_remove (RTYPE * head, RDATA data) R_ATTR_WARN_UNUSED_RESULT;          \
FUNCSPECS RTYPE * RTYPE_LOW##_remove_link (RTYPE * head, RTYPE * entry) R_ATTR_WARN_UNUSED_RESULT;  \
FUNCSPECS RTYPE * RTYPE_LOW##_destroy_link (RTYPE * head, RTYPE * entry) R_ATTR_WARN_UNUSED_RESULT; \
FUNCSPECS void RTYPE_LOW##_destroy (RTYPE * head);                            \
FUNCSPECS void RTYPE_LOW##_destroy_full (RTYPE * head, RDestroyNotify notify);\
struct _##RTYPE {                                                             \
  RDATA data;                                                                 \
  RTYPE * next;                                                               \
};

#define R__SLIST_IMPL(RTYPE, RTYPE_LOW, RDATA, RREF, FUNCSPECS)               \
FUNCSPECS RTYPE * RTYPE_LOW##_last (RTYPE * lst)                              \
{                                                                             \
  if (lst != NULL) while (lst->next != NULL) lst = lst->next;                 \
  return lst;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_nth (RTYPE * lst, rsize n)                      \
{                                                                             \
  while (n-- > 0 && lst != NULL) lst = lst->next;                             \
  return lst;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_copy (RTYPE * lst)                              \
{                                                                             \
  RTYPE * ret, * last;                                                        \
  if (R_UNLIKELY (lst == NULL)) return NULL;                                  \
  ret = last = RTYPE_LOW##_alloc_copy (lst->data);                            \
  for (lst = lst->next; lst != NULL; lst = lst->next, last = last->next)      \
    last->next = RTYPE_LOW##_alloc_copy (lst->data);                          \
  return ret;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_merge (RTYPE * a, RTYPE * b)                    \
{                                                                             \
  if (a != NULL)                                                              \
    RTYPE_LOW##_last (a)->next = b;                                           \
  else                                                                        \
    a = b;                                                                    \
  return a;                                                                   \
}                                                                             \
FUNCSPECS rsize RTYPE_LOW##_len (RTYPE * lst)                                 \
{                                                                             \
  rsize ret = 0;                                                              \
  for (; lst != NULL; lst = lst->next) ret++;                                 \
  return ret;                                                                 \
}                                                                             \
FUNCSPECS rboolean RTYPE_LOW##_contains_full (RTYPE * lst, RDATA data)        \
{                                                                             \
  for (; lst != NULL; lst = lst->next) {                                      \
    if (RTYPE_LOW##_data_equal (&lst->data, &data))                           \
      return TRUE;                                                            \
  }                                                                           \
  return FALSE;                                                               \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_foreach (RTYPE * lst, RFunc func, rpointer user)   \
{                                                                             \
  for (; lst != NULL; lst = lst->next)                                        \
    func (RREF lst->data, user);                                              \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_alloc0 (void)                                   \
{                                                                             \
  return r_mem_new0 (RTYPE);                                                  \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_alloc_copy (RDATA data)                         \
{                                                                             \
  RTYPE * ret;                                                                \
  if ((ret = r_mem_new (RTYPE)) != NULL) {                                    \
    ret->data = data;                                                         \
    ret->next  = NULL;                                                        \
  }                                                                           \
  return ret;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_prepend_link (RTYPE * lst, RTYPE * entry)       \
{                                                                             \
  entry->next = lst;                                                          \
  return entry;                                                               \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_append_link (RTYPE * lst, RTYPE * entry)        \
{                                                                             \
  if (lst != NULL) {                                                          \
    RTYPE * last = RTYPE_LOW##_last (lst);                                    \
    last->next = entry;                                                       \
    entry = lst;                                                              \
  }                                                                           \
  return entry;                                                               \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_prepend_copy (RTYPE * lst, RDATA data)          \
{                                                                             \
  return RTYPE_LOW##_prepend_link (lst, RTYPE_LOW##_alloc_copy (data));       \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_append_copy (RTYPE * lst, RDATA data)           \
{                                                                             \
  return RTYPE_LOW##_append_link (lst, RTYPE_LOW##_alloc_copy (data));        \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_insert_after (RTYPE * head, RTYPE * entry, RDATA data) \
{                                                                             \
  RTYPE * lst = RTYPE_LOW##_alloc_copy (data);                                \
  if (R_UNLIKELY (head == NULL)) return lst;                                  \
  if (entry == NULL) entry = head;                                            \
  lst->next = entry->next;                                                    \
  entry->next = lst;                                                          \
  return head;                                                                \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_free1 (RTYPE * lst)                                \
{                                                                             \
  RTYPE_LOW##_clear (lst);                                                    \
  r_free (lst);                                                               \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_free1_full (RTYPE * lst, RDestroyNotify notify)    \
{                                                                             \
  if (lst != NULL) {                                                          \
    if (notify != NULL) notify (RREF lst->data);                              \
    RTYPE_LOW##_free1 (lst);                                                  \
  }                                                                           \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_remove (RTYPE * head, RDATA data)               \
{                                                                             \
  RTYPE * ret = head, * prev;                                                 \
  for (prev = NULL; head != NULL; head = head->next) {                        \
    if (RTYPE_LOW##_data_equal (&head->data, &data)) {                        \
      if (ret == head) ret = ret->next;                                       \
      if (prev != NULL) prev->next = head->next;                              \
      RTYPE_LOW##_free1 (head);                                               \
      break;                                                                  \
    }                                                                         \
    prev = head;                                                              \
  }                                                                           \
  return ret;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_remove_link (RTYPE * head, RTYPE * entry)       \
{                                                                             \
  RTYPE * it;                                                                 \
  if (R_UNLIKELY (head == NULL || entry == NULL)) return head;                \
  if (head == entry) return head->next;                                       \
  for (it = head; it->next != NULL; it = it->next) {                          \
    if (it->next == entry) {                                                  \
      it->next = entry->next;                                                 \
      break;                                                                  \
    }                                                                         \
  }                                                                           \
  return head;                                                                \
}                                                                             \
FUNCSPECS rsize RTYPE_LOW##_foreach_remove (RTYPE ** head,                    \
    RFuncReturn func, rpointer user)                                          \
{                                                                             \
  rsize ret = 0;                                                              \
  RTYPE * it, * prev;                                                         \
  for (it = *head, prev = NULL; it != NULL; prev = it, it = it->next) {       \
    if (func (RREF it->data, user)) {                                         \
      if (prev != NULL)                                                       \
        prev->next = it->next;                                                \
      else                                                                    \
        head = &it->next;                                                     \
      RTYPE_LOW##_free1 (it);                                                 \
      ret++;                                                                  \
    }                                                                         \
  }                                                                           \
  return ret;                                                                 \
}                                                                             \
FUNCSPECS RTYPE * RTYPE_LOW##_destroy_link (RTYPE * head, RTYPE * entry)      \
{                                                                             \
  head = RTYPE_LOW##_remove_link (head, entry);                               \
  RTYPE_LOW##_free1 (entry);                                                  \
  return head;                                                                \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_destroy (RTYPE * head)                             \
{                                                                             \
  RTYPE * next;                                                               \
  for (; head != NULL; head = next) {                                         \
    next = head->next;                                                        \
    RTYPE_LOW##_free1 (head);                                                 \
  }                                                                           \
}                                                                             \
FUNCSPECS void RTYPE_LOW##_destroy_full (RTYPE * head, RDestroyNotify notify) \
{                                                                             \
  RTYPE * next;                                                               \
  for (; head != NULL; head = next) {                                         \
    next = head->next;                                                        \
    RTYPE_LOW##_free1_full (head, notify);                                    \
  }                                                                           \
}                                                                             \


R_END_DECLS

#endif /* __R_LIST_INTERNAL_H__ */
