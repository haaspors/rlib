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

#include "config.h"
#include <rlib/data/rhzrptr.h>

#include <rlib/data/rlist.h>

#include <rlib/rassert.h>
#include <rlib/rthreads.h>

#define R_HZR_PTR_R g__r_hzrptr_count

static raptr        g__r_hzrptr; /* (RHzrPtrRec *) */
static ruint        g__r_hzrptr_count;
static RTss         g__r_hzrptr_tss = R_TSS_INIT (r_hzr_ptr_rec_free);

struct _RHzrPtrRec {
  rpointer ptr;
  raint active;

  RFreeList * rlist;
  ruint rcount;

  RHzrPtrRec * next;
};


rpointer
r_hzr_ptr_aqcuire (rhzrptr * hzrptr, RHzrPtrRec * rec)
{
  rpointer ret;

  if (rec == NULL) {
    if ((rec = r_tss_get (&g__r_hzrptr_tss)) == NULL)
      r_tss_set (&g__r_hzrptr_tss, (rec = r_hzr_ptr_rec_new ()));
  }

  r_assert_cmpptr (rec->ptr, ==, NULL);

  do {
    ret = r_atomic_ptr_load (&hzrptr->ptr);
    rec->ptr = ret; /* ret could be NULL! */
  } while (r_atomic_ptr_load (&hzrptr->ptr) != ret);

  return ret;
}

void
r_hzr_ptr_release (rhzrptr * hzrptr, RHzrPtrRec * rec)
{
  (void)hzrptr;

  if (rec == NULL) {
    rec = r_tss_get (&g__r_hzrptr_tss);
    r_assert_cmpptr (rec, !=, NULL);
  }

  /* We can't assert that rec->ptr is non-NULL */
  rec->ptr = NULL;
}

static rboolean
r_hzr_ptr_remove_entry (rpointer data, rpointer user)
{
  RSList * plist = user;
  /* Remove from rlist if not found in plist */
  return !r_slist_contains (plist, data);
}

static void
r_hzr_ptr_rec_scan (RHzrPtrRec * rec)
{
  RSList * plist = NULL;
  RHzrPtrRec * it;

  /* FIXME: Optimize by using a sorted data structure and binary search? */
  for (it = r_atomic_ptr_load (&g__r_hzrptr); it != NULL; it = it->next) {
    if (it->ptr != NULL)
      plist = r_slist_prepend (plist, it->ptr);
  }

  r_free_list_foreach_remove (&rec->rlist, r_hzr_ptr_remove_entry, plist);

  r_slist_destroy (plist);
}

void
r_hzr_ptr_replace (rhzrptr * hzrptr, rpointer ptr)
{
  RHzrPtrRec * rec;
  rpointer retired;

  if ((rec = r_tss_get (&g__r_hzrptr_tss)) == NULL)
    r_tss_set (&g__r_hzrptr_tss, (rec = r_hzr_ptr_rec_new ()));

  retired = r_atomic_ptr_exchange (&hzrptr->ptr, ptr);
  if (retired != NULL) {
    rec->rlist = r_free_list_prepend (rec->rlist, retired, hzrptr->notify);
    if (++rec->rcount > R_HZR_PTR_R)
      r_hzr_ptr_rec_scan (rec);
  }
}

RHzrPtrRec *
r_hzr_ptr_rec_new (void)
{
  RHzrPtrRec * rec;
  rpointer old;

  for (rec = r_atomic_ptr_load (&g__r_hzrptr); rec != NULL; rec = rec->next) {
    int oa = FALSE;
    if (r_atomic_int_cmp_xchg_strong (&rec->active, &oa, TRUE))
      goto done;
  }

  rec = r_mem_new0 (RHzrPtrRec);
  rec->active = TRUE;

  old = r_atomic_ptr_load (&g__r_hzrptr);
  while (!r_atomic_ptr_cmp_xchg_weak (&g__r_hzrptr, &old, rec));

done:
  return rec;
}

void
r_hzr_ptr_rec_free (RHzrPtrRec * rec)
{
  if (rec != NULL) {
    r_assert_cmpptr (rec->ptr, ==, NULL);
    r_atomic_int_store (&rec->active, FALSE);
  }
}

