/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/ev/revresolve.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

struct _REvResolve {
  RRef ref;

  rchar * host;
  rchar * service;
  RResolveHints hints;
  RResolveAddrFlags flags;

  REvResolveFunc func;
  rpointer data;
  RDestroyNotify datanotify;

  RTask * task;

  RResolvedAddr * resolved;
  RResolveResult result;
};

static void
r_ev_resolve_addr (rpointer data, RTaskQueue * queue, RTask * task)
{
  REvResolve * resolve = data;

  (void) queue;
  (void) task;

  resolve->resolved = r_resolve_sync (resolve->host, resolve->service,
      resolve->flags, &resolve->hints, &resolve->result);
}

static void
r_ev_resolve_done_clear (REvResolve * resolve)
{
  if (resolve->datanotify != NULL)
    resolve->datanotify (resolve->data);

  resolve->func = NULL;
  resolve->data = NULL;
  resolve->datanotify = NULL;
  resolve->task = NULL;
}

static void
r_ev_resolve_done (rpointer data, REvLoop * loop)
{
  REvResolve * resolve = data;

  (void) loop;

  r_task_unref (resolve->task);
  resolve->task = NULL;
  resolve->func (resolve->data, resolve->resolved, resolve->result);
  r_ev_resolve_done_clear (resolve);
}

static void
r_ev_resolve_free (REvResolve * resolve)
{
  if (R_UNLIKELY (resolve->task != NULL)) {
    r_task_wait (resolve->task);
    r_task_unref (resolve->task);
  }
  if (resolve->datanotify != NULL)
    resolve->datanotify (resolve->data);

  r_resolved_addr_unref (resolve->resolved);

  r_free (resolve->host);
  r_free (resolve->service);
  r_free (resolve);
}

REvResolve *
r_ev_resolve_addr_new (const rchar * host, const rchar * service,
    RResolveAddrFlags flags, const RResolveHints * hints,
    REvLoop * loop, REvResolveFunc func, rpointer data, RDestroyNotify datanotify)
{
  REvResolve * ret;

  if (R_UNLIKELY (host == NULL && service == NULL)) return NULL;
  if (R_UNLIKELY (loop == NULL)) return NULL;
  if (R_UNLIKELY (func == NULL)) return NULL;

  if ((ret = r_mem_new0 (REvResolve)) != NULL) {
    r_ref_init (ret, r_ev_resolve_free);

    ret->host = r_strdup (host);
    ret->service = r_strdup (service);
    ret->flags = flags;
    r_memcpy (&ret->hints, hints, sizeof (RResolveHints));

    ret->func = func;
    ret->data = data;
    ret->datanotify = datanotify;
    if ((ret->task = r_ev_loop_add_task (loop, r_ev_resolve_addr,
            r_ev_resolve_done, ret, r_ev_resolve_unref)) != NULL) {
      ret->result = R_RESOLVE_IN_PROGRESS;
      r_ev_resolve_ref (ret);
    } else {
      r_ev_resolve_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

