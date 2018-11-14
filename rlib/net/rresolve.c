/* RLIB - Convenience library for useful things
 * Copyright (C) 2017-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rnet-private.h"
#include "rsocket-private.h"
#include "../rlib-private.h"

#include <rlib/net/rresolve.h>

#include <rlib/rlog.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#define R_LOG_CAT_DEFAULT &rlib_logcat

typedef struct {
  RRef ref;
  struct addrinfo * ai;
} RAIStorage;

static void
r_ai_storage_free (RAIStorage * ais)
{
  freeaddrinfo (ais->ai);
  r_free(ais);
}

static RAIStorage *
r_ai_storage_new (struct addrinfo * ai)
{
  RAIStorage * ret;

  if ((ret = r_mem_new (RAIStorage)) != NULL) {
    r_ref_init (ret, r_ai_storage_free);
    ret->ai = ai;
  }

  return ret;
}

struct _RResolvedAddr {
  RRef ref;

  struct addrinfo * ai;
  RAIStorage * storage;
};

static void
r_resolved_addr_free (RResolvedAddr * addr)
{
  r_ref_unref (addr->storage);
  r_free (addr);
}

static RResolvedAddr *
r_resolved_addr_new (struct addrinfo * ai, RAIStorage * storage)
{
  RResolvedAddr * ret;

  if (ai == NULL) return NULL;

  if ((ret = r_mem_new (RResolvedAddr)) != NULL) {
    r_ref_init (ret, r_resolved_addr_free);
    ret->ai = ai;
    ret->storage = (storage == NULL) ? r_ai_storage_new (ai) : r_ref_ref (storage);
  }

  return ret;
}

RResolveAddrFlags
r_resolved_addr_get_flags (const RResolvedAddr * addr)
{
  return (RResolveAddrFlags)addr->ai->ai_flags;
}

RSocketFamily
r_resolved_addr_get_family (const RResolvedAddr * addr)
{
  return (RSocketFamily)addr->ai->ai_family;
}

RSocketType
r_resolved_addr_get_type (const RResolvedAddr * addr)
{
  switch (addr->ai->ai_socktype) {
    case SOCK_STREAM:
      return R_SOCKET_TYPE_STREAM;
    case SOCK_DGRAM:
      return R_SOCKET_TYPE_DATAGRAM;
#ifdef SOCK_RAW
    case SOCK_RAW:
      return R_SOCKET_TYPE_RAW;
#endif
#ifdef SOCK_RDM
    case SOCK_RDM:
      return R_SOCKET_TYPE_RDM;
#endif
#ifdef SOCK_SEQPACKET
    case SOCK_SEQPACKET:
      return R_SOCKET_TYPE_SEQPACKET;
#endif
    default:
      return 0;
  }
}

RSocketProtocol
r_resolved_addr_get_protocol (const RResolvedAddr * addr)
{
  return (RSocketProtocol)addr->ai->ai_protocol;
}

const rchar *
r_resolved_addr_get_canonical_name (const RResolvedAddr * addr)
{
  return addr->ai->ai_canonname;
}

RSocketAddress *
r_resolved_addr_get_socket_addr (const RResolvedAddr * addr)
{
  return r_socket_address_new_from_native (addr->ai->ai_addr, addr->ai->ai_addrlen);
}

RResolvedAddr *
r_resolved_addr_get_next (RResolvedAddr * addr)
{
  return r_resolved_addr_new (addr->ai->ai_next, addr->storage);
}



RResolvedAddr *
r_resolve_sync (const rchar * host, const rchar * service,
    RResolveAddrFlags flags, const RResolveHints * hints, RResolveResult * res)
{
  RResolvedAddr * ret = NULL;
#ifdef HAVE_MOCK_SOCKETS
  (void) host;
  (void) service;
  (void) flags;
  (void) hints;

  if (res != NULL)
    *res = R_RESOLVE_NOT_SUPPORTED;
#else
  struct addrinfo aihints;
  struct addrinfo * ai;
  int r;

  r_memclear (&aihints, sizeof (aihints));
  aihints.ai_flags = (int)flags;
  if (hints != NULL) {
    aihints.ai_family = (int)hints->family;
    if (hints->type == R_SOCKET_TYPE_STREAM)
      aihints.ai_socktype = SOCK_STREAM;
    else if (hints->type == R_SOCKET_TYPE_DATAGRAM)
      aihints.ai_socktype = SOCK_DGRAM;
  }

  if ((r = getaddrinfo (host, service, &aihints, &ai)) == 0) {
    R_LOG_DEBUG ("getaddrinfo (family %d, protocol %d, type %d, flags %d)",
        ai->ai_family, ai->ai_protocol, ai->ai_socktype, ai->ai_flags);
    R_LOG_MEM_DUMP (R_LOG_LEVEL_TRACE, ai->ai_addr, ai->ai_addrlen);

    if (R_UNLIKELY ((ret = r_resolved_addr_new (ai, NULL)) == NULL))
      freeaddrinfo (ai);

    if (res != NULL)
      *res = R_RESOLVE_OK;
  } else {
    /* FIXME: set result based on r! */
    if (res != NULL)
      *res = R_RESOLVE_ERROR;
  }
#endif

  return ret;
}


struct _RResolveAsync {
  RRef ref;

  rchar * host;
  rchar * service;
  RResolveAddrFlags flags;
  RResolveHints hints;

  RResolveResult res;
  RResolvedAddr * addr;

  RTask * task;
  RResolvedFunc func;
  rpointer data;
  RDestroyNotify datanotify;
};

static void
r_resolve_async_free (RResolveAsync * async)
{
  r_task_unref (async->task);

  if (async->addr != NULL)
    r_resolve_async_unref (async->addr);

  r_free (async->service);
  r_free (async->host);
  r_free (async);
}

RTask *
r_resolve_async_get_task (RResolveAsync * async)
{
  if (R_UNLIKELY (async == NULL)) return NULL;
  if (R_UNLIKELY (async->task == NULL)) return NULL;

  return r_task_ref (async->task);
}

RResolvedAddr *
r_resolve_async_get_addr (RResolveAsync * async)
{
  if (R_UNLIKELY (async == NULL)) return NULL;
  if (R_UNLIKELY (async->addr == NULL)) return NULL;

  return r_resolved_addr_ref (async->addr);
}

RResolveResult
r_resolve_async_get_result (const RResolveAsync * async)
{
  if (R_UNLIKELY (async == NULL)) return R_RESOLVE_INVAL;
  return async->res;
}

RResolvedAddr *
r_resolve_async_wait (RResolveAsync * async)
{
  if (R_UNLIKELY (async == NULL)) return NULL;
  if (R_UNLIKELY (async->task == NULL)) return NULL;

  r_task_wait (async->task);

  return r_resolved_addr_ref (async->addr);
}


static void
r_resolve_perform_async (rpointer data, RTaskQueue * queue, RTask * task)
{
  RResolveAsync * async = data;

  (void) queue;
  (void) task;

  async->addr = r_resolve_sync (async->host, async->service, async->flags,
      &async->hints, &async->res);
}

RResolveAsync *
r_resolve_async_task_queue (const rchar * host, const rchar * service,
    RResolveAddrFlags flags, const RResolveHints * hints, RTaskQueue * queue)
{
  RResolveAsync * ret;

  if (R_UNLIKELY (host == NULL && service == NULL)) return NULL;
  if (R_UNLIKELY (queue == NULL)) return NULL;

  if ((ret = r_mem_new0 (RResolveAsync)) != NULL) {
    r_ref_init (ret, r_resolve_async_free);

    ret->host = r_strdup (host);
    ret->service = r_strdup (service);
    ret->flags = flags;
    if (hints != NULL)
      ret->hints = *hints;

    ret->addr = NULL;
    ret->res = R_RESOLVE_IN_PROGRESS;
    if ((ret->task = r_task_queue_add (queue, r_resolve_perform_async,
            ret, r_ref_unref)) != NULL) {
      r_resolve_async_ref (ret);
    } else {
      r_resolve_async_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

static void
r_resolved_async_done (rpointer data, REvLoop * loop)
{
  RResolveAsync * async = data;

  (void) loop;

  if (async->func != NULL) {
    async->func (async->data, async->addr, async->res);
    async->func = NULL;
  }

  if (async->datanotify != NULL) {
    async->datanotify (async->data);
    async->datanotify = NULL;
  }

  async->data = NULL;
}

RResolveAsync *
r_resolve_async_ev_loop (const rchar * host, const rchar * service,
    RResolveAddrFlags flags, const RResolveHints * hints,
    REvLoop * loop, RResolvedFunc func, rpointer data, RDestroyNotify datanotify)
{
  RResolveAsync * ret;

  if (R_UNLIKELY (host == NULL && service == NULL)) return NULL;
  if (R_UNLIKELY (loop == NULL)) return NULL;

  if ((ret = r_mem_new0 (RResolveAsync)) != NULL) {
    r_ref_init (ret, r_resolve_async_free);

    ret->host = r_strdup (host);
    ret->service = r_strdup (service);
    ret->flags = flags;
    if (hints != NULL)
      ret->hints = *hints;

    ret->addr = NULL;
    ret->res = R_RESOLVE_IN_PROGRESS;

    ret->func = func;
    ret->data = data;
    ret->datanotify = datanotify;
    if ((ret->task = r_ev_loop_add_task (loop, r_resolve_perform_async,
            r_resolved_async_done, ret, r_ref_unref)) != NULL) {
      r_resolve_async_ref (ret);
    } else {
      r_resolve_async_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}
