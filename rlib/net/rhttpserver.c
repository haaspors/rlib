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
#include "../rlib-private.h"
#include <rlib/ev/rev-private.h>
#include <rlib/net/rhttpserver.h>

#include <rlib/ev/revtcp.h>

#include <rlib/rdirtree.h>
#include <rlib/rmem.h>
#include <rlib/rptrarray.h>

struct _RHttpServer {
  RRef ref;

  REvLoop * loop;
  RDirTree * dt;

  RPtrArray * clients;
  RPtrArray * listen;
};

typedef struct {
  RRef ref;
  RHttpServer * server;
  REvTCP * evtcp;

  RHttpRequest * req;
  rssize bodysize;
  RBuffer * inbuf;

  rboolean keepalive;
} RHttpClientCtx;

#define R_LOG_CAT_DEFAULT &httpsrvcat
R_LOG_CATEGORY_DEFINE_STATIC (httpsrvcat, "httpserver", "RLib HTTP server",
    R_CLR_FG_WHITE | R_CLR_BG_BLUE | R_CLR_FMT_BOLD);

void
r_http_server_init (void)
{
  r_log_category_register (&httpsrvcat);
}


static void
r_http_client_ctx_free (RHttpClientCtx * ctx)
{
  if (ctx->inbuf != NULL)
    r_buffer_unref (ctx->inbuf);
  if (ctx->req != NULL)
    r_http_request_unref (ctx->req);

  r_ev_tcp_unref (ctx->evtcp);
  r_http_server_unref (ctx->server);
  r_free (ctx);
}

static RHttpClientCtx *
r_http_client_ctx_new (RHttpServer * server, REvTCP * evtcp)
{
  RHttpClientCtx * ret;

  if (R_UNLIKELY (server == NULL)) return NULL;
  if (R_UNLIKELY (evtcp == NULL)) return NULL;

  if ((ret = r_mem_new0 (RHttpClientCtx)) != NULL) {
    r_ref_init (ret, r_http_client_ctx_free);

    ret->server = r_http_server_ref (server);
    ret->evtcp = r_ev_tcp_ref (evtcp);
  }

  return ret;
}

static void
r_http_client_ctx_close (RHttpClientCtx * ctx, rpointer data, RDestroyNotify notify)
{
  R_LOG_INFO ("%p: "R_EV_IO_FORMAT, ctx->server, R_EV_IO_ARGS (ctx->evtcp));

  r_ev_tcp_close (ctx->evtcp, NULL, data, notify);
  r_ptr_array_remove_first_fast (ctx->server->clients, ctx);
}

static void
r_http_client_ctx_response_sent (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RHttpClientCtx * ctx = data;
  (void) buf;

  R_LOG_TRACE ("%p: response sent "R_EV_IO_FORMAT" closing",
      ctx->server, R_EV_IO_ARGS (evtcp));
  r_http_client_ctx_close (ctx, NULL, NULL);
}

static void
r_http_client_ctx_tcp_response_ready (rpointer data, RHttpResponse * res,
    RHttpServer * server)
{
  RHttpClientCtx * ctx = data;
  RBuffer * buf;

  if ((buf = r_http_response_get_buffer (res)) != NULL) {
    R_LOG_TRACE ("%p: Buffer %p on "R_EV_IO_FORMAT,
        server, buf, R_EV_IO_ARGS (ctx->evtcp));
    R_LOG_BUF_DUMP (R_LOG_LEVEL_TRACE, buf);

    if (!ctx->keepalive) {
      r_ev_tcp_send (ctx->evtcp, buf, r_http_client_ctx_response_sent,
          r_ref_ref (ctx), r_ref_unref);
    } else {
      r_ev_tcp_send_and_forget (ctx->evtcp, buf);
    }
    r_buffer_unref (buf);
  }
}

static rboolean
r_http_client_ctx_process (RHttpClientCtx * ctx)
{
  RSocketAddress * addr = r_ev_tcp_get_remote_address (ctx->evtcp);
  rboolean ret;

  if ((ret = r_http_server_process_request (ctx->server, ctx->req, addr,
      r_http_client_ctx_tcp_response_ready, r_ref_ref (ctx), r_ref_unref))) {
    r_http_request_unref (ctx->req);
    ctx->req = NULL;
  }

  if (addr != NULL)
    r_socket_address_unref (addr);

  return ret;
}

static void
r_http_client_ctx_tcp_recv (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RHttpClientCtx * ctx = data;
  RHttpError err;

  if (buf != NULL) {
    R_LOG_TRACE ("%p: Buffer %p on "R_EV_IO_FORMAT" (%"RSIZE_FMT")",
        ctx->server, buf, R_EV_IO_ARGS (evtcp), r_buffer_get_size (buf));
    R_LOG_BUF_DUMP (R_LOG_LEVEL_TRACE, buf);

    if (ctx->inbuf == NULL)
      ctx->inbuf = r_buffer_ref (buf);
    else
      r_buffer_append_mem_from_buffer (ctx->inbuf, buf);
  } else {
    /* FIXME */
    ctx->keepalive = FALSE;

    if (ctx->req == NULL) {
      r_http_client_ctx_process (ctx);
    } else {
      R_LOG_INFO ("%p: "R_EV_IO_FORMAT" closing, but nothing parsed",
          ctx->server, R_EV_IO_ARGS (evtcp));
      r_http_client_ctx_close (ctx, NULL, NULL);
    }

    return;
  }

  do {
    /* Process request-line and headers */
    if (ctx->req == NULL) {
      buf = NULL;
      if ((ctx->req = r_http_request_new_from_buffer (ctx->inbuf, &err, &buf)) != NULL) {
        ctx->bodysize = r_http_request_calc_body_size (ctx->req, NULL);
        if (r_http_request_has_header_of_value (ctx->req, "Connection", -1, "close", -1))
          ctx->keepalive = FALSE;
        else
          ctx->keepalive = r_http_request_has_header_of_value (ctx->req,
              "Connection", -1, "keep-alive", -1);

        R_LOG_TRACE ("%p: "R_EV_IO_FORMAT" request created %p waiting for body size %"RSSIZE_FMT,
            ctx->server, R_EV_IO_ARGS (evtcp), ctx->req, ctx->bodysize);
      } else if (err == R_HTTP_BUF_TOO_SMALL) {
        R_LOG_TRACE ("%p: "R_EV_IO_FORMAT" waiting for more data (%"RSIZE_FMT")",
            ctx->server, R_EV_IO_ARGS (evtcp), r_buffer_get_size (ctx->inbuf));
      } else {
        RHttpResponse * res;

        R_LOG_TRACE ("%p: "R_EV_IO_FORMAT" request not parsed. err: %d",
            ctx->server, R_EV_IO_ARGS (evtcp), (int)err);

        /* Send error and close! */
        ctx->keepalive = FALSE;
        if ((res = r_http_response_new (NULL, R_HTTP_STATUS_BAD_REQUEST,
                NULL, NULL, NULL)) != NULL) {
          r_http_client_ctx_tcp_response_ready (ctx, res, ctx->server);
          r_http_response_unref (res);
        } else {
          R_LOG_WARNING ("%p: "R_EV_IO_FORMAT" closing, error and unable to respond",
              ctx->server, R_EV_IO_ARGS (evtcp));
          r_http_client_ctx_close (ctx, NULL, NULL);
        }
      }

      if (buf != NULL) {
        R_LOG_TRACE ("%p: "R_EV_IO_FORMAT" data buffered: %"RSIZE_FMT,
            ctx->server, R_EV_IO_ARGS (evtcp), r_buffer_get_size (buf));
      }
      r_buffer_unref (ctx->inbuf);
      ctx->inbuf = buf;

      if (ctx->req == NULL)
        break;
    }

    /* Process body */
    if (ctx->bodysize == 0) {
      r_http_client_ctx_process (ctx);
    } else if (ctx->bodysize > 0) {
      if (ctx->inbuf != NULL) {
        rsize cur = r_buffer_get_size (ctx->inbuf);

        if (cur < (rsize)ctx->bodysize) {
          return;
        } else if (cur == (rsize)ctx->bodysize) {
          r_http_request_set_body_buffer (ctx->req, ctx->inbuf);
          r_buffer_unref (ctx->inbuf);
          ctx->inbuf = NULL;
        } else if (cur > (rsize)ctx->bodysize) {
          RBuffer * body = r_buffer_view (ctx->inbuf, 0, (rsize)ctx->bodysize);
          RBuffer * rest = r_buffer_view (ctx->inbuf, (rsize)ctx->bodysize, -1);
          r_http_request_set_body_buffer (ctx->req, body);
          r_buffer_unref (body);
          r_buffer_unref (ctx->inbuf);
          ctx->inbuf = rest;
        }

        r_http_client_ctx_process (ctx);
      }
    } else if (ctx->bodysize < 0) {
      /* TODO: chunked */
      return;
    }
  } while (ctx->req == NULL && ctx->inbuf != NULL);
}


static void
r_http_server_free (RHttpServer * server)
{
  r_dir_tree_unref (server->dt);
  r_ev_loop_unref (server->loop);
  r_ptr_array_unref (server->clients);
  r_ptr_array_unref (server->listen);
  r_free (server);
}

RHttpServer *
r_http_server_new (REvLoop * loop)
{
  RHttpServer * ret;

  loop = (loop != NULL) ? r_ev_loop_ref (loop) : r_ev_loop_default ();
  if (R_UNLIKELY (loop == NULL)) return NULL;

  if ((ret = r_mem_new (RHttpServer)) != NULL) {
    r_ref_init (ret, r_http_server_free);

    ret->loop = loop;
    ret->dt = r_dir_tree_new ();

    ret->clients = r_ptr_array_new_sized (1024);
    ret->listen = r_ptr_array_new ();

    R_LOG_INFO ("New HTTP server %p", ret);
  } else {
    r_ev_loop_unref ( loop);
  }

  return ret;
}

rboolean
r_http_server_set_handler (RHttpServer * server,
  const rchar * pattern, rssize size, RHttpRequestHandler handler,
  rpointer data, RDestroyNotify notify)
{
  if (R_UNLIKELY (handler == NULL)) return FALSE;

  if (size < 0) {
    R_LOG_INFO ("%p: Handler %p for %s", server, handler, pattern);
  } else {
    R_LOG_INFO ("%p: Handler %p for %.*s", server, handler, (int)size, pattern);
  }

  return r_dir_tree_set_full (server->dt, pattern, size,
      data, notify, (RFunc)handler) != NULL;
}

typedef struct {
  RHttpRequestHandler handler;
  RHttpServer * server;
  RHttpRequest * req;
  RSocketAddress * addr;
  rpointer handlerdata;

  RHttpResponseReady ready;
  rpointer data;
  RDestroyNotify notify;
} RHttpServerHandlerCtx;

static void
r_http_server_handler_ctx_free (rpointer data)
{
  RHttpServerHandlerCtx * ctx = data;

  /* DONT touch ctx->server */
  if (ctx->req != NULL)
    r_http_request_unref (ctx->req);
  if (ctx->addr != NULL)
    r_socket_address_unref (ctx->addr);
  if (ctx->notify != NULL)
    ctx->notify (ctx->data);

  r_free (data);
}

static void
r_http_server_request_handler (rpointer data, REvLoop * loop)
{
  RHttpServerHandlerCtx * ctx = data;
  RHttpResponse * res;

  (void) loop;

  if (ctx->handler != NULL) {
    if ((res = ctx->handler (ctx->handlerdata, ctx->req, ctx->addr, ctx->server)) == NULL) {
      R_LOG_FIXME ("%p: Request %p handled with %p, but no response",
          ctx->server, ctx->req, ctx->handler);
      res = r_http_response_new (ctx->req, R_HTTP_STATUS_INTERNAL_SERVER_ERROR,
          NULL, NULL, NULL);
    }
  } else {
    res = r_http_response_new (ctx->req, R_HTTP_STATUS_NOT_FOUND,
        NULL, NULL, NULL);
  }

  ctx->ready (ctx->data, res, ctx->server);
  if (res != NULL)
    r_http_response_unref (res);
}

rboolean
r_http_server_process_request (RHttpServer * server,
    RHttpRequest * req, RSocketAddress * addr,
    RHttpResponseReady ready, rpointer data, RDestroyNotify notify)
{
  RUri * uri;

  if (req != NULL && ready != NULL &&
      (uri = r_http_request_get_uri (req)) != NULL) {
    const rchar * path;
    rsize size = 0;
    RDirTreeNode * node;
    RHttpServerHandlerCtx * ctx = r_mem_new0 (RHttpServerHandlerCtx);

    ctx->server = server;
    ctx->req = r_http_request_ref (req);
    ctx->addr = addr != NULL ? r_socket_address_ref (addr) : NULL;
    ctx->ready = ready;
    ctx->data = data;
    ctx->notify = notify;

    if ((path = r_uri_get_path_ptr (uri, &size)) != NULL &&
        (node = r_dir_tree_get_or_any_parent (server->dt, path, (rssize)size)) != NULL &&
        (ctx->handler = (RHttpRequestHandler) r_dir_tree_node_func (node))) {
      R_LOG_TRACE ("%p: Request %p for '%.*s'", server, req, (int)size, path);
      ctx->handlerdata = r_dir_tree_node_get (node);
    } else {
      R_LOG_DEBUG ("%p: Request %p for '%.*s' no handler -> not found",
          server, req, (int)size, path);
    }

    r_ev_loop_add_callback (server->loop, FALSE,
        r_http_server_request_handler, ctx, r_http_server_handler_ctx_free);
    r_uri_unref (uri);
    return TRUE;
  }

  R_LOG_WARNING ("%p: Request %p not processed", server, req);
  return FALSE;
}

static void
r_http_server_tcp_connection_ready (rpointer data,
    REvTCP * newtcp, REvTCP * listening)
{
  RHttpServer * server = data;
  RHttpClientCtx * ctx;

  if ((ctx = r_http_client_ctx_new (server, newtcp)) != NULL) {
    R_LOG_TRACE ("%p: New connection "R_EV_IO_FORMAT" on "R_EV_IO_FORMAT,
        server, R_EV_IO_ARGS (newtcp), R_EV_IO_ARGS (listening));

    if (r_ev_tcp_recv_start (newtcp, NULL, r_http_client_ctx_tcp_recv, ctx, NULL)) {
      r_ptr_array_add (server->clients, r_ref_ref (ctx), r_ref_unref);
    }
  } else {
    R_LOG_WARNING ("%p: New connection "R_EV_IO_FORMAT" on "R_EV_IO_FORMAT
        " failed to create context! OOM?",
        server, R_EV_IO_ARGS (newtcp), R_EV_IO_ARGS (listening));
  }
}

rboolean
r_http_server_listen (RHttpServer * server, RSocketAddress * addr)
{
  REvTCP * tcp;
  rchar * addrstr;

  addrstr = r_socket_address_to_str (addr);

  if ((tcp = r_ev_tcp_new_bind (addr, server->loop)) != NULL) {
    if (r_ev_tcp_listen (tcp, R_SOCKET_DEFAULT_BACKLOG,
          r_http_server_tcp_connection_ready, server, NULL) >= R_SOCKET_OK) {
      if (r_ptr_array_add (server->listen, tcp, r_ev_tcp_unref) != R_PTR_ARRAY_INVALID_IDX) {
        R_LOG_INFO ("%p: TCP listen %s", server, addrstr);
        r_free (addrstr);
        return TRUE;
      }
    }

    r_ev_tcp_unref (tcp);
  }

  R_LOG_ERROR ("%p: Failed for %s", server, addrstr);
  r_free (addrstr);
  return FALSE;
}

typedef struct {
  RRef ref;
  RHttpServer * server;
  RHttpServerStop func;
  rpointer data;
  RDestroyNotify notify;
} RHttpServerStopCtx;

static void
r_http_server_stop_ctx_free (RHttpServerStopCtx * ctx)
{
  if (ctx->func != NULL)
    ctx->func (ctx->data, ctx->server);
  if (ctx->notify != NULL)
    ctx->notify (ctx->data);

  r_http_server_unref (ctx->server);
  r_free (ctx);
}

static void
r_http_server_tcp_close (rpointer data, rpointer user)
{
  REvTCP * tcp = data;
  RHttpServerStopCtx * ctx = user;

  R_LOG_DEBUG ("%p: Close TCP socket "R_EV_IO_FORMAT,
      ctx->server, R_EV_IO_ARGS (tcp));

  /* This looks wierd, and yes, no close callback,
   * but rather use ref counting of the ctx object */
  r_ev_tcp_close (tcp, NULL, r_ref_ref (ctx), r_ref_unref);
}

static void
r_http_server_close_client_ctx (rpointer data, rpointer user)
{
  RHttpClientCtx * cli = data;
  RHttpServerStopCtx * ctx = user;
  R_LOG_DEBUG ("%p: Force close client socket "R_EV_IO_FORMAT,
      ctx->server, R_EV_IO_ARGS (cli->evtcp));
  r_http_client_ctx_close (cli, r_ref_ref (ctx), r_ref_unref);
}

rsize
r_http_server_stop (RHttpServer * server, RHttpServerStop func,
    rpointer data, RDestroyNotify notify)
{
  RHttpServerStopCtx * ctx;
  rsize ret;

  if ((ctx = r_mem_new (RHttpServerStopCtx)) != NULL) {
    r_ref_init (ctx, r_http_server_stop_ctx_free);
    ctx->server = r_http_server_ref (server);
    ctx->func = func;
    ctx->data = data;
    ctx->notify = notify;

    ret = r_ptr_array_remove_all_full (server->listen,
        r_http_server_tcp_close, ctx);
    ret = r_ptr_array_remove_all_full (server->clients,
        r_http_server_close_client_ctx, ctx);
    r_ref_unref (ctx);
  } else {
    ret = 0;
  }

  R_LOG_INFO ("%p: Close %"RSIZE_FMT" sockets", server, ret);
  return ret;
}

