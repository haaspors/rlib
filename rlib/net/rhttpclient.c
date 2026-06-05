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
#include <rlib/net/rhttpclient.h>

#include <rlib/ev/revtcp.h>

#include <rlib/data/rptrarray.h>

#include <rlib/rmem.h>

/* Cap unparsed response-header bytes so a peer that never sends the
 * terminating CRLFCRLF can't grow the input buffer without bound. */
#define R_HTTP_CLIENT_MAX_HEADER  (64 * 1024)

struct RHttpClient {
  RRef ref;

  REvLoop * loop;
  RPtrArray * reqs;
};

typedef struct {
  RRef ref;
  RHttpClient * client;
  REvTCP * evtcp;

  RHttpRequest * req;
  RBuffer * inbuf;

  RHttpResponse * res;
  rssize bodysize;
  RHttpBodyParseType bodytype;

  RHttpClientResponseFunc cb;
  rpointer data;
  RDestroyNotify notify;

  rboolean finished;
} RHttpClientReqCtx;

#define R_LOG_CAT_DEFAULT &httpclicat
R_LOG_CATEGORY_DEFINE_STATIC (httpclicat, "httpclient", "RLib HTTP client",
    R_CLR_FG_WHITE | R_CLR_BG_BLUE | R_CLR_FMT_BOLD);

void
r_http_client_init (void)
{
  r_log_category_register (&httpclicat);
}


static void
r_http_client_req_ctx_free (RHttpClientReqCtx * ctx)
{
  if (ctx->notify != NULL)
    ctx->notify (ctx->data);
  if (ctx->res != NULL)
    r_http_response_unref (ctx->res);
  if (ctx->inbuf != NULL)
    r_buffer_unref (ctx->inbuf);
  if (ctx->req != NULL)
    r_http_request_unref (ctx->req);
  if (ctx->evtcp != NULL)
    r_ev_tcp_unref (ctx->evtcp);

  r_http_client_unref (ctx->client);
  r_free (ctx);
}

static void
r_http_client_req_do_close (rpointer data, REvLoop * loop)
{
  RHttpClientReqCtx * ctx = data;
  (void) loop;

  r_ev_tcp_close (ctx->evtcp, NULL, NULL, NULL);
}

/* Deliver the outcome once and tear the request down. Idempotent: a
 * receive-path error and a later error event can both land here.
 *
 * @defer is TRUE when called from inside a connect/recv callback, where
 * closing the socket synchronously would free the io-watch entry the loop is
 * still iterating; the close is then deferred to a loop callback. It is FALSE
 * only for a synchronous connect failure raised from r_http_client_send (not a
 * loop callback, and the failed socket has no active watch), where deferring
 * would strand the close if the caller never runs the loop again. */
static void
r_http_client_req_teardown (RHttpClientReqCtx * ctx, RHttpClientResult result,
    rboolean defer)
{
  if (ctx->finished)
    return;
  ctx->finished = TRUE;

  /* Keep ctx alive across the callback and the array removal below (the
   * array holds the only other reference). */
  r_ref_ref (ctx);

  R_LOG_TRACE ("%p: request %p finished (%d)", ctx->client, ctx, (int) result);
  if (ctx->cb != NULL)
    ctx->cb (ctx->data, result == R_HTTP_CLIENT_OK ? ctx->res : NULL,
        result, ctx->client);

  if (defer)
    r_ev_loop_add_callback (ctx->client->loop, FALSE,
        r_http_client_req_do_close, r_ref_ref (ctx), r_ref_unref);
  else
    r_ev_tcp_close (ctx->evtcp, NULL, NULL, NULL);
  r_ptr_array_remove_first_fast (ctx->client->reqs, ctx);

  r_ref_unref (ctx);
}

#define r_http_client_req_finish(ctx, result) \
  r_http_client_req_teardown (ctx, result, TRUE)

static void
r_http_client_req_recv (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RHttpClientReqCtx * ctx = data;
  (void) evtcp;

  /* The recv watch stays armed until the deferred close runs, so a late
   * event after the request finished must be ignored. */
  if (ctx->finished)
    return;

  if (buf == NULL) {
    /* End-of-stream: a CLOSE-framed body ends here; anything else mid-body
     * is a truncated response. */
    if (ctx->res != NULL && ctx->bodytype == R_HTTP_BODY_PARSE_CLOSE) {
      if (ctx->inbuf != NULL)
        r_http_response_set_body_buffer (ctx->res, ctx->inbuf);
      r_http_client_req_finish (ctx, R_HTTP_CLIENT_OK);
    } else {
      r_http_client_req_finish (ctx, R_HTTP_CLIENT_RECV_FAILED);
    }
    return;
  }

  if (ctx->inbuf == NULL)
    ctx->inbuf = r_buffer_ref (buf);
  else
    r_buffer_append_mem_from_buffer (ctx->inbuf, buf);

  /* Parse the status line + headers once enough bytes have arrived. */
  if (ctx->res == NULL) {
    RHttpError err;
    RBuffer * remainder = NULL;

    ctx->res = r_http_response_new_from_buffer (ctx->req, ctx->inbuf, &err, &remainder);
    if (ctx->res != NULL) {
      ctx->bodysize = r_http_response_calc_body_size (ctx->res, &ctx->bodytype);
    } else if (err == R_HTTP_BUF_TOO_SMALL) {
      if (r_buffer_get_size (ctx->inbuf) > R_HTTP_CLIENT_MAX_HEADER) {
        r_buffer_unref (ctx->inbuf);
        ctx->inbuf = remainder;
        r_http_client_req_finish (ctx, R_HTTP_CLIENT_PARSE_FAILED);
        return;
      }
      /* Wait for more header bytes (remainder re-holds the pending data). */
    } else {
      r_buffer_unref (ctx->inbuf);
      ctx->inbuf = remainder;
      r_http_client_req_finish (ctx, R_HTTP_CLIENT_PARSE_FAILED);
      return;
    }

    /* On success remainder is the post-header bytes; on BUF_TOO_SMALL it
     * re-holds the pending data. Either way it becomes the new inbuf. */
    r_buffer_unref (ctx->inbuf);
    ctx->inbuf = remainder;

    if (ctx->res == NULL)
      return;
  }

  /* Headers parsed; collect the body per its framing. */
  switch (ctx->bodytype) {
    case R_HTTP_BODY_PARSE_SIZED:
      if (ctx->bodysize <= 0) {
        r_http_client_req_finish (ctx, R_HTTP_CLIENT_OK);
      } else if (ctx->inbuf != NULL &&
          r_buffer_get_size (ctx->inbuf) >= (rsize) ctx->bodysize) {
        RBuffer * body = r_buffer_view (ctx->inbuf, 0, (rsize) ctx->bodysize);
        r_http_response_set_body_buffer (ctx->res, body);
        r_buffer_unref (body);
        r_http_client_req_finish (ctx, R_HTTP_CLIENT_OK);
      }
      /* else wait for more body bytes */
      break;
    case R_HTTP_BODY_PARSE_CLOSE:
      /* Body runs until the connection closes; handled on end-of-stream. */
      break;
    case R_HTTP_BODY_PARSE_CHUNKED: {
      RBuffer * body = NULL;
      RHttpError err = (ctx->inbuf != NULL) ?
          r_http_chunked_decode (ctx->inbuf, &body) : R_HTTP_BUF_TOO_SMALL;
      if (err == R_HTTP_OK) {
        r_http_response_set_body_buffer (ctx->res, body);
        r_buffer_unref (body);
        r_http_client_req_finish (ctx, R_HTTP_CLIENT_OK);
      } else if (err != R_HTTP_BUF_TOO_SMALL) {
        r_http_client_req_finish (ctx, R_HTTP_CLIENT_PARSE_FAILED);
      }
      /* else wait for more chunk bytes */
      break;
    }
    default:
      /* Tunnel framing (after CONNECT) isn't implemented. */
      R_LOG_DEBUG ("%p: request %p unsupported body framing %d",
          ctx->client, ctx, (int) ctx->bodytype);
      r_http_client_req_finish (ctx, R_HTTP_CLIENT_PARSE_FAILED);
      break;
  }
}

static void
r_http_client_req_connected (rpointer data, REvTCP * evtcp, int status)
{
  RHttpClientReqCtx * ctx = data;
  RBuffer * buf;
  (void) evtcp;

  if (status != 0) {
    R_LOG_DEBUG ("%p: request %p connect failed (%d)", ctx->client, ctx, status);
    r_http_client_req_finish (ctx, R_HTTP_CLIENT_CONNECT_FAILED);
    return;
  }

  if ((buf = r_http_msg_get_buffer ((RHttpMsg *) ctx->req)) == NULL) {
    r_http_client_req_finish (ctx, R_HTTP_CLIENT_SEND_FAILED);
    return;
  }
  r_ev_tcp_send_and_forget (ctx->evtcp, buf);
  r_buffer_unref (buf);

  if (!r_ev_tcp_recv_start (ctx->evtcp, NULL, r_http_client_req_recv, ctx, NULL))
    r_http_client_req_finish (ctx, R_HTTP_CLIENT_RECV_FAILED);
}

static void
r_http_client_req_error (rpointer data, REvTCP * evtcp, RSocketStatus error)
{
  RHttpClientReqCtx * ctx = data;
  (void) evtcp;

  R_LOG_DEBUG ("%p: request %p socket error (%d)", ctx->client, ctx, (int) error);
  r_http_client_req_finish (ctx, R_HTTP_CLIENT_RECV_FAILED);
}

rboolean
r_http_client_send (RHttpClient * client, RHttpRequest * req,
    const RSocketAddress * addr,
    RHttpClientResponseFunc cb, rpointer data, RDestroyNotify notify)
{
  RHttpClientReqCtx * ctx;

  if (R_UNLIKELY (client == NULL || req == NULL || addr == NULL || cb == NULL))
    return FALSE;

  if ((ctx = r_mem_new0 (RHttpClientReqCtx)) == NULL)
    return FALSE;
  r_ref_init (ctx, r_http_client_req_ctx_free);
  ctx->client = r_http_client_ref (client);
  ctx->req = r_http_request_ref (req);
  ctx->bodytype = R_HTTP_BODY_PARSE_SIZED;

  /* Set cb/data/notify only once the request is committed (TRUE return):
   * a FALSE return must not invoke notify -- the caller keeps ownership. */
  if ((ctx->evtcp = r_ev_tcp_new (r_socket_address_get_family (addr),
          client->loop)) == NULL) {
    r_ref_unref (ctx);
    return FALSE;
  }
  ctx->cb = cb;
  ctx->data = data;
  ctx->notify = notify;

  /* The array owns the request context; the in-flight callbacks borrow it. */
  r_ptr_array_add (client->reqs, ctx, r_ref_unref);
  r_ev_tcp_set_error_handler (ctx->evtcp, r_http_client_req_error, ctx, NULL);

  R_LOG_TRACE ("%p: request %p started", client, ctx);
  if (r_ev_tcp_connect (ctx->evtcp, addr,
        r_http_client_req_connected, ctx, NULL) < R_SOCKET_OK)
    r_http_client_req_teardown (ctx, R_HTTP_CLIENT_CONNECT_FAILED, FALSE);

  return TRUE;
}



static void
r_http_client_free (RHttpClient * client)
{
  /* A request context holds a reference on the client, so the client can
   * only be freed once every request has finished and left client->reqs. */
  r_ptr_array_unref (client->reqs);
  r_ev_loop_unref (client->loop);
  r_free (client);
}

RHttpClient *
r_http_client_new (REvLoop * loop)
{
  RHttpClient * ret;

  loop = (loop != NULL) ? r_ev_loop_ref (loop) : r_ev_loop_default ();
  if (R_UNLIKELY (loop == NULL)) return NULL;

  if ((ret = r_mem_new (RHttpClient)) != NULL) {
    r_ref_init (ret, r_http_client_free);

    ret->loop = loop;
    ret->reqs = r_ptr_array_new ();

    R_LOG_INFO ("New HTTP client %p", ret);
  } else {
    r_ev_loop_unref (loop);
  }

  return ret;
}


struct RHttpClientSync {
  RRef ref;
  REvLoop * loop;
  RHttpClient * client;
};

typedef struct {
  RHttpResponse * res;
  RHttpClientResult result;
  rboolean done;
  REvLoop * loop;
} RHttpClientSyncState;

static void
r_http_client_sync_free (RHttpClientSync * sync)
{
  if (sync->client != NULL)
    r_http_client_unref (sync->client);
  r_ev_loop_unref (sync->loop);
  r_free (sync);
}

RHttpClientSync *
r_http_client_sync_new (void)
{
  RHttpClientSync * ret;
  REvLoop * loop;

  /* A private loop (real system clock) the blocking request drives itself, so
   * the caller never manages an event loop. */
  if ((loop = r_ev_loop_new_full (NULL, NULL)) == NULL)
    return NULL;

  if ((ret = r_mem_new0 (RHttpClientSync)) != NULL) {
    r_ref_init (ret, r_http_client_sync_free);
    ret->loop = loop;
    if (R_UNLIKELY ((ret->client = r_http_client_new (loop)) == NULL)) {
      r_ref_unref (ret);
      return NULL;
    }
    R_LOG_INFO ("New blocking HTTP client %p", ret);
  } else {
    r_ev_loop_unref (loop);
  }

  return ret;
}

static void
r_http_client_sync_cb (rpointer data, RHttpResponse * res,
    RHttpClientResult result, RHttpClient * client)
{
  RHttpClientSyncState * state = data;
  (void) client;

  state->result = result;
  state->res = (res != NULL) ? r_http_response_ref (res) : NULL;
  state->done = TRUE;
  /* Break out of the r_ev_loop_run below now that the exchange is complete. */
  r_ev_loop_stop (state->loop);
}

RHttpResponse *
r_http_client_sync_request (RHttpClientSync * sync, RHttpRequest * req,
    const RSocketAddress * addr, RHttpClientResult * result)
{
  RHttpClientSyncState state = { NULL, R_HTTP_CLIENT_CONNECT_FAILED, FALSE,
      sync != NULL ? sync->loop : NULL };

  if (R_UNLIKELY (sync == NULL) ||
      !r_http_client_send (sync->client, req, addr,
          r_http_client_sync_cb, &state, NULL)) {
    if (result != NULL)
      *result = R_HTTP_CLIENT_CONNECT_FAILED;
    return NULL;
  }

  while (!state.done)
    r_ev_loop_run (sync->loop, R_EV_LOOP_RUN_LOOP);

  if (result != NULL)
    *result = state.result;
  return state.res;
}
