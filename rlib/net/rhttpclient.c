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
#include <rlib/ev/revresolve.h>

#include <rlib/net/rsocket.h>
#include <rlib/net/rtlsclient.h>
#include <rlib/crypto/rtruststore.h>
#include <rlib/crypto/rx509.h>
#include <rlib/data/rptrarray.h>

#include <rlib/rrand.h>
#include <rlib/ruri.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>
#include <rlib/rtime.h>

/* Cap unparsed response-header bytes so a peer that never sends the
 * terminating CRLFCRLF can't grow the input buffer without bound. */
#define R_HTTP_CLIENT_MAX_HEADER  (64 * 1024)

/* Default idle-connection timeout before a pooled connection is evicted. */
#define R_HTTP_CLIENT_IDLE_TIMEOUT  (60 * R_SECOND)

typedef struct RHttpClientConn RHttpClientConn;
typedef struct RHttpClientReqCtx RHttpClientReqCtx;

struct RHttpClient {
  RRef ref;

  REvLoop * loop;
  RPtrArray * reqs;     /* in-flight request contexts */
  RPtrArray * idle;     /* idle RHttpClientConn, scanned by destination addr */
  rboolean keepalive;
  RClockTimeDiff idle_timeout;
  RPrng * prng;         /* lazily created on the first HTTPS request */
  RTrustStore * trust;  /* anchors/pins for HTTPS server verification */
  rboolean insecure;    /* skip certificate verification (opt-in) */
};

struct RHttpClientReqCtx {
  RRef ref;
  RHttpClient * client;
  RHttpClientConn * conn;   /* serving connection; holds a ref while in use */

  RHttpRequest * req;
  RBuffer * inbuf;

  RHttpResponse * res;
  rssize bodysize;
  rsize bodyconsumed;       /* inbuf bytes the chunked decoder used (CHUNKED) */
  RHttpBodyParseType bodytype;

  RHttpClientResponseFunc cb;
  rpointer data;
  RDestroyNotify notify;

  RSocketAddress * dest;  /* connect target; keys reuse and drives the retry */
  rboolean tls;           /* HTTPS: terminate the connection with TLS */
  rboolean reused;        /* running on a pooled connection */
  rboolean retried;       /* a stale-connection retry has already happened */
  rboolean finished;
};

/* A client connection. It owns the socket and keeps its recv watch armed for
 * its whole life, so reuse needs no re-arming. While serving a request conn->req
 * is set; when idle it is NULL and the connection sits in client->idle awaiting
 * reuse, watched only so a peer close evicts it. */
struct RHttpClientConn {
  RRef ref;
  RHttpClient * client;       /* borrowed */
  REvTCP * evtcp;
  RTLSClient * tls;           /* per-connection TLS engine; NULL for plaintext */
  RSocketAddress * addr;      /* destination key */
  RHttpClientReqCtx * req;    /* current request, or NULL when idle */
  RClockEntry * timer;        /* idle-eviction timer, set only when idle */
  rboolean recving;           /* recv watch armed */
  rboolean closing;
};

#define r_http_client_conn_ref   r_ref_ref
#define r_http_client_conn_unref r_ref_unref

#define R_LOG_CAT_DEFAULT &httpclicat
R_LOG_CATEGORY_DEFINE_STATIC (httpclicat, "httpclient", "RLib HTTP client",
    R_CLR_FG_WHITE | R_CLR_BG_BLUE | R_CLR_FMT_BOLD);

void
r_http_client_init (void)
{
  r_log_category_register (&httpclicat);
}


/* Forward declarations (the request and connection flows are mutually
 * recursive: connect -> send -> recv -> complete, with reuse and retry). */
static void r_http_client_req_complete (RHttpClientReqCtx * ctx,
    RHttpClientResult result, rboolean defer);
static void r_http_client_req_fail (RHttpClientReqCtx * ctx,
    RHttpClientResult result, rboolean defer);
static void r_http_client_req_connect (RHttpClientReqCtx * ctx, rboolean defer);
static void r_http_client_req_send (RHttpClientReqCtx * ctx, rboolean defer);
static void r_http_client_conn_evict (RHttpClientConn * conn);


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
  /* Normally cleared at completion; only set here on an abnormal teardown
   * (e.g. the loop torn down mid-connect). Detach and drop our connection ref
   * (conn_free closes the socket). */
  if (ctx->conn != NULL) {
    ctx->conn->req = NULL;
    r_http_client_conn_unref (ctx->conn);
  }
  if (ctx->dest != NULL)
    r_socket_address_unref (ctx->dest);

  r_http_client_unref (ctx->client);
  r_free (ctx);
}

/* --- connection lifecycle ------------------------------------------------- */

static void
r_http_client_conn_free (RHttpClientConn * conn)
{
  if (conn->timer != NULL)
    r_ev_loop_cancel_timer (conn->client->loop, conn->timer);
  if (conn->evtcp != NULL) {
    /* When closed via conn_close the close is already done/scheduled
     * (closing == TRUE); otherwise (pool torn down with the client) close it
     * here, synchronously -- we are not inside an io callback. */
    if (!conn->closing)
      r_ev_tcp_abort (conn->evtcp, NULL, NULL, NULL);
    r_ev_tcp_unref (conn->evtcp);
  }
  if (conn->tls != NULL)
    r_tls_client_unref (conn->tls);
  if (conn->addr != NULL)
    r_socket_address_unref (conn->addr);
  r_free (conn);
}

static void
r_http_client_conn_do_close (rpointer data, REvLoop * loop)
{
  RHttpClientConn * conn = data;
  (void) loop;

  r_ev_tcp_abort (conn->evtcp, NULL, NULL, NULL);
}

/* Close conn's socket. Idempotent. @defer is TRUE when called from inside one
 * of the socket's own callbacks, where closing synchronously would free the
 * io-watch the loop is still iterating. Does not touch refs or pool membership. */
static void
r_http_client_conn_close (RHttpClientConn * conn, rboolean defer)
{
  if (conn->closing)
    return;
  conn->closing = TRUE;

  if (conn->timer != NULL) {
    r_ev_loop_cancel_timer (conn->client->loop, conn->timer);
    conn->timer = NULL;
  }
  if (conn->evtcp != NULL) {
    if (defer)
      r_ev_loop_add_callback (conn->client->loop, FALSE,
          r_http_client_conn_do_close, r_http_client_conn_ref (conn),
          r_http_client_conn_unref);
    else
      r_ev_tcp_abort (conn->evtcp, NULL, NULL, NULL);
  }
}

/* Drop an idle connection from the pool and close it (deferred -- this runs
 * from the idle recv/error/timer callbacks). Idempotent. */
static void
r_http_client_conn_evict (RHttpClientConn * conn)
{
  if (conn->closing)
    return;

  /* Hold a ref across the pool removal, which drops the array's ref. */
  r_http_client_conn_ref (conn);
  r_http_client_conn_close (conn, TRUE);
  r_ptr_array_remove_first_fast (conn->client->idle, conn);
  r_http_client_conn_unref (conn);
}

static void
r_http_client_conn_idle_timeout (rpointer data, REvLoop * loop)
{
  RHttpClientConn * conn = data;
  (void) loop;

  conn->timer = NULL;   /* the entry fired; evict must not cancel it */
  R_LOG_TRACE ("%p: idle connection %p timed out", conn->client, conn);
  r_http_client_conn_evict (conn);
}

/* Receive on a connection. Routed to the current request, or -- when the
 * connection is idle in the pool -- treated as a peer close that evicts it. */
static void r_http_client_req_recv_data (RHttpClientReqCtx * ctx, RBuffer * buf);

/* Route one plaintext/decrypted chunk (or EOS, @buf == NULL) to the current
 * request, or -- on a parked connection the peer is done with -- evict it. */
static void
r_http_client_conn_deliver (RHttpClientConn * conn, RBuffer * buf)
{
  if (conn->req == NULL || conn->req->finished) {
    r_http_client_conn_evict (conn);
    return;
  }
  r_http_client_req_recv_data (conn->req, buf);
}

static void
r_http_client_conn_recv (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RHttpClientConn * conn = data;
  (void) evtcp;

  if (conn->tls != NULL) {
    if (buf == NULL) {
      r_http_client_conn_deliver (conn, NULL);   /* transport end-of-stream */
      return;
    }
    /* Ciphertext: incoming_data synchronously fires appdata (-> parser) and may
     * tear the connection down via the error/closed callbacks; hold a reference
     * so the conn survives the chain. */
    r_http_client_conn_ref (conn);
    r_tls_client_incoming_data (conn->tls, buf);
    r_http_client_conn_unref (conn);
  } else {
    r_http_client_conn_deliver (conn, buf);
  }
}

static void
r_http_client_conn_error (rpointer data, REvTCP * evtcp, RSocketStatus error)
{
  RHttpClientConn * conn = data;
  (void) evtcp;

  R_LOG_DEBUG ("%p: connection %p socket error (%d)", conn->client, conn,
      (int) error);
  if (conn->req == NULL)
    r_http_client_conn_evict (conn);
  else
    r_http_client_req_fail (conn->req, R_HTTP_CLIENT_RECV_FAILED, TRUE);
}

static void
r_http_client_conn_connected (rpointer data, REvTCP * evtcp, int status)
{
  RHttpClientConn * conn = data;
  (void) evtcp;

  if (conn->req == NULL)        /* request gone (e.g. torn down); drop conn */
    return;
  if (status != 0) {
    R_LOG_DEBUG ("%p: request %p connect failed (%d)", conn->client, conn->req,
        status);
    r_http_client_req_fail (conn->req, R_HTTP_CLIENT_CONNECT_FAILED, TRUE);
    return;
  }

  if (conn->tls != NULL) {
    /* Arm recv before the handshake so the server's records are received, then
     * drive the ClientHello; the request is sent once handshake_done fires. */
    if (!conn->recving) {
      if (!r_ev_tcp_recv_start (conn->evtcp, NULL, r_http_client_conn_recv,
              conn, NULL)) {
        r_http_client_req_fail (conn->req, R_HTTP_CLIENT_RECV_FAILED, TRUE);
        return;
      }
      conn->recving = TRUE;
    }
    if (r_tls_client_start (conn->tls, conn->client->loop, conn->client->prng,
            R_TLS_VERSION_TLS_1_2) != R_TLS_ERROR_OK) {
      r_http_client_req_fail (conn->req, R_HTTP_CLIENT_TLS_FAILED, TRUE);
      return;
    }
    return;
  }

  r_http_client_req_send (conn->req, TRUE);
}

/* --- TLS termination (HTTPS) ---------------------------------------------
 * A per-connection RTLSClient filters the socket: ciphertext recv ->
 * incoming_data -> appdata (decrypted) -> the existing response parser; the
 * serialized request -> send_appdata -> out -> socket send. The callback
 * userdata is the RHttpClientConn (a back-pointer; the conn owns the
 * RTLSClient, hence the NULL destroy-notify on r_tls_client_new). */

static rboolean
r_http_client_tls_out (rpointer data, RBuffer * buf, rpointer session)
{
  RHttpClientConn * conn = data;
  (void) session;

  /* Borrowed buffer: the send path queues its own reference. */
  r_ev_tcp_send_and_forget (conn->evtcp, buf);
  return TRUE;
}

static void
r_http_client_tls_handshake_done (rpointer data, rpointer session)
{
  RHttpClientConn * conn = data;
  (void) session;

  if (conn->req != NULL)
    r_http_client_req_send (conn->req, TRUE);
}

static rboolean
r_http_client_tls_appdata (rpointer data, RBuffer * buf, rpointer session)
{
  RHttpClientConn * conn = data;
  (void) session;

  r_http_client_conn_deliver (conn, buf);
  return TRUE;
}

static void
r_http_client_tls_error (rpointer data, RTLSAlertType alert, rpointer session)
{
  RHttpClientConn * conn = data;
  (void) alert;
  (void) session;

  if (conn->req != NULL)
    r_http_client_req_fail (conn->req, R_HTTP_CLIENT_TLS_FAILED, TRUE);
  else
    r_http_client_conn_evict (conn);
}

static void
r_http_client_tls_closed (rpointer data, rpointer session)
{
  RHttpClientConn * conn = data;
  (void) session;

  r_http_client_conn_deliver (conn, NULL);   /* close_notify == end-of-stream */
}

/* Authenticate the server certificate: the configured trust store must accept
 * the chain for TLS server use, and the leaf must match the request's host.
 * With no trust store the connection fails closed unless the client was put in
 * insecure mode. */
static rboolean
r_http_client_tls_verify (rpointer data, RCryptoCert * const * chain, ruint count)
{
  RHttpClientConn * conn = data;
  RHttpClient * client = conn->client;
  rchar * host = NULL;
  rboolean ok;

  if (client->insecure)
    return TRUE;
  if (client->trust == NULL)
    return FALSE;

  if (r_trust_store_verify (client->trust, chain, count, r_time_get_unix_time (),
        R_X509_EXT_KEY_USAGE_SERVER_AUTH) != R_TRUST_OK)
    return FALSE;

  if (conn->req != NULL && conn->req->req != NULL) {
    RUri * uri = r_http_request_get_uri (conn->req->req);
    if (uri != NULL) {
      host = r_uri_get_hostname (uri);
      r_uri_unref (uri);
    }
  }
  ok = (host != NULL) && r_crypto_x509_cert_verify_host (chain[0], host);
  r_free (host);
  return ok;
}

static const RTLSCallbacks g__r_http_client_tls_callbacks = {
  NULL,                                  /* preferred_cipher_suites (defaults) */
  r_http_client_tls_handshake_done,      /* handshake_done */
  r_http_client_tls_out,                 /* out */
  r_http_client_tls_appdata,             /* appdata */
  r_http_client_tls_error,               /* error */
  r_http_client_tls_verify,              /* verify_cert */
  r_http_client_tls_closed,              /* closed */
};

static RHttpClientConn *
r_http_client_conn_new (RHttpClient * client, RSocketAddress * addr, rboolean tls)
{
  RHttpClientConn * conn;

  if ((conn = r_mem_new0 (RHttpClientConn)) == NULL)
    return NULL;
  r_ref_init (conn, r_http_client_conn_free);
  conn->client = client;
  conn->addr = r_socket_address_ref (addr);
  if ((conn->evtcp = r_ev_tcp_new (r_socket_address_get_family (addr),
          client->loop)) == NULL) {
    r_http_client_conn_unref (conn);
    return NULL;
  }
  if (tls && (conn->tls = r_tls_client_new (&g__r_http_client_tls_callbacks,
          conn, NULL)) == NULL) {
    r_http_client_conn_unref (conn);
    return NULL;
  }
  r_ev_tcp_set_error_handler (conn->evtcp, r_http_client_conn_error, conn, NULL);
  return conn;
}

/* Take a live pooled connection to @addr out of the pool for reuse, or NULL.
 * The returned connection carries the reference the pool held. */
static RHttpClientConn *
r_http_client_pool_acquire (RHttpClient * client, const RSocketAddress * addr,
    rboolean tls)
{
  rsize i = 0;

  while (i < r_ptr_array_size (client->idle)) {
    RHttpClientConn * conn = r_ptr_array_get (client->idle, i);

    if (conn->closing || (conn->tls != NULL) != tls ||
        !r_socket_address_is_equal (conn->addr, addr)) {
      i++;
      continue;
    }
    if (!r_socket_is_alive (r_ev_tcp_get_socket (conn->evtcp))) {
      r_http_client_conn_evict (conn);   /* dead; drop and re-check this slot */
      continue;
    }

    r_http_client_conn_ref (conn);       /* keep across the pool removal */
    if (conn->timer != NULL) {
      r_ev_loop_cancel_timer (client->loop, conn->timer);
      conn->timer = NULL;
    }
    r_ptr_array_remove_first_fast (client->idle, conn);
    return conn;                         /* ref transfers to the caller */
  }

  return NULL;
}

/* --- request flow --------------------------------------------------------- */

/* TRUE if conn may be parked for reuse after this exchange. */
static rboolean
r_http_client_req_reusable (RHttpClientReqCtx * ctx, RHttpClientConn * conn)
{
  rsize leftover;

  if (!ctx->client->keepalive || conn->closing || conn->evtcp == NULL)
    return FALSE;
  if (ctx->res == NULL)
    return FALSE;
  /* Only self-delimited bodies are poolable (a read-until-close body needs the
   * connection to close). */
  if (ctx->bodytype != R_HTTP_BODY_PARSE_SIZED &&
      ctx->bodytype != R_HTTP_BODY_PARSE_CHUNKED)
    return FALSE;
  /* Both sides must agree to persist. */
  if (!r_http_response_is_keepalive (ctx->res) ||
      !r_http_request_is_keepalive (ctx->req))
    return FALSE;
  /* Unconsumed bytes past the body would corrupt the next response. The body
   * consumed inbuf's leading bodysize bytes (SIZED) or bodyconsumed bytes as
   * reported by the chunked decoder (CHUNKED). */
  leftover = (ctx->inbuf != NULL ? r_buffer_get_size (ctx->inbuf) : 0) -
      (ctx->bodytype == R_HTTP_BODY_PARSE_CHUNKED ? ctx->bodyconsumed :
          (ctx->bodysize > 0 ? (rsize) ctx->bodysize : 0));
  return leftover == 0;
}

/* Deliver the outcome once, then either park the connection for reuse (on a
 * successful, reusable exchange) or close it, and tear the request down. */
static void
r_http_client_req_complete (RHttpClientReqCtx * ctx, RHttpClientResult result,
    rboolean defer)
{
  RHttpClientConn * conn;

  if (ctx->finished)
    return;
  ctx->finished = TRUE;

  /* Keep ctx alive across the callback and the array removal below. */
  r_ref_ref (ctx);

  R_LOG_TRACE ("%p: request %p finished (%d)", ctx->client, ctx, (int) result);
  if (ctx->cb != NULL)
    ctx->cb (ctx->data, result == R_HTTP_CLIENT_OK ? ctx->res : NULL,
        result, ctx->client);

  /* Detach the connection (a safe pointer flip -- the recv watch stays armed)
   * and decide its fate. conn is NULL if the request failed before connecting. */
  conn = ctx->conn;
  ctx->conn = NULL;
  if (conn != NULL) {
    conn->req = NULL;
    if (result == R_HTTP_CLIENT_OK && r_http_client_req_reusable (ctx, conn)) {
      if (ctx->client->idle_timeout > 0)
        r_ev_loop_add_callback_later (ctx->client->loop, &conn->timer,
            ctx->client->idle_timeout, r_http_client_conn_idle_timeout, conn,
            NULL);
      R_LOG_TRACE ("%p: parking idle connection %p", ctx->client, conn);
      r_ptr_array_add (ctx->client->idle, conn, r_http_client_conn_unref);
    } else {
      r_http_client_conn_close (conn, defer);
      r_http_client_conn_unref (conn);
    }
  }

  r_ptr_array_remove_first_fast (ctx->client->reqs, ctx);
  r_ref_unref (ctx);
}

/* Deliver a failure, but first transparently retry once if it happened on a
 * pooled connection before any response arrived -- the request almost
 * certainly never reached the server, so reconnect and resend. */
static void
r_http_client_req_fail (RHttpClientReqCtx * ctx, RHttpClientResult result,
    rboolean defer)
{
  if (ctx->finished)
    return;

  if (ctx->reused && !ctx->retried && ctx->res == NULL) {
    RHttpClientConn * conn = ctx->conn;

    ctx->retried = TRUE;
    ctx->reused = FALSE;
    ctx->conn = NULL;
    if (conn != NULL) {
      conn->req = NULL;
      r_http_client_conn_close (conn, defer);
      r_http_client_conn_unref (conn);
    }
    if (ctx->inbuf != NULL) {
      r_buffer_unref (ctx->inbuf);
      ctx->inbuf = NULL;
    }
    R_LOG_DEBUG ("%p: request %p retrying on a fresh connection", ctx->client, ctx);
    r_http_client_req_connect (ctx, defer);
    return;
  }

  r_http_client_req_complete (ctx, result, defer);
}

static void
r_http_client_req_recv_data (RHttpClientReqCtx * ctx, RBuffer * buf)
{
  if (buf == NULL) {
    /* End-of-stream: a CLOSE-framed body ends here; anything else mid-body is a
     * truncated response (and, on a reused connection with nothing received
     * yet, a candidate for the stale-connection retry). */
    if (ctx->res != NULL && ctx->bodytype == R_HTTP_BODY_PARSE_CLOSE) {
      if (ctx->inbuf != NULL)
        r_http_response_set_body_buffer (ctx->res, ctx->inbuf);
      r_http_client_req_complete (ctx, R_HTTP_CLIENT_OK, TRUE);
    } else {
      r_http_client_req_fail (ctx, R_HTTP_CLIENT_RECV_FAILED, TRUE);
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
        r_http_client_req_complete (ctx, R_HTTP_CLIENT_PARSE_FAILED, TRUE);
        return;
      }
      /* Wait for more header bytes (remainder re-holds the pending data). */
    } else {
      r_buffer_unref (ctx->inbuf);
      ctx->inbuf = remainder;
      r_http_client_req_complete (ctx, R_HTTP_CLIENT_PARSE_FAILED, TRUE);
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
        r_http_client_req_complete (ctx, R_HTTP_CLIENT_OK, TRUE);
      } else if (ctx->inbuf != NULL &&
          r_buffer_get_size (ctx->inbuf) >= (rsize) ctx->bodysize) {
        RBuffer * body = r_buffer_view (ctx->inbuf, 0, (rsize) ctx->bodysize);
        r_http_response_set_body_buffer (ctx->res, body);
        r_buffer_unref (body);
        r_http_client_req_complete (ctx, R_HTTP_CLIENT_OK, TRUE);
      }
      /* else wait for more body bytes */
      break;
    case R_HTTP_BODY_PARSE_CLOSE:
      /* Body runs until the connection closes; handled on end-of-stream. */
      break;
    case R_HTTP_BODY_PARSE_CHUNKED: {
      RBuffer * body = NULL;
      RHttpError err = (ctx->inbuf != NULL) ?
          r_http_chunked_decode (ctx->inbuf, &body, &ctx->bodyconsumed) :
          R_HTTP_BUF_TOO_SMALL;
      if (err == R_HTTP_OK) {
        r_http_response_set_body_buffer (ctx->res, body);
        r_buffer_unref (body);
        r_http_client_req_complete (ctx, R_HTTP_CLIENT_OK, TRUE);
      } else if (err != R_HTTP_BUF_TOO_SMALL) {
        r_http_client_req_complete (ctx, R_HTTP_CLIENT_PARSE_FAILED, TRUE);
      }
      /* else wait for more chunk bytes */
      break;
    }
    default:
      /* Tunnel framing (after CONNECT) isn't implemented. */
      R_LOG_DEBUG ("%p: request %p unsupported body framing %d",
          ctx->client, ctx, (int) ctx->bodytype);
      r_http_client_req_complete (ctx, R_HTTP_CLIENT_PARSE_FAILED, TRUE);
      break;
  }
}

/* Serialize and send the request on ctx's connection, arming its recv watch
 * once. Used by both a fresh connect and a reused pooled connection. */
static void
r_http_client_req_send (RHttpClientReqCtx * ctx, rboolean defer)
{
  RHttpClientConn * conn = ctx->conn;
  RBuffer * buf;

  /* Advertise keep-alive so the peer persists the connection (our server, and
   * RFC 7230 strictly, treat 1.1 as persistent, but an explicit header is the
   * interoperable signal). Idempotent across a retry's re-send. */
  if (ctx->client->keepalive &&
      !r_http_request_has_header (ctx->req, "Connection", -1))
    r_http_request_add_header (ctx->req, "Connection", -1, "keep-alive", -1);

  if ((buf = r_http_msg_get_buffer ((RHttpMsg *) ctx->req)) == NULL) {
    r_http_client_req_fail (ctx, R_HTTP_CLIENT_SEND_FAILED, defer);
    return;
  }
  if (conn->tls != NULL)
    r_tls_client_send_appdata (conn->tls, buf);   /* encrypt -> out -> socket */
  else
    r_ev_tcp_send_and_forget (conn->evtcp, buf);
  r_buffer_unref (buf);

  /* The recv watch is bound to the connection for its whole life; a reused
   * connection already has it armed. */
  if (!conn->recving) {
    if (!r_ev_tcp_recv_start (conn->evtcp, NULL, r_http_client_conn_recv,
            conn, NULL)) {
      r_http_client_req_fail (ctx, R_HTTP_CLIENT_RECV_FAILED, defer);
      return;
    }
    conn->recving = TRUE;
  }
}

/* Open a fresh connection to ctx->dest and send once connected. */
static void
r_http_client_req_connect (RHttpClientReqCtx * ctx, rboolean defer)
{
  RHttpClientConn * conn;

  ctx->reused = FALSE;
  /* The TLS handshake draws randomness from a lazily created, client-owned PRNG. */
  if (ctx->tls && ctx->client->prng == NULL &&
      (ctx->client->prng = r_prng_new_mt ()) == NULL) {
    r_http_client_req_complete (ctx, R_HTTP_CLIENT_TLS_FAILED, defer);
    return;
  }
  if ((conn = r_http_client_conn_new (ctx->client, ctx->dest, ctx->tls)) == NULL) {
    r_http_client_req_complete (ctx, R_HTTP_CLIENT_CONNECT_FAILED, defer);
    return;
  }
  ctx->conn = conn;     /* ctx owns the new connection's reference */
  conn->req = ctx;
  if (r_ev_tcp_connect (conn->evtcp, ctx->dest,
        r_http_client_conn_connected, conn, NULL) < R_SOCKET_OK)
    r_http_client_req_complete (ctx, R_HTTP_CLIENT_CONNECT_FAILED, defer);
}

/* Reuse a pooled connection to ctx->dest if one is idle, else connect fresh. */
static void
r_http_client_req_dispatch (RHttpClientReqCtx * ctx, rboolean defer)
{
  RHttpClientConn * conn = r_http_client_pool_acquire (ctx->client, ctx->dest,
      ctx->tls);

  if (conn != NULL) {
    ctx->conn = conn;   /* acquire transferred the pool's reference to us */
    ctx->reused = TRUE;
    conn->req = ctx;
    R_LOG_TRACE ("%p: request %p reusing pooled connection %p", ctx->client,
        ctx, conn);
    r_http_client_req_send (ctx, defer);
    return;
  }

  r_http_client_req_connect (ctx, defer);
}

static RHttpClientReqCtx *
r_http_client_req_ctx_new (RHttpClient * client, RHttpRequest * req,
    RHttpClientResponseFunc cb, rpointer data, RDestroyNotify notify)
{
  RHttpClientReqCtx * ctx;

  if ((ctx = r_mem_new0 (RHttpClientReqCtx)) == NULL)
    return NULL;
  r_ref_init (ctx, r_http_client_req_ctx_free);
  ctx->client = r_http_client_ref (client);
  ctx->req = r_http_request_ref (req);
  ctx->bodytype = R_HTTP_BODY_PARSE_SIZED;
  ctx->cb = cb;
  ctx->data = data;
  ctx->notify = notify;
  return ctx;
}

/* TRUE if the request URI's scheme is https (selects TLS termination). */
static rboolean
r_http_request_uri_is_https (RHttpRequest * req)
{
  RUri * uri;
  rchar * scheme;
  rboolean tls = FALSE;

  if ((uri = r_http_request_get_uri (req)) != NULL) {
    if ((scheme = r_uri_get_scheme (uri)) != NULL) {
      tls = (r_strcasecmp (scheme, "https") == 0);
      r_free (scheme);
    }
    r_uri_unref (uri);
  }
  return tls;
}

rboolean
r_http_client_request_to_addr (RHttpClient * client, RHttpRequest * req,
    const RSocketAddress * addr,
    RHttpClientResponseFunc cb, rpointer data, RDestroyNotify notify)
{
  RHttpClientReqCtx * ctx;

  if (R_UNLIKELY (client == NULL || req == NULL || addr == NULL || cb == NULL))
    return FALSE;

  if ((ctx = r_http_client_req_ctx_new (client, req, cb, data, notify)) == NULL)
    return FALSE;
  ctx->tls = r_http_request_uri_is_https (req);
  if ((ctx->dest = r_socket_address_copy (addr)) == NULL) {
    ctx->cb = NULL;     /* not committed: notify must not run */
    ctx->notify = NULL;
    r_ref_unref (ctx);
    return FALSE;
  }

  /* Committed: the array owns ctx and every outcome is delivered via cb. */
  r_ptr_array_add (client->reqs, ctx, r_ref_unref);
  R_LOG_TRACE ("%p: request %p started", client, ctx);
  r_http_client_req_dispatch (ctx, FALSE);

  return TRUE;
}

/* DNS resolution completed: reuse a pooled connection for, or connect to, the
 * first resolved address. ctx is borrowed -- it stays alive in client->reqs
 * for the duration of the resolution (nothing else can tear it down first). */
static void
r_http_client_req_resolved (rpointer data, RResolvedAddr * addr,
    RResolveResult res)
{
  RHttpClientReqCtx * ctx = data;

  if (ctx->finished)
    return;

  if (res != R_RESOLVE_OK || addr == NULL || addr->addr == NULL) {
    R_LOG_DEBUG ("%p: request %p resolve failed (%d)", ctx->client, ctx, (int) res);
    r_http_client_req_complete (ctx, R_HTTP_CLIENT_RESOLVE_FAILED, TRUE);
    return;
  }

  if ((ctx->dest = r_socket_address_copy (addr->addr)) == NULL) {
    r_http_client_req_complete (ctx, R_HTTP_CLIENT_RESOLVE_FAILED, TRUE);
    return;
  }
  r_http_client_req_dispatch (ctx, TRUE);
}

rboolean
r_http_client_request (RHttpClient * client, RHttpRequest * req,
    RHttpClientResponseFunc cb, rpointer data, RDestroyNotify notify)
{
  RHttpClientReqCtx * ctx;
  RUri * uri;
  rchar * host, * scheme;
  ruint16 port;
  rboolean tls;
  rchar service[8];
  RResolveHints hints = { R_SOCKET_FAMILY_NONE, R_SOCKET_TYPE_STREAM,
      R_SOCKET_PROTOCOL_DEFAULT };
  REvResolve * resolve;

  if (R_UNLIKELY (client == NULL || req == NULL || cb == NULL))
    return FALSE;
  if (R_UNLIKELY ((uri = r_http_request_get_uri (req)) == NULL))
    return FALSE;

  host = r_uri_get_hostname (uri);
  scheme = r_uri_get_scheme (uri);
  port = r_uri_get_port (uri);
  r_uri_unref (uri);

  /* http and https are supported; fall back to the scheme's default port. */
  tls = (scheme != NULL && r_strcasecmp (scheme, "https") == 0);
  if (port == 0 && scheme != NULL) {
    if (tls)
      port = 443;
    else if (r_strcasecmp (scheme, "http") == 0)
      port = 80;
  }
  r_free (scheme);
  if (R_UNLIKELY (host == NULL || port == 0)) {
    r_free (host);
    return FALSE;
  }
  r_snprintf (service, sizeof (service), "%u", (ruint) port);

  if ((ctx = r_http_client_req_ctx_new (client, req, cb, data, notify)) == NULL) {
    r_free (host);
    return FALSE;
  }
  ctx->tls = tls;

  /* Committed: the array owns ctx and every outcome is delivered via cb. */
  r_ptr_array_add (client->reqs, ctx, r_ref_unref);

  R_LOG_TRACE ("%p: request %p resolving %s:%s", client, ctx, host, service);
  resolve = r_ev_resolve_addr_new (host, service, 0, &hints, client->loop,
      r_http_client_req_resolved, ctx, NULL);
  r_free (host);
  if (R_UNLIKELY (resolve == NULL)) {
    r_http_client_req_complete (ctx, R_HTTP_CLIENT_RESOLVE_FAILED, FALSE);
    return TRUE;
  }
  /* The queued task keeps the resolve alive until the callback fires; we
   * don't retain the handle (the request can't be cancelled mid-resolve). */
  r_ev_resolve_unref (resolve);

  return TRUE;
}



static void
r_http_client_free (RHttpClient * client)
{
  /* A request context holds a reference on the client, so the client can only
   * be freed once every request has finished and left client->reqs. Pooled
   * connections are owned by client->idle; unref'ing it closes each one
   * (conn_free, synchronous close -- we are not inside an io callback here). */
  r_ptr_array_unref (client->idle);
  r_ptr_array_unref (client->reqs);
  if (client->prng != NULL)
    r_prng_unref (client->prng);
  if (client->trust != NULL)
    r_trust_store_unref (client->trust);
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
    ret->idle = r_ptr_array_new ();
    ret->keepalive = TRUE;
    ret->idle_timeout = R_HTTP_CLIENT_IDLE_TIMEOUT;
    ret->prng = NULL;
    ret->trust = NULL;
    ret->insecure = FALSE;

    R_LOG_INFO ("New HTTP client %p", ret);
  } else {
    r_ev_loop_unref (loop);
  }

  return ret;
}

void
r_http_client_set_keepalive (RHttpClient * client, rboolean enabled)
{
  if (R_UNLIKELY (client == NULL)) return;
  client->keepalive = enabled;
}

rboolean
r_http_client_get_keepalive (RHttpClient * client)
{
  return client != NULL ? client->keepalive : FALSE;
}

void
r_http_client_set_idle_timeout (RHttpClient * client, RClockTimeDiff timeout)
{
  if (R_UNLIKELY (client == NULL)) return;
  client->idle_timeout = timeout;
}

RClockTimeDiff
r_http_client_get_idle_timeout (RHttpClient * client)
{
  return client != NULL ? client->idle_timeout : 0;
}

void
r_http_client_set_trust_store (RHttpClient * client, RTrustStore * store)
{
  if (R_UNLIKELY (client == NULL)) return;
  if (store != NULL)
    r_trust_store_ref (store);
  if (client->trust != NULL)
    r_trust_store_unref (client->trust);
  client->trust = store;
}

void
r_http_client_set_insecure (RHttpClient * client, rboolean insecure)
{
  if (R_UNLIKELY (client == NULL)) return;
  client->insecure = insecure;
}

rboolean
r_http_client_get_insecure (RHttpClient * client)
{
  return client != NULL ? client->insecure : FALSE;
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

void
r_http_client_sync_set_keepalive (RHttpClientSync * sync, rboolean enabled)
{
  if (R_UNLIKELY (sync == NULL)) return;
  r_http_client_set_keepalive (sync->client, enabled);
}

rboolean
r_http_client_sync_get_keepalive (RHttpClientSync * sync)
{
  return sync != NULL ? r_http_client_get_keepalive (sync->client) : FALSE;
}

void
r_http_client_sync_set_idle_timeout (RHttpClientSync * sync, RClockTimeDiff timeout)
{
  if (R_UNLIKELY (sync == NULL)) return;
  r_http_client_set_idle_timeout (sync->client, timeout);
}

RClockTimeDiff
r_http_client_sync_get_idle_timeout (RHttpClientSync * sync)
{
  return sync != NULL ? r_http_client_get_idle_timeout (sync->client) : 0;
}

void
r_http_client_sync_set_trust_store (RHttpClientSync * sync, RTrustStore * store)
{
  if (R_UNLIKELY (sync == NULL)) return;
  r_http_client_set_trust_store (sync->client, store);
}

void
r_http_client_sync_set_insecure (RHttpClientSync * sync, rboolean insecure)
{
  if (R_UNLIKELY (sync == NULL)) return;
  r_http_client_set_insecure (sync->client, insecure);
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
}

RHttpResponse *
r_http_client_sync_request_to_addr (RHttpClientSync * sync, RHttpRequest * req,
    const RSocketAddress * addr, RHttpClientResult * result)
{
  RHttpClientSyncState state = { NULL, R_HTTP_CLIENT_CONNECT_FAILED, FALSE };

  if (R_UNLIKELY (sync == NULL) ||
      !r_http_client_request_to_addr (sync->client, req, addr,
          r_http_client_sync_cb, &state, NULL)) {
    if (result != NULL)
      *result = R_HTTP_CLIENT_CONNECT_FAILED;
    return NULL;
  }

  /* Drive the private loop a round at a time until the exchange completes; the
   * loop is not "stopped" (that is sticky), so it stays reusable for the next
   * request on this client. */
  while (!state.done)
    r_ev_loop_run (sync->loop, R_EV_LOOP_RUN_ONCE);

  if (result != NULL)
    *result = state.result;
  return state.res;
}

RHttpResponse *
r_http_client_sync_request (RHttpClientSync * sync, RHttpRequest * req,
    RHttpClientResult * result)
{
  RHttpClientSyncState state = { NULL, R_HTTP_CLIENT_RESOLVE_FAILED, FALSE };

  if (R_UNLIKELY (sync == NULL) ||
      !r_http_client_request (sync->client, req,
          r_http_client_sync_cb, &state, NULL)) {
    if (result != NULL)
      *result = R_HTTP_CLIENT_RESOLVE_FAILED;
    return NULL;
  }

  while (!state.done)
    r_ev_loop_run (sync->loop, R_EV_LOOP_RUN_ONCE);

  if (result != NULL)
    *result = state.result;
  return state.res;
}
