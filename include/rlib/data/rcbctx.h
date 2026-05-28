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
#ifndef __R_CBCTX_H__
#define __R_CBCTX_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_cbctx Callback context tuples
 * @ingroup r_data
 *
 * @brief @c (function, data, user, datanotify, usernotify) tuples
 * used by the callback-flavoured lists and queues to store
 * deferred work without losing track of ownership.
 *
 * Two variants are provided: @ref RFuncCallbackCtx for callbacks
 * returning @c void and @ref RFuncReturnCallbackCtx for callbacks
 * returning @c rboolean. The @c r_func_callback_ctx_* / @c
 * r_func_return_callback_ctx_* inline accessors initialise the
 * tuple, invoke its destroy notifiers, and call the wrapped
 * function with the correct argument order.
 *
 * @{
 */

/**
 * @file rlib/data/rcbctx.h
 * @brief Callback + data + user-data + per-side destroy-notify
 * tuples used by @ref r_list, @ref r_queue and
 * @ref r_timeoutcblist to store deferred callbacks.
 */

#include <rlib/rtypes.h>

R_BEGIN_DECLS

/**
 * @brief Callback context for a @c void-returning function.
 *
 * @c data and @c user are passed as the function's two arguments;
 * @c datanotify and @c usernotify (each may be @c NULL) are
 * invoked when the tuple is cleared.
 */
typedef struct {
  RFunc cb;                     /**< Function to call. */
  rpointer data;                /**< First argument (function-side data). */
  RDestroyNotify datanotify;    /**< Destroy notifier for @c data. */
  rpointer user;                /**< Second argument (caller-side cookie). */
  RDestroyNotify usernotify;    /**< Destroy notifier for @c user. */
} RFuncCallbackCtx;

static inline void r_func_callback_ctx_init (RFuncCallbackCtx * ctx,
    RFunc cb, rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify)
{
  ctx->cb = cb;
  ctx->data = data;
  ctx->datanotify = datanotify;
  ctx->user = user;
  ctx->usernotify = usernotify;
}
static inline void r_func_callback_ctx_clear (RFuncCallbackCtx * ctx)
{
  if (ctx->datanotify != NULL)
    ctx->datanotify (ctx->data);
  if (ctx->usernotify != NULL)
    ctx->usernotify (ctx->user);
}
static inline void r_func_callback_ctx_call (RFuncCallbackCtx * ctx)
{
  ctx->cb (ctx->data, ctx->user);
}


/**
 * @brief Callback context for a function that returns @c rboolean.
 *
 * Used by @c RCBRList where the call result drives whether the
 * iteration continues.
 */
typedef struct {
  RFuncReturn cb;               /**< Function to call. */
  rpointer data;                /**< First argument (function-side data). */
  RDestroyNotify datanotify;    /**< Destroy notifier for @c data. */
  rpointer user;                /**< Second argument (caller-side cookie). */
  RDestroyNotify usernotify;    /**< Destroy notifier for @c user. */
} RFuncReturnCallbackCtx;

static inline void r_func_return_callback_ctx_init (RFuncReturnCallbackCtx * ctx,
    RFuncReturn cb, rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify)
{
  ctx->cb = cb;
  ctx->data = data;
  ctx->datanotify = datanotify;
  ctx->user = user;
  ctx->usernotify = usernotify;
}
static inline void r_func_return_callback_ctx_clear (RFuncReturnCallbackCtx * ctx)
{
  if (ctx->datanotify != NULL)
    ctx->datanotify (ctx->data);
  if (ctx->usernotify != NULL)
    ctx->usernotify (ctx->user);
}
static inline rboolean r_func_return_callback_ctx_call (RFuncReturnCallbackCtx * ctx)
{
  return ctx->cb (ctx->data, ctx->user);
}


R_END_DECLS

/** @} */

#endif /* __R_CBCTX_H__ */
