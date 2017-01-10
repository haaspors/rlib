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
#ifndef __R_NET_SRTP_H__
#define __R_NET_SRTP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/crypto/rsrtpciphersuite.h>
#include <rlib/net/proto/rrtp.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>


#define R_SRTP_FILTER_ANY         RUINT32_MAX

R_BEGIN_DECLS

typedef enum {
  R_SRTP_ERROR_OK,
  R_SRTP_ERROR_OOM,
  R_SRTP_ERROR_INVAL,
  R_SRTP_ERROR_INTERNAL,
  R_SRTP_ERROR_NO_CRYPTO_CTX,
  R_SRTP_ERROR_CRYPTO_CTX_EXISTS,
  R_SRTP_ERROR_WRONG_DIRECTION,
  R_SRTP_ERROR_BAD_RTP_HDR,
  R_SRTP_ERROR_BAD_RTCP_HDR,
  R_SRTP_ERROR_REPLAYED,
  R_SRTP_ERROR_REPLAY_TOO_OLD,
  R_SRTP_ERROR_AUTH,
} RSRTPError;

typedef struct _RSRTPCtx RSRTPCtx;

R_API RSRTPCtx * r_srtp_ctx_new (void) R_ATTR_MALLOC;
#define r_srtp_ctx_ref      r_ref_ref
#define r_srtp_ctx_unref    r_ref_unref

R_API RSRTPError r_srtp_add_crypto_context_for_ssrc (RSRTPCtx * ctx,
    ruint32 ssrc, RSRTPCipherSuite cs, const ruint8 * key);
R_API RSRTPError r_srtp_add_crypto_context_with_filter (RSRTPCtx * ctx,
    ruint32 filter, RSRTPCipherSuite cs, const ruint8 * key);

R_API RBuffer * r_srtp_encrypt_rtp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * err) R_ATTR_WARN_UNUSED_RESULT;
R_API RBuffer * r_srtp_decrypt_rtp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * err) R_ATTR_WARN_UNUSED_RESULT;

R_END_DECLS

#endif /* __R_NET_SRTP_H__ */


