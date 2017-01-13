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
#include <rlib/net/rsrtp.h>

#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rmac.h>

#include <rlib/rbitset.h>
#include <rlib/rhashtable.h>
#include <rlib/rlist.h>
#include <rlib/rmem.h>

#define R_SRTP_MAX_SALT_SIZE      16
#define R_SRTP_WINDOW_SIZE        1024
#define R_SRTCP_E_BIT             0x80000000

#define R_SRTP_ERRRET(errval, lbl)            \
  R_STMT_START {                              \
    err = errval;                             \
    goto lbl;                                 \
  } R_STMT_END

typedef enum {
  R_SRTP_KDPRF_LABEL_RTP_ENCRYPTION           = 0x00,
  R_SRTP_KDPRF_LABEL_RTP_MSG_AUTH             = 0x01,
  R_SRTP_KDPRF_LABEL_RTP_SALT                 = 0x02,
  R_SRTP_KDPRF_LABEL_RTCP_ENCRYPTION          = 0x03,
  R_SRTP_KDPRF_LABEL_RTCP_MSG_AUTH            = 0x04,
  R_SRTP_KDPRF_LABEL_RTCP_SALT                = 0x05,
  R_SRTP_KDPRF_LABEL_RTP_HEADER_ENCRYPTION    = 0x06,
  R_SRTP_KDPRF_LABEL_RTP_HEADER_SALT          = 0x07
} RSRTPKeyDerivationPRFLabel;

typedef enum {
  R_SRTP_DIRECTION_UNKNOWN      = 0,
  R_SRTP_DIRECTION_INBOUND,
  R_SRTP_DIRECTION_OUTBOUND,
} RSRTPDirection;

typedef struct {
  const RSRTPCipherSuiteInfo * csinfo;
  ruint32 ssrc;
  ruint32 filter;
  ruint8 key[0];
} RSRTPCryptoCtx;

typedef struct {
  ruint64 index;
  RBitset * window;
  RCryptoCipher * cipher;
  RHmac * mac;
  ruint8 salt[R_SRTP_MAX_SALT_SIZE];
  rsize saltsize;
} RSRTPState;

typedef struct {
  ruint32 ssrc;
  const RSRTPCryptoCtx * cctx;
  RSRTPDirection dir;
  ruint8 rtpmkisize;

  RSRTPState rtp;
  RSRTPState rtcp;

  /* FIXME: EKT? */
  /* FIXME: extended header crypto */
} RSRTPStream;

struct _RSRTPCtx {
  RRef ref;

  RList * crypto_filter;
  RHashTable * crypto_ssrc;

  RHashTable * streams;
};

#define R_LOG_CAT_DEFAULT &srtpcat
R_LOG_CATEGORY_DEFINE_STATIC (srtpcat, "srtp", "RLib SRTP",
    R_CLR_FG_MAGENTA | R_CLR_BG_YELLOW | R_CLR_FMT_BOLD);

void
r_srtp_init (void)
{
  r_log_category_register (&srtpcat);
}

static RCryptoCipherResult
r_srtp_kdprf_generate (ruint8 * buf, rsize bufsize,
    const RCryptoCipher * cipher, RSRTPKeyDerivationPRFLabel lbl,
    ruint64 index, ruint kdr, const ruint8 * salt, rsize saltsize)
{
  ruint8 * iv = r_alloca (cipher->info->ivsize);

  r_memcpy (iv, salt, saltsize);
  iv[saltsize - 7] ^= (ruint8)lbl;

  if (kdr > 0) index %= kdr;
  if (index != 0) {
    iv[saltsize - 6] ^= ((index >> 40) & 0xff);
    iv[saltsize - 5] ^= ((index >> 32) & 0xff);
    iv[saltsize - 4] ^= ((index >> 24) & 0xff);
    iv[saltsize - 3] ^= ((index >> 16) & 0xff);
    iv[saltsize - 2] ^= ((index >>  8) & 0xff);
    iv[saltsize - 1] ^= ((index      ) & 0xff);
  }

  r_memclear (iv + saltsize, cipher->info->ivsize - saltsize);
  r_memclear (buf, bufsize);
  return r_crypto_cipher_encrypt (cipher, buf, bufsize, buf,
      iv, cipher->info->ivsize);
}

static RCryptoCipherResult
r_srtp_state_init (RSRTPState * state, ruint lbloffset,
    const RCryptoCipher * kdprf, ruint kdr, const RSRTPCipherSuiteInfo * csinfo,
    const ruint8 * salt, rsize saltsize)
{
  RCryptoCipherResult ret;
  ruint8 scratch[64];

  if (state->cipher != NULL) {
    r_crypto_cipher_unref (state->cipher);
    state->cipher = NULL;
  }
  if (state->mac != NULL) {
    r_hmac_free (state->mac);
    state->mac = NULL;
  }

  /* Session salt */
  if (R_LIKELY ((state->saltsize = saltsize) > 0)) {
    if ((ret = r_srtp_kdprf_generate (state->salt, saltsize, kdprf,
            lbloffset + R_SRTP_KDPRF_LABEL_RTP_SALT, state->index, kdr,
            salt, saltsize)) != R_CRYPTO_CIPHER_OK)
      return ret;
  }

  /* Session encryption key and session auth key */
  if ((ret = r_srtp_kdprf_generate (scratch, csinfo->cipher->keybits / 8, kdprf,
      lbloffset + R_SRTP_KDPRF_LABEL_RTP_ENCRYPTION, state->index, kdr,
      salt, saltsize)) == R_CRYPTO_CIPHER_OK) {
    rsize authsize = r_hash_type_size (csinfo->auth);
    if ((state->cipher = r_crypto_cipher_new (csinfo->cipher, scratch)) == NULL) {
      ret = R_CRYPTO_CIPHER_OOM;
    } else if ((ret = r_srtp_kdprf_generate (scratch, authsize, kdprf,
            lbloffset + R_SRTP_KDPRF_LABEL_RTP_MSG_AUTH, state->index, kdr,
            salt, saltsize)) == R_CRYPTO_CIPHER_OK) {
      if ((state->mac = r_hmac_new (csinfo->auth, scratch, authsize)) == NULL)
        ret = R_CRYPTO_CIPHER_OOM;
    } else {
      r_crypto_cipher_unref (state->cipher);
      state->cipher = NULL;
    }
  }

  /* Be nice and clear secrets on stack */
  r_memclear (scratch, sizeof (scratch));
  return ret;
}

static void
r_srtp_state_clear (RSRTPState * state)
{
  if (state->cipher)
    r_crypto_cipher_unref (state->cipher);
  r_hmac_free (state->mac);
  r_free (state->window);
}

static void
r_srtp_stream_free (RSRTPStream * stream)
{
  r_srtp_state_clear (&stream->rtcp);
  r_srtp_state_clear (&stream->rtp);
  r_free (stream);
}

static RSRTPStream *
r_srtp_stream_new (ruint32 ssrc, const RSRTPCryptoCtx * cctx)
{
  RSRTPStream * ret;
  RCryptoCipher * kdcipher;

  if (R_UNLIKELY ((kdcipher = r_crypto_cipher_new (cctx->csinfo->kdprf,
            cctx->key)) == NULL)) {
    R_LOG_WARNING ("Unable to create key derivation PRF cipher");
    return NULL;
  }

  if ((ret = r_mem_new0 (RSRTPStream)) != NULL) {
    RCryptoCipherResult res;
    rsize keysize = cctx->csinfo->cipher->keybits / 8;
    rsize saltsize = cctx->csinfo->saltbits / 8;

    ret->ssrc = ssrc;
    ret->cctx = cctx;
    r_bitset_init_heap (ret->rtp.window, R_SRTP_WINDOW_SIZE);
    r_bitset_init_heap (ret->rtcp.window, R_SRTP_WINDOW_SIZE);

    if (R_UNLIKELY ((res = r_srtp_state_init (&ret->rtp,
              R_SRTP_KDPRF_LABEL_RTP_ENCRYPTION, kdcipher, 0, cctx->csinfo,
              cctx->key + keysize, saltsize)) != R_CRYPTO_CIPHER_OK)) {
      R_LOG_WARNING ("stream: 0x%.8x - RTP crypto init failed %d", ssrc, res);
      r_srtp_stream_free (ret);
      ret = NULL;
    } else if (R_UNLIKELY ((res = r_srtp_state_init (&ret->rtcp,
              R_SRTP_KDPRF_LABEL_RTCP_ENCRYPTION, kdcipher, 0, cctx->csinfo,
              cctx->key + keysize, saltsize)) != R_CRYPTO_CIPHER_OK)) {
      R_LOG_WARNING ("stream: 0x%.8x - RTCP crypto init failed %d", ssrc, res);
      r_srtp_stream_free (ret);
      ret = NULL;
    } else {
      R_LOG_DEBUG ("stream: 0x%.8x - %p", ssrc, ret);
    }
  }

  r_crypto_cipher_unref (kdcipher);
  return ret;
}

static void
r_srtp_ctx_free (RSRTPCtx * ctx)
{
  r_list_destroy_full (ctx->crypto_filter, r_free);
  r_hash_table_unref (ctx->crypto_ssrc);
  r_hash_table_unref (ctx->streams);
  r_free (ctx);
}

RSRTPCtx *
r_srtp_ctx_new (void)
{
  RSRTPCtx * ret;

  if ((ret = r_mem_new (RSRTPCtx)) != NULL) {
    r_ref_init (ret, r_srtp_ctx_free);

    ret->crypto_filter = NULL;
    ret->crypto_ssrc = r_hash_table_new_full (NULL, NULL, NULL, r_free);
    ret->streams = r_hash_table_new_full (NULL, NULL,
        NULL, (RDestroyNotify) r_srtp_stream_free);
  }

  R_LOG_DEBUG ("ctx %p", ret);
  return ret;
}

RSRTPError
r_srtp_add_crypto_context_for_ssrc (RSRTPCtx * ctx,
    ruint32 ssrc, RSRTPCipherSuite cs, const ruint8 * key)
{
  const RSRTPCipherSuiteInfo * info;
  RSRTPCryptoCtx * cctx;
  rsize keysize;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (key == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((info = r_srtp_cipher_suite_get_info (cs)) == NULL))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (r_hash_table_contains (ctx->crypto_ssrc,
          RUINT_TO_POINTER (ssrc)) == R_HASH_TABLE_OK))
    return R_SRTP_ERROR_CRYPTO_CTX_EXISTS;

  keysize = (info->cipher->keybits + info->saltbits) / 8;
  if ((cctx = r_malloc (sizeof (RSRTPCryptoCtx) + keysize)) != NULL) {
    cctx->csinfo = info;
    cctx->ssrc = ssrc;
    cctx->filter = 0;
    r_memcpy (cctx->key, key, keysize);

    r_hash_table_insert (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc), cctx);
    R_LOG_TRACE ("ctx: %p ssrc: 0x%.8x crypto: %s", ctx, ssrc, info->str);
    return R_SRTP_ERROR_OK;
  }

  return R_SRTP_ERROR_OOM;
}

RSRTPError
r_srtp_add_crypto_context_with_filter (RSRTPCtx * ctx,
    ruint32 filter, RSRTPCipherSuite cs, const ruint8 * key)
{
  const RSRTPCipherSuiteInfo * info;
  RSRTPCryptoCtx * cctx;
  rsize keysize;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (filter == 0)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (key == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((info = r_srtp_cipher_suite_get_info (cs)) == NULL))
    return R_SRTP_ERROR_INVAL;

  keysize = (info->cipher->keybits + info->saltbits) / 8;
  if ((cctx = r_malloc (sizeof (RSRTPCryptoCtx) + keysize)) != NULL) {
    cctx->csinfo = info;
    cctx->ssrc = 0;
    cctx->filter = filter;
    r_memcpy (cctx->key, key, keysize);

    ctx->crypto_filter = r_list_prepend (ctx->crypto_filter, cctx);
    R_LOG_TRACE ("ctx: %p filter: 0x%.8x crypto: %s", ctx, filter, info->str);
    return R_SRTP_ERROR_OK;
  }

  return R_SRTP_ERROR_OOM;
}

static const RSRTPCryptoCtx *
r_srtp_lookup_crypto_ctx (RSRTPCtx * ctx, ruint32 ssrc)
{
  const RSRTPCryptoCtx * ret;
  RList * it;

  if ((ret = r_hash_table_lookup (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc))) != NULL)
    return ret;

  for (it = ctx->crypto_filter; it != NULL; it = r_list_next (it)) {
    RSRTPCryptoCtx * cctx = r_list_data (it);
    if ((cctx->filter & ssrc) == ssrc) {
      ret = cctx;
      break;
    }
  }

  return ret;
}

static RSRTPStream *
r_srtp_get_stream (RSRTPCtx * ctx, ruint32 ssrc)
{
  RSRTPStream * ret;
  const RSRTPCryptoCtx * cctx;

  if ((ret = r_hash_table_lookup (ctx->streams, RUINT_TO_POINTER (ssrc))) != NULL)
    return ret;

  if ((cctx = r_srtp_lookup_crypto_ctx (ctx, ssrc)) != NULL) {
    if ((ret = r_srtp_stream_new (ssrc, cctx)) != NULL)
      r_hash_table_insert (ctx->streams, RUINT_TO_POINTER (ssrc), ret);
  }

  return ret;
}

static RSRTPError
r_srtp_stream_replay_check (RSRTPState * s, ruint64 idx, ruint32 ssrc)
{
  R_LOG_TRACE ("stream: 0x%.8x: cur 0x%"R_RTP_SEQIDX_FMT" est 0x%"R_RTP_SEQIDX_FMT,
      ssrc, s->index, idx);

  if (idx <= s->index) {
    if (idx + s->window->bsize < s->index) {
      R_LOG_INFO ("stream: 0x%.8x: est 0x%"R_RTP_SEQIDX_FMT" is too old"
          " (cur 0x%"R_RTP_SEQIDX_FMT")",
          ssrc, s->index, idx);
      return R_SRTP_ERROR_REPLAY_TOO_OLD;
    } else if (r_bitset_is_bit_set (s->window, s->index - idx)) {
      R_LOG_INFO ("stream: 0x%.8x: est 0x%"R_RTP_SEQIDX_FMT" already received",
          ssrc, idx);
      return R_SRTP_ERROR_REPLAYED;
    }
  }

  return R_SRTP_ERROR_OK;
}

static RSRTPError
r_srtp_stream_rtp_replay_add (RSRTPState * s, ruint64 idx)
{
  if (idx > s->index) {
    r_bitset_shl (s->window, idx - s->index);
    r_bitset_set_bit (s->window, 0, TRUE);
    s->index = idx;
  } else {
    r_bitset_set_bit (s->window, s->index - idx, TRUE);
  }

  return R_SRTP_ERROR_OK;
}

static inline void
r_srtp_state_create_iv (ruint8 * iv, rsize ivsize, const RSRTPState * state,
    ruint32 ssrc, ruint64 idx)
{
  r_memcpy (iv + ivsize - (sizeof (ruint16) + state->saltsize),
      state->salt, state->saltsize);
  iv[ivsize - (sizeof (ruint16) + 10)] ^= ((ssrc >> 24) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  9)] ^= ((ssrc >> 16) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  8)] ^= ((ssrc >>  8) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  7)] ^= ((ssrc      ) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  6)] ^= ((idx >> 40) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  5)] ^= ((idx >> 32) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  4)] ^= ((idx >> 24) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  3)] ^= ((idx >> 16) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  2)] ^= ((idx >>  8) & 0xff);
  iv[ivsize - (sizeof (ruint16) +  1)] ^= ((idx      ) & 0xff);
}

RBuffer *
r_srtp_encrypt_rtp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * errout)
{
  RSRTPError err;
  RBuffer * ret = NULL;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;

  if (R_UNLIKELY (ctx == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
  if (R_UNLIKELY (packet == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);

  if (r_rtp_buffer_map (&rtp, packet, R_MEM_MAP_READ)) {
    RSRTPStream * stream;

    if ((stream = r_srtp_get_stream (ctx, r_rtp_buffer_get_ssrc (&rtp))) != NULL) {
      ruint64 idx;

      if (R_UNLIKELY (stream->dir != R_SRTP_DIRECTION_OUTBOUND)) {
        if (stream->dir == R_SRTP_DIRECTION_UNKNOWN) {
          stream->dir = R_SRTP_DIRECTION_OUTBOUND;
        } else {
          R_LOG_INFO ("ssrc (0x%.8x) collision?", stream->ssrc);
          err = R_SRTP_ERROR_WRONG_DIRECTION;
          goto beach_map;
        }
      }

      idx = r_rtp_buffer_estimate_seq_idx (&rtp, stream->rtp.index);
      if ((err = r_srtp_stream_replay_check (&stream->rtp, idx, stream->ssrc)) == R_SRTP_ERROR_OK) {
        rsize tagsize = stream->cctx->csinfo->srtp_tagbits / 8;
        rsize payloadsize = rtp.pay.size + tagsize + stream->rtpmkisize;
        RBuffer * payload;

        r_srtp_stream_rtp_replay_add (&stream->rtp, idx);

        if (stream->cctx->csinfo->authprefixlen > 0) {
          /* FIXME: Handle keystream prefix */
          R_LOG_ERROR ("SRTP Auth prefix not implmented yet...");
          err = R_SRTP_ERROR_INTERNAL;
          goto beach_map;
        }

        if ((payload = r_buffer_new_alloc (NULL, payloadsize, NULL)) != NULL) {
          RMemMapInfo info = R_MEM_MAP_INFO_INIT;

          if (r_buffer_map (payload, &info, R_MEM_MAP_WRITE)) {
            rsize ivsize = stream->rtp.cipher->info->ivsize;
            ruint8 * iv = r_alloca0 (ivsize);

            r_srtp_state_create_iv (iv, ivsize, &stream->rtp, stream->ssrc, idx);

            R_LOG_TRACE ("Encrypting %u bytes", (ruint)rtp.pay.size);
            r_crypto_cipher_encrypt (stream->rtp.cipher, info.data, rtp.pay.size,
                rtp.pay.data, iv, ivsize);

            if (stream->rtpmkisize > 0) {
              /* FIXME: insert mki */
            }

            /* add auth tag */
            if (stream->rtp.mac != NULL && tagsize > 0) {
              ruint32 roc = RUINT32_TO_BE ((ruint32)(idx >> 16));

              r_hmac_reset (stream->rtp.mac);
              if (r_hmac_update (stream->rtp.mac, rtp.hdr.data, rtp.hdr.size) &&
                  (rtp.ext.data == NULL ||
                   r_hmac_update (stream->rtp.mac, rtp.ext.data, rtp.ext.size)) &&
                  r_hmac_update (stream->rtp.mac, info.data, rtp.pay.size) &&
                  r_hmac_update (stream->rtp.mac, &roc, sizeof (ruint32))) {
                ruint8 calctag[32];
                rsize calcsize = sizeof (calctag);

                r_hmac_get_data (stream->rtp.mac, calctag, &calcsize);
                r_memcpy (info.data + payloadsize - tagsize, calctag, tagsize);
              } else {
                R_LOG_ERROR ("HMAC update for SRTP auth failed");
                err = R_SRTP_ERROR_INTERNAL;
                goto beach_map;
              }
            }

            r_buffer_unmap (payload, &info);

            if (R_UNLIKELY ((ret = r_buffer_replace_byte_range (packet,
                rtp.hdr.size + rtp.ext.size, -1, payload)) == NULL)) {
              err = R_SRTP_ERROR_INTERNAL;
            }
          } else {
            err = R_SRTP_ERROR_INTERNAL;
          }
          r_buffer_unref (payload);
        } else {
          err = R_SRTP_ERROR_OOM;
        }
      }
    } else {
      err = R_SRTP_ERROR_NO_CRYPTO_CTX;
    }

beach_map:
    r_rtp_buffer_unmap (&rtp, packet);
  } else {
    err = R_SRTP_ERROR_BAD_RTP_HDR;
  }

beach:
  if (errout != NULL)
    *errout = err;
  return ret;
}

RBuffer *
r_srtp_decrypt_rtp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * errout)
{
  RSRTPError err;
  RBuffer * ret = NULL;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;

  if (R_UNLIKELY (ctx == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
  if (R_UNLIKELY (packet == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);

  if (r_rtp_buffer_map (&rtp, packet, R_MEM_MAP_READ)) {
    RSRTPStream * stream;

    if ((stream = r_srtp_get_stream (ctx, r_rtp_buffer_get_ssrc (&rtp))) != NULL) {
      ruint64 idx;

      if (R_UNLIKELY (stream->dir != R_SRTP_DIRECTION_INBOUND)) {
        if (stream->dir == R_SRTP_DIRECTION_UNKNOWN) {
          stream->dir = R_SRTP_DIRECTION_INBOUND;
        } else {
          R_LOG_INFO ("ssrc (0x%.8x) collision?", stream->ssrc);
          err = R_SRTP_ERROR_WRONG_DIRECTION;
          goto beach_map;
        }
      }

      idx = r_rtp_buffer_estimate_seq_idx (&rtp, stream->rtp.index);
      if ((err = r_srtp_stream_replay_check (&stream->rtp, idx, stream->ssrc)) == R_SRTP_ERROR_OK) {
        rsize tagsize = stream->cctx->csinfo->srtp_tagbits / 8;
        rsize payloadsize = rtp.pay.size - tagsize - stream->rtpmkisize;
        RBuffer * payload;

        if (stream->cctx->csinfo->authprefixlen > 0) {
          /* FIXME: Handle keystream prefix */
          R_LOG_ERROR ("SRTP Auth prefix not implmented yet...");
          err = R_SRTP_ERROR_INTERNAL;
          goto beach_map;
        }

        if (stream->rtp.mac != NULL && tagsize > 0) {
          ruint8 * authtag = rtp.pay.data + rtp.pay.size - tagsize;
          ruint8 calctag[32];
          rsize calcsize = sizeof (calctag);
          ruint32 roc = RUINT32_TO_BE ((ruint32)(idx >> 16));

          r_hmac_reset (stream->rtp.mac);
          if (r_hmac_update (stream->rtp.mac, rtp.hdr.data, rtp.hdr.size) &&
              (rtp.ext.data == NULL ||
               r_hmac_update (stream->rtp.mac, rtp.ext.data, rtp.ext.size)) &&
              r_hmac_update (stream->rtp.mac, rtp.pay.data, payloadsize) &&
              r_hmac_update (stream->rtp.mac, &roc, sizeof (ruint32)) &&
              r_hmac_get_data (stream->rtp.mac, calctag, &calcsize)) {
            if (R_UNLIKELY (r_memcmp (authtag, calctag, tagsize) != 0)) {
              R_LOG_INFO ("stream: 0x%.8x - SRTP auth failed for idx 0x%"R_RTP_SEQIDX_FMT,
                  stream->ssrc, idx);
              err = R_SRTP_ERROR_AUTH;
              goto beach_map;
            }
          } else {
            R_LOG_ERROR ("HMAC update for SRTP auth failed");
            err = R_SRTP_ERROR_INTERNAL;
            goto beach_map;
          }
        }

        if ((payload = r_buffer_new_alloc (NULL, payloadsize, NULL)) != NULL) {
          RMemMapInfo info = R_MEM_MAP_INFO_INIT;

          if (r_buffer_map (payload, &info, R_MEM_MAP_WRITE)) {
            rsize ivsize = stream->rtp.cipher->info->ivsize;
            ruint8 * iv = r_alloca0 (ivsize);

            r_srtp_state_create_iv (iv, ivsize, &stream->rtp, stream->ssrc, idx);

            R_LOG_TRACE ("Decrypting %u bytes", (ruint)info.size);
            r_crypto_cipher_decrypt (stream->rtp.cipher, info.data, info.size,
                rtp.pay.data, iv, ivsize);
            r_buffer_unmap (payload, &info);

            if (R_UNLIKELY ((ret = r_buffer_replace_byte_range (packet,
                rtp.hdr.size + rtp.ext.size, -1, payload)) == NULL)) {
              err = R_SRTP_ERROR_INTERNAL;
            }
          } else {
            err = R_SRTP_ERROR_INTERNAL;
          }
          r_buffer_unref (payload);
        } else {
          err = R_SRTP_ERROR_OOM;
        }

        r_srtp_stream_rtp_replay_add (&stream->rtp, idx);
      }
    } else {
      err = R_SRTP_ERROR_NO_CRYPTO_CTX;
    }

beach_map:
    r_rtp_buffer_unmap (&rtp, packet);
  } else {
    err = R_SRTP_ERROR_BAD_RTP_HDR;
  }

beach:
  if (errout != NULL)
    *errout = err;
  return ret;
}

RBuffer *
r_srtp_encrypt_rtcp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * errout)
{
  RSRTPError err;
  RBuffer * ret = NULL;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;

  if (R_UNLIKELY (ctx == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
  if (R_UNLIKELY (packet == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);

  if (r_rtcp_buffer_map (&rtcp, packet, R_MEM_MAP_READ)) {
    RRTCPPacket * rtcppacket;
    RSRTPStream * stream;

    if ((rtcppacket = r_rtcp_buffer_get_first_packet (&rtcp)) != NULL &&
        (stream = r_srtp_get_stream (ctx, r_rtcp_packet_get_ssrc (rtcppacket))) != NULL) {
      rsize tagsize, newsize;
      ruint32 idx;

      if (R_UNLIKELY (stream->dir != R_SRTP_DIRECTION_OUTBOUND)) {
        if (stream->dir == R_SRTP_DIRECTION_UNKNOWN) {
          stream->dir = R_SRTP_DIRECTION_OUTBOUND;
        } else {
          R_LOG_INFO ("ssrc (0x%.8x) collision?", stream->ssrc);
          err = R_SRTP_ERROR_WRONG_DIRECTION;
          goto beach_map;
        }
      }

      if ((idx = (ruint32)++stream->rtcp.index) >= R_SRTCP_E_BIT) {
        R_LOG_INFO ("ssrc (0x%.8x) collision?", stream->ssrc);
        err = R_SRTP_ERROR_WRONG_DIRECTION;
        goto beach_map;
      }

      if (stream->cctx->csinfo->authprefixlen > 0) {
        /* FIXME: Handle keystream prefix */
        R_LOG_ERROR ("SRTP Auth prefix not implmented yet...");
        err = R_SRTP_ERROR_INTERNAL;
        goto beach_map;
      }

      tagsize = stream->cctx->csinfo->srtp_tagbits / 8;
      newsize = rtcp.info.size + sizeof (ruint32) + tagsize + stream->rtpmkisize;
      if ((ret = r_buffer_new_alloc (NULL, newsize, NULL)) != NULL) {
        RMemMapInfo info = R_MEM_MAP_INFO_INIT;

        if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
          rsize ivsize = stream->rtcp.cipher->info->ivsize;
          ruint8 * iv = r_alloca0 (ivsize);
          ruint8 * ptr = info.data;

          r_memcpy (ptr, rtcp.info.data, 2 * sizeof (ruint32));
          ptr += 2 * sizeof (ruint32);

          r_srtp_state_create_iv (iv, ivsize, &stream->rtcp, stream->ssrc, idx);

          R_LOG_TRACE ("Encrypting %u bytes", (ruint)(rtcp.info.size - 2 * sizeof (ruint32)));
          r_crypto_cipher_encrypt (stream->rtcp.cipher, ptr,
              rtcp.info.size - 2 * sizeof (ruint32), rtcp.info.data + 2 * sizeof (ruint32),
              iv, ivsize);
          ptr += rtcp.info.size - 2 * sizeof (ruint32);

          if (stream->rtcp.cipher->info->type > R_CRYPTO_CIPHER_ALGO_NULL)
            *(ruint32 *)ptr = RUINT32_TO_BE ((ruint32)idx | R_SRTCP_E_BIT);
          else
            *(ruint32 *)ptr = RUINT32_TO_BE ((ruint32)idx);
          ptr += sizeof (ruint32);

          if (stream->rtpmkisize > 0) {
            /* FIXME: insert mki */
          }

          /* add auth tag */
          if (stream->rtcp.mac != NULL && tagsize > 0) {
            r_hmac_reset (stream->rtcp.mac);
            if (r_hmac_update (stream->rtcp.mac, info.data,
                  info.size - stream->rtpmkisize - tagsize)) {
              ruint8 calctag[32];
              rsize calcsize = sizeof (calctag);

              r_hmac_get_data (stream->rtcp.mac, calctag, &calcsize);
              r_memcpy (info.data + info.size - tagsize, calctag, tagsize);
            } else {
              R_LOG_ERROR ("HMAC update for SRTP auth failed");
              err = R_SRTP_ERROR_INTERNAL;
              goto beach_map;
            }
          }

          err = R_SRTP_ERROR_OK;
          r_buffer_unmap (ret, &info);
        } else {
          err = R_SRTP_ERROR_INTERNAL;
        }
      } else {
        err = R_SRTP_ERROR_OOM;
      }
    } else {
      err = R_SRTP_ERROR_NO_CRYPTO_CTX;
    }

beach_map:
    r_rtcp_buffer_unmap (&rtcp, packet);
  } else {
    err = R_SRTP_ERROR_BAD_RTP_HDR;
  }

beach:
  if (errout != NULL)
    *errout = err;
  return ret;
}

RBuffer *
r_srtp_decrypt_rtcp (RSRTPCtx * ctx, RBuffer * packet, RSRTPError * errout)
{
  RSRTPError err;
  RBuffer * ret = NULL;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;

  if (R_UNLIKELY (ctx == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
  if (R_UNLIKELY (packet == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);

  if (r_rtcp_buffer_map (&rtcp, packet, R_MEM_MAP_READ)) {
    RRTCPPacket * rtcppacket;
    RSRTPStream * stream;

    if ((rtcppacket = r_rtcp_buffer_get_first_packet (&rtcp)) != NULL &&
        (stream = r_srtp_get_stream (ctx, r_rtcp_packet_get_ssrc (rtcppacket))) != NULL) {
      rsize tagsize = stream->cctx->csinfo->srtp_tagbits / 8;
      const ruint8 * authtag = rtcp.info.data + rtcp.info.size - tagsize;
      const ruint8 * srtpidx = authtag - stream->rtpmkisize - sizeof (ruint32);
      ruint32 idx;

      if (R_UNLIKELY (stream->dir != R_SRTP_DIRECTION_INBOUND)) {
        if (stream->dir == R_SRTP_DIRECTION_UNKNOWN) {
          stream->dir = R_SRTP_DIRECTION_INBOUND;
        } else {
          R_LOG_INFO ("ssrc (0x%.8x) collision?", stream->ssrc);
          err = R_SRTP_ERROR_WRONG_DIRECTION;
          goto beach_map;
        }
      }

      idx = RUINT32_TO_BE (*(const ruint32 *)srtpidx);
      if (idx & R_SRTCP_E_BIT) {
        if (stream->rtcp.cipher->info->type <= R_CRYPTO_CIPHER_ALGO_NULL) {
          R_LOG_INFO ("ssrc (0x%.8x) idx (0x%.8x) SRTCP e-bit mismatch",
              stream->ssrc, idx);
          err = R_SRTP_ERROR_E_BIT_MISMATCH;
          goto beach_map;
        }
        idx &= ~R_SRTCP_E_BIT;
      } else {
        if (stream->rtcp.cipher->info->type > R_CRYPTO_CIPHER_ALGO_NULL) {
          R_LOG_INFO ("ssrc (0x%.8x) idx (0x%.8x) SRTCP e-bit mismatch",
              stream->ssrc, idx);
          err = R_SRTP_ERROR_E_BIT_MISMATCH;
          goto beach_map;
        }
      }

      if ((err = r_srtp_stream_replay_check (&stream->rtcp, idx, stream->ssrc)) == R_SRTP_ERROR_OK) {
        rsize newsize = srtpidx - rtcp.info.data;

        if (stream->cctx->csinfo->authprefixlen > 0) {
          /* FIXME: Handle keystream prefix */
          R_LOG_ERROR ("SRTP Auth prefix not implmented yet...");
          err = R_SRTP_ERROR_INTERNAL;
          goto beach_map;
        }

        if (stream->rtcp.mac != NULL && tagsize > 0) {
          ruint8 calctag[32];
          rsize calcsize = sizeof (calctag);

          r_hmac_reset (stream->rtcp.mac);
          if (r_hmac_update (stream->rtcp.mac, rtcp.info.data, newsize + sizeof (ruint32)) &&
              r_hmac_get_data (stream->rtcp.mac, calctag, &calcsize)) {
            if (R_UNLIKELY (r_memcmp (authtag, calctag, tagsize) != 0)) {
              R_LOG_INFO ("stream: 0x%.8x - SRTP auth failed for idx 0x%"R_RTP_SEQIDX_FMT,
                  stream->ssrc, (ruint64)idx);
              err = R_SRTP_ERROR_AUTH;
              goto beach_map;
            }
          } else {
            R_LOG_ERROR ("HMAC update for SRTP auth failed");
            err = R_SRTP_ERROR_INTERNAL;
            goto beach_map;
          }
        }

        if ((ret = r_buffer_new_alloc (NULL, newsize, NULL)) != NULL) {
          RMemMapInfo info = R_MEM_MAP_INFO_INIT;

          if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
            rsize ivsize = stream->rtcp.cipher->info->ivsize;
            ruint8 * iv = r_alloca0 (ivsize);

            r_srtp_state_create_iv (iv, ivsize, &stream->rtcp, stream->ssrc, idx);

            /* Copy header and ssrc */
            r_memcpy (info.data, rtcp.info.data, 2 * sizeof (ruint32));

            R_LOG_TRACE ("Decrypting %u bytes", (ruint)info.size);
            r_crypto_cipher_decrypt (stream->rtcp.cipher,
                info.data + 2 * sizeof (ruint32), info.size - 2 * sizeof (ruint32),
                rtcp.info.data + 2 * sizeof (ruint32), iv, ivsize);
            r_buffer_unmap (ret, &info);
          } else {
            err = R_SRTP_ERROR_INTERNAL;
          }
        } else {
          err = R_SRTP_ERROR_OOM;
        }

        r_srtp_stream_rtp_replay_add (&stream->rtcp, idx);
      }
    } else {
      err = R_SRTP_ERROR_NO_CRYPTO_CTX;
    }

beach_map:
    r_rtcp_buffer_unmap (&rtcp, packet);
  } else {
    err = R_SRTP_ERROR_BAD_RTP_HDR;
  }

beach:
  if (errout != NULL)
    *errout = err;
  return ret;
}

