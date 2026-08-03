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
#include <rlib/crypto/rhmac.h>

#include <rlib/data/rbitset.h>
#include <rlib/data/rhashtable.h>
#include <rlib/data/rlist.h>

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

  /* RFC 6904 header-extension keystream: derived only when the session
   * encrypts one or more header extensions, NULL otherwise. */
  RCryptoCipher * hdrcipher;
  ruint8 hdrsalt[R_SRTP_MAX_SALT_SIZE];
  rsize hdrsaltsize;

  /* FIXME: EKT? */
} RSRTPStream;

struct RSRTPCtx {
  RRef ref;

  RList * crypto_filter;
  RHashTable * crypto_ssrc;

  RHashTable * streams;

  /* RFC 6904: bit set per RTP header-extension ID that is encrypted, indexed
   * by the ID (1..255). NULL until the first ID is registered. */
  RBitset * hdrext_ids;
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
    rsize authsize = r_msg_digest_type_size (csinfo->auth);
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

/* Derive the RFC 6904 header-extension encryption key (label 0x06) and salt
 * (label 0x07) into @p stream. Unlike a full session state there is no auth
 * key: the header extension is covered by the packet's SRTP auth tag. */
static RCryptoCipherResult
r_srtp_stream_init_hdrext (RSRTPStream * stream, const RCryptoCipher * kdprf,
    const RSRTPCipherSuiteInfo * csinfo, const ruint8 * salt, rsize saltsize)
{
  RCryptoCipherResult ret;
  ruint8 scratch[64];

  if (R_LIKELY ((stream->hdrsaltsize = saltsize) > 0)) {
    if ((ret = r_srtp_kdprf_generate (stream->hdrsalt, saltsize, kdprf,
            R_SRTP_KDPRF_LABEL_RTP_HEADER_SALT, stream->rtp.index, 0,
            salt, saltsize)) != R_CRYPTO_CIPHER_OK)
      return ret;
  }

  if ((ret = r_srtp_kdprf_generate (scratch, csinfo->cipher->keybits / 8, kdprf,
          R_SRTP_KDPRF_LABEL_RTP_HEADER_ENCRYPTION, stream->rtp.index, 0,
          salt, saltsize)) == R_CRYPTO_CIPHER_OK) {
    if ((stream->hdrcipher = r_crypto_cipher_new (csinfo->cipher, scratch)) == NULL)
      ret = R_CRYPTO_CIPHER_OOM;
  }

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
  /* The session salt is key-derived material; don't leave it in freed heap. */
  r_memclear (state->salt, sizeof (state->salt));
}

static void
r_srtp_stream_free (RSRTPStream * stream)
{
  if (stream->hdrcipher != NULL)
    r_crypto_cipher_unref (stream->hdrcipher);
  r_memclear (stream->hdrsalt, sizeof (stream->hdrsalt));
  r_srtp_state_clear (&stream->rtcp);
  r_srtp_state_clear (&stream->rtp);
  r_free (stream);
}

/* Select the recv or send key+salt blob for @p dir (see r_srtp_crypto_ctx_new). */
static inline const ruint8 *
r_srtp_crypto_ctx_key (const RSRTPCryptoCtx * cctx, RSRTPDirection dir)
{
  rsize blob = (cctx->csinfo->cipher->keybits + cctx->csinfo->saltbits) / 8;
  return dir == R_SRTP_DIRECTION_OUTBOUND ? cctx->key + blob : cctx->key;
}

static RSRTPStream *
r_srtp_stream_new (ruint32 ssrc, const RSRTPCryptoCtx * cctx, RSRTPDirection dir,
    rboolean hdrext)
{
  RSRTPStream * ret;
  RCryptoCipher * kdcipher;
  const ruint8 * key = r_srtp_crypto_ctx_key (cctx, dir);

  if (R_UNLIKELY ((kdcipher = r_crypto_cipher_new (cctx->csinfo->kdprf,
            key)) == NULL)) {
    R_LOG_WARNING ("Unable to create key derivation PRF cipher");
    return NULL;
  }

  if ((ret = r_mem_new0 (RSRTPStream)) != NULL) {
    RCryptoCipherResult res;
    rsize keysize = cctx->csinfo->cipher->keybits / 8;
    rsize saltsize = cctx->csinfo->saltbits / 8;

    ret->ssrc = ssrc;
    ret->cctx = cctx;
    ret->dir = dir;
    if (R_UNLIKELY (!r_bitset_init_heap (ret->rtp.window, R_SRTP_WINDOW_SIZE) ||
          !r_bitset_init_heap (ret->rtcp.window, R_SRTP_WINDOW_SIZE))) {
      /* Without the replay window, r_srtp_stream_replay_check would later
       * dereference a NULL bitset. */
      R_LOG_WARNING ("stream: 0x%.8x - replay window alloc failed", ssrc);
      r_srtp_stream_free (ret);
      ret = NULL;
    } else if (R_UNLIKELY ((res = r_srtp_state_init (&ret->rtp,
              R_SRTP_KDPRF_LABEL_RTP_ENCRYPTION, kdcipher, 0, cctx->csinfo,
              key + keysize, saltsize)) != R_CRYPTO_CIPHER_OK)) {
      R_LOG_WARNING ("stream: 0x%.8x - RTP crypto init failed %d", ssrc, res);
      r_srtp_stream_free (ret);
      ret = NULL;
    } else if (R_UNLIKELY ((res = r_srtp_state_init (&ret->rtcp,
              R_SRTP_KDPRF_LABEL_RTCP_ENCRYPTION, kdcipher, 0, cctx->csinfo,
              key + keysize, saltsize)) != R_CRYPTO_CIPHER_OK)) {
      R_LOG_WARNING ("stream: 0x%.8x - RTCP crypto init failed %d", ssrc, res);
      r_srtp_stream_free (ret);
      ret = NULL;
    } else if (R_UNLIKELY (hdrext && (res = r_srtp_stream_init_hdrext (ret,
              kdcipher, cctx->csinfo, key + keysize, saltsize)) != R_CRYPTO_CIPHER_OK)) {
      R_LOG_WARNING ("stream: 0x%.8x - hdr-ext crypto init failed %d", ssrc, res);
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
  r_free (ctx->hdrext_ids);
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
    ret->hdrext_ids = NULL;
  }

  R_LOG_DEBUG ("ctx %p", ret);
  return ret;
}

/* A crypto context carries two key+salt blobs, [recv || send], so a single
 * DTLS-SRTP filter can key both directions (RFC 5764 4.2). A single-key
 * context duplicates the one key into both slots. */
static RSRTPCryptoCtx *
r_srtp_crypto_ctx_new (const RSRTPCipherSuiteInfo * info, ruint32 ssrc,
    ruint32 filter, const ruint8 * recvkey, const ruint8 * sendkey)
{
  RSRTPCryptoCtx * cctx;
  rsize blob = (info->cipher->keybits + info->saltbits) / 8;

  if ((cctx = r_malloc (sizeof (RSRTPCryptoCtx) + 2 * blob)) != NULL) {
    cctx->csinfo = info;
    cctx->ssrc = ssrc;
    cctx->filter = filter;
    r_memcpy (cctx->key, recvkey, blob);
    r_memcpy (cctx->key + blob, sendkey, blob);
  }

  return cctx;
}

RSRTPError
r_srtp_add_crypto_context_for_ssrc (RSRTPCtx * ctx,
    ruint32 ssrc, RSRTPCipherSuite cs, const ruint8 * key)
{
  const RSRTPCipherSuiteInfo * info;
  RSRTPCryptoCtx * cctx;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (key == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((info = r_srtp_cipher_suite_get_info (cs)) == NULL))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (r_hash_table_contains (ctx->crypto_ssrc,
          RUINT_TO_POINTER (ssrc)) == R_HASH_TABLE_OK))
    return R_SRTP_ERROR_CRYPTO_CTX_EXISTS;

  if ((cctx = r_srtp_crypto_ctx_new (info, ssrc, 0, key, key)) != NULL) {
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
  return r_srtp_add_crypto_context_with_filter_dual (ctx, filter, cs, key, key);
}

RSRTPError
r_srtp_add_crypto_context_with_filter_dual (RSRTPCtx * ctx,
    ruint32 filter, RSRTPCipherSuite cs,
    const ruint8 * recvkey, const ruint8 * sendkey)
{
  const RSRTPCipherSuiteInfo * info;
  RSRTPCryptoCtx * cctx;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (filter == 0)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (recvkey == NULL || sendkey == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((info = r_srtp_cipher_suite_get_info (cs)) == NULL))
    return R_SRTP_ERROR_INVAL;

  if ((cctx = r_srtp_crypto_ctx_new (info, 0, filter, recvkey, sendkey)) != NULL) {
    ctx->crypto_filter = r_list_prepend (ctx->crypto_filter, cctx);
    R_LOG_TRACE ("ctx: %p filter: 0x%.8x crypto: %s", ctx, filter, info->str);
    return R_SRTP_ERROR_OK;
  }

  return R_SRTP_ERROR_OOM;
}

RSRTPError
r_srtp_set_encrypted_header_extension (RSRTPCtx * ctx, ruint8 id,
    rboolean encrypted)
{
  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  /* 0 is padding, never an element ID (RFC 8285); reject it so a stray 0
   * can never mark the padding run as encrypted. */
  if (R_UNLIKELY (id == 0)) return R_SRTP_ERROR_INVAL;

  if (ctx->hdrext_ids == NULL) {
    if (!encrypted)
      return R_SRTP_ERROR_OK;
    /* One bit per one/two-byte header ID (RFC 8285: 1..14 / 1..255). */
    if (R_UNLIKELY (!r_bitset_init_heap (ctx->hdrext_ids, 256)))
      return R_SRTP_ERROR_OOM;
  }

  r_bitset_set_bit (ctx->hdrext_ids, id, encrypted);
  R_LOG_TRACE ("ctx: %p hdr-ext id: %u encrypted: %d", ctx, id, encrypted);
  return R_SRTP_ERROR_OK;
}

static const RSRTPCryptoCtx *
r_srtp_lookup_crypto_ctx (RSRTPCtx * ctx, ruint32 ssrc)
{
  const RSRTPCryptoCtx * ret;
  RList * it;

  if ((ret = r_hash_table_lookup (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc))) != NULL)
    return ret;

  for (it = ctx->crypto_filter; it != NULL; it = it->next) {
    RSRTPCryptoCtx * cctx = it->data;
    if ((cctx->filter & ssrc) == ssrc) {
      ret = cctx;
      break;
    }
  }

  return ret;
}

static RSRTPStream *
r_srtp_get_stream (RSRTPCtx * ctx, ruint32 ssrc, RSRTPDirection dir)
{
  RSRTPStream * ret;
  const RSRTPCryptoCtx * cctx;

  if ((ret = r_hash_table_lookup (ctx->streams, RUINT_TO_POINTER (ssrc))) != NULL)
    return ret;

  if ((cctx = r_srtp_lookup_crypto_ctx (ctx, ssrc)) != NULL) {
    if ((ret = r_srtp_stream_new (ssrc, cctx, dir,
            ctx->hdrext_ids != NULL)) != NULL)
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
    if (idx + s->window->bits < s->index) {
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
    r_bitset_shl (s->window, (ruint)(idx - s->index));
    r_bitset_set_bit (s->window, 0, TRUE);
    s->index = idx;
  } else {
    r_bitset_set_bit (s->window, s->index - idx, TRUE);
  }

  return R_SRTP_ERROR_OK;
}

static inline void
r_srtp_state_create_iv (ruint8 * iv, rsize ivsize, const ruint8 * salt,
    rsize saltsize, ruint32 ssrc, ruint64 idx)
{
  r_memcpy (iv + ivsize - (sizeof (ruint16) + saltsize), salt, saltsize);
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

static inline rboolean
r_srtp_hdrext_id_encrypted (const RSRTPCtx * ctx, ruint8 id)
{
  return ctx->hdrext_ids != NULL && r_bitset_is_bit_set (ctx->hdrext_ids, id);
}

/* TRUE if @p ext (the 4-byte extension header) uses an RFC 8285 profile that
 * RFC 6904 can encrypt: 0xBEDE (one-byte) or 0x100x (two-byte). */
static inline rboolean
r_srtp_hdrext_profile_supported (const ruint8 * ext, ruint16 * profile)
{
  ruint16 p = RUINT16_FROM_BE (*(const ruint16 *)ext);
  *profile = p;
  return p == 0xbede || (p & 0xfff0) == 0x1000;
}

/* RFC 6904: XOR the header-extension keystream over the bodies of the
 * elements whose IDs are configured for encryption, in place over @p ext (the
 * whole extension including its 4-byte header). Element headers, padding, the
 * 4-byte header and the bodies of non-encrypted elements are left untouched.
 * CTR keystream is symmetric, so the same routine encrypts and decrypts. */
static rboolean
r_srtp_crypt_hdrext (const RSRTPCtx * ctx, RSRTPStream * stream,
    ruint16 profile, ruint8 * ext, rsize extsize, ruint32 ssrc, ruint64 idx)
{
  rboolean twobyte = (profile & 0xfff0) == 0x1000;
  ruint8 * data, * ks, * iv;
  rsize datalen, ivsize, i;

  if (extsize <= sizeof (ruint32))
    return TRUE;                              /* header only, no elements */
  data = ext + sizeof (ruint32);
  datalen = extsize - sizeof (ruint32);

  if (R_UNLIKELY ((ks = r_malloc (datalen)) == NULL))
    return FALSE;
  r_memclear (ks, datalen);
  ivsize = stream->hdrcipher->info->ivsize;
  iv = r_alloca0 (ivsize);
  r_srtp_state_create_iv (iv, ivsize, stream->hdrsalt, stream->hdrsaltsize,
      ssrc, idx);
  r_crypto_cipher_encrypt (stream->hdrcipher, ks, datalen, ks, iv, ivsize);

  for (i = 0; i < datalen; ) {
    ruint8 eid;
    rsize hdrlen, bodylen;

    if (data[i] == 0x00) {                    /* inter-element padding */
      i++;
      continue;
    }

    if (twobyte) {
      if (i + 2 > datalen) break;
      eid = data[i];
      bodylen = data[i + 1];
      hdrlen = 2;
    } else {
      eid = data[i] >> 4;
      if (eid == 15) break;                   /* RFC 8285: stop parsing */
      bodylen = (data[i] & 0x0f) + 1;
      hdrlen = 1;
    }
    if (i + hdrlen + bodylen > datalen) break; /* truncated element */

    if (r_srtp_hdrext_id_encrypted (ctx, eid)) {
      rsize j;
      for (j = i + hdrlen; j < i + hdrlen + bodylen; j++)
        data[j] ^= ks[j];
    }
    i += hdrlen + bodylen;
  }

  r_memclear (ks, datalen);
  r_free (ks);
  return TRUE;
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

    if ((stream = r_srtp_get_stream (ctx, r_rtp_buffer_get_ssrc (&rtp),
            R_SRTP_DIRECTION_OUTBOUND)) != NULL) {
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
        ruint16 profile = 0;
        /* RFC 6904: when an encrypted extension is present it is carried at
         * the front of the new buffer so its ciphertext feeds the auth tag;
         * extlead is its size, 0 when there is nothing to encrypt. */
        rboolean do_hdrext = stream->hdrcipher != NULL && rtp.ext.data != NULL &&
            r_srtp_hdrext_profile_supported (rtp.ext.data, &profile);
        rsize extlead = do_hdrext ? rtp.ext.size : 0;
        rsize payloadsize = extlead + rtp.pay.size + tagsize + stream->rtpmkisize;
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

            if (do_hdrext) {
              r_memcpy (info.data, rtp.ext.data, rtp.ext.size);
              if (R_UNLIKELY (!r_srtp_crypt_hdrext (ctx, stream, profile,
                      info.data, rtp.ext.size, stream->ssrc, idx))) {
                r_buffer_unmap (payload, &info);
                r_buffer_unref (payload);
                err = R_SRTP_ERROR_OOM;
                goto beach_map;
              }
            }

            r_srtp_state_create_iv (iv, ivsize, stream->rtp.salt,
                stream->rtp.saltsize, stream->ssrc, idx);

            R_LOG_TRACE ("Encrypting %u bytes", (ruint)rtp.pay.size);
            /* Fail closed: never emit an unencrypted payload if the cipher
             * rejects the request (e.g. an AEAD suite used on this path). */
            if (R_UNLIKELY (r_crypto_cipher_encrypt (stream->rtp.cipher,
                    info.data + extlead, rtp.pay.size, rtp.pay.data, iv, ivsize)
                    != R_CRYPTO_CIPHER_OK)) {
              err = R_SRTP_ERROR_INTERNAL;
              goto beach_map;
            }

            if (stream->rtpmkisize > 0) {
              /* FIXME: insert mki */
            }

            /* add auth tag */
            if (stream->rtp.mac != NULL && tagsize > 0) {
              ruint32 roc = RUINT32_TO_BE ((ruint32)(idx >> 16));

              r_hmac_reset (stream->rtp.mac);
              if (r_hmac_update (stream->rtp.mac, rtp.hdr.data, rtp.hdr.size) &&
                  (do_hdrext ?
                   r_hmac_update (stream->rtp.mac, info.data, extlead) :
                   (rtp.ext.data == NULL ||
                    r_hmac_update (stream->rtp.mac, rtp.ext.data, rtp.ext.size))) &&
                  r_hmac_update (stream->rtp.mac, info.data + extlead, rtp.pay.size) &&
                  r_hmac_update (stream->rtp.mac, &roc, sizeof (ruint32))) {
                ruint8 calctag[32];
                rsize calcsize;

                r_hmac_get_data (stream->rtp.mac, calctag, sizeof (calctag), &calcsize);
                r_memcpy (info.data + payloadsize - tagsize, calctag, tagsize);
              } else {
                R_LOG_ERROR ("HMAC update for SRTP auth failed");
                err = R_SRTP_ERROR_INTERNAL;
                goto beach_map;
              }
            }

            r_buffer_unmap (payload, &info);

            if (R_UNLIKELY ((ret = r_buffer_replace_byte_range (packet,
                rtp.hdr.size + rtp.ext.size - extlead, -1, payload)) == NULL)) {
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

    if ((stream = r_srtp_get_stream (ctx, r_rtp_buffer_get_ssrc (&rtp),
            R_SRTP_DIRECTION_INBOUND)) != NULL) {
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
        ruint16 profile = 0;
        /* RFC 6904: an encrypted extension is decrypted into the front of the
         * output buffer (extlead bytes) only after the auth tag verifies. */
        rboolean do_hdrext = stream->hdrcipher != NULL && rtp.ext.data != NULL &&
            r_srtp_hdrext_profile_supported (rtp.ext.data, &profile);
        rsize extlead = do_hdrext ? rtp.ext.size : 0;
        rsize payloadsize;
        RBuffer * payload;

        if (R_UNLIKELY (rtp.pay.size < tagsize + stream->rtpmkisize)) {
          err = R_SRTP_ERROR_INVAL;
          goto beach_map;
        }
        payloadsize = rtp.pay.size - tagsize - stream->rtpmkisize;

        if (stream->cctx->csinfo->authprefixlen > 0) {
          /* FIXME: Handle keystream prefix */
          R_LOG_ERROR ("SRTP Auth prefix not implmented yet...");
          err = R_SRTP_ERROR_INTERNAL;
          goto beach_map;
        }

        if (stream->rtp.mac != NULL && tagsize > 0) {
          ruint8 * authtag = rtp.pay.data + rtp.pay.size - tagsize;
          ruint32 roc = RUINT32_TO_BE ((ruint32)(idx >> 16));

          r_hmac_reset (stream->rtp.mac);
          if (r_hmac_update (stream->rtp.mac, rtp.hdr.data, rtp.hdr.size) &&
              (rtp.ext.data == NULL ||
               r_hmac_update (stream->rtp.mac, rtp.ext.data, rtp.ext.size)) &&
              r_hmac_update (stream->rtp.mac, rtp.pay.data, payloadsize) &&
              r_hmac_update (stream->rtp.mac, &roc, sizeof (ruint32))) {
            if (R_UNLIKELY (!r_hmac_verify (stream->rtp.mac, authtag, tagsize))) {
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

        if ((payload = r_buffer_new_alloc (NULL, extlead + payloadsize, NULL)) != NULL) {
          RMemMapInfo info = R_MEM_MAP_INFO_INIT;

          if (r_buffer_map (payload, &info, R_MEM_MAP_WRITE)) {
            rsize ivsize = stream->rtp.cipher->info->ivsize;
            ruint8 * iv = r_alloca0 (ivsize);

            if (do_hdrext) {
              r_memcpy (info.data, rtp.ext.data, rtp.ext.size);
              if (R_UNLIKELY (!r_srtp_crypt_hdrext (ctx, stream, profile,
                      info.data, rtp.ext.size, stream->ssrc, idx))) {
                r_buffer_unmap (payload, &info);
                r_buffer_unref (payload);
                err = R_SRTP_ERROR_OOM;
                goto beach_map;
              }
            }

            r_srtp_state_create_iv (iv, ivsize, stream->rtp.salt,
                stream->rtp.saltsize, stream->ssrc, idx);

            R_LOG_TRACE ("Decrypting %u bytes", (ruint)payloadsize);
            if (R_UNLIKELY (r_crypto_cipher_decrypt (stream->rtp.cipher,
                    info.data + extlead, payloadsize, rtp.pay.data, iv, ivsize)
                    != R_CRYPTO_CIPHER_OK)) {
              err = R_SRTP_ERROR_INTERNAL;
              goto beach_map;
            }
            r_buffer_unmap (payload, &info);

            if (R_UNLIKELY ((ret = r_buffer_replace_byte_range (packet,
                rtp.hdr.size + rtp.ext.size - extlead, -1, payload)) == NULL)) {
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
        (stream = r_srtp_get_stream (ctx, r_rtcp_packet_get_ssrc (rtcppacket),
            R_SRTP_DIRECTION_OUTBOUND)) != NULL) {
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
        R_LOG_INFO ("ssrc (0x%.8x) SRTCP index space exhausted", stream->ssrc);
        err = R_SRTP_ERROR_INTERNAL;
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

          r_srtp_state_create_iv (iv, ivsize, stream->rtcp.salt,
              stream->rtcp.saltsize, stream->ssrc, idx);

          R_LOG_TRACE ("Encrypting %u bytes", (ruint)(rtcp.info.size - 2 * sizeof (ruint32)));
          if (R_UNLIKELY (r_crypto_cipher_encrypt (stream->rtcp.cipher, ptr,
                  rtcp.info.size - 2 * sizeof (ruint32),
                  rtcp.info.data + 2 * sizeof (ruint32), iv, ivsize) != R_CRYPTO_CIPHER_OK)) {
            err = R_SRTP_ERROR_INTERNAL;
            goto beach_map;
          }
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
              rsize calcsize;

              r_hmac_get_data (stream->rtcp.mac, calctag, sizeof (calctag), &calcsize);
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
        (stream = r_srtp_get_stream (ctx, r_rtcp_packet_get_ssrc (rtcppacket),
            R_SRTP_DIRECTION_INBOUND)) != NULL) {
      rsize tagsize = stream->cctx->csinfo->srtp_tagbits / 8;
      const ruint8 * authtag;
      const ruint8 * srtpidx;
      ruint32 idx;

      if (R_UNLIKELY (rtcp.info.size < tagsize + stream->rtpmkisize + sizeof (ruint32))) {
        err = R_SRTP_ERROR_INVAL;
        goto beach_map;
      }
      authtag = rtcp.info.data + rtcp.info.size - tagsize;
      srtpidx = authtag - stream->rtpmkisize - sizeof (ruint32);

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
          r_hmac_reset (stream->rtcp.mac);
          if (r_hmac_update (stream->rtcp.mac, rtcp.info.data, newsize + sizeof (ruint32))) {
            if (R_UNLIKELY (!r_hmac_verify (stream->rtcp.mac, authtag, tagsize))) {
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

            r_srtp_state_create_iv (iv, ivsize, stream->rtcp.salt,
                stream->rtcp.saltsize, stream->ssrc, idx);

            /* Copy header and ssrc */
            r_memcpy (info.data, rtcp.info.data, 2 * sizeof (ruint32));

            R_LOG_TRACE ("Decrypting %u bytes", (ruint)info.size);
            if (R_UNLIKELY (r_crypto_cipher_decrypt (stream->rtcp.cipher,
                    info.data + 2 * sizeof (ruint32), info.size - 2 * sizeof (ruint32),
                    rtcp.info.data + 2 * sizeof (ruint32), iv, ivsize) != R_CRYPTO_CIPHER_OK)) {
              err = R_SRTP_ERROR_INTERNAL;
              goto beach_map;
            }
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

