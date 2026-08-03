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

#include <rlib/crypto/raes.h>
#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rhmac.h>

#include <rlib/data/rbitset.h>
#include <rlib/data/rhashtable.h>
#include <rlib/data/rlist.h>

#include <rlib/rmem.h>
#include <rlib/rtime.h>

#define R_SRTP_MAX_SALT_SIZE      16
#define R_SRTP_WINDOW_SIZE        1024
#define R_SRTCP_E_BIT             0x80000000

/* EKT (RFC 8870). The FullEKTField is EKTCiphertext || SPI(2) || Epoch(2) ||
 * Length(2) || MessageType(1); the ShortEKTField is a single 0x00 byte. */
#define R_SRTP_EKT_TYPE_SHORT     0x00
#define R_SRTP_EKT_TYPE_FULL      0x02
#define R_SRTP_EKT_FULL_TRAILER   7       /* SPI + Epoch + Length + MessageType */
#define R_SRTP_EKT_FULL_BURST     3       /* Full fields sent for a new/rekeyed key */
/* Max wraps under one EKTKey: the AES Key Wrap cap T = 2^48 (RFC 8870 4.4.1). */
#define R_SRTP_EKT_MAX_USES       RUINT64_CONSTANT (0x1000000000000)
#define R_SRTP_EKT_MAX_MASTERKEY  32      /* bounds the EKTPlaintext scratch */

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

/* A master key within a crypto context: an MKI tag (RFC 3711 3.1) followed by
 * the [recv || send] key+salt blobs (see r_srtp_crypto_ctx_new). A context can
 * hold several, one per MKI, so keys can roll without tearing it down. */
typedef struct _RSRTPMasterKey RSRTPMasterKey;
struct _RSRTPMasterKey {
  RSRTPMasterKey * next;
  ruint8 data[0];                   /* [mkisize][blob recv][blob send] */
};

typedef struct {
  const RSRTPCipherSuiteInfo * csinfo;
  ruint32 ssrc;
  ruint32 filter;
  ruint8 mkisize;                   /* MKI length in bytes; 0 when unused */
  RSRTPMasterKey * keys;            /* head of the master-key list */
  RSRTPMasterKey * sendkey;         /* active key for outbound packets */
} RSRTPCryptoCtx;

typedef struct {
  ruint64 index;
  RBitset * window;
  RCryptoCipher * cipher;
  RHmac * mac;
  ruint8 salt[R_SRTP_MAX_SALT_SIZE];
  rsize saltsize;
} RSRTPState;

/* An EKTKey (RFC 8870 5.2.2): the AES Key Wrap cipher and key that wrap the
 * transported SRTP master key, plus the SRTP suite and master salt those keys
 * are used with. Identified by its SPI within an EKT field. */
typedef struct _RSRTPEktKey RSRTPEktKey;
struct _RSRTPEktKey {
  RSRTPEktKey * next;
  ruint16 spi;
  RCryptoCipher * kek;                    /* AES-ECB cipher for AES Key Wrap */
  const RSRTPCipherSuiteInfo * csinfo;    /* suite for keys carried under this SPI */
  ruint8 salt[R_SRTP_MAX_SALT_SIZE];
  rsize saltsize;
  /* Usage limits (RFC 8870 4.5 / 5.2.2): once the key has wrapped for ttl or
   * hit the cipher's wrap cap, the sender stops emitting Full fields under it. */
  RClockTime ttl;                         /* lifetime once first used; 0 = unlimited */
  RClockTime first_used;                  /* monotonic time of the first wrap */
  rboolean used;                          /* whether first_used has been stamped */
  ruint64 uses;                           /* Full fields wrapped under this key */
};

/* Receiver epoch state, kept outside the stream so it survives the stream
 * teardown a key reinstall performs. RFC 8870 4.3.2 anti-replay is per (SPI,
 * SSRC), so each SSRC holds the highest epoch seen for every SPI it has seen
 * -- tracking only the last SPI would let an attacker alternate SPIs to
 * reinstall a stale key. */
typedef struct _RSRTPEktRx RSRTPEktRx;
struct _RSRTPEktRx {
  RSRTPEktRx * next;
  ruint16 spi;
  ruint16 epoch;
};

typedef struct {
  RSRTPEktKey * keys;                     /* configured EKTKeys, by SPI */
  RSRTPEktKey * sendkey;                  /* EKTKey for outbound Full fields, or NULL */
  RHashTable * rx;                        /* ssrc -> RSRTPEktRx, highest epoch seen */
  RClockTime full_interval;               /* periodic Full-field interval, 0 = burst only */
} RSRTPEkt;

typedef struct {
  ruint32 ssrc;
  const RSRTPCryptoCtx * cctx;
  RSRTPDirection dir;
  ruint8 rtpmkisize;

  /* Master key the session state below was derived from, NULL until first
   * keyed. On an MKI context this tracks the selected key so a rollover
   * re-derives only when the key actually changes. */
  const RSRTPMasterKey * mkey;
  rboolean wanthdrext;              /* derive the RFC 6904 keystream when keying */

  RSRTPState rtp;
  RSRTPState rtcp;

  /* RFC 6904 header-extension keystream: derived only when the session
   * encrypts one or more header extensions, NULL otherwise. */
  RCryptoCipher * hdrcipher;
  ruint8 hdrsalt[R_SRTP_MAX_SALT_SIZE];
  rsize hdrsaltsize;

  /* EKT (RFC 8870) sender state; receiver epoch state lives in RSRTPEkt.rx. */
  const RSRTPMasterKey * ekt_tx_key; /* send key last announced, NULL until first */
  RClockTime ekt_tx_last_full;      /* monotonic time the last Full field was sent */
  ruint16 ekt_tx_epoch;             /* epoch, bumped when the send key rolls */
  ruint8 ekt_tx_burst;              /* Full fields left in the current burst */
} RSRTPStream;

struct RSRTPCtx {
  RRef ref;

  RList * crypto_filter;
  RHashTable * crypto_ssrc;

  RHashTable * streams;

  /* RFC 6904: bit set per RTP header-extension ID that is encrypted, indexed
   * by the ID (1..255). NULL until the first ID is registered. */
  RBitset * hdrext_ids;

  /* EKT (RFC 8870): NULL until the first EKTKey is configured, at which point
   * EKT framing is active for the context. */
  RSRTPEkt * ekt;

  /* TRUE once an MKI crypto context is installed. EKT and MKI are mutually
   * exclusive on one context: an EKT-ingested key installs an MKI-less context,
   * which would then misparse an MKI trailer, so the two cannot coexist. */
  rboolean has_mki;
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

  /* r = index DIV kdr selects the session-key generation. kdr == 0 (the
   * default, RFC 3711 4.3.1) means a single derivation with r always 0, so the
   * packet index must not enter the KDF -- otherwise re-deriving on a master
   * key rollover would yield a different key depending on how far the stream
   * index had advanced, and the two peers (at different indices) would disagree. */
  if (kdr > 0) index %= kdr;
  else         index = 0;
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

/* The MKI tag of a master key. */
static inline const ruint8 *
r_srtp_master_key_mki (const RSRTPMasterKey * mk)
{
  return mk->data;
}

/* The recv or send key+salt blob of @p mk for @p dir (see r_srtp_crypto_ctx_new). */
static inline const ruint8 *
r_srtp_master_key_blob (const RSRTPCryptoCtx * cctx, const RSRTPMasterKey * mk,
    RSRTPDirection dir)
{
  rsize blob = (cctx->csinfo->cipher->keybits + cctx->csinfo->saltbits) / 8;
  const ruint8 * key = mk->data + cctx->mkisize;
  return dir == R_SRTP_DIRECTION_OUTBOUND ? key + blob : key;
}

static RSRTPMasterKey *
r_srtp_master_key_new (const RSRTPCipherSuiteInfo * info, ruint8 mkisize,
    const ruint8 * recvkey, const ruint8 * sendkey, const ruint8 * mki)
{
  RSRTPMasterKey * mk;
  rsize blob = (info->cipher->keybits + info->saltbits) / 8;

  if ((mk = r_malloc (sizeof (RSRTPMasterKey) + mkisize + 2 * blob)) != NULL) {
    mk->next = NULL;
    if (mkisize > 0)
      r_memcpy (mk->data, mki, mkisize);
    r_memcpy (mk->data + mkisize, recvkey, blob);
    r_memcpy (mk->data + mkisize + blob, sendkey, blob);
  }

  return mk;
}

/* The master key tagged with @p mki, or NULL. The MKI is not secret and not
 * authenticated, so a plain compare is fine; a mismatch just fails auth. */
static const RSRTPMasterKey *
r_srtp_find_master_key (const RSRTPCryptoCtx * cctx, const ruint8 * mki)
{
  const RSRTPMasterKey * mk;

  for (mk = cctx->keys; mk != NULL; mk = mk->next) {
    if (r_memcmp (r_srtp_master_key_mki (mk), mki, cctx->mkisize) == 0)
      return mk;
  }

  return NULL;
}

/* (Re-)derive the RTP/RTCP (and, when wanted, RFC 6904) session state of
 * @p stream from master key @p mk for its current direction. r_srtp_state_init
 * keeps the replay window and packet index, so a rollover to a new master key
 * continues the same crypto context (RFC 3711 8.1) rather than resetting it. */
static RCryptoCipherResult
r_srtp_stream_key (RSRTPStream * stream, const RSRTPMasterKey * mk)
{
  const RSRTPCryptoCtx * cctx = stream->cctx;
  RCryptoCipher * kdcipher;
  const ruint8 * key = r_srtp_master_key_blob (cctx, mk, stream->dir);
  rsize keysize = cctx->csinfo->cipher->keybits / 8;
  rsize saltsize = cctx->csinfo->saltbits / 8;
  RCryptoCipherResult res;

  if (R_UNLIKELY ((kdcipher = r_crypto_cipher_new (cctx->csinfo->kdprf,
            key)) == NULL)) {
    R_LOG_WARNING ("Unable to create key derivation PRF cipher");
    return R_CRYPTO_CIPHER_OOM;
  }

  if ((res = r_srtp_state_init (&stream->rtp, R_SRTP_KDPRF_LABEL_RTP_ENCRYPTION,
          kdcipher, 0, cctx->csinfo, key + keysize, saltsize)) == R_CRYPTO_CIPHER_OK &&
      (res = r_srtp_state_init (&stream->rtcp, R_SRTP_KDPRF_LABEL_RTCP_ENCRYPTION,
          kdcipher, 0, cctx->csinfo, key + keysize, saltsize)) == R_CRYPTO_CIPHER_OK &&
      stream->wanthdrext) {
    if (stream->hdrcipher != NULL) {
      r_crypto_cipher_unref (stream->hdrcipher);
      stream->hdrcipher = NULL;
    }
    res = r_srtp_stream_init_hdrext (stream, kdcipher, cctx->csinfo,
        key + keysize, saltsize);
  }

  if (R_LIKELY (res == R_CRYPTO_CIPHER_OK))
    stream->mkey = mk;

  r_crypto_cipher_unref (kdcipher);
  return res;
}

/* Ensure @p stream's session state is derived from master key @p mk, keying it
 * on first use and re-keying only when the selected key actually changes. */
static RSRTPError
r_srtp_stream_ensure_key (RSRTPStream * stream, const RSRTPMasterKey * mk)
{
  if (R_LIKELY (stream->mkey == mk))
    return R_SRTP_ERROR_OK;

  switch (r_srtp_stream_key (stream, mk)) {
    case R_CRYPTO_CIPHER_OK:
      return R_SRTP_ERROR_OK;
    case R_CRYPTO_CIPHER_OOM:
      return R_SRTP_ERROR_OOM;
    default:
      R_LOG_WARNING ("stream: 0x%.8x - crypto init failed", stream->ssrc);
      return R_SRTP_ERROR_INTERNAL;
  }
}

/* The session keys are derived lazily (r_srtp_stream_ensure_key), once the
 * settled direction and — on an MKI context — the selected master key are
 * known, so all this needs is the replay windows. */
static RSRTPStream *
r_srtp_stream_new (ruint32 ssrc, const RSRTPCryptoCtx * cctx, RSRTPDirection dir,
    rboolean hdrext)
{
  RSRTPStream * ret;

  if ((ret = r_mem_new0 (RSRTPStream)) != NULL) {
    ret->ssrc = ssrc;
    ret->cctx = cctx;
    ret->dir = dir;
    ret->rtpmkisize = cctx->mkisize;
    ret->wanthdrext = hdrext;
    ret->mkey = NULL;
    if (R_UNLIKELY (!r_bitset_init_heap (ret->rtp.window, R_SRTP_WINDOW_SIZE) ||
          !r_bitset_init_heap (ret->rtcp.window, R_SRTP_WINDOW_SIZE))) {
      /* Without the replay window, r_srtp_stream_replay_check would later
       * dereference a NULL bitset. */
      R_LOG_WARNING ("stream: 0x%.8x - replay window alloc failed", ssrc);
      r_srtp_stream_free (ret);
      ret = NULL;
    } else {
      R_LOG_DEBUG ("stream: 0x%.8x - %p", ssrc, ret);
    }
  }

  return ret;
}

static void
r_srtp_crypto_ctx_free (RSRTPCryptoCtx * cctx)
{
  rsize blob = (cctx->csinfo->cipher->keybits + cctx->csinfo->saltbits) / 8;
  RSRTPMasterKey * mk = cctx->keys;

  while (mk != NULL) {
    RSRTPMasterKey * next = mk->next;
    /* Master keys are the most sensitive material here; don't leave them
     * behind in freed heap. */
    r_memclear (mk, sizeof (RSRTPMasterKey) + cctx->mkisize + 2 * blob);
    r_free (mk);
    mk = next;
  }

  r_free (cctx);
}

static void
r_srtp_ekt_rx_free (rpointer data)
{
  RSRTPEktRx * rx = data;

  while (rx != NULL) {
    RSRTPEktRx * next = rx->next;
    r_free (rx);
    rx = next;
  }
}

static void
r_srtp_ekt_free (RSRTPEkt * ekt)
{
  RSRTPEktKey * k = ekt->keys;

  while (k != NULL) {
    RSRTPEktKey * next = k->next;
    if (k->kek != NULL)
      r_crypto_cipher_unref (k->kek);
    /* The master salt is key-derived material paired with the KEK. */
    r_memclear (k->salt, sizeof (k->salt));
    r_free (k);
    k = next;
  }

  if (ekt->rx != NULL)
    r_hash_table_unref (ekt->rx);
  r_free (ekt);
}

static void
r_srtp_ctx_free (RSRTPCtx * ctx)
{
  r_list_destroy_full (ctx->crypto_filter, (RDestroyNotify) r_srtp_crypto_ctx_free);
  r_hash_table_unref (ctx->crypto_ssrc);
  r_hash_table_unref (ctx->streams);
  r_free (ctx->hdrext_ids);
  if (ctx->ekt != NULL)
    r_srtp_ekt_free (ctx->ekt);
  r_free (ctx);
}

RSRTPCtx *
r_srtp_ctx_new (void)
{
  RSRTPCtx * ret;

  if ((ret = r_mem_new (RSRTPCtx)) != NULL) {
    r_ref_init (ret, r_srtp_ctx_free);

    ret->crypto_filter = NULL;
    ret->crypto_ssrc = r_hash_table_new_full (NULL, NULL, NULL,
        (RDestroyNotify) r_srtp_crypto_ctx_free);
    ret->streams = r_hash_table_new_full (NULL, NULL,
        NULL, (RDestroyNotify) r_srtp_stream_free);
    ret->hdrext_ids = NULL;
    ret->ekt = NULL;
    ret->has_mki = FALSE;
  }

  R_LOG_DEBUG ("ctx %p", ret);
  return ret;
}

/* A crypto context holds a list of master keys, each two key+salt blobs
 * [recv || send] so a single DTLS-SRTP filter can key both directions
 * (RFC 5764 4.2); a single-key context duplicates the one key into both slots.
 * With MKI (mkisize > 0) more than one key can be staged for rollover, each
 * tagged with its @p mki (RFC 3711 8.1); without it there is exactly one key
 * and @p mki is ignored. The first key is the initial send key. */
static RSRTPCryptoCtx *
r_srtp_crypto_ctx_new (const RSRTPCipherSuiteInfo * info, ruint32 ssrc,
    ruint32 filter, ruint8 mkisize,
    const ruint8 * recvkey, const ruint8 * sendkey, const ruint8 * mki)
{
  RSRTPCryptoCtx * cctx;

  if ((cctx = r_mem_new (RSRTPCryptoCtx)) != NULL) {
    cctx->csinfo = info;
    cctx->ssrc = ssrc;
    cctx->filter = filter;
    cctx->mkisize = mkisize;
    if ((cctx->keys = r_srtp_master_key_new (info, mkisize,
            recvkey, sendkey, mki)) == NULL) {
      r_free (cctx);
      return NULL;
    }
    cctx->sendkey = cctx->keys;
  }

  return cctx;
}

/* Find the context created for @p id: an ssrc (per-SSRC context) or an exact
 * filter value. Used by the MKI key-management entry points. */
static RSRTPCryptoCtx *
r_srtp_find_crypto_ctx (RSRTPCtx * ctx, ruint32 id)
{
  RSRTPCryptoCtx * cctx;
  RList * it;

  if ((cctx = r_hash_table_lookup (ctx->crypto_ssrc,
          RUINT_TO_POINTER (id))) != NULL)
    return cctx;

  for (it = ctx->crypto_filter; it != NULL; it = it->next) {
    cctx = it->data;
    if (cctx->filter == id)
      return cctx;
  }

  return NULL;
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

  if ((cctx = r_srtp_crypto_ctx_new (info, ssrc, 0, 0, key, key, NULL)) != NULL) {
    r_hash_table_insert (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc), cctx);
    R_LOG_TRACE ("ctx: %p ssrc: 0x%.8x crypto: %s", ctx, ssrc, info->str);
    return R_SRTP_ERROR_OK;
  }

  return R_SRTP_ERROR_OOM;
}

RSRTPError
r_srtp_update_crypto_context_for_ssrc (RSRTPCtx * ctx,
    ruint32 ssrc, RSRTPCipherSuite cs, const ruint8 * key)
{
  const RSRTPCipherSuiteInfo * info;
  RSRTPCryptoCtx * cctx;
  RSRTPStream * stream;

  if (R_UNLIKELY (ctx == NULL || key == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((info = r_srtp_cipher_suite_get_info (cs)) == NULL))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((cctx = r_srtp_crypto_ctx_new (info, ssrc, 0, 0,
            key, key, NULL)) == NULL))
    return R_SRTP_ERROR_OOM;

  /* Re-point any live stream at the new context in place (dropping it would
   * lose the SRTP index and the EKT sender epoch) BEFORE freeing the old
   * context, so stream->cctx never dangles. */
  stream = r_hash_table_lookup (ctx->streams, RUINT_TO_POINTER (ssrc));
  if (stream != NULL) {
    stream->cctx = cctx;
    stream->mkey = NULL;                    /* re-derive from the new key */
    /* If EKT was already announcing this stream, this is a rollover: bump the
     * epoch and restart the Full burst so receivers learn the new key. */
    if (stream->ekt_tx_key != NULL) {
      stream->ekt_tx_epoch++;
      stream->ekt_tx_burst = R_SRTP_EKT_FULL_BURST;
      stream->ekt_tx_key = cctx->sendkey;
    }
  }
  r_hash_table_remove (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc));
  r_hash_table_insert (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc), cctx);

  R_LOG_TRACE ("ctx: %p ssrc: 0x%.8x rekeyed crypto: %s", ctx, ssrc, info->str);
  return R_SRTP_ERROR_OK;
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

  if ((cctx = r_srtp_crypto_ctx_new (info, 0, filter, 0,
          recvkey, sendkey, NULL)) != NULL) {
    ctx->crypto_filter = r_list_prepend (ctx->crypto_filter, cctx);
    R_LOG_TRACE ("ctx: %p filter: 0x%.8x crypto: %s", ctx, filter, info->str);
    return R_SRTP_ERROR_OK;
  }

  return R_SRTP_ERROR_OOM;
}

RSRTPError
r_srtp_add_crypto_context_for_ssrc_with_mki (RSRTPCtx * ctx,
    ruint32 ssrc, RSRTPCipherSuite cs, ruint8 mkisize,
    const ruint8 * recvkey, const ruint8 * sendkey, const ruint8 * mki)
{
  const RSRTPCipherSuiteInfo * info;
  RSRTPCryptoCtx * cctx;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (recvkey == NULL || sendkey == NULL || mki == NULL))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (mkisize == 0 || mkisize > R_SRTP_MAX_MKI_SIZE))
    return R_SRTP_ERROR_INVAL;
  /* EKT and MKI cannot share a context (see RSRTPCtx.has_mki). */
  if (R_UNLIKELY (ctx->ekt != NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((info = r_srtp_cipher_suite_get_info (cs)) == NULL))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (r_hash_table_contains (ctx->crypto_ssrc,
          RUINT_TO_POINTER (ssrc)) == R_HASH_TABLE_OK))
    return R_SRTP_ERROR_CRYPTO_CTX_EXISTS;

  if ((cctx = r_srtp_crypto_ctx_new (info, ssrc, 0, mkisize,
          recvkey, sendkey, mki)) != NULL) {
    ctx->has_mki = TRUE;
    r_hash_table_insert (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc), cctx);
    R_LOG_TRACE ("ctx: %p ssrc: 0x%.8x crypto: %s mki: %u bytes",
        ctx, ssrc, info->str, mkisize);
    return R_SRTP_ERROR_OK;
  }

  return R_SRTP_ERROR_OOM;
}

RSRTPError
r_srtp_add_crypto_context_with_filter_with_mki (RSRTPCtx * ctx,
    ruint32 filter, RSRTPCipherSuite cs, ruint8 mkisize,
    const ruint8 * recvkey, const ruint8 * sendkey, const ruint8 * mki)
{
  const RSRTPCipherSuiteInfo * info;
  RSRTPCryptoCtx * cctx;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (filter == 0)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (recvkey == NULL || sendkey == NULL || mki == NULL))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (mkisize == 0 || mkisize > R_SRTP_MAX_MKI_SIZE))
    return R_SRTP_ERROR_INVAL;
  /* EKT and MKI cannot share a context (see RSRTPCtx.has_mki). */
  if (R_UNLIKELY (ctx->ekt != NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((info = r_srtp_cipher_suite_get_info (cs)) == NULL))
    return R_SRTP_ERROR_INVAL;

  if ((cctx = r_srtp_crypto_ctx_new (info, 0, filter, mkisize,
          recvkey, sendkey, mki)) != NULL) {
    ctx->has_mki = TRUE;
    ctx->crypto_filter = r_list_prepend (ctx->crypto_filter, cctx);
    R_LOG_TRACE ("ctx: %p filter: 0x%.8x crypto: %s mki: %u bytes",
        ctx, filter, info->str, mkisize);
    return R_SRTP_ERROR_OK;
  }

  return R_SRTP_ERROR_OOM;
}

RSRTPError
r_srtp_add_master_key (RSRTPCtx * ctx, ruint32 id,
    const ruint8 * recvkey, const ruint8 * sendkey, const ruint8 * mki)
{
  RSRTPCryptoCtx * cctx;
  RSRTPMasterKey * mk;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (recvkey == NULL || sendkey == NULL || mki == NULL))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((cctx = r_srtp_find_crypto_ctx (ctx, id)) == NULL))
    return R_SRTP_ERROR_NO_CRYPTO_CTX;
  if (R_UNLIKELY (cctx->mkisize == 0))
    return R_SRTP_ERROR_NO_CRYPTO_CTX;
  if (R_UNLIKELY (r_srtp_find_master_key (cctx, mki) != NULL))
    return R_SRTP_ERROR_CRYPTO_CTX_EXISTS;

  if ((mk = r_srtp_master_key_new (cctx->csinfo, cctx->mkisize,
          recvkey, sendkey, mki)) == NULL)
    return R_SRTP_ERROR_OOM;

  mk->next = cctx->keys;
  cctx->keys = mk;
  R_LOG_TRACE ("ctx: %p id: 0x%.8x added master key", ctx, id);
  return R_SRTP_ERROR_OK;
}

RSRTPError
r_srtp_set_send_master_key (RSRTPCtx * ctx, ruint32 id, const ruint8 * mki)
{
  RSRTPCryptoCtx * cctx;
  const RSRTPMasterKey * mk;

  if (R_UNLIKELY (ctx == NULL || mki == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((cctx = r_srtp_find_crypto_ctx (ctx, id)) == NULL))
    return R_SRTP_ERROR_NO_CRYPTO_CTX;
  if (R_UNLIKELY (cctx->mkisize == 0))
    return R_SRTP_ERROR_NO_CRYPTO_CTX;
  if (R_UNLIKELY ((mk = r_srtp_find_master_key (cctx, mki)) == NULL))
    return R_SRTP_ERROR_NO_CRYPTO_CTX;

  cctx->sendkey = (RSRTPMasterKey *) mk;
  R_LOG_TRACE ("ctx: %p id: 0x%.8x selected send master key", ctx, id);
  return R_SRTP_ERROR_OK;
}

static RSRTPEktKey *
r_srtp_ekt_find_key (const RSRTPEkt * ekt, ruint16 spi)
{
  RSRTPEktKey * k;

  for (k = ekt->keys; k != NULL; k = k->next) {
    if (k->spi == spi)
      return k;
  }

  return NULL;
}

RSRTPError
r_srtp_add_ekt_key (RSRTPCtx * ctx, ruint16 spi, RSRTPEktCipher cipher,
    const ruint8 * key, RSRTPCipherSuite cs, const ruint8 * salt, rsize saltsize)
{
  const RSRTPCipherSuiteInfo * info;
  RSRTPEktKey * k;
  RCryptoCipher * kek;

  if (R_UNLIKELY (ctx == NULL || key == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (salt == NULL && saltsize > 0)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (saltsize > R_SRTP_MAX_SALT_SIZE)) return R_SRTP_ERROR_INVAL;
  /* EKT and MKI cannot share a context (see RSRTPCtx.has_mki). */
  if (R_UNLIKELY (ctx->has_mki)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((info = r_srtp_cipher_suite_get_info (cs)) == NULL))
    return R_SRTP_ERROR_INVAL;
  /* The transported salt must match the suite it keys, so a recovered master
   * key + this salt form a complete key+salt blob for that suite. */
  if (R_UNLIKELY (saltsize != info->saltbits / 8))
    return R_SRTP_ERROR_INVAL;

  switch (cipher) {
    case R_SRTP_EKT_CIPHER_AESKW_128:
      kek = r_cipher_aes_128_ecb_new (key);
      break;
    case R_SRTP_EKT_CIPHER_AESKW_256:
      kek = r_cipher_aes_256_ecb_new (key);
      break;
    default:
      return R_SRTP_ERROR_INVAL;
  }
  if (R_UNLIKELY (kek == NULL))
    return R_SRTP_ERROR_OOM;

  if (ctx->ekt == NULL) {
    if (R_UNLIKELY ((ctx->ekt = r_mem_new0 (RSRTPEkt)) == NULL)) {
      r_crypto_cipher_unref (kek);
      return R_SRTP_ERROR_OOM;
    }
    ctx->ekt->rx = r_hash_table_new_full (NULL, NULL, NULL, r_srtp_ekt_rx_free);
  }
  if (R_UNLIKELY (r_srtp_ekt_find_key (ctx->ekt, spi) != NULL)) {
    r_crypto_cipher_unref (kek);
    return R_SRTP_ERROR_CRYPTO_CTX_EXISTS;
  }
  if (R_UNLIKELY ((k = r_mem_new0 (RSRTPEktKey)) == NULL)) {
    r_crypto_cipher_unref (kek);
    return R_SRTP_ERROR_OOM;
  }

  k->spi = spi;
  k->kek = kek;
  k->csinfo = info;
  k->saltsize = saltsize;
  if (saltsize > 0)
    r_memcpy (k->salt, salt, saltsize);
  k->next = ctx->ekt->keys;
  ctx->ekt->keys = k;
  R_LOG_TRACE ("ctx: %p ekt spi: 0x%.4x crypto: %s", ctx, spi, info->str);
  return R_SRTP_ERROR_OK;
}

RSRTPError
r_srtp_set_ekt_send_key (RSRTPCtx * ctx, ruint16 spi)
{
  RSRTPEktKey * k;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (ctx->ekt == NULL)) return R_SRTP_ERROR_NO_CRYPTO_CTX;
  if (R_UNLIKELY ((k = r_srtp_ekt_find_key (ctx->ekt, spi)) == NULL))
    return R_SRTP_ERROR_NO_CRYPTO_CTX;

  ctx->ekt->sendkey = k;
  R_LOG_TRACE ("ctx: %p ekt send spi: 0x%.4x", ctx, spi);
  return R_SRTP_ERROR_OK;
}

RSRTPError
r_srtp_set_ekt_full_interval (RSRTPCtx * ctx, RClockTime interval)
{
  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (ctx->ekt == NULL)) return R_SRTP_ERROR_NO_CRYPTO_CTX;

  ctx->ekt->full_interval = interval;
  return R_SRTP_ERROR_OK;
}

RSRTPError
r_srtp_set_ekt_key_ttl (RSRTPCtx * ctx, ruint16 spi, RClockTime ttl)
{
  RSRTPEktKey * k;

  if (R_UNLIKELY (ctx == NULL)) return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (ctx->ekt == NULL)) return R_SRTP_ERROR_NO_CRYPTO_CTX;
  if (R_UNLIKELY ((k = r_srtp_ekt_find_key (ctx->ekt, spi)) == NULL))
    return R_SRTP_ERROR_NO_CRYPTO_CTX;

  k->ttl = ttl;
  return R_SRTP_ERROR_OK;
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

/* --- EKT (RFC 8870) ------------------------------------------------------ */

/* Length of a FullEKTField wrapping a @p keysize-octet master key under @p k. */
static inline rsize
r_srtp_ekt_full_size (const RSRTPEktKey * k)
{
  rsize keysize = k->csinfo->cipher->keybits / 8;
  return R_AES_KEY_WRAP_PAD_SIZE (1 + keysize + 8) + R_SRTP_EKT_FULL_TRAILER;
}

/* TRUE while @p k may still wrap a key, counting the wrap. RFC 8870 4.5 / 5.2.2:
 * a sender must stop using an EKTKey past its TTL or the cipher's wrap cap. */
static rboolean
r_srtp_ekt_key_usable (const RSRTPEktKey * k)
{
  if (R_UNLIKELY (k->uses >= R_SRTP_EKT_MAX_USES))
    return FALSE;
  if (k->ttl > 0 && k->used &&
      r_time_get_ts_monotonic () - k->first_used >= k->ttl)
    return FALSE;
  return TRUE;
}

/* Decide whether an outbound packet carries a Full EKT field, and advance the
 * sender policy state (RFC 8870 4.6): a burst of Full fields when the send key
 * first appears or rolls (bumping the epoch), then periodically thereafter.
 * An expired/over-used EKTKey stops emitting Full fields (degrades to Short) so
 * it never wraps a key beyond its limits; the app is expected to have rolled to
 * a fresh EKTKey by then. This only decides -- the wrap is counted when the
 * Full field is actually emitted (r_srtp_ekt_tx_sent_full), so a protect that
 * fails after sizing neither burns usage nor starts the TTL clock. */
static rboolean
r_srtp_ekt_tx_prepare (const RSRTPEkt * ekt, RSRTPStream * stream)
{
  rboolean full;

  if (stream->ekt_tx_key != stream->cctx->sendkey) {
    if (stream->ekt_tx_key != NULL)
      stream->ekt_tx_epoch++;               /* the app rolled the send key */
    stream->ekt_tx_key = stream->cctx->sendkey;
    stream->ekt_tx_burst = R_SRTP_EKT_FULL_BURST;
  }

  full = stream->ekt_tx_burst > 0 ||
      (ekt->full_interval > 0 &&
       r_time_get_ts_monotonic () - stream->ekt_tx_last_full >= ekt->full_interval);

  return full && r_srtp_ekt_key_usable (ekt->sendkey);
}

/* Record an emitted Full field: retire a burst slot, restart the periodic
 * timer, and count the wrap under the send EKTKey (stamping its first use). */
static void
r_srtp_ekt_tx_sent_full (RSRTPEkt * ekt, RSRTPStream * stream)
{
  RSRTPEktKey * k = ekt->sendkey;

  if (stream->ekt_tx_burst > 0)
    stream->ekt_tx_burst--;
  stream->ekt_tx_last_full = r_time_get_ts_monotonic ();

  if (!k->used) {
    k->used = TRUE;
    k->first_used = stream->ekt_tx_last_full;
  }
  k->uses++;
}

/* Build a FullEKTField into @p out: AES-KW(EKTPlaintext) followed by
 * SPI || Epoch || Length || 0x02 (RFC 8870 4.1). EKTPlaintext is
 * SRTPMasterKeyLength || SRTPMasterKey || SSRC || ROC. */
static rboolean
r_srtp_ekt_build_full (const RSRTPEktKey * k, const ruint8 * mk, rsize keysize,
    ruint32 ssrc, ruint32 roc, ruint16 epoch, ruint8 * out)
{
  ruint8 pt[1 + R_SRTP_EKT_MAX_MASTERKEY + 8];
  rsize ptlen = 1 + keysize + 8;
  rsize wlen = R_AES_KEY_WRAP_PAD_SIZE (ptlen);
  rsize total = wlen + R_SRTP_EKT_FULL_TRAILER;
  ruint8 * p;

  pt[0] = (ruint8) keysize;
  r_memcpy (pt + 1, mk, keysize);
  p = pt + 1 + keysize;
  p[0] = (ruint8)(ssrc >> 24); p[1] = (ruint8)(ssrc >> 16);
  p[2] = (ruint8)(ssrc >>  8); p[3] = (ruint8)(ssrc      );
  p[4] = (ruint8)(roc  >> 24); p[5] = (ruint8)(roc  >> 16);
  p[6] = (ruint8)(roc  >>  8); p[7] = (ruint8)(roc       );

  if (R_UNLIKELY (!r_cipher_aes_key_wrap_pad (k->kek, out, pt, ptlen))) {
    r_memclear (pt, sizeof (pt));
    return FALSE;
  }
  r_memclear (pt, sizeof (pt));

  p = out + wlen;
  p[0] = (ruint8)(k->spi >> 8); p[1] = (ruint8)(k->spi);
  p[2] = (ruint8)(epoch  >> 8); p[3] = (ruint8)(epoch );
  p[4] = (ruint8)(total  >> 8); p[5] = (ruint8)(total );
  p[6] = R_SRTP_EKT_TYPE_FULL;
  return TRUE;
}

/* Install a master key recovered from a FullEKTField as the crypto context for
 * @p ssrc, replacing any prior context/stream, and seed the ROC (RFC 8870
 * 4.3.2). The per-SSRC receiver epoch state lives outside the stream, so it is
 * unaffected by this teardown. */
static rboolean
r_srtp_ekt_install (RSRTPCtx * ctx, const RSRTPEktKey * k, ruint32 ssrc,
    const ruint8 * mk, rsize mklen, ruint32 roc)
{
  const RSRTPCipherSuiteInfo * info = k->csinfo;
  rsize keysize = info->cipher->keybits / 8;
  ruint8 blob[R_SRTP_EKT_MAX_MASTERKEY + R_SRTP_MAX_SALT_SIZE];
  RSRTPCryptoCtx * cctx;
  RSRTPStream * stream;

  if (R_UNLIKELY (mklen != keysize))
    return FALSE;

  r_memcpy (blob, mk, keysize);
  r_memcpy (blob + keysize, k->salt, k->saltsize);
  cctx = r_srtp_crypto_ctx_new (info, ssrc, 0, 0, blob, blob, NULL);
  r_memclear (blob, sizeof (blob));
  if (R_UNLIKELY (cctx == NULL))
    return FALSE;

  /* Drop the stale stream (it points at the old context) before freeing that
   * context, then install the new one and rebuild the stream from it. */
  r_hash_table_remove (ctx->streams, RUINT_TO_POINTER (ssrc));
  r_hash_table_remove (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc));
  r_hash_table_insert (ctx->crypto_ssrc, RUINT_TO_POINTER (ssrc), cctx);

  if ((stream = r_srtp_get_stream (ctx, ssrc, R_SRTP_DIRECTION_INBOUND)) != NULL)
    stream->rtp.index = ((ruint64) roc) << 16;

  R_LOG_TRACE ("ctx: %p ekt installed key for ssrc 0x%.8x roc %u", ctx, ssrc, roc);
  return TRUE;
}

/* Process the EKT field trailing an inbound @p size-octet packet for @p ssrc,
 * returning its length to strip in @p fieldlen. A ShortEKTField is a no-op; a
 * FullEKTField installs the recovered key unless its epoch was already seen.
 * Returns an error (drop the packet) on a malformed field, unknown SPI, failed
 * unwrap or SSRC mismatch. */
static RSRTPError
r_srtp_ekt_ingest (RSRTPCtx * ctx, ruint32 ssrc, const ruint8 * data,
    rsize size, rsize * fieldlen)
{
  const ruint8 * field;
  const RSRTPEktKey * k;
  RSRTPEktRx * rxhead, * rxnode;
  ruint8 pt[64];
  rsize flen, ctlen, ptlen, mklen;
  ruint16 spi, epoch;
  ruint32 inner_ssrc, roc;

  if (R_UNLIKELY (size < 1))
    return R_SRTP_ERROR_BAD_RTP_HDR;
  if (data[size - 1] == R_SRTP_EKT_TYPE_SHORT) {
    *fieldlen = 1;
    return R_SRTP_ERROR_OK;
  }
  if (R_UNLIKELY (data[size - 1] != R_SRTP_EKT_TYPE_FULL))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY (size < R_SRTP_EKT_FULL_TRAILER))
    return R_SRTP_ERROR_INVAL;

  flen = ((rsize) data[size - 3] << 8) | data[size - 2];
  /* The ciphertext must be a whole number of 64-bit blocks, at least 16, and
   * small enough that its plaintext fits the scratch (our suites need far less). */
  if (R_UNLIKELY (flen > size || flen < R_SRTP_EKT_FULL_TRAILER + 16))
    return R_SRTP_ERROR_INVAL;
  field = data + size - flen;
  ctlen = flen - R_SRTP_EKT_FULL_TRAILER;
  if (R_UNLIKELY ((ctlen & 7) != 0 || ctlen > sizeof (pt) + 8))
    return R_SRTP_ERROR_INVAL;

  spi   = ((ruint16) field[ctlen] << 8) | field[ctlen + 1];
  epoch = ((ruint16) field[ctlen + 2] << 8) | field[ctlen + 3];
  if (R_UNLIKELY ((((rsize) field[ctlen + 4] << 8) | field[ctlen + 5]) != flen))
    return R_SRTP_ERROR_INVAL;
  if (R_UNLIKELY ((k = r_srtp_ekt_find_key (ctx->ekt, spi)) == NULL))
    return R_SRTP_ERROR_NO_CRYPTO_CTX;

  /* Already keyed at this epoch or newer for this SPI (the startup burst
   * repeats an epoch; a replay repeats or lowers it): keep the packet but skip
   * re-installing. Tracking is per (SPI, SSRC) so alternating SPIs cannot
   * sidestep the check (RFC 8870 4.3.2). The 16-bit epoch is treated as
   * strictly increasing; a wrap past 0xffff (2^16 rekeys of one SPI, not
   * reachable in practice) would stall re-keying rather than accept a replay. */
  rxhead = r_hash_table_lookup (ctx->ekt->rx, RUINT_TO_POINTER (ssrc));
  for (rxnode = rxhead; rxnode != NULL; rxnode = rxnode->next) {
    if (rxnode->spi == spi)
      break;
  }
  if (rxnode != NULL && epoch <= rxnode->epoch) {
    *fieldlen = flen;
    return R_SRTP_ERROR_OK;
  }

  if (R_UNLIKELY (!r_cipher_aes_key_unwrap_pad (k->kek, pt, &ptlen, field, ctlen)))
    return R_SRTP_ERROR_AUTH;

  mklen = pt[0];
  if (R_UNLIKELY (ptlen != 1 + mklen + 8)) {
    r_memclear (pt, sizeof (pt));
    return R_SRTP_ERROR_INVAL;
  }
  inner_ssrc = ((ruint32) pt[1 + mklen] << 24) | ((ruint32) pt[1 + mklen + 1] << 16) |
      ((ruint32) pt[1 + mklen + 2] << 8) | (ruint32) pt[1 + mklen + 3];
  roc = ((ruint32) pt[1 + mklen + 4] << 24) | ((ruint32) pt[1 + mklen + 5] << 16) |
      ((ruint32) pt[1 + mklen + 6] << 8) | (ruint32) pt[1 + mklen + 7];
  if (R_UNLIKELY (inner_ssrc != ssrc)) {
    /* RFC 8870 4.3.2: the EKTPlaintext SSRC must match the packet. */
    r_memclear (pt, sizeof (pt));
    return R_SRTP_ERROR_AUTH;
  }
  if (R_UNLIKELY (!r_srtp_ekt_install (ctx, k, ssrc, pt + 1, mklen, roc))) {
    r_memclear (pt, sizeof (pt));
    return R_SRTP_ERROR_INTERNAL;
  }
  r_memclear (pt, sizeof (pt));

  /* Record the epoch for this SPI, after installing: should the node alloc
   * fail, the worst case is a redundant re-install of this same authenticated
   * key on the next Full field -- recording before installing could instead
   * mark an epoch seen whose key never installed, locking that key out. A new
   * node links in after the head so the hash-table entry (the head pointer)
   * stays valid without a re-insert. */
  if (rxnode == NULL) {
    if ((rxnode = r_mem_new (RSRTPEktRx)) != NULL) {
      rxnode->spi = spi;
      if (rxhead != NULL) {
        rxnode->next = rxhead->next;
        rxhead->next = rxnode;
      } else {
        rxnode->next = NULL;
        r_hash_table_insert (ctx->ekt->rx, RUINT_TO_POINTER (ssrc), rxnode);
      }
    }
  }
  if (rxnode != NULL)
    rxnode->epoch = epoch;

  *fieldlen = flen;
  return R_SRTP_ERROR_OK;
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

      /* Key (or roll to) the active send key before touching the ciphers. */
      if ((err = r_srtp_stream_ensure_key (stream,
              stream->cctx->sendkey)) != R_SRTP_ERROR_OK)
        goto beach_map;

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
        /* EKT (RFC 8870): a Full field in the startup burst, else a Short field;
         * it trails the auth tag, so srtplen bounds the SRTP-authenticated part. */
        const RSRTPEktKey * ektkey = ctx->ekt != NULL ? ctx->ekt->sendkey : NULL;
        rboolean ekt_full = FALSE;
        rsize ektlen = 0;
        rsize srtplen = extlead + rtp.pay.size + tagsize + stream->rtpmkisize;
        rsize payloadsize;
        RBuffer * payload;

        if (ctx->ekt != NULL) {
          if (ektkey != NULL)
            ekt_full = r_srtp_ekt_tx_prepare (ctx->ekt, stream);
          ektlen = ekt_full ? r_srtp_ekt_full_size (ektkey) : 1;
        }
        payloadsize = srtplen + ektlen;

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

            /* MKI (RFC 3711 3.1): between the encrypted payload and the auth
             * tag, identifying the send key. Not covered by the auth tag. */
            if (stream->rtpmkisize > 0)
              r_memcpy (info.data + extlead + rtp.pay.size,
                  r_srtp_master_key_mki (stream->cctx->sendkey),
                  stream->rtpmkisize);

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
                r_memcpy (info.data + srtplen - tagsize, calctag, tagsize);
              } else {
                R_LOG_ERROR ("HMAC update for SRTP auth failed");
                err = R_SRTP_ERROR_INTERNAL;
                goto beach_map;
              }
            }

            /* EKT field (RFC 8870), appended after the auth tag; the SRTP auth
             * does not cover it (the Full field carries its own AES-KW check). */
            if (ekt_full) {
              rsize keysize = stream->cctx->csinfo->cipher->keybits / 8;
              const ruint8 * mk = r_srtp_master_key_blob (stream->cctx,
                  stream->cctx->sendkey, R_SRTP_DIRECTION_OUTBOUND);
              if (R_UNLIKELY (!r_srtp_ekt_build_full (ektkey, mk, keysize,
                      stream->ssrc, (ruint32)(idx >> 16), stream->ekt_tx_epoch,
                      info.data + srtplen))) {
                r_buffer_unmap (payload, &info);
                r_buffer_unref (payload);
                err = R_SRTP_ERROR_INTERNAL;
                goto beach_map;
              }
              r_srtp_ekt_tx_sent_full (ctx->ekt, stream);
            } else if (ektlen == 1) {
              info.data[srtplen] = R_SRTP_EKT_TYPE_SHORT;
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
  RBuffer * srtp;
  RBuffer * ektview = NULL;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;

  if (R_UNLIKELY (ctx == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
  if (R_UNLIKELY (packet == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
  srtp = packet;

  /* EKT (RFC 8870): the EKT field trails the SRTP packet. Ingest it (a Full
   * field installs the sender's key before we decrypt this same packet with
   * it) and decode the SRTP packet from a view with the field stripped. */
  if (ctx->ekt != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;
    rsize fieldlen = 0;
    ruint32 ssrc;

    if (R_UNLIKELY (!r_buffer_map (packet, &info, R_MEM_MAP_READ)))
      R_SRTP_ERRRET (R_SRTP_ERROR_BAD_RTP_HDR, beach);
    if (R_UNLIKELY (info.size < 12)) {
      r_buffer_unmap (packet, &info);
      R_SRTP_ERRRET (R_SRTP_ERROR_BAD_RTP_HDR, beach);
    }
    ssrc = ((ruint32) info.data[8] << 24) | ((ruint32) info.data[9] << 16) |
        ((ruint32) info.data[10] << 8) | (ruint32) info.data[11];
    err = r_srtp_ekt_ingest (ctx, ssrc, info.data, info.size, &fieldlen);
    r_buffer_unmap (packet, &info);
    if (R_UNLIKELY (err != R_SRTP_ERROR_OK))
      goto beach;
    if (R_UNLIKELY (fieldlen >= r_buffer_get_size (packet)))
      R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
    if (R_UNLIKELY ((ektview = r_buffer_view (packet, 0,
            r_buffer_get_size (packet) - fieldlen)) == NULL))
      R_SRTP_ERRRET (R_SRTP_ERROR_OOM, beach);
    srtp = ektview;
  }

  if (r_rtp_buffer_map (&rtp, srtp, R_MEM_MAP_READ)) {
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
        rboolean do_hdrext;
        rsize extlead;
        rsize payloadsize;
        RBuffer * payload;

        if (R_UNLIKELY (rtp.pay.size < tagsize + stream->rtpmkisize)) {
          err = R_SRTP_ERROR_INVAL;
          goto beach_map;
        }
        payloadsize = rtp.pay.size - tagsize - stream->rtpmkisize;

        /* Select the master key: by the packet's MKI when the context uses
         * one, else the sole key. A wrong pick just fails auth below, so
         * reading the MKI ahead of verification is not an oracle. */
        if (stream->rtpmkisize > 0) {
          const ruint8 * mki = rtp.pay.data + payloadsize;
          const RSRTPMasterKey * mk = r_srtp_find_master_key (stream->cctx, mki);
          if (R_UNLIKELY (mk == NULL)) {
            R_LOG_INFO ("stream: 0x%.8x - no master key matches packet MKI",
                stream->ssrc);
            err = R_SRTP_ERROR_NO_CRYPTO_CTX;
            goto beach_map;
          }
          if ((err = r_srtp_stream_ensure_key (stream, mk)) != R_SRTP_ERROR_OK)
            goto beach_map;
        } else if ((err = r_srtp_stream_ensure_key (stream,
                stream->cctx->keys)) != R_SRTP_ERROR_OK) {
          goto beach_map;
        }

        /* RFC 6904: an encrypted extension is decrypted into the front of the
         * output buffer (extlead bytes) only after the auth tag verifies. */
        do_hdrext = stream->hdrcipher != NULL && rtp.ext.data != NULL &&
            r_srtp_hdrext_profile_supported (rtp.ext.data, &profile);
        extlead = do_hdrext ? rtp.ext.size : 0;

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

            if (R_UNLIKELY ((ret = r_buffer_replace_byte_range (srtp,
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
    r_rtp_buffer_unmap (&rtp, srtp);
  } else {
    err = R_SRTP_ERROR_BAD_RTP_HDR;
  }

beach:
  if (ektview != NULL)
    r_buffer_unref (ektview);
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
      rsize tagsize, newsize, srtcplen, ektlen = 0;
      const RSRTPEktKey * ektkey = NULL;
      rboolean ekt_full = FALSE;
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

      /* Key (or roll to) the active send key before touching the ciphers. */
      if ((err = r_srtp_stream_ensure_key (stream,
              stream->cctx->sendkey)) != R_SRTP_ERROR_OK)
        goto beach_map;

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
      /* EKT (RFC 8870): Full field in the startup burst, else Short; it trails
       * the auth tag, so srtcplen bounds the SRTP-authenticated part. */
      ektkey = ctx->ekt != NULL ? ctx->ekt->sendkey : NULL;
      if (ctx->ekt != NULL) {
        if (ektkey != NULL)
          ekt_full = r_srtp_ekt_tx_prepare (ctx->ekt, stream);
        ektlen = ekt_full ? r_srtp_ekt_full_size (ektkey) : 1;
      }
      srtcplen = rtcp.info.size + sizeof (ruint32) + tagsize + stream->rtpmkisize;
      newsize = srtcplen + ektlen;
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

          /* MKI (RFC 3711 3.4): after the SRTCP index, before the auth tag,
           * identifying the send key. Not covered by the auth tag. */
          if (stream->rtpmkisize > 0) {
            r_memcpy (ptr, r_srtp_master_key_mki (stream->cctx->sendkey),
                stream->rtpmkisize);
            ptr += stream->rtpmkisize;
          }

          /* add auth tag */
          if (stream->rtcp.mac != NULL && tagsize > 0) {
            r_hmac_reset (stream->rtcp.mac);
            if (r_hmac_update (stream->rtcp.mac, info.data,
                  srtcplen - stream->rtpmkisize - tagsize)) {
              ruint8 calctag[32];
              rsize calcsize;

              r_hmac_get_data (stream->rtcp.mac, calctag, sizeof (calctag), &calcsize);
              r_memcpy (info.data + srtcplen - tagsize, calctag, tagsize);
            } else {
              R_LOG_ERROR ("HMAC update for SRTP auth failed");
              err = R_SRTP_ERROR_INTERNAL;
              goto beach_map;
            }
          }

          /* EKT field (RFC 8870), after the auth tag; not covered by it. */
          if (ekt_full) {
            rsize keysize = stream->cctx->csinfo->cipher->keybits / 8;
            const ruint8 * mk = r_srtp_master_key_blob (stream->cctx,
                stream->cctx->sendkey, R_SRTP_DIRECTION_OUTBOUND);
            if (R_UNLIKELY (!r_srtp_ekt_build_full (ektkey, mk, keysize,
                    stream->ssrc, (ruint32)(stream->rtp.index >> 16),
                    stream->ekt_tx_epoch, info.data + srtcplen))) {
              r_buffer_unmap (ret, &info);
              r_buffer_unref (ret);
              ret = NULL;
              err = R_SRTP_ERROR_INTERNAL;
              goto beach_map;
            }
            r_srtp_ekt_tx_sent_full (ctx->ekt, stream);
          } else if (ektlen == 1) {
            info.data[srtcplen] = R_SRTP_EKT_TYPE_SHORT;
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
  RBuffer * srtcp;
  RBuffer * ektview = NULL;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;

  if (R_UNLIKELY (ctx == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
  if (R_UNLIKELY (packet == NULL)) R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
  srtcp = packet;

  /* EKT (RFC 8870): ingest the trailing EKT field (a Full field installs the
   * sender's key) and decode the SRTCP packet from a view with it stripped.
   * The sender SSRC sits just after the 4-byte RTCP header. */
  if (ctx->ekt != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;
    rsize fieldlen = 0;
    ruint32 ssrc;

    if (R_UNLIKELY (!r_buffer_map (packet, &info, R_MEM_MAP_READ)))
      R_SRTP_ERRRET (R_SRTP_ERROR_BAD_RTP_HDR, beach);
    if (R_UNLIKELY (info.size < 8)) {
      r_buffer_unmap (packet, &info);
      R_SRTP_ERRRET (R_SRTP_ERROR_BAD_RTP_HDR, beach);
    }
    ssrc = ((ruint32) info.data[4] << 24) | ((ruint32) info.data[5] << 16) |
        ((ruint32) info.data[6] << 8) | (ruint32) info.data[7];
    err = r_srtp_ekt_ingest (ctx, ssrc, info.data, info.size, &fieldlen);
    r_buffer_unmap (packet, &info);
    if (R_UNLIKELY (err != R_SRTP_ERROR_OK))
      goto beach;
    if (R_UNLIKELY (fieldlen >= r_buffer_get_size (packet)))
      R_SRTP_ERRRET (R_SRTP_ERROR_INVAL, beach);
    if (R_UNLIKELY ((ektview = r_buffer_view (packet, 0,
            r_buffer_get_size (packet) - fieldlen)) == NULL))
      R_SRTP_ERRRET (R_SRTP_ERROR_OOM, beach);
    srtcp = ektview;
  }

  if (r_rtcp_buffer_map (&rtcp, srtcp, R_MEM_MAP_READ)) {
    RRTCPPacket * rtcppacket;
    RSRTPStream * stream;

    if ((rtcppacket = r_rtcp_buffer_get_first_packet (&rtcp)) != NULL &&
        (stream = r_srtp_get_stream (ctx, r_rtcp_packet_get_ssrc (rtcppacket),
            R_SRTP_DIRECTION_INBOUND)) != NULL) {
      rsize tagsize = stream->cctx->csinfo->srtp_tagbits / 8;
      const ruint8 * authtag;
      const ruint8 * srtpidx;
      ruint32 idx;
      rboolean ebit;

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
      ebit = (idx & R_SRTCP_E_BIT) != 0;
      idx &= ~R_SRTCP_E_BIT;

      /* Drop replays before deriving any keys: on an MKI context this keeps an
       * attacker from forcing repeated key derivation by replaying packets that
       * alternate between configured MKIs (the RTP path filters first too). */
      if ((err = r_srtp_stream_replay_check (&stream->rtcp, idx, stream->ssrc)) == R_SRTP_ERROR_OK) {
        rsize newsize = srtpidx - rtcp.info.data;

        /* Select the master key by the packet's MKI, which sits between the
         * SRTCP index and the auth tag (RFC 3711 3.4). A wrong pick just fails
         * auth below, so this is not a decryption oracle. */
        if (stream->rtpmkisize > 0) {
          const RSRTPMasterKey * mk = r_srtp_find_master_key (stream->cctx,
              srtpidx + sizeof (ruint32));
          if (R_UNLIKELY (mk == NULL)) {
            R_LOG_INFO ("stream: 0x%.8x - no master key matches packet MKI",
                stream->ssrc);
            err = R_SRTP_ERROR_NO_CRYPTO_CTX;
            goto beach_map;
          }
          if ((err = r_srtp_stream_ensure_key (stream, mk)) != R_SRTP_ERROR_OK)
            goto beach_map;
        } else if ((err = r_srtp_stream_ensure_key (stream,
                stream->cctx->keys)) != R_SRTP_ERROR_OK) {
          goto beach_map;
        }

        /* The SRTCP E-bit must agree with the negotiated cipher; checked here
         * as it needs the now-derived session state. */
        if (ebit) {
          if (stream->rtcp.cipher->info->type <= R_CRYPTO_CIPHER_ALGO_NULL) {
            R_LOG_INFO ("ssrc (0x%.8x) idx (0x%.8x) SRTCP e-bit mismatch",
                stream->ssrc, idx);
            err = R_SRTP_ERROR_E_BIT_MISMATCH;
            goto beach_map;
          }
        } else if (stream->rtcp.cipher->info->type > R_CRYPTO_CIPHER_ALGO_NULL) {
          R_LOG_INFO ("ssrc (0x%.8x) idx (0x%.8x) SRTCP e-bit mismatch",
              stream->ssrc, idx);
          err = R_SRTP_ERROR_E_BIT_MISMATCH;
          goto beach_map;
        }

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
    r_rtcp_buffer_unmap (&rtcp, srtcp);
  } else {
    err = R_SRTP_ERROR_BAD_RTP_HDR;
  }

beach:
  if (ektview != NULL)
    r_buffer_unref (ektview);
  if (errout != NULL)
    *errout = err;
  return ret;
}

