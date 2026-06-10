/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/net/rtlsclient.h>
#include "proto/rtls-private.h"

#include <rlib/crypto/rx509.h>

#include <rlib/data/rqueue.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

#define R_TLS_CLIENT_MAX_CHAIN  16

typedef enum {
  R_TLS_CLIENT_INITIAL = 0,
  R_TLS_CLIENT_SERVER_HELLO,        /* await ServerHello */
  R_TLS_CLIENT_CERTIFICATE,         /* await Certificate */
  R_TLS_CLIENT_SERVER_HELLO_DONE,   /* await ServerHelloDone (then send flight) */
  R_TLS_CLIENT_CHANGE_CIPHER,       /* await server ChangeCipherSpec */
  R_TLS_CLIENT_FINISHED,            /* await server Finished */
  R_TLS_CLIENT_APPDATA,
  R_TLS_CLIENT_ERROR,
} RTLSClientState;

typedef RTLSError (*RTLSClientStateFunc) (RTLSClient * client, const RTLSParser * parser);
typedef RBuffer * (*RTLSClientEncryptFunc) (RTLSClient * client, RBuffer * buf);
typedef RTLSError (*RTLSClientDecryptFunc) (RTLSParser * parser,
    const RCryptoCipher * cipher, RHmac * mac, rboolean etm, const ruint8 * salt);

typedef struct {
  RHmac * hmac;
  RCryptoCipher * cipher;
  ruint8 * fixediv;

  ruint16 epoch;
  ruint64 seqno;
  ruint16 msgseq;
} RTLSConnectionState;

struct RTLSClient {
  RRef ref;
  RTLSClientState state;

  RTLSClientEncryptFunc encrypt;
  RTLSClientDecryptFunc decrypt;
  RTLSPrfFunc prf;

  RMsgDigest * hshash;          /* created once the suite (hence its hash) is known */
  ruint8 * clienthello;         /* buffered ClientHello body, folded into hshash on ServerHello */
  rsize clienthellolen;
  ruint8 mastersecret[48];
  ruint8 clirandom[R_TLS_HELLO_RANDOM_BYTES];
  ruint8 servrandom[R_TLS_HELLO_RANDOM_BYTES];
  rboolean clirandompinned;

  RTLSVersion version;
  RTLSVersion recordver;
  RTLSCompressionMethod comp;
  const RTLSCipherSuiteInfo * csinfo;
  rboolean support_ext_master_secret;
  rboolean encrypt_then_mac;
  RSRTPCipherSuite dtls_srtp_profile;

  /* write direction = client, read direction = server (reversed from the
   * server, where the local side writes with the 'server' connection state). */
  RTLSConnectionState client;
  RTLSConnectionState server;

  RTLSCallbacks cb;
  rpointer userdata;
  RDestroyNotify notify;

  REvLoop * loop;
  RPrng * prng;
  RCryptoCert * peer_cert;

  RCryptoCert * cert;          /* own certificate for mTLS, or NULL */
  RCryptoKey * privkey;        /* own private key for mTLS, or NULL */
  rboolean cert_requested;     /* server sent a CertificateRequest */

  rboolean ecdhe;                  /* an ECDHE suite was negotiated */
  REcurveID ecdhe_curve;           /* the server-selected named group */
  RCryptoKey * ecdhe_key;          /* client ephemeral ECDH private key */
  RCryptoKey * ecdhe_server_pub;   /* server's ephemeral public point */

  RBuffer * inbuf;
  RQueue qsend;
};

R_LOG_CATEGORY_DEFINE_STATIC (tlsclicat, "tlsclient", "RLib TLS Client",
    R_CLR_FG_WHITE | R_CLR_BG_BLUE | R_CLR_FMT_BOLD);
#define R_LOG_CAT_DEFAULT &tlsclicat

void
r_tls_client_init (void)
{
  r_log_category_register (&tlsclicat);
}

static void
r_tls_client_free (RTLSClient * client)
{
  if (client->loop != NULL)
    r_ev_loop_unref (client->loop);
  if (client->notify != NULL)
    client->notify (client->userdata);
  if (client->prng != NULL)
    r_prng_unref (client->prng);
  if (client->peer_cert != NULL)
    r_crypto_cert_unref (client->peer_cert);
  if (client->cert != NULL)
    r_crypto_cert_unref (client->cert);
  if (client->privkey != NULL)
    r_crypto_key_unref (client->privkey);
  if (client->ecdhe_key != NULL)
    r_crypto_key_unref (client->ecdhe_key);
  if (client->ecdhe_server_pub != NULL)
    r_crypto_key_unref (client->ecdhe_server_pub);
  if (client->client.hmac != NULL)
    r_hmac_free (client->client.hmac);
  if (client->client.cipher != NULL)
    r_crypto_cipher_unref (client->client.cipher);
  r_free (client->client.fixediv);
  if (client->server.hmac != NULL)
    r_hmac_free (client->server.hmac);
  if (client->server.cipher != NULL)
    r_crypto_cipher_unref (client->server.cipher);
  r_free (client->server.fixediv);
  r_msg_digest_free (client->hshash);
  r_free (client->clienthello);

  if (client->inbuf != NULL)
    r_buffer_unref (client->inbuf);
  r_queue_clear (&client->qsend, r_buffer_unref);
  r_memclear_secure (client->mastersecret, sizeof (client->mastersecret));
  r_free (client);
}

static RTLSError
r_tls_client_null_decrypt (RTLSParser * parser, const RCryptoCipher * cipher,
    RHmac * mac, rboolean etm, const ruint8 * salt)
{
  (void) parser; (void) cipher; (void) mac; (void) etm; (void) salt;
  return R_TLS_ERROR_OK;
}

static RBuffer *
r_tls_client_null_encrypt (RTLSClient * client, RBuffer * buf)
{
  (void) client;
  return r_buffer_ref (buf);
}

RTLSClient *
r_tls_client_new (const RTLSCallbacks * cb, rpointer userdata, RDestroyNotify notify)
{
  RTLSClient * ret;

  if ((ret = r_mem_new0 (RTLSClient)) != NULL) {
    r_ref_init (ret, r_tls_client_free);

    r_memcpy (&ret->cb, cb, sizeof (RTLSCallbacks));
    ret->userdata = userdata;
    ret->notify = notify;
    r_queue_init (&ret->qsend);
    ret->decrypt = r_tls_client_null_decrypt;
    ret->encrypt = r_tls_client_null_encrypt;
  }

  return ret;
}

static RTLSError
r_tls_client_change_state (RTLSClient * client, RTLSClientState state)
{
  if (state > client->state) {
    R_LOG_DEBUG ("%p - state change %u -> %u", client, client->state, state);
    client->state = state;
    return R_TLS_ERROR_OK;
  }

  return R_TLS_ERROR_WRONG_STATE;
}

RTLSError
r_tls_client_set_cert (RTLSClient * client, RCryptoCert * cert, RCryptoKey * privkey)
{
  if (R_UNLIKELY (client == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (cert == NULL || privkey == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (client->state != R_TLS_CLIENT_INITIAL)) return R_TLS_ERROR_WRONG_STATE;

  if (client->cert != NULL)
    r_crypto_cert_unref (client->cert);
  if (client->privkey != NULL)
    r_crypto_key_unref (client->privkey);
  client->cert = r_crypto_cert_ref (cert);
  client->privkey = r_crypto_key_ref (privkey);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_client_set_random (RTLSClient * client,
    const ruint8 clirandom[R_TLS_HELLO_RANDOM_BYTES])
{
  if (R_UNLIKELY (client == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (clirandom == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (client->state != R_TLS_CLIENT_INITIAL))
    return R_TLS_ERROR_WRONG_STATE;

  r_memcpy (client->clirandom, clirandom, R_TLS_HELLO_RANDOM_BYTES);
  client->clirandompinned = TRUE;

  return R_TLS_ERROR_OK;
}

static RBuffer *
r_tls_client_alloc_buffer (RTLSClient * client)
{
  (void) client;
  return r_buffer_new_alloc (NULL, 4096, NULL);
}

static RBuffer *
r_tls_client_cipher_encrypt (RTLSClient * client, RBuffer * buf)
{
  RBuffer * ret;

  if (client->client.cipher->info->mode == R_CRYPTO_CIPHER_MODE_GCM) {
    if (r_tls_version_is_dtls (client->version))
      ret = r_dtls_encrypt_buffer_aead (buf, client->client.cipher, client->client.fixediv);
    else
      ret = r_tls_encrypt_buffer_aead (buf, client->client.seqno,
          client->client.cipher, client->client.fixediv);
  } else {
    ruint8 * iv = r_alloca (client->client.cipher->info->ivsize);
    r_prng_fill (client->prng, iv, client->client.cipher->info->ivsize);
    if (r_tls_version_is_dtls (client->version)) {
      ret = r_dtls_encrypt_buffer (buf,
          client->client.cipher, iv, client->client.hmac, client->encrypt_then_mac);
    } else {
      ret = r_tls_encrypt_buffer (buf, client->client.seqno,
          client->client.cipher, iv, client->client.hmac, client->encrypt_then_mac);
    }
  }

  return ret;
}

static RTLSError
r_tls_client_send_record (RTLSClient * client, RBuffer * buf)
{
  RTLSError ret;
  RBuffer * encbuf;

  if ((encbuf = client->encrypt (client, buf)) != NULL) {
    if (r_queue_push (&client->qsend, encbuf) != NULL) {
      client->client.seqno++;
      ret = R_TLS_ERROR_OK;
    } else {
      r_buffer_unref (encbuf);
      ret = R_TLS_ERROR_QUEUE_FULL;
    }
  } else {
    ret = R_TLS_ERROR_ENCRYPTION_FAILED;
  }

  return ret;
}

static void
r_tls_client_send_out (RTLSClient * client)
{
  RBuffer * buf;

  while ((buf = r_queue_pop (&client->qsend)) != NULL) {
    client->cb.out (client->userdata, buf, client);
    r_buffer_unref (buf);
  }
}

static void
r_tls_client_send_alert (RTLSClient * client, RTLSAlertType alert)
{
  RBuffer * buf;
  RTLSError ret = R_TLS_ERROR_OOM;
  RTLSVersion ver = (client->version != 0) ? client->version : client->recordver;

  R_LOG_WARNING ("Sending alert: 0x%.2x in state (%d)", alert, client->state);

  if ((buf = r_tls_client_alloc_buffer (client)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
      rsize sz = 0;

      if (r_tls_version_is_dtls (ver))
        ret = r_dtls_write_alert (info.data, info.size, &sz, ver,
            client->client.epoch, client->client.seqno,
            R_TLS_ALERT_LEVEL_FATAL, alert);
      else
        ret = r_tls_write_alert (info.data, info.size, &sz, ver,
            R_TLS_ALERT_LEVEL_FATAL, alert);
      r_buffer_unmap (buf, &info);

      if (ret == R_TLS_ERROR_OK) {
        r_buffer_set_size (buf, sz);
        ret = r_tls_client_send_record (client, buf);
      }
    }
    r_buffer_unref (buf);
  }

  if (ret == R_TLS_ERROR_OK)
    r_tls_client_send_out (client);

  if (client->cb.error != NULL)
    client->cb.error (client->userdata, alert, client);

  r_tls_client_change_state (client, R_TLS_CLIENT_ERROR);
}

/* ClientHello offers these extensions unconditionally (the server echoes the
 * ones it honours); use_srtp is offered for DTLS only. */
static ruint16
r_tls_client_write_hs_ext_renegotiation (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_RENEGOTIATION_INFO);
  r_store_be16 (&ptr[2], 1);
  ptr[4] = 0;
  return 5;
}

static ruint16
r_tls_client_write_hs_ext_extended_ms (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET);
  r_store_be16 (&ptr[2], 0);
  return 4;
}

static ruint16
r_tls_client_write_hs_ext_encrypt_then_mac (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_ENCRYPT_THEN_MAC);
  r_store_be16 (&ptr[2], 0);
  return 4;
}

static ruint16
r_tls_client_write_hs_ext_supported_groups (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_SUPPORTED_GROUPS);
  r_store_be16 (&ptr[2], 2 + 2 * sizeof (ruint16));   /* list length + 2 groups */
  r_store_be16 (&ptr[4], 2 * sizeof (ruint16));       /* named-group list length */
  r_store_be16 (&ptr[6], (ruint16)R_TLS_SUPPORTED_GROUP_SECP256R1);
  r_store_be16 (&ptr[8], (ruint16)R_TLS_SUPPORTED_GROUP_X25519);
  return 10;
}

static ruint16
r_tls_client_write_hs_ext_ec_point_formats (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_EC_POINT_FORMATS);
  r_store_be16 (&ptr[2], 2);
  ptr[4] = 1;                                         /* format list length */
  ptr[5] = R_TLS_EC_POINT_FORMAT_UNCOMPRESSED;
  return 6;
}

static ruint16
r_tls_client_write_hs_ext_use_srtp (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_USE_SRTP);
  r_store_be16 (&ptr[2], 5);
  r_store_be16 (&ptr[4], 1 * sizeof (ruint16));
  r_store_be16 (&ptr[6], (ruint16)R_SRTP_CS_AES_128_CM_HMAC_SHA1_80);
  ptr[8] = 0;                  /* empty MKI */
  return 9;
}

static rboolean
r_tls_client_default_cipher_suites (rpointer ctx, RTLSVersion ver,
    RTLSCipherSuite * cs, rsize * count)
{
  /* Most preferred first: AEAD (AES-GCM) over CBC, ECDHE (forward secrecy) over
   * static RSA, AES-128 over AES-256, SHA-256 MAC over SHA-1 as the tiebreak. */
  const RTLSCipherSuite preferred[] = {
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256,
    R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384,
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256,
    R_TLS_CS_RSA_WITH_AES_256_CBC_SHA256,
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_RSA_WITH_AES_256_CBC_SHA,
  };

  (void) ctx; (void) ver;

  *count = MIN (*count, R_N_ELEMENTS (preferred));
  r_memcpy (cs, preferred, *count * sizeof (RTLSCipherSuite));

  return TRUE;
}

static RTLSError
r_tls_client_send_hello (RTLSClient * client)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;
  RTLSCipherSuite cs[16];
  rsize ncs = R_N_ELEMENTS (cs);
  rboolean dtls = r_tls_version_is_dtls (client->version);

  R_LOG_DEBUG ("%p - client hello", client);

  if (!client->clirandompinned) {
    r_tls_generate_hello_random (client->clirandom, client->prng);
    client->clirandompinned = TRUE;
  }

  if (client->cb.preferred_cipher_suites == NULL ||
      !client->cb.preferred_cipher_suites (client->userdata, client->version, cs, &ncs)) {
    ncs = R_N_ELEMENTS (cs);
    r_tls_client_default_cipher_suites (client->userdata, client->version, cs, &ncs);
  }

  if ((buf = r_tls_client_alloc_buffer (client)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    ruint8 * ptr;
    rsize hssize, size = 0;
    ruint16 extsize;
    ruint8 hdrsize;

    if (dtls) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO, 0,
          client->client.epoch, client->client.seqno, client->client.msgseq, 0, 0);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO, 0);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }
    ptr = info.data + hssize;
    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_write_hs_client_hello (ptr, info.size - hssize, &size,
          client->version, client->clirandom, NULL, 0, NULL, 0,
          cs, (ruint16)ncs, client->comp);
    ptr += size;

    extsize = 0;
    extsize += r_tls_client_write_hs_ext_renegotiation (ptr + 2 + extsize);
    extsize += r_tls_client_write_hs_ext_extended_ms (ptr + 2 + extsize);
    extsize += r_tls_client_write_hs_ext_encrypt_then_mac (ptr + 2 + extsize);
    extsize += r_tls_client_write_hs_ext_supported_groups (ptr + 2 + extsize);
    extsize += r_tls_client_write_hs_ext_ec_point_formats (ptr + 2 + extsize);
    if (dtls)
      extsize += r_tls_client_write_hs_ext_use_srtp (ptr + 2 + extsize);
    r_store_be16 (ptr, extsize);
    ptr += extsize + 2;

    size = RPOINTER_TO_SIZE (ptr) - RPOINTER_TO_SIZE (info.data);
    if (ret == R_TLS_ERROR_OK) {
      if (dtls)
        ret = r_dtls_update_handshake_len (info.data, info.size,
            (ruint16)(size - hssize), 0, (ruint32)(size - hssize));
      else
        ret = r_tls_update_handshake_len (info.data, info.size, (ruint16)(size - hssize));

      /* Buffer the ClientHello handshake message; it is folded into the
       * transcript once the ServerHello picks the suite (hence the hash). */
      if (ret == R_TLS_ERROR_OK) {
        client->clienthellolen = size - hdrsize;
        if ((client->clienthello = r_memdup (info.data + hdrsize, client->clienthellolen)) == NULL)
          ret = R_TLS_ERROR_OOM;
      }
    }
    r_buffer_unmap (buf, &info);
    r_buffer_set_size (buf, size);

    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_client_send_record (client, buf);
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

RTLSError
r_tls_client_start (RTLSClient * client, REvLoop * loop, RPrng * prng,
    RTLSVersion version)
{
  if (R_UNLIKELY (client == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (loop == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (client->loop != NULL)) return R_TLS_ERROR_WRONG_STATE;
  if (R_UNLIKELY (version != R_TLS_VERSION_TLS_1_2 &&
        version != R_TLS_VERSION_DTLS_1_2))
    return R_TLS_ERROR_VERSION;

  R_LOG_DEBUG ("%p - start (ver %.4x)", client, version);

  if (prng != NULL) r_prng_ref (prng);
  client->loop = r_ev_loop_ref (loop);
  client->prng = prng;
  client->version = version;
  client->comp = R_TLS_COMPRESSION_NULL;

  /* The PRF and transcript hash depend on the suite the server selects, which
   * is not known until its ServerHello. The ClientHello is buffered and the
   * transcript started in nego_server_hello. */

  r_tls_client_change_state (client, R_TLS_CLIENT_SERVER_HELLO);

  if (r_tls_client_send_hello (client) != R_TLS_ERROR_OK)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  client->client.msgseq++;
  r_tls_client_send_out (client);

  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_client_nego_server_hello (RTLSClient * client, const RTLSParser * parser)
{
  RTLSHelloMsg hello;
  RTLSHelloExt ext;
  RTLSError r;

  if ((r = r_tls_parser_parse_hello (parser, &hello)) != R_TLS_ERROR_OK)
    return r;

  if (hello.version != client->version)
    return R_TLS_ERROR_VERSION;
  if (hello.cslen != sizeof (ruint16))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if ((client->csinfo = r_tls_cipher_suite_get_info (
          (RTLSCipherSuite) r_load_be16 (hello.cs))) == NULL ||
      !r_tls_cipher_suite_is_supported (client->csinfo->suite))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* The suite (hence its PRF / transcript hash) is now known: start the
   * transcript and fold in the buffered ClientHello. The ServerHello is folded
   * by the caller right after this returns. */
  if (R_UNLIKELY (client->hshash != NULL || client->clienthello == NULL))
    return R_TLS_ERROR_WRONG_STATE;
  if (!r_tls_prf_and_hash_for (client->csinfo->prf, &client->prf, &client->hshash))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  r_msg_digest_update (client->hshash, client->clienthello, client->clienthellolen);
  r_free (client->clienthello);     /* folded; no longer needed */
  client->clienthello = NULL;
  client->clienthellolen = 0;

  /* The key-exchange type is only known once the server picks the suite; the
   * ServerKeyExchange and ClientKeyExchange handling branch on this. */
  client->ecdhe = (client->csinfo->key_exchange == R_KEY_EXCHANGE_ECDHE_RSA);

  r_memcpy (client->servrandom, hello.random, R_TLS_HELLO_RANDOM_BYTES);

  for (r = r_tls_hello_msg_extension_first (&hello, &ext); r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (&hello, &ext)) {
    switch (ext.type) {
      case R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET:
        client->support_ext_master_secret = TRUE;
        break;
      case R_TLS_EXT_TYPE_ENCRYPT_THEN_MAC:
        if (client->csinfo->cipher->mode == R_CRYPTO_CIPHER_MODE_CBC)
          client->encrypt_then_mac = TRUE;
        break;
      case R_TLS_EXT_TYPE_USE_SRTP:
        if (r_tls_hello_ext_use_srtp_profile_count (&ext) > 0)
          client->dtls_srtp_profile = r_tls_hello_ext_use_srtp_profile (&ext, 0);
        break;
      default:
        break;
    }
  }

  return R_TLS_ERROR_OK;
}

/* RFC 7627: with extended master secret the seed is the handshake-transcript
 * hash through ClientKeyExchange; otherwise the client + server randoms. The
 * caller must have absorbed the ClientKeyExchange into hshash first. */
static RTLSError
r_tls_client_derive_master_secret (RTLSClient * client,
    const ruint8 * pms, rsize pmslen)
{
  if (client->support_ext_master_secret) {
    rsize hashsize = r_msg_digest_size (client->hshash);
    ruint8 * sessionhash = r_alloca (hashsize);

    if (!r_msg_digest_get_data (client->hshash, sessionhash, hashsize, NULL))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;

    return client->prf (client->mastersecret, sizeof (client->mastersecret),
        pms, pmslen, R_STR_WITH_SIZE_ARGS ("extended master secret"),
        sessionhash, hashsize, NULL);
  }

  return client->prf (client->mastersecret, sizeof (client->mastersecret),
      pms, pmslen, R_STR_WITH_SIZE_ARGS ("master secret"),
      client->clirandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
      client->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
      NULL);
}

static RTLSError
r_tls_client_expand_master_secret (RTLSClient * client)
{
  ruint8 keyblock[256];
  RTLSError ret;

  if (client->prf (keyblock, sizeof (keyblock),
        client->mastersecret, sizeof (client->mastersecret),
        R_STR_WITH_SIZE_ARGS ("key expansion"),
        client->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        client->clirandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        NULL) != R_TLS_ERROR_OK) {
    r_memclear_secure (keyblock, sizeof (keyblock));
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }

  {
    ruint8 * ptr = keyblock;
    rsize size;

    ret = R_TLS_ERROR_OK;

    /* keyblock: client MAC | server MAC | client key | server key |
     * client IV | server IV. The client writes with its own state and reads
     * with the server state. */
    if ((size = r_msg_digest_type_size (client->csinfo->mac)) > 0) {
      client->client.hmac = r_hmac_new (client->csinfo->mac, ptr, size); ptr += size;
      client->server.hmac = r_hmac_new (client->csinfo->mac, ptr, size); ptr += size;
      if (client->client.hmac == NULL || client->server.hmac == NULL)
        ret = R_TLS_ERROR_OOM;
    }
    if (ret == R_TLS_ERROR_OK && (size = client->csinfo->cipher->keybits / 8) > 0) {
      client->client.cipher = r_crypto_cipher_new (client->csinfo->cipher, ptr); ptr += size;
      client->server.cipher = r_crypto_cipher_new (client->csinfo->cipher, ptr); ptr += size;
      if (client->client.cipher == NULL || client->server.cipher == NULL)
        ret = R_TLS_ERROR_OOM;
    }
    /* IV — AEAD takes the 4-byte fixed salt (ivsize-8); CBC keeps ivsize. */
    if (ret == R_TLS_ERROR_OK) {
      const RCryptoCipherInfo * ci = client->csinfo->cipher;
      size = (ci->mode == R_CRYPTO_CIPHER_MODE_GCM) ?
          ci->ivsize - R_TLS_AEAD_EXPLICIT_NONCE_SIZE : ci->ivsize;
      if (size > 0) {
        client->client.fixediv = r_memdup (ptr, size); ptr += size;
        client->server.fixediv = r_memdup (ptr, size); ptr += size;
        if (client->client.fixediv == NULL || client->server.fixediv == NULL)
          ret = R_TLS_ERROR_OOM;
      }
    }
  }

  r_memclear_secure (keyblock, sizeof (keyblock));
  return ret;
}

static RTLSError
r_tls_client_send_certificate (RTLSClient * client)
{
  RBuffer * buf, * certder = NULL;
  RTLSError ret;
  RMemMapInfo info, dinfo = R_MEM_MAP_INFO_INIT;
  const ruint8 * der = NULL;
  rsize dersize = 0;

  if (client->cert != NULL) {
    if ((certder = r_crypto_cert_get_data_buffer (client->cert)) == NULL)
      return R_TLS_ERROR_NO_CERTIFICATE;
    if (!r_buffer_map (certder, &dinfo, R_MEM_MAP_READ)) {
      r_buffer_unref (certder);
      return R_TLS_ERROR_OOM;
    }
    der = dinfo.data;
    dersize = dinfo.size;
  }

  if ((buf = r_tls_client_alloc_buffer (client)) == NULL) {
    if (certder != NULL) { r_buffer_unmap (certder, &dinfo); r_buffer_unref (certder); }
    return R_TLS_ERROR_OOM;
  }

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hssize, bodylen;
    ruint8 hdrsize;
    rsize totalbody = 3 + ((der != NULL && dersize > 0) ? (3 + dersize) : 0);

    if (r_tls_version_is_dtls (client->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE, (ruint16)totalbody,
          client->client.epoch, client->client.seqno, client->client.msgseq,
          0, (ruint32)totalbody);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE, (ruint16)totalbody);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }

    if (ret == R_TLS_ERROR_OK &&
        (ret = r_tls_write_hs_certificate (info.data + hssize, info.size - hssize,
            &bodylen, der, dersize)) == R_TLS_ERROR_OK) {
      r_msg_digest_update (client->hshash, info.data + hdrsize,
          (hssize + bodylen) - hdrsize);
      r_buffer_unmap (buf, &info);
      r_buffer_set_size (buf, hssize + bodylen);
      ret = r_tls_client_send_record (client, buf);
    } else {
      r_buffer_unmap (buf, &info);
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  if (certder != NULL) { r_buffer_unmap (certder, &dinfo); r_buffer_unref (certder); }
  return ret;
}

static RTLSError
r_tls_client_send_certificate_verify (RTLSClient * client)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;
  ruint8 hash[64], sig[512];
  rsize hashsize = r_msg_digest_size (client->hshash);
  rsize sigsize = sizeof (sig);

  /* Sign the transcript through ClientKeyExchange (current hshash). */
  if (!r_msg_digest_get_data (client->hshash, hash, hashsize, NULL))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (r_crypto_key_sign (client->privkey, client->prng, R_MSG_DIGEST_TYPE_SHA256,
        hash, hashsize, sig, &sigsize) != R_CRYPTO_OK)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  if ((buf = r_tls_client_alloc_buffer (client)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hssize, bodylen;
    ruint8 hdrsize;
    rsize totalbody = sizeof (ruint16) + sizeof (ruint16) + sigsize;

    if (r_tls_version_is_dtls (client->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, (ruint16)totalbody,
          client->client.epoch, client->client.seqno, client->client.msgseq,
          0, (ruint32)totalbody);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, (ruint16)totalbody);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }

    if (ret == R_TLS_ERROR_OK &&
        (ret = r_tls_write_hs_certificate_verify (info.data + hssize, info.size - hssize,
            &bodylen, R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA256, sig, (ruint16)sigsize)) == R_TLS_ERROR_OK) {
      r_msg_digest_update (client->hshash, info.data + hdrsize,
          (hssize + bodylen) - hdrsize);
      r_buffer_unmap (buf, &info);
      r_buffer_set_size (buf, hssize + bodylen);
      ret = r_tls_client_send_record (client, buf);
    } else {
      r_buffer_unmap (buf, &info);
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

/* ECDHE ClientKeyExchange: send our ephemeral public point and compute the
 * premaster from the ECDH shared secret. */
static RTLSError
r_tls_client_send_key_exchange_ecdhe (RTLSClient * client, ruint8 pms[48], rsize * pmslen)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;
  ruint8 point[65];
  ruint8 pointlen;

  if (client->ecdhe_key == NULL || client->ecdhe_server_pub == NULL)
    return R_TLS_ERROR_WRONG_STATE;
  if (!r_tls_ecdhe_point_write (client->ecdhe_key, client->ecdhe_curve,
        point, sizeof (point), &pointlen))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!r_tls_ecdhe_compute (client->ecdhe_key, client->ecdhe_server_pub, pms, 48, pmslen))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  if ((buf = r_tls_client_alloc_buffer (client)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hssize;
    ruint8 hdrsize;
    ruint16 bodysize = (ruint16)(sizeof (ruint8) + pointlen);

    if (r_tls_version_is_dtls (client->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, bodysize,
          client->client.epoch, client->client.seqno, client->client.msgseq,
          0, bodysize);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, bodysize);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }

    if (ret == R_TLS_ERROR_OK) {
      info.data[hssize] = pointlen;
      r_memcpy (info.data + hssize + sizeof (ruint8), point, pointlen);
      r_msg_digest_update (client->hshash, info.data + hdrsize,
          hssize - hdrsize + bodysize);
      r_buffer_unmap (buf, &info);
      r_buffer_set_size (buf, hssize + bodysize);

      ret = r_tls_client_send_record (client, buf);
    } else {
      r_buffer_unmap (buf, &info);
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

static RTLSError
r_tls_client_send_key_exchange (RTLSClient * client, ruint8 pms[48], rsize * pmslen)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;
  RCryptoKey * pub;
  ruint8 enc[512];
  rsize enclen = sizeof (enc);

  if (client->ecdhe)
    return r_tls_client_send_key_exchange_ecdhe (client, pms, pmslen);

  *pmslen = 48;
  if ((pub = r_crypto_cert_get_public_key (client->peer_cert)) == NULL)
    return R_TLS_ERROR_NO_CERTIFICATE;

  pms[0] = (((ruint16)client->version) >> 8) & 0xff;
  pms[1] = (((ruint16)client->version)     ) & 0xff;
  r_prng_fill (client->prng, pms + 2, 48 - 2);

  if (r_crypto_key_encrypt (pub, client->prng, pms, 48, enc, &enclen) != R_CRYPTO_OK) {
    r_crypto_key_unref (pub);
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }
  r_crypto_key_unref (pub);

  if ((buf = r_tls_client_alloc_buffer (client)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hssize;
    ruint8 hdrsize;
    ruint16 bodysize = (ruint16)(sizeof (ruint16) + enclen);

    if (r_tls_version_is_dtls (client->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, bodysize,
          client->client.epoch, client->client.seqno, client->client.msgseq,
          0, bodysize);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          client->version, R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, bodysize);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }

    if (ret == R_TLS_ERROR_OK) {
      r_store_be16 (info.data + hssize, (ruint16)enclen);
      r_memcpy (info.data + hssize + sizeof (ruint16), enc, enclen);
      r_msg_digest_update (client->hshash, info.data + hdrsize,
          hssize - hdrsize + bodysize);
      r_buffer_unmap (buf, &info);
      r_buffer_set_size (buf, hssize + bodysize);

      ret = r_tls_client_send_record (client, buf);
    } else {
      r_buffer_unmap (buf, &info);
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

static RTLSError
r_tls_client_send_change_cipher (RTLSClient * client)
{
  RBuffer * buf;
  RTLSError ret;
  rsize size;
  RMemMapInfo info;

  if ((buf = r_tls_client_alloc_buffer (client)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    if (r_tls_version_is_dtls (client->version))
      ret = r_dtls_write_change_cipher (info.data, info.size, &size,
          client->version, client->client.epoch, client->client.seqno);
    else
      ret = r_tls_write_change_cipher (info.data, info.size, &size, client->version);
    r_buffer_unmap (buf, &info);
    r_buffer_set_size (buf, size);

    if (ret == R_TLS_ERROR_OK) {
      if ((ret = r_tls_client_send_record (client, buf)) == R_TLS_ERROR_OK) {
        client->client.epoch++;
        client->client.seqno = 0;
      }
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

static RTLSError
r_tls_client_send_finished (RTLSClient * client)
{
  RBuffer * buf;
  RTLSError ret;
  rsize size;
  RMemMapInfo info;

  if ((buf = r_tls_client_alloc_buffer (client)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize verifysize = 12, hashsize = r_msg_digest_size (client->hshash);
    ruint8 * hash = r_alloca (hashsize);
    ruint8 hdrsize;

    if (!r_msg_digest_get_data (client->hshash, hash, hashsize, NULL)) {
      r_buffer_unmap (buf, &info);
      r_buffer_unref (buf);
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    }

    if (r_tls_version_is_dtls (client->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &size,
          client->version, R_TLS_HANDSHAKE_TYPE_FINISHED, (ruint16)verifysize,
          client->client.epoch, client->client.seqno, client->client.msgseq,
          0, (ruint32)verifysize);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &size,
          client->version, R_TLS_HANDSHAKE_TYPE_FINISHED, (ruint16)verifysize);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }

    if (ret == R_TLS_ERROR_OK &&
        (ret = client->prf (info.data + size, verifysize,
            client->mastersecret, sizeof (client->mastersecret),
            R_STR_WITH_SIZE_ARGS ("client finished"),
            hash, hashsize, NULL)) == R_TLS_ERROR_OK) {
      /* hash our own Finished into the transcript for the server-Finished
       * verification that follows. */
      r_msg_digest_update (client->hshash, info.data + hdrsize,
          size - hdrsize + verifysize);
      r_buffer_unmap (buf, &info);
      size += verifysize;
      r_buffer_set_size (buf, size);

      ret = r_tls_client_send_record (client, buf);
    } else {
      r_buffer_unmap (buf, &info);
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

static RTLSError
r_tls_client_parse_finished (RTLSClient * client, const RTLSParser * parser)
{
  RTLSError ret;
  const ruint8 * verify_data;
  rsize size;

  if ((ret = r_tls_parser_parse_finished (parser, &verify_data, &size)) == R_TLS_ERROR_OK) {
    if (size >= 12 && size <= 64) {
      ruint8 * verify_calc = r_alloca (size);
      rsize hashsize = r_msg_digest_size (client->hshash);
      ruint8 * hash = r_alloca (hashsize);
      r_msg_digest_get_data (client->hshash, hash, hashsize, NULL);

      if ((ret = client->prf (verify_calc, size,
            client->mastersecret, sizeof (client->mastersecret),
            R_STR_WITH_SIZE_ARGS ("server finished"),
            hash, hashsize, NULL)) == R_TLS_ERROR_OK) {
        if (r_memcmp (verify_calc, verify_data, size) != 0) {
          R_LOG_WARNING ("Server Finished NOT verified");
          ret = R_TLS_ERROR_HS_VERIFICATION_FAILED;
        }
      }
    } else {
      ret = R_TLS_ERROR_CORRUPT_RECORD;
    }
  }

  return ret;
}

/* Build and send ClientKeyExchange, derive + install keys, send
 * ChangeCipherSpec and the (now encrypted) client Finished. */
static RTLSError
r_tls_client_send_flight (RTLSClient * client)
{
  RTLSError ret = R_TLS_ERROR_OK;
  ruint8 pms[48];
  rsize pmslen = sizeof (pms);

  /* mTLS: a Certificate (the configured one, or empty) precedes the
   * ClientKeyExchange when the server requested one. */
  if (client->cert_requested) {
    if ((ret = r_tls_client_send_certificate (client)) == R_TLS_ERROR_OK)
      client->client.msgseq++;
  }

  if (ret == R_TLS_ERROR_OK &&
      (ret = r_tls_client_send_key_exchange (client, pms, &pmslen)) == R_TLS_ERROR_OK)
    client->client.msgseq++;

  if (ret == R_TLS_ERROR_OK)
    ret = r_tls_client_derive_master_secret (client, pms, pmslen);
  r_memclear_secure (pms, sizeof (pms));
  if (ret == R_TLS_ERROR_OK)
    ret = r_tls_client_expand_master_secret (client);

  /* mTLS: prove possession of the certificate's private key, but only when a
   * real certificate was sent. */
  if (ret == R_TLS_ERROR_OK && client->cert_requested && client->cert != NULL) {
    if ((ret = r_tls_client_send_certificate_verify (client)) == R_TLS_ERROR_OK)
      client->client.msgseq++;
  }

  if (ret == R_TLS_ERROR_OK)
    ret = r_tls_client_send_change_cipher (client);
  if (ret == R_TLS_ERROR_OK) {
    client->encrypt = r_tls_client_cipher_encrypt;
    if ((ret = r_tls_client_send_finished (client)) == R_TLS_ERROR_OK)
      client->client.msgseq++;
  }

  return ret;
}

static RTLSError
r_tls_client_state_error (RTLSClient * client, const RTLSParser * parser)
{
  (void) client; (void) parser;
  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_client_state_server_hello (RTLSClient * client, const RTLSParser * parser)
{
  RTLSError err;
  RTLSHandshakeType type;

  if ((err = r_tls_parser_parse_handshake_peek_type (parser, &type)) == R_TLS_ERROR_OK) {
    if (type != R_TLS_HANDSHAKE_TYPE_SERVER_HELLO)
      err = R_TLS_ERROR_WRONG_TYPE;
    else if ((err = r_tls_client_nego_server_hello (client, parser)) == R_TLS_ERROR_OK)
      err = r_tls_client_change_state (client, R_TLS_CLIENT_CERTIFICATE);
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      break;
    case R_TLS_ERROR_WRONG_TYPE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
      break;
    case R_TLS_ERROR_VERSION:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_PROTOCOL_VERSION);
      break;
    case R_TLS_ERROR_HANDSHAKE_FAILURE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
      break;
    case R_TLS_ERROR_CORRUPT_RECORD:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_DECODE_ERROR);
      break;
    default:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
      break;
  }

  return err;
}

static RTLSError
r_tls_client_state_certificate (RTLSClient * client, const RTLSParser * parser)
{
  RTLSError err;
  RTLSHandshakeType type;
  RCryptoCert * chain[R_TLS_CLIENT_MAX_CHAIN];
  ruint n = 0, i;

  if ((err = r_tls_parser_parse_handshake_peek_type (parser, &type)) == R_TLS_ERROR_OK) {
    if (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE) {
      err = R_TLS_ERROR_WRONG_TYPE;
    } else {
      RTLSCertificate tlscert = R_TLS_CERTIFICATE_INIT;

      while (n < R_TLS_CLIENT_MAX_CHAIN &&
          r_tls_parser_parse_certificate_next (parser, &tlscert) == R_TLS_ERROR_OK) {
        if ((chain[n] = r_tls_certificate_get_cert (&tlscert)) != NULL)
          n++;
      }

      if (n == 0) {
        err = R_TLS_ERROR_NO_CERTIFICATE;
      } else if (client->cb.verify_cert != NULL &&
          !client->cb.verify_cert (client->userdata, chain, n)) {
        err = R_TLS_ERROR_CORRUPT_CERTIFICATE;
      } else {
        client->peer_cert = r_crypto_cert_ref (chain[0]);
        err = r_tls_client_change_state (client, R_TLS_CLIENT_SERVER_HELLO_DONE);
      }

      for (i = 0; i < n; i++)
        r_crypto_cert_unref (chain[i]);
    }
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      break;
    case R_TLS_ERROR_NO_CERTIFICATE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_NO_CERTIFICATE);
      break;
    case R_TLS_ERROR_CORRUPT_CERTIFICATE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_BAD_CERTIFICATE);
      break;
    case R_TLS_ERROR_WRONG_TYPE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
      break;
    default:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
      break;
  }

  return err;
}

/* Parse and verify an ECDHE ServerKeyExchange: check the signature over
 * client_random || server_random || ECParameters || ECPoint against the server
 * certificate, then stash the server's point and generate our ephemeral key.
 * The message is folded into the transcript by the caller, only on success. */
static RTLSError
r_tls_client_parse_server_key_exchange (RTLSClient * client, const RTLSParser * parser)
{
  RTLSEcCurveType curve_type;
  RTLSSupportedGroup named_curve;
  const ruint8 * point, * sig, * signed_params;
  ruint8 pointlen;
  RTLSSignatureScheme scheme;
  ruint16 sigsize;
  rsize signed_params_len, tbslen = 0, hashsize;
  REcurveID curve;
  RMsgDigestType md;
  RCryptoKey * pub;
  RMsgDigest * digest;
  ruint8 tbs[2 * R_TLS_HELLO_RANDOM_BYTES + 4 + 65];
  ruint8 hash[64];
  RTLSError err;

  if (!client->ecdhe || client->peer_cert == NULL)
    return R_TLS_ERROR_WRONG_STATE;
  /* exactly one ServerKeyExchange per handshake; a duplicate would otherwise
   * overwrite (and leak) the ephemeral keys */
  if (client->ecdhe_key != NULL || client->ecdhe_server_pub != NULL)
    return R_TLS_ERROR_WRONG_STATE;

  if ((err = r_tls_parser_parse_server_key_exchange_ecdhe (parser, &curve_type,
          &named_curve, &point, &pointlen, &scheme, &sig, &sigsize,
          &signed_params, &signed_params_len)) != R_TLS_ERROR_OK)
    return err;

  if (curve_type != R_TLS_EC_TYPE_NAMED_CURVE ||
      !r_tls_ecdhe_group_to_curve (named_curve, &curve) ||
      !r_tls_sign_scheme_to_md (scheme, &md))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (signed_params_len > sizeof (tbs) - 2 * R_TLS_HELLO_RANDOM_BYTES)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  r_memcpy (tbs + tbslen, client->clirandom, R_TLS_HELLO_RANDOM_BYTES);
  tbslen += R_TLS_HELLO_RANDOM_BYTES;
  r_memcpy (tbs + tbslen, client->servrandom, R_TLS_HELLO_RANDOM_BYTES);
  tbslen += R_TLS_HELLO_RANDOM_BYTES;
  r_memcpy (tbs + tbslen, signed_params, signed_params_len);
  tbslen += signed_params_len;

  if ((pub = r_crypto_cert_get_public_key (client->peer_cert)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  if ((digest = r_sha256_new ()) == NULL) {
    r_crypto_key_unref (pub);
    return R_TLS_ERROR_OOM;
  }
  r_msg_digest_update (digest, tbs, tbslen);
  hashsize = r_msg_digest_size (digest);
  if (!r_msg_digest_get_data (digest, hash, hashsize, NULL)) {
    r_msg_digest_free (digest);
    r_crypto_key_unref (pub);
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }
  r_msg_digest_free (digest);

  err = (r_crypto_key_verify (pub, md, hash, hashsize, sig, sigsize) == R_CRYPTO_OK) ?
      R_TLS_ERROR_OK : R_TLS_ERROR_HS_VERIFICATION_FAILED;   /* -> decrypt_error */
  r_crypto_key_unref (pub);
  if (err != R_TLS_ERROR_OK)
    return err;

  /* point_read decodes/checks the server's point; identity and zero secrets
   * are rejected when the shared secret is computed. */
  client->ecdhe_curve = curve;
  if ((client->ecdhe_server_pub = r_tls_ecdhe_point_read (curve, point, pointlen)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if ((client->ecdhe_key = r_tls_ecdhe_keygen (curve, client->prng)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_client_state_server_hello_done (RTLSClient * client, const RTLSParser * parser)
{
  RTLSError err;
  RTLSHandshakeType type;

  if ((err = r_tls_parser_parse_handshake_peek_type (parser, &type)) == R_TLS_ERROR_OK) {
    if (type == R_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE) {
      err = R_TLS_ERROR_OK;
    } else if (type == R_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST) {
      /* Remember to present a (configured or empty) certificate in our flight;
       * fold into the transcript and keep waiting for ServerHelloDone. */
      client->cert_requested = TRUE;
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      return R_TLS_ERROR_OK;
    } else if (type == R_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE) {
      /* ECDHE: verify the signed EC params before folding into the transcript.
       * The static-RSA path never sends this, so it is unexpected there. */
      if ((err = r_tls_client_parse_server_key_exchange (client, parser)) != R_TLS_ERROR_OK) {
        r_tls_client_send_alert (client, (err == R_TLS_ERROR_HS_VERIFICATION_FAILED) ?
            R_TLS_ALERT_TYPE_DECRYPT_ERROR : R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
        return err;
      }
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      return R_TLS_ERROR_OK;
    } else {
      err = R_TLS_ERROR_WRONG_TYPE;
    }
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      if ((err = r_tls_client_send_flight (client)) == R_TLS_ERROR_OK)
        err = r_tls_client_change_state (client, R_TLS_CLIENT_CHANGE_CIPHER);
      if (err != R_TLS_ERROR_OK)
        r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
      break;
    case R_TLS_ERROR_WRONG_TYPE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
      break;
    default:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
      break;
  }

  return err;
}

static RTLSError
r_tls_client_state_change_cipher (RTLSClient * client, const RTLSParser * parser)
{
  RTLSError err;

  if (parser->content == R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC)
    err = r_tls_client_change_state (client, R_TLS_CLIENT_FINISHED);
  else
    err = R_TLS_ERROR_WRONG_TYPE;

  switch (err) {
    case R_TLS_ERROR_OK:
      client->decrypt = r_tls_parser_decrypt;
      client->server.epoch++;
      client->server.seqno = 0;
      break;
    case R_TLS_ERROR_WRONG_TYPE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
      break;
    default:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
      break;
  }

  return err;
}

static RTLSError
r_tls_client_state_finished (RTLSClient * client, const RTLSParser * parser)
{
  RTLSError err;

  if ((err = r_tls_client_parse_finished (client, parser)) == R_TLS_ERROR_OK)
    err = r_tls_client_change_state (client, R_TLS_CLIENT_APPDATA);

  switch (err) {
    case R_TLS_ERROR_OK:
      r_msg_digest_free (client->hshash);
      client->hshash = NULL;
      if (client->cb.handshake_done != NULL)
        client->cb.handshake_done (client->userdata, client);
      break;
    case R_TLS_ERROR_HS_VERIFICATION_FAILED:
    case R_TLS_ERROR_HANDSHAKE_FAILURE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
      break;
    case R_TLS_ERROR_CORRUPT_RECORD:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_DECODE_ERROR);
      break;
    default:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
      break;
  }

  return err;
}

static RTLSError
r_tls_client_state_appdata (RTLSClient * client, const RTLSParser * parser)
{
  RBuffer * buf;

  if (parser->content == R_TLS_CONTENT_TYPE_APPLICATION_DATA) {
    if ((buf = r_buffer_view (parser->buf, parser->offset, parser->fragment.size)) != NULL) {
      client->cb.appdata (client->userdata, buf, client);
      r_buffer_unref (buf);
    }
  } else {
    R_LOG_WARNING ("Received non-app-data record");
  }

  return R_TLS_ERROR_OK;
}

rboolean
r_tls_client_incoming_data (RTLSClient * client, RBuffer * buffer)
{
  static RTLSClientStateFunc statefuncs[] = {
    r_tls_client_state_error,
    r_tls_client_state_server_hello,
    r_tls_client_state_certificate,
    r_tls_client_state_server_hello_done,
    r_tls_client_state_change_cipher,
    r_tls_client_state_finished,
    r_tls_client_state_appdata,
    r_tls_client_state_error,
  };
  /* Zero-init: a record that fails init_buffer never sets parser.buf, and the
   * post-loop r_tls_parser_clear must not free an uninitialised pointer. */
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSError err;

  if (R_UNLIKELY (client == NULL)) return FALSE;
  if (R_UNLIKELY (buffer == NULL)) return FALSE;

  if (client->inbuf == NULL) {
    client->inbuf = r_buffer_ref (buffer);
  } else {
    if (R_UNLIKELY (!r_buffer_append_mem_from_buffer (client->inbuf, buffer)))
      return FALSE;
  }

  for (err = r_tls_parser_init_buffer (&parser, client->inbuf);
      err == R_TLS_ERROR_OK;
      err = r_tls_parser_init_next (&parser, &client->inbuf)) {
    r_buffer_unref (client->inbuf);
    client->inbuf = NULL;

    client->recordver = parser.version;

    /* TLS carries no explicit record sequence number; feed the running read
     * counter to the MAC. (DTLS reads epoch/seqno from the record header.) */
    if (!r_tls_parser_is_dtls (&parser))
      parser.seqno = client->server.seqno;

    if (!r_tls_parser_is_dtls (&parser) || parser.epoch == client->server.epoch) {
      if ((err = client->decrypt (&parser, client->server.cipher, client->server.hmac,
              client->encrypt_then_mac, client->server.fixediv)) != R_TLS_ERROR_OK) {
        R_LOG_WARNING ("Decryption returned: %d", err);
        continue;
      }
    }

    client->server.seqno++;

    if (parser.content == R_TLS_CONTENT_TYPE_ALERT) {
      RTLSAlertLevel alevel;
      RTLSAlertType atype;

      if (r_tls_parser_parse_alert (&parser, &alevel, &atype) == R_TLS_ERROR_OK) {
        R_LOG_WARNING ("Received Alert, %.2x %.2x", alevel, atype);
        if (alevel == R_TLS_ALERT_LEVEL_FATAL) {
          if (client->cb.error != NULL)
            client->cb.error (client->userdata, atype, client);
          r_tls_client_change_state (client, R_TLS_CLIENT_ERROR);
        }
      } else {
        r_tls_client_change_state (client, R_TLS_CLIENT_ERROR);
      }
      continue;
    }

    do {
      err = statefuncs[client->state] (client, &parser);
    } while (err == R_TLS_ERROR_NOT_NEEDED);
  }

  r_tls_parser_clear (&parser);

  if (err >= R_TLS_ERROR_OK) {
    r_tls_client_send_out (client);
  } else {
    if (client->inbuf != NULL) {
      r_buffer_unref (client->inbuf);
      client->inbuf = NULL;
    }
    return (err == R_TLS_ERROR_BUF_TOO_SMALL);
  }

  return TRUE;
}

rboolean
r_tls_client_send_appdata (RTLSClient * client, RBuffer * buffer)
{
  RBuffer * rec;
  RMemMapInfo in = R_MEM_MAP_INFO_INIT, out = R_MEM_MAP_INFO_INIT;
  RTLSError ret = R_TLS_ERROR_OOM;
  rboolean dtls;
  rsize recsize;

  if (R_UNLIKELY (client == NULL || buffer == NULL)) return FALSE;
  if (R_UNLIKELY (client->state != R_TLS_CLIENT_APPDATA)) return FALSE;
  if (R_UNLIKELY (!r_buffer_map (buffer, &in, R_MEM_MAP_READ))) return FALSE;

  dtls = r_tls_version_is_dtls (client->version);
  recsize = (dtls ? R_DTLS_RECORD_HDR_SIZE : R_TLS_RECORD_HDR_SIZE) + in.size;

  if ((rec = r_buffer_new_alloc (NULL, recsize, NULL)) != NULL) {
    if (r_buffer_map (rec, &out, R_MEM_MAP_WRITE)) {
      if (dtls)
        ret = r_dtls_write_application_data (out.data, out.size, NULL,
            client->version, client->client.epoch, client->client.seqno,
            in.data, in.size);
      else
        ret = r_tls_write_application_data (out.data, out.size, NULL,
            client->version, in.data, in.size);
      r_buffer_unmap (rec, &out);
    }
  }
  r_buffer_unmap (buffer, &in);

  if (rec != NULL) {
    if (ret == R_TLS_ERROR_OK) {
      r_buffer_set_size (rec, recsize);
      ret = r_tls_client_send_record (client, rec);
    }
    r_buffer_unref (rec);
  }

  if (ret != R_TLS_ERROR_OK)
    return FALSE;

  r_tls_client_send_out (client);
  return TRUE;
}

RTLSError
r_tls_client_export_keying_material (const RTLSClient * client,
    ruint8 * material, rsize size, const rchar * label, rsize len,
    const ruint8 * ctx, rsize ctxsize)
{
  if (R_UNLIKELY (client == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (material == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size == 0)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (label == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (len == 0)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (client->state < R_TLS_CLIENT_CHANGE_CIPHER))
    return R_TLS_ERROR_WRONG_STATE;

  if (ctxsize == 0)
    ctx = NULL;

  return client->prf (material, size,
      client->mastersecret, sizeof (client->mastersecret), label, len,
      client->clirandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
      client->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
      ctx, ctxsize, NULL);
}

RTLSVersion
r_tls_client_get_version (const RTLSClient * client)
{
  return client->version;
}

const RTLSCipherSuiteInfo *
r_tls_client_get_cipher_suite (const RTLSClient * client)
{
  return client->csinfo;
}

RCryptoCert *
r_tls_client_get_peer_cert (const RTLSClient * client)
{
  return client->peer_cert;
}

RSRTPCipherSuite
r_tls_client_get_dtls_srtp_profile (const RTLSClient * client)
{
  return client->dtls_srtp_profile;
}
