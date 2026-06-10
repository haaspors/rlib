/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/net/rtlsserver.h>
#include "rtlssessiontickets-private.h"
#include "proto/rtls-private.h"

#include <rlib/crypto/rx509.h>

#include <rlib/data/rqueue.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>
#include <rlib/rtime.h>

typedef enum {
  R_TLS_SERVER_INITIAL = 0,
  R_TLS_SERVER_HELLO,
  R_TLS_SERVER_CERTIFICATE,
  R_TLS_SERVER_KEY_EXCHANGE,
  R_TLS_SERVER_CERTIFICATE_VERIFY,
  R_TLS_SERVER_CHANGE_CIPHER,
  R_TLS_SERVER_FINISHED,
  R_TLS_SERVER_APPDATA,
  R_TLS_SERVER_ERROR,
} RTLSServerState;

typedef RTLSError (*RTLSServerStateFunc) (RTLSServer * server, const RTLSParser * parser);
typedef RBuffer * (*RTLSServerEncryptFunc) (RTLSServer * server, RBuffer * buf);
typedef RTLSError (*RTLSServerDecryptFunc) (RTLSParser * parser,
    const RCryptoCipher * cipher, RHmac * mac, rboolean etm, const ruint8 * salt);

typedef struct {
  RHmac * hmac;
  RCryptoCipher * cipher;
  ruint8 * fixediv;

  ruint16 epoch;
  ruint64 seqno;
  ruint16 msgseq;
} RTLSConnectionState;

struct RTLSServer {
  RRef ref;
  RTLSServerState state;

  RTLSServerEncryptFunc encrypt;
  RTLSServerDecryptFunc decrypt;
  RTLSPrfFunc prf;

  RTLSHelloMsg hello;
  RBuffer * hellobuf;

  RMsgDigest * hshash;
  ruint8 mastersecret[48];
  ruint8 servrandom[R_TLS_HELLO_RANDOM_BYTES];
  rboolean servrandompinned;
  rboolean resumed;             /* abbreviated (RFC 5077) handshake in progress */
  ruint8 session_id[32];        /* session id sent in the ServerHello on resume */
  ruint8 session_id_len;

  RTLSVersion version;
  RTLSVersion recordver;        /* version of the last record seen, for pre-nego alerts */
  RTLSCompressionMethod comp;
  const RTLSCipherSuiteInfo * csinfo;
  rboolean support_renego;
  rboolean support_new_session_ticket;
  rboolean support_ext_master_secret;
  rboolean encrypt_then_mac;
  RSRTPCipherSuite dtls_srtp_profile;
  ruint8 srtp_mki_size;
  const ruint8 * srtp_mki;
  ruint8 * ticket;
  ruint16 ticketsize;
  RTLSSessionTicketKeys * ticket_keys;  /* shared STEK store; NULL disables tickets */

  RTLSConnectionState client;
  RTLSConnectionState server;

  RTLSCallbacks cb;
  rpointer userdata;
  RDestroyNotify notify;

  REvLoop * loop;
  RPrng * prng;
  RCryptoCert * cert;
  RCryptoKey * privkey;

  RTLSClientCertMode client_cert_mode;  /* mTLS policy; default NONE */
  rboolean client_cert_received;        /* a non-empty client cert was parsed */
  RCryptoCert * peer_cert;              /* client leaf cert, ref'd; NULL if none */
  RCryptoKey * peer_pubkey;             /* client leaf public key, for CertificateVerify */

  rboolean ecdhe;                       /* an ECDHE suite + curve were negotiated */
  REcurveID ecdhe_curve;                /* the negotiated named group */
  RCryptoKey * ecdhe_key;               /* server ephemeral ECDH private key */

  RBuffer * inbuf;
  RQueue qsend;
};

R_LOG_CATEGORY_DEFINE_STATIC (tlsservcat, "tlsserver", "RLib TLS Server",
    R_CLR_FG_WHITE | R_CLR_BG_MAGENTA | R_CLR_FMT_BOLD);
#define R_LOG_CAT_DEFAULT &tlsservcat

static inline void
_r_write_u24 (ruint8 * ptr, ruint32 u24)
{
  *ptr++ = (ruint8)(u24 >> 16) & 0xff;
  *ptr++ = (ruint8)(u24 >>  8) & 0xff;
  *ptr++ = (ruint8)(u24      ) & 0xff;
}

void
r_tls_server_init (void)
{
  r_log_category_register (&tlsservcat);
}

static void
r_tls_server_free (RTLSServer * server)
{
  if (server->hellobuf != NULL)
    r_buffer_unref (server->hellobuf);
  if (server->loop != NULL)
    r_ev_loop_unref (server->loop);
  if (server->notify != NULL)
    server->notify (server->userdata);
  if (server->prng != NULL)
    r_prng_unref (server->prng);
  if (server->cert != NULL)
    r_crypto_cert_unref (server->cert);
  if (server->privkey != NULL)
    r_crypto_key_unref (server->privkey);
  if (server->peer_cert != NULL)
    r_crypto_cert_unref (server->peer_cert);
  if (server->peer_pubkey != NULL)
    r_crypto_key_unref (server->peer_pubkey);
  if (server->ecdhe_key != NULL)
    r_crypto_key_unref (server->ecdhe_key);
  if (server->client.hmac != NULL)
    r_hmac_free (server->client.hmac);
  if (server->client.cipher != NULL)
    r_crypto_cipher_unref (server->client.cipher);
  r_free (server->client.fixediv);
  if (server->server.hmac != NULL)
    r_hmac_free (server->server.hmac);
  if (server->server.cipher != NULL)
    r_crypto_cipher_unref (server->server.cipher);
  r_free (server->server.fixediv);
  r_msg_digest_free (server->hshash);

  r_free (server->ticket);
  if (server->ticket_keys != NULL)
    r_tls_session_ticket_keys_unref (server->ticket_keys);
  r_queue_clear (&server->qsend, r_buffer_unref);
  /* Scrub key material before releasing the struct. */
  r_memclear_secure (server->mastersecret, sizeof (server->mastersecret));
  r_free (server);
}

static RTLSError
r_tls_server_null_decrypt (RTLSParser * parser, const RCryptoCipher * cipher,
    RHmac * mac, rboolean etm, const ruint8 * salt)
{
  (void) parser;
  (void) cipher;
  (void) mac;
  (void) etm;
  (void) salt;

  return R_TLS_ERROR_OK;
}

static RBuffer *
r_tls_server_null_encrypt (RTLSServer * server, RBuffer * buf)
{
  (void) server;
  return r_buffer_ref (buf);
}

RTLSServer *
r_tls_server_new (const RTLSCallbacks * cb, rpointer userdata, RDestroyNotify notify)
{
  RTLSServer * ret;

  if ((ret = r_mem_new0 (RTLSServer)) != NULL) {
    r_ref_init (ret, r_tls_server_free);

    r_memcpy (&ret->cb, cb, sizeof (RTLSCallbacks));
    ret->userdata = userdata;
    ret->notify = notify;
    r_queue_init (&ret->qsend);
    ret->decrypt = r_tls_server_null_decrypt;
    ret->encrypt = r_tls_server_null_encrypt;
  }

  return ret;
}

static RTLSError
r_tls_server_change_state (RTLSServer * server, RTLSServerState state)
{
  if (state > server->state) {
    R_LOG_DEBUG ("%p - state change %u -> %u", server, server->state, state);
    server->state = state;
    return R_TLS_ERROR_OK;
  }

  return R_TLS_ERROR_WRONG_STATE;
}

RTLSError
r_tls_server_set_cert (RTLSServer * server,
    RCryptoCert * cert, RCryptoKey * privkey)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (cert == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (privkey == NULL)) return R_TLS_ERROR_INVAL;

  if (server->cert != NULL)
    r_crypto_cert_unref (server->cert);
  if (server->privkey != NULL)
    r_crypto_key_unref (server->privkey);

  server->cert = r_crypto_cert_ref (cert);
  server->privkey = r_crypto_key_ref (privkey);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_server_set_client_cert_mode (RTLSServer * server, RTLSClientCertMode mode)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  /* The mode drives the ServerHello flight (CertificateRequest); fix it first. */
  if (R_UNLIKELY (server->state > R_TLS_SERVER_HELLO)) return R_TLS_ERROR_WRONG_STATE;

  server->client_cert_mode = mode;
  return R_TLS_ERROR_OK;
}

RCryptoCert *
r_tls_server_get_peer_cert (const RTLSServer * server)
{
  if (R_UNLIKELY (server == NULL)) return NULL;
  return server->peer_cert;
}

RTLSError
r_tls_server_set_session_ticket_keys (RTLSServer * server,
    RTLSSessionTicketKeys * keys)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (keys == NULL)) return R_TLS_ERROR_INVAL;

  if (server->ticket_keys != NULL)
    r_tls_session_ticket_keys_unref (server->ticket_keys);
  server->ticket_keys = r_tls_session_ticket_keys_ref (keys);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_server_set_random (RTLSServer * server,
    const ruint8 servrandom[R_TLS_HELLO_RANDOM_BYTES])
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (servrandom == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (server->state > R_TLS_SERVER_HELLO))
    return R_TLS_ERROR_WRONG_STATE;

  r_memcpy (server->servrandom, servrandom, R_TLS_HELLO_RANDOM_BYTES);
  server->servrandompinned = TRUE;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_server_start (RTLSServer * server, REvLoop * loop, RPrng * prng)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (loop == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (server->loop != NULL)) return R_TLS_ERROR_WRONG_STATE;

  R_LOG_DEBUG ("%p - start", server);

  if (server->prng != NULL)
    r_prng_unref (server->prng);
  if (prng != NULL)     r_prng_ref (prng);

  server->loop = r_ev_loop_ref (loop);
  server->prng = prng;

  return r_tls_server_change_state (server, R_TLS_SERVER_HELLO);
}

static RBuffer *
r_tls_server_cipher_encrypt (RTLSServer * server, RBuffer * buf)
{
  RBuffer * ret;

  R_LOG_TRACE ("Encrypting buffer %p", buf);
  if (server->server.cipher->info->mode == R_CRYPTO_CIPHER_MODE_GCM) {
    if (r_tls_version_is_dtls (server->version))
      ret = r_dtls_encrypt_buffer_aead (buf, server->server.cipher, server->server.fixediv);
    else
      ret = r_tls_encrypt_buffer_aead (buf, server->server.seqno,
          server->server.cipher, server->server.fixediv);
  } else {
    ruint8 * iv = r_alloca (server->server.cipher->info->ivsize);
    r_prng_fill (server->prng, iv, server->server.cipher->info->ivsize);
    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_encrypt_buffer (buf,
          server->server.cipher, iv, server->server.hmac, server->encrypt_then_mac);
    } else {
      ret = r_tls_encrypt_buffer (buf, server->server.seqno,
          server->server.cipher, iv, server->server.hmac, server->encrypt_then_mac);
    }
  }

  return ret;
}

static RTLSError
r_tls_server_send_record (RTLSServer * server, RBuffer * buf)
{
  RTLSError ret;
  RBuffer * encbuf;

  if ((encbuf = server->encrypt (server, buf)) != NULL) {
    if (r_queue_push (&server->qsend, encbuf) != NULL) {
      server->server.seqno++;
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

static RBuffer *
r_tls_server_alloc_buffer (RTLSServer * server)
{
  (void) server;
  return r_buffer_new_alloc (NULL, 4096, NULL);
}

static ruint16
r_tls_server_write_hs_ext_renegotiation (const RTLSServer * server, ruint8 * ptr)
{
  if (!server->support_renego)
    return 0;

  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_RENEGOTIATION_INFO);
  r_store_be16 (&ptr[2], 1);
  ptr[4] = 0;
  return 5;
}

static ruint16
r_tls_server_write_hs_ext_extended_ms (const RTLSServer * server, ruint8 * ptr)
{
  if (!server->support_ext_master_secret)
    return 0;

  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET);
  r_store_be16 (&ptr[2], 0);
  return 4;
}

static ruint16
r_tls_server_write_hs_ext_encrypt_then_mac (const RTLSServer * server, ruint8 * ptr)
{
  if (!server->encrypt_then_mac)
    return 0;

  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_ENCRYPT_THEN_MAC);
  r_store_be16 (&ptr[2], 0);
  return 4;
}

static ruint16
r_tls_server_write_hs_ext_session_ticket (const RTLSServer * server, ruint8 * ptr)
{
  /* The ticket itself is minted in the final flight (it binds the master
   * secret), so this only signals that a NewSessionTicket will follow.
   * Without a key store the server can neither seal nor later open a ticket,
   * so it makes no promise. On a resumed handshake no fresh ticket is issued,
   * so the extension must not be echoed (RFC 5077 3.4) -- promising a ticket
   * the abbreviated flight never sends would leave the client waiting. */
  if (!server->support_new_session_ticket || server->ticket_keys == NULL ||
      server->resumed)
    return 0;

  /* NewSessionTicket will come! */
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_SESSION_TICKET);
  r_store_be16 (&ptr[2], 0);

  return 4;
}

static ruint16
r_tls_server_write_hs_ext_ec_point_formats (const RTLSServer * server, ruint8 * ptr)
{
  /* Echo a one-entry ec_point_formats (uncompressed) for an ECDHE suite so
   * the client knows the SKE/CKE points are in SEC 1 uncompressed form. */
  if (!server->ecdhe)
    return 0;

  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_EC_POINT_FORMATS);
  r_store_be16 (&ptr[2], 2);
  ptr[4] = 1;                                       /* list length */
  ptr[5] = R_TLS_EC_POINT_FORMAT_UNCOMPRESSED;

  return 6;
}

static ruint16
r_tls_server_write_hs_ext_use_srtp (const RTLSServer * server, ruint8 * ptr)
{
  if (server->dtls_srtp_profile == R_SRTP_CS_NONE)
    return 0;

  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_USE_SRTP);
  r_store_be16 (&ptr[2], 5 + server->srtp_mki_size);
  r_store_be16 (&ptr[4], 1 * sizeof (ruint16));
  r_store_be16 (&ptr[6], (ruint16)server->dtls_srtp_profile);
  if ((ptr[8] = server->srtp_mki_size) > 0)
    r_memcpy (&ptr[9], server->srtp_mki, server->srtp_mki_size);

  return 9 + server->srtp_mki_size;
}

static RTLSError
r_tls_server_write_hello (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;
  ruint8 hdrsize;

  R_LOG_DEBUG ("%p - server hello", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    ruint8 * ptr;
    rsize hssize, size;
    ruint16 extsize;

    if (!server->servrandompinned) {
      r_tls_generate_hello_random (server->servrandom, server->prng);
      server->servrandompinned = TRUE;
    }

    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO, 0,
          server->server.epoch, server->server.seqno, server->server.msgseq,
          0, 0);
      ptr = info.data + hssize;
      ret = r_dtls_write_hs_server_hello (ptr, info.size - hssize, &size,
          server->version, server->servrandom,
          server->session_id, server->session_id_len,
          server->csinfo->suite, server->comp);
      ptr += size;
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO, 0);
      ptr = info.data + hssize;
      ret = r_tls_write_hs_server_hello (ptr, info.size - hssize, &size,
          server->version, server->servrandom,
          server->session_id, server->session_id_len,
          server->csinfo->suite, server->comp);
      ptr += size;
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }
    extsize = 0;
    extsize += r_tls_server_write_hs_ext_renegotiation (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_extended_ms (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_encrypt_then_mac (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_session_ticket (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_ec_point_formats (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_use_srtp (server, ptr + 2 + extsize);

    if (extsize > 0) {
      r_store_be16 (ptr, extsize);
      ptr += extsize + 2;
    }

    size = RPOINTER_TO_SIZE (ptr) - RPOINTER_TO_SIZE (info.data);
    if (ret == R_TLS_ERROR_OK) {
      if (r_tls_version_is_dtls (server->version)) {
        ret = r_dtls_update_handshake_len (info.data, info.size, (ruint16)(size - hssize),
            0, (ruint32)(size - hssize));
      } else {
        ret = r_tls_update_handshake_len (info.data, info.size, (ruint16)(size - hssize));
      }

      if (ret == R_TLS_ERROR_OK) {
        R_LOG_TRACE ("Updating HS hash with ServerHello %u bytes",
            (ruint)(size - hdrsize));
        r_msg_digest_update (server->hshash, info.data + hdrsize, size - hdrsize);
      }
    }
    r_buffer_unmap (buf, &info);
    r_buffer_set_size (buf, size);

    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_server_send_record (server, buf);
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

static RTLSError
r_tls_server_write_hello_done (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  rsize size;
  RMemMapInfo info;

  R_LOG_DEBUG ("%p - server hello done", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hdrsize;
    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &size,
          server->version, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE, 0,
          server->server.epoch, server->server.seqno, server->server.msgseq,
          0, 0);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &size,
          server->version, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE, 0);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }
    if (ret == R_TLS_ERROR_OK) {
      R_LOG_TRACE ("Updating HS hash with ServerHelloDone %u bytes",
          (ruint)(size - hdrsize));
      r_msg_digest_update (server->hshash, info.data + hdrsize, size - hdrsize);
    }
    r_buffer_unmap (buf, &info);
    r_buffer_set_size (buf, size);

    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_server_send_record (server, buf);
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

static RTLSError
r_tls_server_write_certificate (RTLSServer * server)
{
  RBuffer * buf, * certbuf;
  RTLSError ret;
  rsize size;
  RMemMapInfo info;

  R_LOG_DEBUG ("%p - server certificate", server);

  if ((certbuf = r_crypto_cert_get_data_buffer (server->cert)) == NULL)
    return R_TLS_ERROR_NO_CERTIFICATE;

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL) {
    r_buffer_unref (certbuf);
    return R_TLS_ERROR_OOM;
  }

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize certsize = r_buffer_get_size (certbuf);
    rsize hssize = 2 * (24 / 8) + certsize;
    rsize hdrsize;

    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &size,
          server->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE, (ruint16)hssize,
          server->server.epoch, server->server.seqno, server->server.msgseq,
          0, (ruint32)hssize);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &size,
          server->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE, (ruint16)hssize);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }

    if (ret == R_TLS_ERROR_OK) {
      _r_write_u24 (&info.data[size], (ruint32)(24 / 8 + certsize)); size += 24 / 8;
      _r_write_u24 (&info.data[size],          (ruint32)certsize); size += 24 / 8;

      r_msg_digest_update (server->hshash, info.data + hdrsize, size - hdrsize);

      r_buffer_unmap (buf, &info);
      r_buffer_set_size (buf, size);
      r_buffer_append_mem_from_buffer (buf, certbuf);

      r_buffer_map (certbuf, &info, R_MEM_MAP_READ);
      R_LOG_TRACE ("Updating HS hash with ServerCertificate %u bytes",
          (ruint)(size - hdrsize + info.size));
      r_msg_digest_update (server->hshash, info.data, info.size);
      r_buffer_unmap (certbuf, &info);

      ret = r_tls_server_send_record (server, buf);
    } else {
      r_buffer_unmap (buf, &info);
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  r_buffer_unref (certbuf);
  return ret;
}

static RTLSError
r_tls_server_write_key_exchange (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;
  ruint8 point[65];                     /* SEC 1 uncompressed P-256; x25519 is 32 */
  ruint8 tbs[2 * R_TLS_HELLO_RANDOM_BYTES + 4 + sizeof (point)];
  ruint8 hash[64];
  ruint8 sig[512];
  rsize tbslen = 0, hashsize, sigsize = sizeof (sig);
  ruint8 pointlen;
  RMsgDigest * md;
  RTLSSupportedGroup named_curve;
  RTLSSignatureScheme sigscheme;

  /* Only ephemeral (ECDHE) suites send a ServerKeyExchange; static RSA does
   * not, and the orchestrator only bumps the message sequence when we do. */
  if (!server->ecdhe)
    return R_TLS_ERROR_NOT_NEEDED;
  if (server->privkey == NULL)
    return R_TLS_ERROR_NO_CERTIFICATE;

  named_curve = (RTLSSupportedGroup)server->ecdhe_curve;

  if ((server->ecdhe_key = r_tls_ecdhe_keygen (server->ecdhe_curve, server->prng)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!r_tls_ecdhe_point_write (server->ecdhe_key, server->ecdhe_curve,
        point, sizeof (point), &pointlen))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* The signature covers client_random || server_random || ECParameters ||
   * ECPoint -- not the handshake transcript. */
  r_memcpy (tbs + tbslen, server->hello.random, R_TLS_HELLO_RANDOM_BYTES);
  tbslen += R_TLS_HELLO_RANDOM_BYTES;
  r_memcpy (tbs + tbslen, server->servrandom, R_TLS_HELLO_RANDOM_BYTES);
  tbslen += R_TLS_HELLO_RANDOM_BYTES;
  tbs[tbslen++] = R_TLS_EC_TYPE_NAMED_CURVE;
  r_store_be16 (tbs + tbslen, (ruint16)named_curve); tbslen += sizeof (ruint16);
  tbs[tbslen++] = pointlen;
  r_memcpy (tbs + tbslen, point, pointlen); tbslen += pointlen;

  if ((md = r_sha256_new ()) == NULL)
    return R_TLS_ERROR_OOM;
  r_msg_digest_update (md, tbs, tbslen);
  hashsize = r_msg_digest_size (md);
  if (!r_msg_digest_get_data (md, hash, hashsize, NULL)) {
    r_msg_digest_free (md);
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }
  r_msg_digest_free (md);

  /* The signature scheme follows the certificate key (RSA or ECDSA); both hash
   * with SHA-256, so the digest above is unchanged. */
  sigscheme = r_tls_sign_scheme_for_key (server->privkey);
  if (r_crypto_key_sign (server->privkey, server->prng, R_MSG_DIGEST_TYPE_SHA256,
        hash, hashsize, sig, &sigsize) != R_CRYPTO_OK)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  R_LOG_DEBUG ("%p - server key exchange (ECDHE)", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hssize, bodylen;
    ruint8 hdrsize = r_tls_version_is_dtls (server->version) ?
        R_DTLS_RECORD_HDR_SIZE : R_TLS_RECORD_HDR_SIZE;

    /* curve_type(1)+named_curve(2)+plen(1)+point + scheme(2)+siglen(2)+sig */
    bodylen = 1 + 2 + 1 + (rsize)pointlen + 2 + 2 + sigsize;
    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE, (ruint16)bodylen,
          server->server.epoch, server->server.seqno, server->server.msgseq,
          0, (ruint32)bodylen);
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE, (ruint16)bodylen);
    }

    if (ret == R_TLS_ERROR_OK &&
        (ret = r_tls_write_hs_server_key_exchange_ecdhe (info.data + hssize,
            info.size - hssize, &bodylen, R_TLS_EC_TYPE_NAMED_CURVE, named_curve,
            point, pointlen, sigscheme,
            sig, (ruint16)sigsize)) == R_TLS_ERROR_OK) {
      r_msg_digest_update (server->hshash, info.data + hdrsize,
          (hssize + bodylen) - hdrsize);
      r_buffer_unmap (buf, &info);
      r_buffer_set_size (buf, hssize + bodylen);
      ret = r_tls_server_send_record (server, buf);
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
r_tls_server_write_cert_req (RTLSServer * server)
{
  static const ruint8 certtypes[] = {
    R_TLS_CLIENT_CERT_TYPE_ECDSA_SIGN, R_TLS_CLIENT_CERT_TYPE_RSA_SIGN };
  static const RTLSSignatureScheme schemes[] = {
    R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256, R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA256 };
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;

  /* Only request a client certificate when mutual TLS is configured. */
  if (server->client_cert_mode == R_TLS_CLIENT_CERT_MODE_NONE)
    return R_TLS_ERROR_NOT_NEEDED;

  R_LOG_DEBUG ("%p - server certificate request", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hssize, bodylen;
    ruint8 hdrsize = r_tls_version_is_dtls (server->version) ?
        R_DTLS_RECORD_HDR_SIZE : R_TLS_RECORD_HDR_SIZE;

    /* cert-type count(1) + types + sig-scheme len(2) + schemes + CA len(2) */
    bodylen = 1 + R_N_ELEMENTS (certtypes) +
        2 + R_N_ELEMENTS (schemes) * sizeof (ruint16) + 2;
    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST, (ruint16)bodylen,
          server->server.epoch, server->server.seqno, server->server.msgseq,
          0, (ruint32)bodylen);
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST, (ruint16)bodylen);
    }

    if (ret == R_TLS_ERROR_OK &&
        (ret = r_tls_write_hs_certificate_request (info.data + hssize,
            info.size - hssize, &bodylen, certtypes, R_N_ELEMENTS (certtypes),
            schemes, R_N_ELEMENTS (schemes), NULL, 0)) == R_TLS_ERROR_OK) {
      r_msg_digest_update (server->hshash, info.data + hdrsize,
          (hssize + bodylen) - hdrsize);
      r_buffer_unmap (buf, &info);
      r_buffer_set_size (buf, hssize + bodylen);
      ret = r_tls_server_send_record (server, buf);
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
r_tls_server_write_change_cipher (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  rsize size;
  RMemMapInfo info;

  R_LOG_DEBUG ("%p - server change cipher", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_write_change_cipher (info.data, info.size, &size,
          server->version, server->server.epoch, server->server.seqno);
    } else {
      ret = r_tls_write_change_cipher (info.data, info.size, &size,
          server->version);
    }
    r_buffer_unmap (buf, &info);
    r_buffer_set_size (buf, size);

    if (ret == R_TLS_ERROR_OK) {
      if ((ret = r_tls_server_send_record (server, buf)) == R_TLS_ERROR_OK) {
        server->server.epoch++;
        server->server.seqno = 0;
      }
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

/* Serialized session state sealed inside a ticket (format version 2):
 *   version(1) | protocol(2) | cipher_suite(2) | ems(1) | issued_at(8) | ms(48)
 * issued_at is a wall-clock nanosecond stamp so the open side can enforce
 * expiry. r_tls_server_open_session_ticket parses the same layout. */
#define R_TLS_TICKET_STATE_VERSION    2
#define R_TLS_TICKET_STATE_SIZE       (1 + 2 + 2 + 1 + 8 + 48)

/* Mint the opaque session ticket: serialize the session state needed to resume
 * and seal it under the shared key store. The ticket stays opaque to the
 * client; only a server sharing the same RTLSSessionTicketKeys can open it. */
static RTLSError
r_tls_server_create_session_ticket (RTLSServer * server)
{
  ruint8 plain[R_TLS_TICKET_STATE_SIZE];
  ruint8 * ticket;
  rsize ticketsize;

  plain[0] = R_TLS_TICKET_STATE_VERSION;
  r_store_be16 (&plain[1], (ruint16)server->version);
  r_store_be16 (&plain[3], (ruint16)server->csinfo->suite);
  plain[5] = server->support_ext_master_secret ? 1 : 0;
  r_store_be64 (&plain[6], (ruint64)r_time_get_ts_wallclock ());
  r_memcpy (&plain[14], server->mastersecret, sizeof (server->mastersecret));

  if (!r_tls_session_ticket_keys_seal (server->ticket_keys, plain,
        sizeof (plain), &ticket, &ticketsize)) {
    r_memclear_secure (plain, sizeof (plain));
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }
  r_memclear_secure (plain, sizeof (plain));

  /* The NewSessionTicket carries the ticket length as a 16-bit field. */
  if (ticketsize > RUINT16_MAX) {
    r_free (ticket);
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }

  r_free (server->ticket);
  server->ticket = ticket;
  server->ticketsize = (ruint16)ticketsize;
  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_server_write_new_session_ticket (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;

  if (!server->support_new_session_ticket || server->ticket_keys == NULL)
    return R_TLS_ERROR_NOT_NEEDED;

  if (server->ticketsize == 0 &&
      (ret = r_tls_server_create_session_ticket (server)) != R_TLS_ERROR_OK)
    return ret;

  R_LOG_DEBUG ("%p - server new session ticket", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hssize, ntsize;
    ruint8 hdrsize = r_tls_version_is_dtls (server->version) ?
        R_DTLS_RECORD_HDR_SIZE : R_TLS_RECORD_HDR_SIZE;

    ntsize = sizeof (ruint32) + sizeof (ruint16) + server->ticketsize;
    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, (ruint16)ntsize,
          server->server.epoch, server->server.seqno, server->server.msgseq,
          0, (ruint32)ntsize);
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, (ruint16)ntsize);
    }

    if (ret == R_TLS_ERROR_OK) {
      if ((ret = r_tls_write_hs_new_session_ticket (info.data + hssize,
            info.size - hssize, &ntsize, R_TLS_SESSION_TICKET_LIFETIME,
            server->ticket, server->ticketsize)) == R_TLS_ERROR_OK) {
        /* The NewSessionTicket precedes the server Finished, so it is part of
         * that Finished's transcript hash. */
        r_msg_digest_update (server->hshash, info.data + hdrsize,
            hssize + ntsize - hdrsize);
        r_buffer_unmap (buf, &info);
        r_buffer_set_size (buf, hssize + ntsize);

        ret = r_tls_server_send_record (server, buf);
      } else {
        r_buffer_unmap (buf, &info);
      }
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
r_tls_server_write_finished (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  rsize size;
  RMemMapInfo info;
  ruint8 hdrsize = r_tls_version_is_dtls (server->version) ?
      R_DTLS_RECORD_HDR_SIZE : R_TLS_RECORD_HDR_SIZE;

  R_LOG_DEBUG ("%p - server finished", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize verifysize = 12, hashsize = r_msg_digest_size (server->hshash);
    ruint8 * hash = r_alloca (hashsize);
    rboolean haveh;

    /* On a resumed handshake the server Finished is sent before the client's,
     * so its verify_data covers the transcript so far and the digest must stay
     * open to absorb the server Finished (below) for the client-Finished check.
     * read it without finalizing. The full handshake sends its Finished last,
     * so it may finalize the digest here. */
    haveh = server->resumed ?
        r_msg_digest_get_data (server->hshash, hash, hashsize, NULL) :
        (r_msg_digest_finish (server->hshash) &&
         r_msg_digest_get_data (server->hshash, hash, hashsize, NULL));

    if (haveh) {
      if (r_tls_version_is_dtls (server->version)) {
        ret = r_dtls_write_handshake (info.data, info.size, &size,
            server->version, R_TLS_HANDSHAKE_TYPE_FINISHED, (ruint16)verifysize,
            server->server.epoch, server->server.seqno, server->server.msgseq,
            0, (ruint32)verifysize);
      } else {
        ret = r_tls_write_handshake (info.data, info.size, &size,
            server->version, R_TLS_HANDSHAKE_TYPE_FINISHED, (ruint16)verifysize);
      }
      if (ret == R_TLS_ERROR_OK &&
          (ret = server->prf (info.data + size, verifysize,
                              server->mastersecret, sizeof (server->mastersecret),
                              R_STR_WITH_SIZE_ARGS ("server finished"),
                              hash, hashsize, NULL)) == R_TLS_ERROR_OK) {
        /* Fold the server Finished into the transcript the client Finished
         * will be verified against (resume path only; the full path has
         * already finalized the digest). */
        if (server->resumed)
          r_msg_digest_update (server->hshash, info.data + hdrsize,
              (size + verifysize) - hdrsize);
        r_buffer_unmap (buf, &info);
        size += verifysize;
        r_buffer_set_size (buf, size);

        ret = r_tls_server_send_record (server, buf);
      } else {
        r_buffer_unmap (buf, &info);
      }
    } else {
      r_buffer_unmap (buf, &info);
      ret = R_TLS_ERROR_HANDSHAKE_FAILURE;;
    }
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_buffer_unref (buf);
  return ret;
}

static rboolean
r_tls_server_default_cipher_suites (rpointer ctx, RTLSVersion ver,
    RTLSCipherSuite * cs, rsize * count)
{
  const RTLSCipherSuite preferred[] = { R_TLS_DEFAULT_CIPHER_SUITES };

  (void)ctx;
  (void)ver;

  *count = MIN (*count, R_N_ELEMENTS (preferred));
  r_memcpy (cs, preferred, *count * sizeof (RTLSCipherSuite));

  return TRUE;
}

/* Clamp the attacker-declared entry count of a hello-extension list to what the
 * extension body can actually hold, so a bogus inner length can't drive reads
 * past ext->data[ext->len]. @hdr is the list-length prefix (1 or 2 bytes),
 * @esz the per-entry size. */
static ruint16
r_tls_ext_list_count (const RTLSHelloExt * ext, ruint16 declared,
    rsize hdr, rsize esz)
{
  rsize avail = (ext->len > hdr) ? (ext->len - hdr) / esz : 0;
  return ((rsize)declared < avail) ? declared : (ruint16)avail;
}

/* Pick a named curve for ECDHE from the ClientHello's supported_groups, gated
 * by the curves we implement. A Weierstrass curve additionally needs the peer
 * to accept uncompressed points (ec_point_formats); per RFC 4492 5.1 an absent
 * extension implies uncompressed is acceptable. Point formats do not apply to
 * the Montgomery curves (RFC 8422 5.1.2). Returns the first usable group in
 * client order, or FALSE if none. */
static rboolean
r_tls_server_nego_ecdhe_curve (RTLSServer * server, REcurveID * out)
{
  RTLSHelloExt ext = R_TLS_HELLO_EXT_INIT;
  RTLSError r;
  rboolean have_uncompressed = TRUE;
  ruint16 n, i;

  for (r = r_tls_hello_msg_extension_first (&server->hello, &ext);
      r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (&server->hello, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_EC_POINT_FORMATS) {
      have_uncompressed = FALSE;
      n = r_tls_ext_list_count (&ext, r_tls_hello_ext_ec_point_format_count (&ext),
          sizeof (ruint8), sizeof (ruint8));
      for (i = 0; i < n; i++) {
        if (r_tls_hello_ext_ec_point_format (&ext, i) ==
            R_TLS_EC_POINT_FORMAT_UNCOMPRESSED) {
          have_uncompressed = TRUE;
          break;
        }
      }
      break;
    }
  }

  for (r = r_tls_hello_msg_extension_first (&server->hello, &ext);
      r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (&server->hello, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_SUPPORTED_GROUPS) {
      n = r_tls_ext_list_count (&ext, r_tls_hello_ext_supported_groups_count (&ext),
          sizeof (ruint16), sizeof (ruint16));
      for (i = 0; i < n; i++) {
        REcurveID c;
        if (r_tls_ecdhe_group_to_curve (r_tls_hello_ext_supported_group (&ext, i), &c) &&
            (r_tls_ecdhe_curve_is_montgomery (c) || have_uncompressed)) {
          *out = c;
          return TRUE;
        }
      }
      break;
    }
  }

  return FALSE;
}

static RTLSError
r_tls_server_nego_hello (RTLSServer * server, RTLSVersion verlo, RTLSVersion verhi)
{
  RTLSHelloExt hsext = R_TLS_HELLO_EXT_INIT;
  RTLSError r;
  ruint16 count, i;
  RTLSCipherSuite preferred[] = {
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE,
    R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE, R_TLS_CS_NONE
  };
  RTLSCipherSuite * incoming;
  RTLSCipherSuite cs;
  rsize psize;

  /* Version check! */
  /* FIXME: Support something else than DTLS/TLS 1.2 */
  if (r_tls_version_is_dtls (verlo)) {
    if (!r_tls_version_is_dtls (verhi)) return R_TLS_ERROR_VERSION;
    if (verlo < R_TLS_VERSION_DTLS_1_2 || verhi > R_TLS_VERSION_DTLS_1_2)
      return R_TLS_ERROR_VERSION;
    server->version = R_TLS_VERSION_DTLS_1_2;
  } else {
    if (r_tls_version_is_dtls (verhi)) return R_TLS_ERROR_VERSION;
    if (verlo > R_TLS_VERSION_TLS_1_2 || verhi < R_TLS_VERSION_TLS_1_2)
      return R_TLS_ERROR_VERSION;
    server->version = R_TLS_VERSION_TLS_1_2;
  }

  R_LOG_DEBUG ("%p - ver %.4x", server, server->version);

  if (R_UNLIKELY (server->hello.cslen == 0 || (server->hello.cslen & 1)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  count = server->hello.cslen / sizeof (ruint16);
  incoming = r_mem_newa_n (RTLSCipherSuite, count);
  for (i = 0; i < count; i++)
    incoming[i] = (RTLSCipherSuite) r_load_be16 (server->hello.cs + i * sizeof (ruint16));

  /* Compression */
  server->comp = R_TLS_COMPRESSION_NULL;

  /* Cipher suite */
  psize = R_N_ELEMENTS (preferred);
  if (server->cb.preferred_cipher_suites == NULL ||
      !server->cb.preferred_cipher_suites (server->userdata, server->version,
        preferred, &psize)) {
    psize = R_N_ELEMENTS (preferred);
    r_tls_server_default_cipher_suites (server->userdata, server->version,
        preferred, &psize);
  }

  /* Drop ECDHE suites from the preference list when the client offered no
   * curve we can do an ephemeral exchange on, so the filter falls back to a
   * static-RSA suite rather than selecting an unusable ECDHE one. */
  {
    rboolean have_curve = r_tls_server_nego_ecdhe_curve (server, &server->ecdhe_curve);
    RCryptoAlgorithm certalgo = (server->privkey != NULL) ?
        r_crypto_key_get_algo (server->privkey) : R_CRYPTO_ALGO_TYPE_COUNT;
    rsize w = 0, k;

    for (k = 0; k < psize; k++) {
      const RTLSCipherSuiteInfo * pi = r_tls_cipher_suite_get_info (preferred[k]);
      RKeyExchangeType kx;

      if (pi == NULL)
        continue;
      kx = pi->key_exchange;

      /* The suite's authentication must match the certificate key: ECDHE_ECDSA
       * needs an ECDSA cert; RSA / ECDHE_RSA need an RSA cert. */
      if (kx == R_KEY_EXCHANGE_ECDHE_ECDSA) {
        if (certalgo != R_CRYPTO_ALGO_ECDSA)
          continue;
      } else if (kx == R_KEY_EXCHANGE_RSA || kx == R_KEY_EXCHANGE_ECDHE_RSA) {
        if (certalgo != R_CRYPTO_ALGO_RSA)
          continue;
      }
      /* Ephemeral suites need a curve the client offered. */
      if ((kx == R_KEY_EXCHANGE_ECDHE_RSA || kx == R_KEY_EXCHANGE_ECDHE_ECDSA) &&
          !have_curve)
        continue;

      preferred[w++] = preferred[k];
    }
    psize = w;
  }

  if ((cs = r_tls_cipher_suite_filter (incoming, count, preferred, (ruint)psize)) == R_TLS_CS_NONE ||
      (server->csinfo = r_tls_cipher_suite_get_info (cs)) == NULL) {
    R_LOG_WARNING ("No common cipher suites (in: %u, preferred: %u)",
        (ruint)count, (ruint)R_N_ELEMENTS (preferred));
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }

  server->ecdhe = (server->csinfo->key_exchange == R_KEY_EXCHANGE_ECDHE_RSA ||
      server->csinfo->key_exchange == R_KEY_EXCHANGE_ECDHE_ECDSA);

  R_LOG_DEBUG ("%p - cipher site %s", server, server->csinfo->str);

  switch (server->version) {
    case R_TLS_VERSION_DTLS_1_2:
    case R_TLS_VERSION_TLS_1_2:
      /* The PRF and transcript hash follow the negotiated suite (SHA-256 for
       * every suite except the AES-256-GCM ones, which are SHA-384). */
      if (!r_tls_prf_and_hash_for (server->csinfo->prf, &server->prf, &server->hshash))
        return R_TLS_ERROR_HANDSHAKE_FAILURE;
      break;
    default:
      return R_TLS_ERROR_VERSION;
  }

  server->support_renego = FALSE;
  server->support_new_session_ticket = FALSE;
  server->support_ext_master_secret = FALSE;
  server->encrypt_then_mac = FALSE;
  server->dtls_srtp_profile = R_SRTP_CS_NONE;

  for (r = r_tls_hello_msg_extension_first (&server->hello, &hsext);
      r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (&server->hello, &hsext)) {
    switch (hsext.type) {
      case R_TLS_EXT_TYPE_RENEGOTIATION_INFO:
        server->support_renego = TRUE;
        /* RFC 5746: extension_data is renegotiated_connection<0..255> (a
         * 1-byte length prefix). It must be empty on the initial handshake;
         * rlib does not renegotiate, so a non-empty value is rejected. */
        if (hsext.len < 1 || hsext.data[0] != hsext.len - 1)
          return R_TLS_ERROR_CORRUPT_RECORD;
        if (hsext.data[0] != 0)
          return R_TLS_ERROR_HANDSHAKE_FAILURE;
        break;
      case R_TLS_EXT_TYPE_SESSION_TICKET:
        server->support_new_session_ticket = TRUE;
        break;
      case R_TLS_EXT_TYPE_USE_SRTP:
        /* FIXME: Use SRTP cipher suite API */
        count = r_tls_ext_list_count (&hsext,
            r_tls_hello_ext_use_srtp_profile_count (&hsext), sizeof (ruint16), sizeof (ruint16));
        for (i = 0; i < count; i++) {
          if (r_tls_hello_ext_use_srtp_profile (&hsext, i) == R_SRTP_CS_AES_128_CM_HMAC_SHA1_80) {
            server->dtls_srtp_profile = R_SRTP_CS_AES_128_CM_HMAC_SHA1_80;
            break;
          } else if (r_tls_hello_ext_use_srtp_profile (&hsext, i) == R_SRTP_CS_AES_128_CM_HMAC_SHA1_32) {
            server->dtls_srtp_profile = R_SRTP_CS_AES_128_CM_HMAC_SHA1_32;
          }
        }
        break;
      case R_TLS_EXT_TYPE_ENCRYPT_THEN_MAC:
        /* RFC 7366: only applies to block (CBC) cipher suites; AEAD and
         * stream/NULL suites ignore it. */
        if (server->csinfo->cipher->mode == R_CRYPTO_CIPHER_MODE_CBC)
          server->encrypt_then_mac = TRUE;
        break;
      case R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET:
        server->support_ext_master_secret = TRUE;
        break;
      case R_TLS_EXT_TYPE_SIGNATURE_ALGORITHMS:
        /* Honour the client's signature_algorithms for the schemes we actually
         * sign with (ServerKeyExchange on ECDHE suites). If the client offered
         * the extension but not our certificate's scheme, we cannot satisfy it.
         * An absent extension means no constraint (RFC 5246 7.4.1.4.1). */
        if (server->ecdhe && server->privkey != NULL) {
          RTLSSignatureScheme want = r_tls_sign_scheme_for_key (server->privkey);
          rboolean ok = FALSE;

          /* Bound the scheme count by the actual extension length: the inner
           * list-length word is attacker-controlled, so it must not drive reads
           * past hsext.data[hsext.len]. */
          if (hsext.len >= sizeof (ruint16)) {
            count = r_tls_hello_ext_sign_scheme_count (&hsext);
            if (count > (hsext.len - sizeof (ruint16)) / sizeof (ruint16))
              count = (hsext.len - sizeof (ruint16)) / sizeof (ruint16);
            for (i = 0; i < count; i++) {
              if (r_tls_hello_ext_sign_scheme (&hsext, i) == want) {
                ok = TRUE;
                break;
              }
            }
          }
          if (!ok)
            return R_TLS_ERROR_HANDSHAKE_FAILURE;
        }
        break;
      default:
        break;
    }
  }

  /* RFC 5746 3.6: the SCSV signals secure-renegotiation support just like
   * an empty renegotiation_info extension. */
  if (r_tls_hello_msg_has_cipher_suite (&server->hello,
        R_TLS_CS_EMPTY_RENEGOTIATION_INFO_SCSV))
    server->support_renego = TRUE;

  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_server_parse_client_certificate (RTLSServer * server,
    const RTLSParser * parser)
{
  RCryptoCert * chain[16];
  RTLSCertificate tlscert = R_TLS_CERTIFICATE_INIT;
  ruint n = 0, i;
  RTLSError err = R_TLS_ERROR_OK;

  while (n < R_N_ELEMENTS (chain) &&
      r_tls_parser_parse_certificate_next (parser, &tlscert) == R_TLS_ERROR_OK) {
    if ((chain[n] = r_tls_certificate_get_cert (&tlscert)) != NULL)
      n++;
  }

  if (n == 0) {
    /* TLS 1.2: a client with no suitable certificate sends an empty list rather
     * than the SSLv3 no_certificate alert. */
    if (server->client_cert_mode == R_TLS_CLIENT_CERT_MODE_REQUIRE)
      return R_TLS_ERROR_NO_CERTIFICATE;          /* -> handshake_failure */
    server->client_cert_received = FALSE;          /* REQUEST: proceed unauthenticated */
    return R_TLS_ERROR_OK;
  }

  /* Trust/chain validation is delegated to the caller's verify_cert callback
   * (as on the client side); keep the leaf for the CertificateVerify check. */
  if (server->cb.verify_cert != NULL &&
      !server->cb.verify_cert (server->userdata, chain, n)) {
    err = R_TLS_ERROR_CORRUPT_CERTIFICATE;         /* -> bad_certificate */
  } else if ((server->peer_pubkey = r_crypto_cert_get_public_key (chain[0])) == NULL) {
    err = R_TLS_ERROR_CORRUPT_CERTIFICATE;
  } else {
    server->peer_cert = r_crypto_cert_ref (chain[0]);
    server->client_cert_received = TRUE;
  }

  for (i = 0; i < n; i++)
    r_crypto_cert_unref (chain[i]);

  return err;
}

/* Verify the client's CertificateVerify: its signature covers the handshake
 * transcript through ClientKeyExchange (a snapshot of hshash, taken before this
 * message is folded in). */
static RTLSError
r_tls_server_parse_certificate_verify (RTLSServer * server, const RTLSParser * parser)
{
  RTLSSignatureScheme scheme;
  const ruint8 * sig;
  ruint16 sigsize;
  RMsgDigestType md;
  RTLSError err;
  rsize hashsize;
  ruint8 * hash;

  if (R_UNLIKELY (server->peer_pubkey == NULL))   /* CertVerify with no cert */
    return R_TLS_ERROR_WRONG_STATE;

  if ((err = r_tls_parser_parse_certificate_verify (parser, &scheme, &sig, &sigsize))
        != R_TLS_ERROR_OK)
    return err;
  if (!r_tls_sign_scheme_to_md (scheme, &md))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  hashsize = r_msg_digest_size (server->hshash);
  hash = r_alloca (hashsize);
  if (!r_msg_digest_get_data (server->hshash, hash, hashsize, NULL))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  if (r_crypto_key_verify (server->peer_pubkey, md, hash, hashsize, sig, sigsize)
        != R_CRYPTO_OK)
    return R_TLS_ERROR_HS_VERIFICATION_FAILED;     /* -> decrypt_error */

  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_server_parse_client_key_exchange (RTLSServer * server,
    const RTLSParser * parser, ruint8 pms[48], rsize * pmslen)
{
  const ruint8 * encpms;
  rsize size;
  RTLSError ret;

  if (server->ecdhe) {
    const ruint8 * point;
    ruint8 pointlen;
    RCryptoKey * peer;
    rboolean ok;

    if ((ret = r_tls_parser_parse_client_key_exchange_ecdhe (parser, &point, &pointlen))
          != R_TLS_ERROR_OK)
      return ret;
    if (server->ecdhe_key == NULL)
      return R_TLS_ERROR_WRONG_STATE;
    /* point_read decodes/checks the peer point, compute rejects identity and
     * zero secrets; the shared secret is the variable-length premaster. */
    if ((peer = r_tls_ecdhe_point_read (server->ecdhe_curve, point, pointlen)) == NULL)
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    ok = r_tls_ecdhe_compute (server->ecdhe_key, peer, pms, 48, pmslen);
    r_crypto_key_unref (peer);
    return ok ? R_TLS_ERROR_OK : R_TLS_ERROR_HANDSHAKE_FAILURE;
  }

  *pmslen = 48;
  if ((ret = r_tls_parser_parse_client_key_exchange_rsa (parser, &encpms, &size)) == R_TLS_ERROR_OK) {
    ruint8 * out;

    /* size is the peer's encrypted-PMS length; cap it before the
     * stack allocation (a real RSA block is at most a few hundred
     * bytes even for very large keys). */
    if (R_UNLIKELY (size > 2048))
      return R_TLS_ERROR_CORRUPT_RECORD;
    out = r_alloca (size);

    r_prng_fill (server->prng, pms, 48);
    if (r_crypto_key_decrypt (server->privkey, server->prng, encpms, size, out, &size) == R_CRYPTO_OK) {
      if (size == 48) {
        r_memcpy (pms, out, size);
        /* FIXME: Should we just skip this version treatment, and rather
         *        check for correct version?*/
        if (R_LIKELY (server->version >= R_TLS_VERSION_SSL_3_0)) {
          pms[0] = (((ruint16)server->version) >> 8) & 0xff;
          pms[1] = (((ruint16)server->version)     ) & 0xff;
        }
      } else {
        pms[0] = (((ruint16)server->version) >> 8) & 0xff;
        pms[1] = (((ruint16)server->version)     ) & 0xff;
      }
    }
  }

  return ret;
}

/* RFC 7627: when extended master secret is negotiated the seed is the
 * handshake-transcript hash through ClientKeyExchange (the session hash)
 * rather than the client/server randoms. The caller must therefore have
 * absorbed the ClientKeyExchange into hshash before calling this. */
static RTLSError
r_tls_server_derive_master_secret (RTLSServer * server,
    const ruint8 * pms, rsize pmslen)
{
  RTLSError ret;

  if (server->support_ext_master_secret) {
    rsize hashsize = r_msg_digest_size (server->hshash);
    ruint8 * sessionhash = r_alloca (hashsize);

    if (!r_msg_digest_get_data (server->hshash, sessionhash, hashsize, NULL))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;

    ret = server->prf (server->mastersecret, sizeof (server->mastersecret),
        pms, pmslen, R_STR_WITH_SIZE_ARGS ("extended master secret"),
        sessionhash, hashsize, NULL);
  } else {
    ret = server->prf (server->mastersecret, sizeof (server->mastersecret),
        pms, pmslen, R_STR_WITH_SIZE_ARGS ("master secret"),
        server->hello.random, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        server->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        NULL);
  }

  return ret;
}

static RTLSError
r_tls_server_expand_master_secret (RTLSServer * server)
{
  ruint8 keyblock[256];
  RTLSError ret;

  if (server->prf (keyblock, sizeof (keyblock),
        server->mastersecret, sizeof (server->mastersecret),
        R_STR_WITH_SIZE_ARGS ("key expansion"),
        server->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        server->hello.random, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        NULL) != R_TLS_ERROR_OK) {
    r_memclear_secure (keyblock, sizeof (keyblock));
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }

  {
    ruint8 * ptr = keyblock;
    rsize size;

    ret = R_TLS_ERROR_OK;

    /* MAC */
    if ((size = r_msg_digest_type_size (server->csinfo->mac)) > 0) {
      R_LOG_DEBUG ("HMAC (%d) from keyblock of size %u", server->csinfo->mac, (ruint)size);
      server->client.hmac = r_hmac_new (server->csinfo->mac, ptr, size); ptr += size;
      server->server.hmac = r_hmac_new (server->csinfo->mac, ptr, size); ptr += size;
      if (server->client.hmac == NULL || server->server.hmac == NULL)
        ret = R_TLS_ERROR_OOM;
    }

    /* Key */
    if (ret == R_TLS_ERROR_OK && (size = server->csinfo->cipher->keybits / 8) > 0) {
      R_LOG_DEBUG ("Key from keyblock of size %u", (ruint)size);
      server->client.cipher = r_crypto_cipher_new (server->csinfo->cipher, ptr); ptr += size;
      server->server.cipher = r_crypto_cipher_new (server->csinfo->cipher, ptr); ptr += size;
      if (server->client.cipher == NULL || server->server.cipher == NULL)
        ret = R_TLS_ERROR_OOM;
    }

    /* IV — for AEAD this is the 4-byte fixed salt (ivsize-8); CBC keeps ivsize
     * (the explicit IV is per-record). */
    if (ret == R_TLS_ERROR_OK) {
      const RCryptoCipherInfo * ci = server->csinfo->cipher;
      size = (ci->mode == R_CRYPTO_CIPHER_MODE_GCM) ?
          ci->ivsize - R_TLS_AEAD_EXPLICIT_NONCE_SIZE : ci->ivsize;
      if (size > 0) {
        R_LOG_DEBUG ("IV from keyblock of size %u", (ruint)size);
        server->client.fixediv = r_memdup (ptr, size); ptr += size;
        server->server.fixediv = r_memdup (ptr, size); ptr += size;
        if (server->client.fixediv == NULL || server->server.fixediv == NULL)
          ret = R_TLS_ERROR_OOM;
      }
    }
  }

  /* Any partial allocations are released by r_tls_server_free. */
  r_memclear_secure (keyblock, sizeof (keyblock));
  return ret;
}

static RTLSError
r_tls_server_parse_finished (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError ret;
  const ruint8 * verify_data;
  rsize size;

  if ((ret = r_tls_parser_parse_finished (parser, &verify_data, &size)) == R_TLS_ERROR_OK) {
    /* verify-data is 12 bytes for TLS 1.x; bound it so a peer can't drive
     * the stack allocations below with a huge length. */
    if (size >= 12 && size <= 64) {
      ruint8 * verify_calc = r_alloca (size);
      rsize hashsize = r_msg_digest_size (server->hshash);
      ruint8 * hash = r_alloca (hashsize);
      r_msg_digest_get_data (server->hshash, hash, hashsize, NULL);

      if ((ret = server->prf (verify_calc, size,
            server->mastersecret, sizeof (server->mastersecret),
            R_STR_WITH_SIZE_ARGS ("client finished"),
            hash, hashsize, NULL)) == R_TLS_ERROR_OK) {
        if (r_memcmp (verify_calc, verify_data, size) != 0) {
          R_LOG_WARNING ("Handshake NOT verified");
          R_LOG_MEM_DUMP (R_LOG_LEVEL_DEBUG, verify_data, size);
          R_LOG_DEBUG ("expected:");
          R_LOG_MEM_DUMP (R_LOG_LEVEL_DEBUG, verify_calc, size);
          ret = R_TLS_ERROR_HS_VERIFICATION_FAILED;
        }
      }
    } else {
      ret = R_TLS_ERROR_CORRUPT_RECORD;
    }
  }

  return ret;
}


static void r_tls_server_send_out (RTLSServer * server);

/* Build an alert record and queue it for sending; the caller flushes. */
static RTLSError
r_tls_server_emit_alert (RTLSServer * server, RTLSAlertLevel level,
    RTLSAlertType alert)
{
  RBuffer * buf;
  RTLSError ret = R_TLS_ERROR_OOM;
  /* Use the negotiated version once known, else the version of the
   * record being processed (the handshake may have failed before
   * negotiation). */
  RTLSVersion ver = (server->version != 0) ? server->version : server->recordver;

  if ((buf = r_tls_server_alloc_buffer (server)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
      rsize sz = 0;

      if (r_tls_version_is_dtls (ver))
        ret = r_dtls_write_alert (info.data, info.size, &sz, ver,
            server->server.epoch, server->server.seqno, level, alert);
      else
        ret = r_tls_write_alert (info.data, info.size, &sz, ver, level, alert);
      r_buffer_unmap (buf, &info);

      if (ret == R_TLS_ERROR_OK) {
        r_buffer_set_size (buf, sz);
        ret = r_tls_server_send_record (server, buf);
      }
    }
    r_buffer_unref (buf);
  }

  return ret;
}

static void
r_tls_server_send_alert (RTLSServer * server, RTLSAlertType alert)
{
  RTLSError ret;

  R_LOG_WARNING ("Sending alert: 0x%.2x in state (%d)", alert, server->state);

  /* Emit a fatal alert record to the peer. Best-effort: even if it
   * cannot be built/sent we still report and move to the error state. */
  if ((ret = r_tls_server_emit_alert (server, R_TLS_ALERT_LEVEL_FATAL, alert))
      != R_TLS_ERROR_OK)
    R_LOG_WARNING ("Failed to emit alert 0x%.2x: %d", alert, ret);
  else
    /* Flush now: the caller returns an error, skipping the normal
     * send_out in r_tls_server_incoming_data. */
    r_tls_server_send_out (server);

  if (server->cb.error != NULL)
    server->cb.error (server->userdata, alert, server);

  r_tls_server_change_state (server, R_TLS_SERVER_ERROR);
}

/* Map a handshake error to the alert the peer should receive (RFC 5246 7.2.2).
 * Errors that reflect a local failure rather than peer behaviour (OOM, bad
 * arguments, encryption failure) fall through to internal_error. */
static RTLSAlertType
r_tls_server_alert_for_error (RTLSError err)
{
  switch (err) {
    case R_TLS_ERROR_WRONG_TYPE:        /* message out of turn for its type */
    case R_TLS_ERROR_WRONG_STATE:       /* message arrived in the wrong state */
      return R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE;
    case R_TLS_ERROR_INVALID_MAC:       /* record MAC / AEAD tag check failed */
      return R_TLS_ALERT_TYPE_BAD_RECORD_MAC;
    case R_TLS_ERROR_NO_CERTIFICATE:    /* required client certificate missing */
    case R_TLS_ERROR_HANDSHAKE_FAILURE:
      return R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE;
    case R_TLS_ERROR_CORRUPT_CERTIFICATE:
      return R_TLS_ALERT_TYPE_BAD_CERTIFICATE;
    case R_TLS_ERROR_INVALID_RECORD:    /* malformed / out-of-spec message */
    case R_TLS_ERROR_CORRUPT_RECORD:
      return R_TLS_ALERT_TYPE_DECODE_ERROR;
    case R_TLS_ERROR_RECORD_OVERFLOW:   /* fragment longer than the limit */
      return R_TLS_ALERT_TYPE_RECORD_OVERFLOW;
    case R_TLS_ERROR_HS_VERIFICATION_FAILED:  /* could not verify Finished */
      return R_TLS_ALERT_TYPE_DECRYPT_ERROR;
    case R_TLS_ERROR_VERSION:
      return R_TLS_ALERT_TYPE_PROTOCOL_VERSION;
    default:
      return R_TLS_ALERT_TYPE_INTERNAL_ERROR;
  }
}

static RTLSError
r_tls_server_state_error (RTLSServer * server, const RTLSParser * parser)
{
  (void) server;
  (void) parser;

  return R_TLS_ERROR_OK;
}

/* Attempt an abbreviated (RFC 5077) handshake from a ticket offered in the
 * ClientHello. On success the master secret and negotiated parameters have been
 * recovered from the ticket, the write keys are installed, and the server is
 * ready to emit the resumed flight; returns TRUE. Any failure -- no / unopenable
 * / expired ticket, or a suite no longer offered -- returns FALSE and leaves the
 * caller to run a full handshake (which issues a fresh ticket). */
static rboolean
r_tls_server_try_resume (RTLSServer * server)
{
  RTLSHelloExt hsext = R_TLS_HELLO_EXT_INIT;
  RTLSError r;
  ruint8 plain[R_TLS_TICKET_STATE_SIZE];
  rsize plainlen;
  const ruint8 * ticket = NULL;
  rsize ticketlen = 0;
  RTLSVersion ver;
  RTLSCipherSuite cs;
  const RTLSCipherSuiteInfo * csinfo;
  RClockTime issued_at, now;
  rboolean ems;

  if (server->ticket_keys == NULL)
    return FALSE;

  for (r = r_tls_hello_msg_extension_first (&server->hello, &hsext);
      r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (&server->hello, &hsext)) {
    if (hsext.type == R_TLS_EXT_TYPE_SESSION_TICKET) {
      ticket = hsext.data;
      ticketlen = hsext.len;
      break;
    }
  }
  if (ticket == NULL || ticketlen == 0)
    return FALSE;

  if (!r_tls_session_ticket_keys_open (server->ticket_keys, ticket, ticketlen,
        plain, sizeof (plain), &plainlen))
    return FALSE;
  if (plainlen != sizeof (plain) || plain[0] != R_TLS_TICKET_STATE_VERSION) {
    r_memclear_secure (plain, sizeof (plain));
    return FALSE;
  }

  ver = (RTLSVersion) r_load_be16 (&plain[1]);
  cs = (RTLSCipherSuite) r_load_be16 (&plain[3]);
  ems = (plain[5] != 0);
  issued_at = (RClockTime) r_load_be64 (&plain[6]);

  /* Validate before adopting the recovered session: same version, not expired,
   * the recovered suite must still be offered (RFC 5077), and the extended
   * master secret state must match this ClientHello -- nego_hello has already
   * set support_ext_master_secret from the offered extension, so resuming an
   * EMS session without the extension (or vice versa) is refused as a downgrade
   * (RFC 7627 5.3). */
  now = r_time_get_ts_wallclock ();
  if (ver != server->version ||
      now < issued_at ||
      now - issued_at > (RClockTime) R_TLS_SESSION_TICKET_LIFETIME * R_SECOND ||
      ems != server->support_ext_master_secret ||
      !r_tls_hello_msg_has_cipher_suite (&server->hello, cs) ||
      (csinfo = r_tls_cipher_suite_get_info (cs)) == NULL) {
    r_memclear_secure (plain, sizeof (plain));
    return FALSE;
  }

  /* Adopt the resumed session: the suite comes from the ticket, not this
   * ClientHello's preference-ordered negotiation (RFC 7627 5.1). */
  server->csinfo = csinfo;
  r_memcpy (server->mastersecret, &plain[14], sizeof (server->mastersecret));
  r_memclear_secure (plain, sizeof (plain));

  /* A fresh session id signals the resumed session to the client. Pin the
   * server random now: key expansion below and the ServerHello both consume it,
   * and they must agree. */
  server->session_id_len = (ruint8) sizeof (server->session_id);
  r_prng_fill (server->prng, server->session_id, server->session_id_len);
  if (!server->servrandompinned) {
    r_tls_generate_hello_random (server->servrandom, server->prng);
    server->servrandompinned = TRUE;
  }

  /* The master secret comes from the ticket, so expand the key block directly
   * (no derivation from a pre-master secret). */
  if (r_tls_server_expand_master_secret (server) != R_TLS_ERROR_OK)
    return FALSE;

  server->resumed = TRUE;
  return TRUE;
}

static RTLSError
r_tls_server_state_hello (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError err;

  if ((err = r_tls_parser_parse_hello (parser, &server->hello)) == R_TLS_ERROR_OK) {
    R_LOG_DEBUG ("%p - client hello parsed record ver %.4x, hello ver %.4x",
        server, parser->version, server->hello.version);
    server->hellobuf = r_buffer_ref (parser->buf);

    if ((err = r_tls_server_nego_hello (server, parser->version, server->hello.version)) == R_TLS_ERROR_OK)
      err = r_tls_server_change_state (server, r_tls_server_try_resume (server) ?
          R_TLS_SERVER_CHANGE_CIPHER : R_TLS_SERVER_CERTIFICATE);
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      R_LOG_TRACE ("Updating HS hash with ClientHello %u bytes",
          (ruint)parser->fragment.size);
      r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);

      if (server->resumed) {
        /* Abbreviated flight: the server Finished is sent now, ahead of the
         * client's. The client answers with its ChangeCipherSpec + Finished. */
        if (r_tls_server_write_hello (server) == R_TLS_ERROR_OK)
          server->server.msgseq++;
        if (r_tls_server_write_change_cipher (server) == R_TLS_ERROR_OK)
          server->encrypt = r_tls_server_cipher_encrypt;
        if (r_tls_server_write_finished (server) == R_TLS_ERROR_OK)
          server->server.msgseq++;
        break;
      }

      if (r_tls_server_write_hello (server) == R_TLS_ERROR_OK)
        server->server.msgseq++;
      if (r_tls_server_write_certificate (server) == R_TLS_ERROR_OK)
        server->server.msgseq++;
      if (r_tls_server_write_key_exchange (server) == R_TLS_ERROR_OK)
        server->server.msgseq++;
      if (r_tls_server_write_cert_req (server) == R_TLS_ERROR_OK)
        server->server.msgseq++;
      if (r_tls_server_write_hello_done (server) == R_TLS_ERROR_OK)
        server->server.msgseq++;
      break;
    default:
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
      break;
  }

  return err;
}

static RTLSError
r_tls_server_state_certificate (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError err;

  RTLSHandshakeType type;
  if ((err = r_tls_parser_parse_handshake_peek_type (parser, &type)) == R_TLS_ERROR_OK) {
    if (type == R_TLS_HANDSHAKE_TYPE_CERTIFICATE) {
      if ((err = r_tls_server_parse_client_certificate (server, parser)) == R_TLS_ERROR_OK)
        err = r_tls_server_change_state (server, R_TLS_SERVER_KEY_EXCHANGE);
    } else if (type == R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE) {
      /* Client sent no Certificate at all; fatal when one is required. */
      if (server->client_cert_mode == R_TLS_CLIENT_CERT_MODE_REQUIRE)
        err = R_TLS_ERROR_NO_CERTIFICATE;
      else if ((err = r_tls_server_change_state (server, R_TLS_SERVER_KEY_EXCHANGE)) == R_TLS_ERROR_OK)
        err = R_TLS_ERROR_NOT_NEEDED;
    } else {
      err = R_TLS_ERROR_WRONG_TYPE;
    }
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      R_LOG_TRACE ("Updating HS hash with ClientCertificate %u bytes",
          (ruint)parser->fragment.size);
      r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);
      break;
    case R_TLS_ERROR_NOT_NEEDED:
      break;
    default:
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
      break;
  }

  return err;
}

static RTLSError
r_tls_server_state_key_exchange (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError err;
  ruint8 pms[48];
  rsize pmslen = sizeof (pms);

  if ((err = r_tls_server_parse_client_key_exchange (server, parser, pms, &pmslen)) == R_TLS_ERROR_OK)
    err = r_tls_server_change_state (server, server->client_cert_received ?
        R_TLS_SERVER_CERTIFICATE_VERIFY : R_TLS_SERVER_CHANGE_CIPHER);

  switch (err) {
    case R_TLS_ERROR_OK:
      R_LOG_TRACE ("Updating HS hash with ClientKeyExchange %u bytes",
          (ruint)parser->fragment.size);
      /* hash CKE first: the extended-master-secret session hash covers it */
      r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);
      if ((err = r_tls_server_derive_master_secret (server, pms, pmslen)) != R_TLS_ERROR_OK ||
          (err = r_tls_server_expand_master_secret (server)) != R_TLS_ERROR_OK)
        r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
      break;
    default:
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
      break;
  }

  r_memclear_secure (pms, sizeof (pms));
  return err;
}

static RTLSError
r_tls_server_state_certificate_verify (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError err;
  RTLSHandshakeType type;

  if ((err = r_tls_parser_parse_handshake_peek_type (parser, &type)) == R_TLS_ERROR_OK) {
    if (type == R_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY) {
      if ((err = r_tls_server_parse_certificate_verify (server, parser)) == R_TLS_ERROR_OK)
        err = r_tls_server_change_state (server, R_TLS_SERVER_CHANGE_CIPHER);
    } else {
      err = R_TLS_ERROR_WRONG_TYPE;
    }
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      R_LOG_TRACE ("Updating HS hash with CertificateVerify %u bytes",
          (ruint)parser->fragment.size);
      /* Fold only after verifying its own signature, so the client Finished
       * (which covers CertificateVerify) still checks out. */
      r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);
      break;
    default:
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
      break;
  }

  return err;
}

static RTLSError
r_tls_server_state_change_cipher (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError err;

  if (parser->content == R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC)
    err = r_tls_server_change_state (server, R_TLS_SERVER_FINISHED);
  else
    err = R_TLS_ERROR_WRONG_TYPE;

  switch (err) {
    case R_TLS_ERROR_OK:
      /* enable cipher */
      R_LOG_DEBUG ("cipher enabled (%s)", server->csinfo->str);
      server->decrypt = r_tls_parser_decrypt;
      server->client.epoch++;
      server->client.seqno = 0;
      break;
    default:
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
      break;
  }

  return err;
}
static RTLSError
r_tls_server_state_finished (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError err;

  if ((err = r_tls_server_parse_finished (server, parser)) == R_TLS_ERROR_OK)
    err = r_tls_server_change_state (server, R_TLS_SERVER_APPDATA);

  switch (err) {
    case R_TLS_ERROR_OK:
      R_LOG_TRACE ("Updating HS hash with ClientFinished %u bytes",
          (ruint)parser->fragment.size);
      r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);

      /* On a resumed handshake the server already sent its flight (Finished
       * first) from state_hello; here it only verifies the client Finished. */
      if (!server->resumed) {
        if (r_tls_server_write_new_session_ticket (server) == R_TLS_ERROR_OK)
          server->server.msgseq++;
        if (r_tls_server_write_change_cipher (server) == R_TLS_ERROR_OK) {
          /* enable cipher */
          server->encrypt = r_tls_server_cipher_encrypt;
        }
        if (r_tls_server_write_finished (server) == R_TLS_ERROR_OK)
          server->server.msgseq++;
      }

      r_msg_digest_free (server->hshash);
      server->hshash = NULL;
      if (server->cb.handshake_done != NULL)
        server->cb.handshake_done (server->userdata, server);
      break;
    default:
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
      break;
  }

  return err;
}

static RTLSError
r_tls_server_state_appdata (RTLSServer * server, const RTLSParser * parser)
{
  RBuffer * buf;

  if (parser->content == R_TLS_CONTENT_TYPE_APPLICATION_DATA) {
    if ((buf = r_buffer_view (parser->buf, parser->offset, parser->fragment.size)) != NULL) {
      server->cb.appdata (server->userdata, buf, server);
      r_buffer_unref (buf);
    } else {
      R_LOG_WARNING ("Unable to create view of TLS appdata buffer");
    }
  } else {
    R_LOG_WARNING ("Received non-app-data record");
  }

  return R_TLS_ERROR_OK;
}

static void
r_tls_server_send_out (RTLSServer * server)
{
  RBuffer * buf;

  while ((buf = r_queue_pop (&server->qsend)) != NULL) {
    /* FIXME: Do this smarter!!! */
    server->cb.out (server->userdata, buf, server);
    r_buffer_unref (buf);
  }
}

rboolean
r_tls_server_incoming_data (RTLSServer * server, RBuffer * buffer)
{
  static RTLSServerStateFunc statefuncs[] = {
    r_tls_server_state_error,
    r_tls_server_state_hello,
    r_tls_server_state_certificate,
    r_tls_server_state_key_exchange,
    r_tls_server_state_certificate_verify,
    r_tls_server_state_change_cipher,
    r_tls_server_state_finished,
    r_tls_server_state_appdata,

    r_tls_server_state_error,
  };
  /* Zero-init: a record that fails init_buffer never sets parser.buf, and the
   * post-loop r_tls_parser_clear must not free an uninitialised pointer. */
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSError err;

  if (R_UNLIKELY (server == NULL)) return FALSE;
  if (R_UNLIKELY (buffer == NULL)) return FALSE;

  if (server->inbuf == NULL) {
    server->inbuf = r_buffer_ref (buffer);
  } else {
    if (R_UNLIKELY (!r_buffer_append_mem_from_buffer (server->inbuf, buffer)))
      return FALSE;
  }

  for (err = r_tls_parser_init_buffer (&parser, server->inbuf);
      err == R_TLS_ERROR_OK;
      err = r_tls_parser_init_next (&parser, &server->inbuf)) {
    r_buffer_unref (server->inbuf);
    server->inbuf = NULL;

    /* Remember the record-layer version so a fatal alert can be framed
     * correctly even before the version is negotiated. */
    server->recordver = parser.version;

    /* TLS carries no explicit record sequence number; feed the running read
     * counter to the MAC. (DTLS reads epoch/seqno from the record header.) */
    if (!r_tls_parser_is_dtls (&parser))
      parser.seqno = server->client.seqno;

    if (!r_tls_parser_is_dtls (&parser) || parser.epoch == server->client.epoch) {
      if ((err = server->decrypt (&parser, server->client.cipher, server->client.hmac,
              server->encrypt_then_mac, server->client.fixediv)) != R_TLS_ERROR_OK) {
        /* A record that fails decrypt / MAC must not be processed. TLS reports
         * it as fatal bad_record_mac (RFC 5246 7.2.2); DTLS silently discards
         * the record and keeps the association (RFC 6347 4.1.2.7). */
        R_LOG_WARNING ("Decryption returned: %d", err);
        if (!r_tls_parser_is_dtls (&parser))
          r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_BAD_RECORD_MAC);
        continue;
      }
    }

    /* Count the accepted record. A ChangeCipherSpec resets the read counter
     * to 0 for the new read state in its handler below, so increment first. */
    server->client.seqno++;

    if (parser.content == R_TLS_CONTENT_TYPE_ALERT) {
      RTLSAlertLevel alevel;
      RTLSAlertType atype;

      if ((err = r_tls_parser_parse_alert (&parser, &alevel, &atype)) == R_TLS_ERROR_OK) {
        R_LOG_WARNING ("Received Alert, %.2x %.2x", alevel, atype);

        if (alevel == R_TLS_ALERT_LEVEL_FATAL)
          err = r_tls_server_change_state (server, R_TLS_SERVER_ERROR);
      } else {
        R_LOG_WARNING ("Received Alert, unable to parse! %d", err);

        r_tls_server_change_state (server, R_TLS_SERVER_ERROR);
      }
      continue;
    }

    do {
      err = statefuncs[server->state] (server, &parser);
    } while (err == R_TLS_ERROR_NOT_NEEDED);
  }

  r_tls_parser_clear (&parser);

  if (err >= R_TLS_ERROR_OK) {
    r_tls_server_send_out (server);
  } else {
    /* A negative err here is a record-layer framing failure from
     * init_buffer / init_next (a per-message error already sent its own alert
     * and left err non-negative via the loop's re-init). BUF_TOO_SMALL just
     * means the record is incomplete -- buffer it and wait for more. Otherwise
     * surface the matching fatal alert, unless the session already failed. */
    if (err != R_TLS_ERROR_BUF_TOO_SMALL && server->state != R_TLS_SERVER_ERROR) {
      /* The failing record never reached the in-loop recordver update; take the
       * version the parser read so the alert is framed correctly. */
      if (parser.version != 0)
        server->recordver = parser.version;
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
    }
    if (server->inbuf != NULL) {
      r_buffer_unref (server->inbuf);
      server->inbuf = NULL;
    }
    return (err == R_TLS_ERROR_BUF_TOO_SMALL);
  }

  return TRUE;
}

rboolean
r_tls_server_send_appdata (RTLSServer * server, RBuffer * buffer)
{
  RBuffer * rec;
  RMemMapInfo in = R_MEM_MAP_INFO_INIT, out = R_MEM_MAP_INFO_INIT;
  RTLSError ret = R_TLS_ERROR_OOM;
  rboolean dtls;
  rsize recsize;

  if (R_UNLIKELY (server == NULL || buffer == NULL)) return FALSE;
  /* Application data may only flow once the handshake has finished. */
  if (R_UNLIKELY (server->state != R_TLS_SERVER_APPDATA)) return FALSE;
  if (R_UNLIKELY (!r_buffer_map (buffer, &in, R_MEM_MAP_READ))) return FALSE;

  dtls = r_tls_version_is_dtls (server->version);
  recsize = (dtls ? R_DTLS_RECORD_HDR_SIZE : R_TLS_RECORD_HDR_SIZE) + in.size;

  if ((rec = r_buffer_new_alloc (NULL, recsize, NULL)) != NULL) {
    if (r_buffer_map (rec, &out, R_MEM_MAP_WRITE)) {
      if (dtls)
        ret = r_dtls_write_application_data (out.data, out.size, NULL,
            server->version, server->server.epoch, server->server.seqno,
            in.data, in.size);
      else
        ret = r_tls_write_application_data (out.data, out.size, NULL,
            server->version, in.data, in.size);
      r_buffer_unmap (rec, &out);
    }
  }
  r_buffer_unmap (buffer, &in);

  if (rec != NULL) {
    if (ret == R_TLS_ERROR_OK) {
      r_buffer_set_size (rec, recsize);
      ret = r_tls_server_send_record (server, rec);
    }
    r_buffer_unref (rec);
  }

  if (ret != R_TLS_ERROR_OK)
    return FALSE;

  r_tls_server_send_out (server);
  return TRUE;
}

RTLSError
r_tls_server_export_keying_material (const RTLSServer * server,
    ruint8 * material, rsize size, const rchar * label, rsize len,
    const ruint8 * ctx, rsize ctxsize)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (material == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size == 0)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (label == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (len == 0)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (server->state <= R_TLS_SERVER_HELLO))
    return R_TLS_ERROR_WRONG_STATE;

  if (ctxsize == 0)
    ctx = NULL;

  return server->prf (material, size,
      server->mastersecret, sizeof (server->mastersecret), label, len,
      server->hello.random, (rsize)R_TLS_HELLO_RANDOM_BYTES,
      server->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
      ctx, ctxsize, NULL);
}

RTLSVersion
r_tls_server_get_version (const RTLSServer * server)
{
  return server->version;
}

const RTLSCipherSuiteInfo *
r_tls_server_get_cipher_suite (const RTLSServer * server)
{
  return server->csinfo;
}

RSRTPCipherSuite
r_tls_server_get_dtls_srtp_profile (const RTLSServer * server)
{
  return server->dtls_srtp_profile;
}

const ruint8 *
r_tls_server_get_dtls_srtp_mki (const RTLSServer * server, ruint8 * size)
{
  if (size != NULL)
    *size = server->srtp_mki_size;

  return server->srtp_mki;
}

