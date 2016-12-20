/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rmac.h>
#include <rlib/crypto/rx509.h>

#include <rlib/rmem.h>
#include <rlib/rqueue.h>

typedef enum {
  R_TLS_SERVER_INITIAL = 0,
  R_TLS_SERVER_HELLO,
  R_TLS_SERVER_CERTIFICATE,
  R_TLS_SERVER_KEY_EXCHANGE,
  R_TLS_SERVER_CHANGE_CIPHER,
  R_TLS_SERVER_FINISHED,
  R_TLS_SERVER_APPDATA,
  R_TLS_SERVER_ERROR,
} RTLSServerState;

typedef RTLSError (*RTLSServerStateFunc) (RTLSServer * server, const RTLSParser * parser);
typedef RBuffer * (*RTLSServerEncryptFunc) (RTLSServer * server, RBuffer * buf);
typedef RTLSError (*RTLSServerDecryptFunc) (RTLSParser * parser,
    const RCryptoCipher * cipher, RHmac * mac);

typedef struct {
  RHmac * hmac;
  RCryptoCipher * cipher;
  ruint8 * fixediv;

  ruint16 epoch;
  ruint64 seqno;
  ruint16 msgseq;
} RTLSConnectionState;

struct _RTLSServer {
  RRef ref;
  RTLSServerState state;

  RTLSServerEncryptFunc encrypt;
  RTLSServerDecryptFunc decrypt;
  RTLSPrfFunc prf;

  RTLSHelloMsg hello;
  RBuffer * hellobuf;

  RHash * hshash;
  ruint8 mastersecret[48];
  ruint8 servrandom[R_TLS_HELLO_RANDOM_BYTES];
  rboolean servrandompinned;

  RTLSVersion version;
  RTLSCompresssionMethod comp;
  const RTLSCipherSuiteInfo * csinfo;
  rboolean support_renego;
  rboolean support_new_session_ticket;
  rboolean support_ext_master_secret;
  RDTLSSRTPProtectionProfile dtls_srtp_profile;
  ruint8 srtp_mki_size;
  const ruint8 * srtp_mki;
  ruint8 * ticket;
  ruint16 ticketsize;

  RTLSConnectionState client;
  RTLSConnectionState server;

  RTLSCallbacks cb;
  rpointer userdata;
  RDestroyNotify notify;

  REvLoop * loop;
  RPrng * prng;
  RCryptoCert * cert;
  RCryptoKey * privkey;

  RBuffer * inbuf;
  RQueue qsend;
};

#define R_LOG_CAT_DEFAULT &tlsservcat
R_LOG_CATEGORY_DEFINE_STATIC (tlsservcat, "rtlsserver", "RLib TLS Server",
    R_CLR_FG_WHITE | R_CLR_BG_MAGENTA | R_CLR_FMT_BOLD);

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

  r_free (server->ticket);
  r_queue_clear (&server->qsend, r_buffer_unref);
  r_free (server);
}

static RTLSError
r_tls_server_null_decrypt (RTLSParser * parser, const RCryptoCipher * cipher,
    RHmac * mac)
{
  (void) parser;
  (void) cipher;
  (void) mac;

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
  ruint8 * iv = r_alloca (server->server.cipher->info->ivsize);

  R_LOG_TRACE ("Encrypting buffer %p", buf);
  r_prng_fill (server->prng, iv, server->server.cipher->info->ivsize);
  if (r_tls_version_is_dtls (server->version)) {
    ret = r_dtls_encrypt_buffer (buf,
        server->server.cipher, iv, server->server.hmac);
  } else {
    ret = r_tls_encrypt_buffer (buf, server->server.seqno,
        server->server.cipher, iv, server->server.hmac);
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

  *(ruint16 *)&ptr[0] = RUINT16_TO_BE ((ruint16)R_TLS_EXT_TYPE_RENEGOTIATION_INFO);
  *(ruint16 *)&ptr[2] = RUINT16_TO_BE (1);
  ptr[4] = 0;
  return 5;
}

static ruint16
r_tls_server_write_hs_ext_session_ticket (const RTLSServer * server, ruint8 * ptr)
{
  if (!server->support_new_session_ticket || server->ticketsize == 0)
    return 0;

  /* NewSessionTicket will come! */
  *(ruint16 *)&ptr[0] = RUINT16_TO_BE ((ruint16)R_TLS_EXT_TYPE_SESSION_TICKET);
  *(ruint16 *)&ptr[2] = RUINT16_TO_BE (0);

  return 4;
}

static ruint16
r_tls_server_write_hs_ext_use_srtp (const RTLSServer * server, ruint8 * ptr)
{
  if (server->dtls_srtp_profile == R_DTLS_SRTP_NONE)
    return 0;

  *(ruint16 *)&ptr[0] = RUINT16_TO_BE ((ruint16)R_TLS_EXT_TYPE_USE_SRTP);
  *(ruint16 *)&ptr[2] = RUINT16_TO_BE (5 + server->srtp_mki_size);
  *(ruint16 *)&ptr[4] = RUINT16_TO_BE (1 * sizeof (ruint16));
  *(ruint16 *)&ptr[6] = RUINT16_TO_BE ((ruint16)server->dtls_srtp_profile);
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
          server->version, server->servrandom, NULL, 0,
          server->csinfo->suite, server->comp);
      ptr += size;
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO, 0);
      ptr = info.data + hssize;
      ret = r_tls_write_hs_server_hello (ptr, info.size - hssize, &size,
          server->version, server->servrandom, NULL, 0,
          server->csinfo->suite, server->comp);
      ptr += size;
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }
    extsize = 0;
    extsize += r_tls_server_write_hs_ext_renegotiation (server, ptr + 2 + extsize);
    /* FIXME: Write ServerHello extensions */
#if 0
    extsize += r_tls_server_write_hs_ext_max_fragment_length (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_truncated_hmac (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_encrypt_then_mac (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_extended_ms (server, ptr + 2 + extsize);
#endif
    extsize += r_tls_server_write_hs_ext_session_ticket (server, ptr + 2 + extsize);
#if 0
    extsize += r_tls_server_write_hs_ext_supported_point_formats (server, ptr + 2 + extsize);
#endif
    extsize += r_tls_server_write_hs_ext_use_srtp (server, ptr + 2 + extsize);
#if 0
    extsize += r_tls_server_write_hs_ext_ecjpake_kkpp (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_alpn (server, ptr + 2 + extsize);
#endif

    if (extsize > 0) {
      *(ruint16 *)ptr = RUINT16_TO_BE (extsize);
      ptr += extsize + 2;
    }

    size = RPOINTER_TO_SIZE (ptr) - RPOINTER_TO_SIZE (info.data);
    if (ret == R_TLS_ERROR_OK) {
      if (r_tls_version_is_dtls (server->version)) {
        ret = r_dtls_update_handshake_len (info.data, info.size, size - hssize,
            0, size - hssize);
      } else {
        ret = r_tls_update_handshake_len (info.data, info.size, size - hssize);
      }

      if (ret == R_TLS_ERROR_OK) {
        R_LOG_TRACE ("Updating HS hash with ServerHello %u bytes",
            (ruint)(size - hdrsize));
        r_hash_update (server->hshash, info.data + hdrsize, size - hdrsize);
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
      r_hash_update (server->hshash, info.data + hdrsize, size - hdrsize);
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
          server->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE, hssize,
          server->server.epoch, server->server.seqno, server->server.msgseq,
          0, hssize);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &size,
          server->version, R_TLS_HANDSHAKE_TYPE_CERTIFICATE, hssize);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }

    if (ret == R_TLS_ERROR_OK) {
      _r_write_u24 (&info.data[size], 24 / 8 + certsize); size += 24 / 8;
      _r_write_u24 (&info.data[size],          certsize); size += 24 / 8;

      r_hash_update (server->hshash, info.data + hdrsize, size - hdrsize);

      r_buffer_unmap (buf, &info);
      r_buffer_set_size (buf, size);
      r_buffer_append_mem_from_buffer (buf, certbuf);

      r_buffer_map (certbuf, &info, R_MEM_MAP_READ);
      R_LOG_TRACE ("Updating HS hash with ServerCertificate %u bytes",
          (ruint)(size - hdrsize + info.size));
      r_hash_update (server->hshash, info.data, info.size);
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
  /* FIXME: Only for certain (anon/ephemral?) cipher suites? */
  (void) server;
  return R_TLS_ERROR_NOT_NEEDED;
}

static RTLSError
r_tls_server_write_cert_req (RTLSServer * server)
{
  /* FIXME: Request certificate? */
  (void) server;
  return R_TLS_ERROR_NOT_NEEDED;
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

static RTLSError
r_tls_server_write_new_session_ticket (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;

  if (!server->support_new_session_ticket || server->ticketsize == 0)
    return R_TLS_ERROR_NOT_NEEDED;

  R_LOG_DEBUG ("%p - server new session ticket", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize hssize, ntsize;

    ntsize = sizeof (ruint32) + sizeof (ruint16) + server->ticketsize;
    if (r_tls_version_is_dtls (server->version)) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, ntsize,
          server->server.epoch, server->server.seqno, server->server.msgseq,
          0, ntsize);
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          server->version, R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET, ntsize);
    }

    if (ret == R_TLS_ERROR_OK) {
      if ((ret = r_tls_write_hs_new_session_ticket (info.data + hssize,
            info.size - hssize, &ntsize, R_TLS_SESSION_TICKET_LIFETIME,
            server->ticket, server->ticketsize)) == R_TLS_ERROR_OK) {
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

  R_LOG_DEBUG ("%p - server finished", server);

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    rsize verifysize = 12, hashsize = r_hash_size (server->hshash);
    ruint8 * hash = r_alloca (hashsize);

    if (r_hash_finish (server->hshash) &&
        r_hash_get_data (server->hshash, hash, &hashsize)) {
      if (r_tls_version_is_dtls (server->version)) {
        ret = r_dtls_write_handshake (info.data, info.size, &size,
            server->version, R_TLS_HANDSHAKE_TYPE_FINISHED, verifysize,
            server->server.epoch, server->server.seqno, server->server.msgseq,
            0, verifysize);
      } else {
        ret = r_tls_write_handshake (info.data, info.size, &size,
            server->version, R_TLS_HANDSHAKE_TYPE_FINISHED, verifysize);
      }
      if (ret == R_TLS_ERROR_OK &&
          (ret = server->prf (info.data + size, verifysize,
                              server->mastersecret, sizeof (server->mastersecret),
                              "server finished", sizeof ("server finished") - 1,
                              hash, hashsize, NULL)) == R_TLS_ERROR_OK) {
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
  const RTLSCipherSuite preferred[] = {
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256,
  };

  (void)ctx;
  (void)ver;

  *count = MIN (*count, R_N_ELEMENTS (preferred));
  r_memcpy (cs, preferred, *count * sizeof (RTLSCipherSuite));

  return TRUE;
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
  const ruint16 * ptr;
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

  count = server->hello.cslen / sizeof (ruint16);
  incoming = r_mem_newa_n (RTLSCipherSuite, count);
  for (ptr = (const ruint16 *)server->hello.cs, i = 0; i < count; ptr++, i++)
    incoming[i] = (RTLSCipherSuite)RUINT16_FROM_BE (*ptr);

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

  if ((cs = r_tls_cipher_suite_filter (incoming, count, preferred, psize)) == R_TLS_CS_NONE ||
      (server->csinfo = r_tls_cipher_suite_get_info (cs)) == NULL) {
    R_LOG_WARNING ("No common cipher suites (in: %u, preferred: %u)",
        (ruint)count, (ruint)R_N_ELEMENTS (preferred));
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }

  R_LOG_DEBUG ("%p - cipher site %s", server, server->csinfo->str);

  switch (server->version) {
    case R_TLS_VERSION_DTLS_1_2:
    case R_TLS_VERSION_TLS_1_2:
      server->prf = r_tls_1_2_prf_sha256;
      server->hshash = r_hash_new_sha256 ();
      break;
#if 0
    case R_TLS_VERSION_DTLS_1_0:
    case R_TLS_VERSION_TLS_1_0:
      server->prf = r_tls_1_0_prf;
      break;
    case R_TLS_VERSION_SSL_3_0:
      switch (server->csinfo->mac) {
        case R_HASH_TYPE_SHA256:
          server->prf = r_tls_1_2_prf_sha256;
          server->hshash = r_hash_new_sha256 ();
          break;
        case R_HASH_TYPE_SHA512:
          server->prf = r_tls_1_2_prf_sha512;
          server->hshash = r_hash_new_sha512 ();
          break;
        case R_HASH_TYPE_SHA224:
          server->prf = r_tls_1_2_prf_sha224;
          server->hshash = r_hash_new_sha224 ();
          break;
        case R_HASH_TYPE_SHA384:
          server->prf = r_tls_1_2_prf_sha384;
          server->hshash = r_hash_new_sha384 ();
          break;
        default:
          return R_TLS_ERROR_WRONG_STATE;
      }
      break;
#endif
    default:
      return R_TLS_ERROR_VERSION;
  }

  server->support_renego = FALSE;
  server->support_new_session_ticket = FALSE;
  server->support_ext_master_secret = FALSE;
  server->dtls_srtp_profile = R_DTLS_SRTP_NONE;

  for (r = r_tls_hello_msg_extension_first (&server->hello, &hsext);
      r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (&server->hello, &hsext)) {
    switch (hsext.type) {
      case R_TLS_EXT_TYPE_RENEGOTIATION_INFO:
        server->support_renego = TRUE;
        /* FIXME: parse renego info */
        break;
      case R_TLS_EXT_TYPE_SESSION_TICKET:
        server->support_new_session_ticket = TRUE;
        break;
      case R_TLS_EXT_TYPE_USE_SRTP:
        count = r_tls_hello_ext_use_srtp_profile_count (&hsext);
        for (i = 0; i < count; i++) {
          if (r_tls_hello_ext_use_srtp_profile (&hsext, i) == R_DTLS_SRTP_AES128_CM_HMAC_SHA1_80) {
            server->dtls_srtp_profile = R_DTLS_SRTP_AES128_CM_HMAC_SHA1_80;
            break;
          } else if (r_tls_hello_ext_use_srtp_profile (&hsext, i) == R_DTLS_SRTP_AES128_CM_HMAC_SHA1_32) {
            server->dtls_srtp_profile = R_DTLS_SRTP_AES128_CM_HMAC_SHA1_32;
          }
        }
        break;
      case R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET: /* Skip it! */
      default:
        break;
    }
  }

  if (server->support_new_session_ticket) {
    /* FIXME: create session ticket server->ticket, server->ticketsize */
  }

  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_server_parse_client_certificate (RTLSServer * server,
    const RTLSParser * parser)
{
  /* TODO: implement */
  (void) server;
  (void) parser;
  return R_TLS_ERROR_NO_CERTIFICATE;
}

static RTLSError
r_tls_server_parse_client_key_exchange (RTLSServer * server,
    const RTLSParser * parser)
{
  const ruint8 * encpms;
  rsize size;
  RTLSError ret;

  if ((ret = r_tls_parser_parse_client_key_exchange_rsa (parser, &encpms, &size)) == R_TLS_ERROR_OK) {
    ruint8 pms[48];
    ruint8 * out = r_alloca (size);

    r_prng_fill (server->prng, pms, sizeof (pms));
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

#if 0
    R_LOG_DEBUG ("RSA PreMasterSecret:");
    R_LOG_MEM_DUMP (R_LOG_LEVEL_DEBUG, pms, sizeof (pms));
    R_LOG_DEBUG ("Client random:");
    R_LOG_MEM_DUMP (R_LOG_LEVEL_DEBUG,
        server->hello.random, (rsize)R_TLS_HELLO_RANDOM_BYTES);
    R_LOG_DEBUG ("Server random:");
    R_LOG_MEM_DUMP (R_LOG_LEVEL_DEBUG,
        server->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES);
#endif

    /* FIXME: implement use of extended master secret */

    /* convert to mastersecret */
    ret = server->prf (server->mastersecret, sizeof (server->mastersecret),
        pms, sizeof (pms), "master secret", sizeof ("master secret") - 1,
        server->hello.random, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        server->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        NULL);
    r_memclear (pms, sizeof (pms));
#if 0
    R_LOG_DEBUG ("RSA MasterSecret:");
    R_LOG_MEM_DUMP (R_LOG_LEVEL_DEBUG,
        server->mastersecret, sizeof (server->mastersecret));
#endif
  }

  return ret;
}

static void
r_tls_server_expand_master_secret (RTLSServer * server)
{
  ruint8 keyblock[256];

  if (server->prf (keyblock, sizeof (keyblock),
        server->mastersecret, sizeof (server->mastersecret),
        "key expansion", sizeof ("key expansion") - 1,
        server->servrandom, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        server->hello.random, (rsize)R_TLS_HELLO_RANDOM_BYTES,
        NULL) == R_TLS_ERROR_OK) {
    ruint8 * ptr = keyblock;
    rsize size;

    /* MAC */
    if ((size = r_hash_type_size (server->csinfo->mac)) > 0) {
      R_LOG_DEBUG ("HMAC (%d) from keyblock of size %u", server->csinfo->mac, (ruint)size);
      server->client.hmac = r_hmac_new (server->csinfo->mac, ptr, size); ptr += size;
      server->server.hmac = r_hmac_new (server->csinfo->mac, ptr, size); ptr += size;
    }

    /* Key */
    if ((size = server->csinfo->cipher->keybits / 8) > 0) {
      R_LOG_DEBUG ("Key from keyblock of size %u", (ruint)size);
      server->client.cipher = r_crypto_cipher_new (server->csinfo->cipher, ptr); ptr += size;
      server->server.cipher = r_crypto_cipher_new (server->csinfo->cipher, ptr); ptr += size;
    }

    /* IV */
    if ((size = server->csinfo->cipher->ivsize) > 0) {
      R_LOG_DEBUG ("IV from keyblock of size %u", (ruint)size);
      server->client.fixediv = r_memdup (ptr, size); ptr += size;
      server->server.fixediv = r_memdup (ptr, size); ptr += size;
    }
  }
}

static RTLSError
r_tls_server_parse_finished (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError ret;
  const ruint8 * verify_data;
  rsize size;

  if ((ret = r_tls_parser_parse_finished (parser, &verify_data, &size)) == R_TLS_ERROR_OK) {
    if (size >= 12) {
      ruint8 * verify_calc = r_alloca (size);
      rsize hashsize = r_hash_size (server->hshash);
      ruint8 * hash = r_alloca (hashsize);
      r_hash_get_data (server->hshash, hash, &hashsize);

      if ((ret = server->prf (verify_calc, size,
            server->mastersecret, sizeof (server->mastersecret),
            "client finished", sizeof ("client finished") - 1,
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


static void
r_tls_server_send_alert (RTLSServer * server, RTLSAlertType alert)
{
  /* TODO: emit error callback */
  /* TODO: Send alert! */

  R_LOG_WARNING ("Sending alert: 0x%.2x in state (%d)", alert, server->state);

  r_tls_server_change_state (server, R_TLS_SERVER_ERROR);
}


static RTLSError
r_tls_server_state_error (RTLSServer * server, const RTLSParser * parser)
{
  (void) server;
  (void) parser;

  return R_TLS_ERROR_OK;
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
      err = r_tls_server_change_state (server, R_TLS_SERVER_CERTIFICATE);
  }

  /* FIXME: Add proper alert codes for error scenarios */
  switch (err) {
    case R_TLS_ERROR_OK:
      R_LOG_TRACE ("Updating HS hash with ClientHello %u bytes",
          (ruint)parser->fragment.size);
      r_hash_update (server->hshash, parser->fragment.data, parser->fragment.size);

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
    case R_TLS_ERROR_WRONG_TYPE:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
      break;
    case R_TLS_ERROR_CORRUPT_RECORD:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_DECODE_ERROR);
      break;
    case R_TLS_ERROR_HANDSHAKE_FAILURE:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
      break;
    case R_TLS_ERROR_VERSION:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_PROTOCOL_VERSION);
      break;
    case R_TLS_ERROR_WRONG_STATE:
    default:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
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
      if ((err = r_tls_server_parse_client_certificate (server, parser)) == R_TLS_ERROR_OK) {
        err = r_tls_server_change_state (server, R_TLS_SERVER_KEY_EXCHANGE);
      } else {
        /* FIXME Error? */
      }
    } else if (type == R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE) {
      if ((err = r_tls_server_change_state (server, R_TLS_SERVER_KEY_EXCHANGE)) == R_TLS_ERROR_OK)
        err = R_TLS_ERROR_NOT_NEEDED;
    } else {
      err = R_TLS_ERROR_WRONG_TYPE;
    }
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      R_LOG_TRACE ("Updating HS hash with ClientCertificate %u bytes",
          (ruint)parser->fragment.size);
      r_hash_update (server->hshash, parser->fragment.data, parser->fragment.size);
    case R_TLS_ERROR_NOT_NEEDED:
      break;
    case R_TLS_ERROR_NO_CERTIFICATE:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_NO_CERTIFICATE);
      break;
    case R_TLS_ERROR_CORRUPT_CERTIFICATE:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_BAD_CERTIFICATE);
      break;
    case R_TLS_ERROR_INVALID_MAC:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_BAD_CERTIFICATE_HASH_VALUE);
      break;
    case R_TLS_ERROR_CORRUPT_RECORD:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_DECODE_ERROR);
      break;
    case R_TLS_ERROR_WRONG_STATE:
    default:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
      break;
  }

  return err;
}

static RTLSError
r_tls_server_state_key_exchange (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError err;

  if ((err = r_tls_server_parse_client_key_exchange (server, parser)) == R_TLS_ERROR_OK)
    err = r_tls_server_change_state (server, R_TLS_SERVER_CHANGE_CIPHER);

  /* FIXME: Add proper alert codes for error scenarios */
  switch (err) {
    case R_TLS_ERROR_OK:
      R_LOG_TRACE ("Updating HS hash with ClientKeyExchange %u bytes",
          (ruint)parser->fragment.size);
      r_hash_update (server->hshash, parser->fragment.data, parser->fragment.size);
      r_tls_server_expand_master_secret (server);
      break;
    case R_TLS_ERROR_CORRUPT_RECORD:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_DECODE_ERROR);
      break;
    case R_TLS_ERROR_WRONG_STATE:
    default:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
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

  /* FIXME: Add proper alert codes for error scenarios */
  switch (err) {
    case R_TLS_ERROR_OK:
      /* enable cipher */
      R_LOG_DEBUG ("cipher enabled (%s)", server->csinfo->str);
      server->decrypt = r_tls_parser_decrypt;
      server->client.epoch++;
      server->client.seqno = 0;
      break;
    case R_TLS_ERROR_CORRUPT_RECORD:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_DECODE_ERROR);
      break;
    case R_TLS_ERROR_WRONG_STATE:
    default:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
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
      r_hash_update (server->hshash, parser->fragment.data, parser->fragment.size);

      if (r_tls_server_write_new_session_ticket (server) == R_TLS_ERROR_OK)
        server->server.msgseq++;
      if (r_tls_server_write_change_cipher (server) == R_TLS_ERROR_OK) {
        /* enable cipher */
        server->encrypt = r_tls_server_cipher_encrypt;
      }
      if (r_tls_server_write_finished (server) == R_TLS_ERROR_OK)
        server->server.msgseq++;

      r_hash_free (server->hshash);
      server->hshash = NULL;
      if (server->cb.handshake_done != NULL)
        server->cb.handshake_done (server->userdata, server);
      break;
    case R_TLS_ERROR_HANDSHAKE_FAILURE:
    case R_TLS_ERROR_HS_VERIFICATION_FAILED:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
      break;
    case R_TLS_ERROR_CORRUPT_RECORD:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_DECODE_ERROR);
      break;
    case R_TLS_ERROR_WRONG_TYPE:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
      break;
    case R_TLS_ERROR_WRONG_STATE:
    default:
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
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
    r_tls_server_state_change_cipher,
    r_tls_server_state_finished,
    r_tls_server_state_appdata,

    r_tls_server_state_error,
  };
  RTLSParser parser;
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
      err = r_tls_parser_init_next (&parser, &server->inbuf), server->client.seqno++) {
    r_buffer_unref (server->inbuf);
    server->inbuf = NULL;

    if (!r_tls_parser_is_dtls (&parser) || parser.epoch == server->client.epoch) {
      if ((err = server->decrypt (&parser, server->client.cipher, server->client.hmac)) != R_TLS_ERROR_OK)
        R_LOG_WARNING ("Decryption returned: %d", err);
    }

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
    if (server->inbuf != NULL) {
      r_buffer_unref (server->inbuf);
      server->inbuf = NULL;
    }
    return (err == R_TLS_ERROR_BUF_TOO_SMALL);
  }

  return TRUE;
}

RTLSError
r_tls_server_export_keying_matierial (const RTLSServer * server,
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

RDTLSSRTPProtectionProfile
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

