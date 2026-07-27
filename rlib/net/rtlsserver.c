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
#include <rlib/net/proto/rtls13.h>

#include <rlib/crypto/rx509.h>
#include <rlib/crypto/rrsa.h>

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
  R_TLS_SERVER_CLOSED,
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
  RTLSVersion min_version;      /* lowest TLS version the server will negotiate */
  RTLSVersion max_version;      /* highest; < 1.3 means the server is not 1.3-capable */
  RTLSCompressionMethod comp;
  const RTLSCipherSuiteInfo * csinfo;
  rboolean support_renego;
  rboolean support_new_session_ticket;
  rboolean support_ext_master_secret;
  rboolean encrypt_then_mac;
  RSRTPCipherSuite dtls_srtp_profile;
  ruint8 srtp_mki_size;
  const ruint8 * srtp_mki;
  rchar ** alpn_protocols;              /* configured supported protocols (owned) */
  rsize alpn_count;
  const rchar * alpn_selected;          /* negotiated protocol, points into alpn_protocols */
  rsize alpn_selected_len;
  rchar * sni;                          /* SNI host_name from the ClientHello (owned), or NULL */
  RTLSServerNameCb server_name_cb;      /* picks cert/policy for the SNI host; may be NULL */
  ruint8 max_fragment;                  /* negotiated max_fragment_length (RFC 6066): 0 none, else 1..4 */
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

  /* TLS 1.3 state (separate from the <=1.2 fields above; see proto/rtls13). */
  rboolean tls13;                       /* TLS 1.3 was negotiated */
  RTLS13Schedule sched13;               /* 1-RTT key schedule */
  RTLS13RecordKeys rk_write, rk_read;   /* installed 1.3 record keys */
  const RCryptoCipherInfo * cs13_cipher;/* AEAD for the 1.3 suite */
  RTLSCipherSuite cs13_suite;           /* 0x1301 / 0x1302 */
  RMsgDigestType cs13_hash;             /* SHA-256 / SHA-384 */
  RTLSSupportedGroup ks_group;          /* selected key_share group */
  RTLSSupportedGroup ks_pref_group;     /* group to require via HRR, or 0 */
  RCryptoKey * ks_peer_pub;             /* client key_share public key */
  RTLSSignatureScheme cv_scheme;        /* CertificateVerify signature scheme */
  rboolean hrr_sent;                    /* a HelloRetryRequest was sent */
  ruint8 cookie[32];                    /* cookie issued in the HRR */
  ruint8 cookielen;
  rboolean resumed13;                   /* 1.3 PSK resumption accepted */
  rboolean psk_dhe_ke13;                /* client offered psk_dhe_ke mode */
  ruint16 selected_identity13;          /* pre_shared_key identity echoed in SH */
  ruint8 psk13[R_TLS13_SECRET_MAX];     /* ticket-derived PSK for the schedule */
  rsize psk13_len;
  ruint32 nst13_count;                  /* NewSessionTicket nonce counter */
  ruint32 max_early_data13;             /* configured 0-RTT max_early_data_size; 0 disables */
  rboolean early13_accepted;            /* 0-RTT accepted this handshake */
  rboolean early13_draining;            /* reading early data under the early key, awaiting EndOfEarlyData */
  rboolean early13_skip;                /* early data offered but rejected: discard the client's 0-RTT records */
  rsize early13_skipped;                /* bytes of rejected early data discarded so far */
  rsize early13_received;               /* bytes of accepted early data delivered so far */

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

static inline ruint32
_r_read_u24 (const ruint8 * ptr)
{
  return ((ruint32)ptr[0] << 16) | ((ruint32)ptr[1] << 8) | (ruint32)ptr[2];
}

static inline void
_r_write_u48 (ruint8 * ptr, ruint64 u48)
{
  *ptr++ = (ruint8)(u48 >> 40) & 0xff;
  *ptr++ = (ruint8)(u48 >> 32) & 0xff;
  *ptr++ = (ruint8)(u48 >> 24) & 0xff;
  *ptr++ = (ruint8)(u48 >> 16) & 0xff;
  *ptr++ = (ruint8)(u48 >>  8) & 0xff;
  *ptr++ = (ruint8)(u48      ) & 0xff;
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
  if (server->ks_peer_pub != NULL)
    r_crypto_key_unref (server->ks_peer_pub);
  if (server->rk_write.cipher != NULL)
    r_crypto_cipher_unref (server->rk_write.cipher);
  if (server->rk_read.cipher != NULL)
    r_crypto_cipher_unref (server->rk_read.cipher);
  if (server->alpn_protocols != NULL) {
    rsize i;
    for (i = 0; i < server->alpn_count; i++)
      r_free (server->alpn_protocols[i]);
    r_free (server->alpn_protocols);
  }
  r_free (server->sni);
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
  r_memclear_secure (&server->sched13, sizeof (server->sched13));
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
    ret->min_version = R_TLS_VERSION_TLS_1_2;
    ret->max_version = R_TLS_VERSION_TLS_1_3;
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
r_tls_server_set_version_range (RTLSServer * server,
    RTLSVersion min, RTLSVersion max)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  /* The range gates version negotiation in the ServerHello; fix it first. */
  if (R_UNLIKELY (server->state > R_TLS_SERVER_HELLO)) return R_TLS_ERROR_WRONG_STATE;
  /* Only the TLS 1.2..1.3 window is configurable; DTLS is fixed at 1.2. */
  if (R_UNLIKELY (min < R_TLS_VERSION_TLS_1_2 || max > R_TLS_VERSION_TLS_1_3 ||
        min > max))
    return R_TLS_ERROR_VERSION;

  server->min_version = min;
  server->max_version = max;
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

RTLSError
r_tls_server_set_server_name_cb (RTLSServer * server, RTLSServerNameCb cb)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (server->state > R_TLS_SERVER_HELLO)) return R_TLS_ERROR_WRONG_STATE;

  server->server_name_cb = cb;
  return R_TLS_ERROR_OK;
}

RCryptoCert *
r_tls_server_get_peer_cert (const RTLSServer * server)
{
  if (R_UNLIKELY (server == NULL)) return NULL;
  return server->peer_cert;
}

const rchar *
r_tls_server_get_server_name (const RTLSServer * server)
{
  if (R_UNLIKELY (server == NULL)) return NULL;
  return server->sni;
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
r_tls_server_set_max_early_data_size (RTLSServer * server, ruint32 size)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (server->state > R_TLS_SERVER_HELLO)) return R_TLS_ERROR_WRONG_STATE;

  server->max_early_data13 = size;
  return R_TLS_ERROR_OK;
}

rboolean
r_tls_server_get_early_data_accepted (const RTLSServer * server)
{
  return server != NULL && server->early13_accepted;
}

RTLSError
r_tls_server_set_key_share_group (RTLSServer * server, RTLSSupportedGroup group)
{
  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (server->state > R_TLS_SERVER_HELLO)) return R_TLS_ERROR_WRONG_STATE;

  /* A configured group is required of TLS 1.3 clients: if a ClientHello does
   * not carry a key_share for it the server answers with a HelloRetryRequest.
   * group 0 (the default) accepts the client's first offered key_share. */
  server->ks_pref_group = group;
  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_server_set_alpn_protocols (RTLSServer * server,
    const rchar * const * protocols, rsize count)
{
  rchar ** copy;
  rsize i;

  if (R_UNLIKELY (server == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (protocols == NULL && count > 0)) return R_TLS_ERROR_INVAL;
  /* ALPN protocol names are opaque<1..255> (RFC 7301). */
  for (i = 0; i < count; i++) {
    rsize len = (protocols[i] != NULL) ? r_strlen (protocols[i]) : 0;
    if (len == 0 || len > 255)
      return R_TLS_ERROR_INVAL;
  }

  /* Replace any previously configured list. */
  if (server->alpn_protocols != NULL) {
    for (i = 0; i < server->alpn_count; i++)
      r_free (server->alpn_protocols[i]);
    r_free (server->alpn_protocols);
    server->alpn_protocols = NULL;
    server->alpn_count = 0;
  }
  if (count == 0)
    return R_TLS_ERROR_OK;

  if ((copy = r_mem_new_n (rchar *, count)) == NULL)
    return R_TLS_ERROR_OOM;
  for (i = 0; i < count; i++) {
    if ((copy[i] = r_strdup (protocols[i])) == NULL) {
      while (i > 0)
        r_free (copy[--i]);
      r_free (copy);
      return R_TLS_ERROR_OOM;
    }
  }
  server->alpn_protocols = copy;
  server->alpn_count = count;

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
r_tls_server_send_record_one (RTLSServer * server, RBuffer * buf)
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

/* Build and send one record (content type @ct) carrying @body[@bodylen], which
 * already fits the fragment cap. Uses the current write seqno (DTLS records
 * carry it in the header; send_record_one then advances it). */
static RTLSError
r_tls_server_send_slice (RTLSServer * server, rboolean dtls, ruint8 ct,
    ruint16 ver, ruint16 epoch, const ruint8 * body, rsize bodylen)
{
  RBuffer * rec;
  RMemMapInfo out = R_MEM_MAP_INFO_INIT;
  rsize hdrlen = dtls ? R_DTLS_RECORD_HDR_SIZE : R_TLS_RECORD_HDR_SIZE;
  RTLSError ret = R_TLS_ERROR_OOM;

  if ((rec = r_buffer_new_alloc (NULL, hdrlen + bodylen, NULL)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (rec, &out, R_MEM_MAP_WRITE)) {
    ruint8 * p = out.data;

    p[0] = ct;
    r_store_be16 (&p[1], ver);
    if (dtls) {
      r_store_be16 (&p[3], epoch);
      _r_write_u48 (&p[5], server->server.seqno);
      r_store_be16 (&p[11], (ruint16) bodylen);
    } else {
      r_store_be16 (&p[3], (ruint16) bodylen);
    }
    r_memcpy (p + hdrlen, body, bodylen);
    r_buffer_unmap (rec, &out);
    r_buffer_set_size (rec, hdrlen + bodylen);
    ret = r_tls_server_send_record_one (server, rec);
  }

  r_buffer_unref (rec);
  return ret;
}

/* Send a complete plaintext record, honouring a negotiated max_fragment_length
 * (RFC 6066): a payload larger than the cap is split into multiple <=cap records
 * before encryption, each with its own write sequence number. With no cap (or a
 * record that already fits) the buffer is encrypted and queued unchanged. */
static RTLSError
r_tls_server_send_record (RTLSServer * server, RBuffer * buf)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rboolean dtls = r_tls_version_is_dtls (server->version);
  rsize hdrlen = dtls ? R_DTLS_RECORD_HDR_SIZE : R_TLS_RECORD_HDR_SIZE;
  rsize cap = server->max_fragment ? ((rsize) 1u << (8 + server->max_fragment)) : 0;
  RTLSError ret;
  ruint8 ct;
  ruint16 ver, epoch = 0;
  const ruint8 * pay;
  rsize paylen, off;

  /* Fast path: no cap negotiated, or the record payload already fits. */
  if (cap == 0 || r_buffer_get_size (buf) <= hdrlen + cap)
    return r_tls_server_send_record_one (server, buf);

  if (!r_buffer_map (buf, &info, R_MEM_MAP_READ))
    return R_TLS_ERROR_OOM;
  ct = info.data[0];
  ver = r_load_be16 (&info.data[1]);
  if (dtls)
    epoch = r_load_be16 (&info.data[3]);
  pay = info.data + hdrlen;
  paylen = info.size - hdrlen;
  ret = R_TLS_ERROR_OK;

  if (dtls && ct == R_TLS_CONTENT_TYPE_HANDSHAKE) {
    /* DTLS handshake messages are not a byte stream: reframe into <=cap
     * fragments, each repeating the handshake header with its own
     * fragment_offset / fragment_length (same message sequence). */
    const ruint8 * hs = pay;
    ruint8 hstype = hs[0];
    ruint32 msglen = _r_read_u24 (&hs[1]);
    ruint16 msgseq = r_load_be16 (&hs[4]);
    const ruint8 * mbody = hs + R_DTLS_HS_HDR_SIZE;
    rsize chunkmax = cap - R_DTLS_HS_HDR_SIZE;
    ruint32 foff;

    for (foff = 0; foff < msglen && ret == R_TLS_ERROR_OK; foff += (ruint32) chunkmax) {
      rsize chunk = MIN (chunkmax, msglen - foff);
      RBuffer * rec;
      RMemMapInfo out = R_MEM_MAP_INFO_INIT;
      rsize reclen = R_DTLS_RECORD_HDR_SIZE + R_DTLS_HS_HDR_SIZE + chunk;

      ret = R_TLS_ERROR_OOM;
      if ((rec = r_buffer_new_alloc (NULL, reclen, NULL)) != NULL) {
        if (r_buffer_map (rec, &out, R_MEM_MAP_WRITE)) {
          ruint8 * p = out.data;

          /* Record header: the record carries only this fragment's bytes. */
          p[0] = R_TLS_CONTENT_TYPE_HANDSHAKE;
          r_store_be16 (&p[1], ver);
          r_store_be16 (&p[3], epoch);
          _r_write_u48 (&p[5], server->server.seqno);
          r_store_be16 (&p[11], (ruint16) (R_DTLS_HS_HDR_SIZE + chunk));
          /* Handshake header: the length is the whole message; this fragment
           * covers [foff, foff+chunk). */
          p[13] = hstype;
          _r_write_u24 (&p[14], msglen);
          r_store_be16 (&p[17], msgseq);
          _r_write_u24 (&p[19], foff);
          _r_write_u24 (&p[22], (ruint32) chunk);
          r_memcpy (p + R_DTLS_RECORD_HDR_SIZE + R_DTLS_HS_HDR_SIZE, mbody + foff, chunk);
          r_buffer_unmap (rec, &out);
          r_buffer_set_size (rec, reclen);
          ret = r_tls_server_send_record_one (server, rec);
        }
        r_buffer_unref (rec);
      }
    }
  } else {
    /* TLS (any content type, a record-layer byte stream) and DTLS
     * application data: slice the payload into <=cap records. */
    for (off = 0; off < paylen && ret == R_TLS_ERROR_OK; off += cap)
      ret = r_tls_server_send_slice (server, dtls, ct, ver, epoch,
          pay + off, MIN (cap, paylen - off));
  }

  r_buffer_unmap (buf, &info);
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
  /* Signals that a NewSessionTicket will follow (the ticket itself is minted in
   * the flight, since it binds the master secret). Without a key store the
   * server can neither seal nor open a ticket, so it makes no promise. On a
   * resumed handshake a fresh ticket IS now issued (RFC 5077 3.4), so the
   * extension is echoed there too. */
  if (!server->support_new_session_ticket || server->ticket_keys == NULL)
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

static ruint16
r_tls_server_write_hs_ext_alpn (const RTLSServer * server, ruint8 * ptr)
{
  ruint8 len;

  if (server->alpn_selected == NULL)
    return 0;

  len = (ruint8) server->alpn_selected_len;
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
  r_store_be16 (&ptr[2], (ruint16)(3 + len));  /* ProtocolNameList: list_len(2) + name_len(1) + name */
  r_store_be16 (&ptr[4], (ruint16)(1 + len));  /* list_len: one name_len(1) + name */
  ptr[6] = len;
  r_memcpy (&ptr[7], server->alpn_selected, len);

  return 7 + len;
}

static ruint16
r_tls_server_write_hs_ext_max_fragment_length (const RTLSServer * server, ruint8 * ptr)
{
  if (server->max_fragment == 0)
    return 0;

  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_MAX_FRAGMENT_LENGTH);
  r_store_be16 (&ptr[2], 1);            /* extension_data is a single byte */
  ptr[4] = server->max_fragment;        /* echo the negotiated value (1..4) */

  return 5;
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
      /* This path only writes a <= 1.2 ServerHello. Stamp the downgrade
       * sentinel (RFC 8446 4.1.3) only when the server is actually 1.3-capable;
       * a range-capped 1.2 server is a genuine 1.2 peer and must not. DTLS is
       * excluded -- the stack has no DTLS 1.3 to be downgraded from. */
      if (!r_tls_version_is_dtls (server->version) &&
          server->max_version >= R_TLS_VERSION_TLS_1_3)
        r_tls13_downgrade_random (server->servrandom, server->version);
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
    extsize += r_tls_server_write_hs_ext_alpn (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_hs_ext_max_fragment_length (server, ptr + 2 + extsize);

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

/* Wall-clock 'now' for ticket issued-at / expiry. A synthetic loop clock drives
 * it deterministically (tests advance it); a real loop clock is monotonic and
 * unsuitable for cross-process ticket expiry, so production uses wall-clock. */
static RClockTime
r_tls_server_now (const RTLSServer * server)
{
  RClock * clock;

  if (server->loop != NULL &&
      (clock = r_ev_loop_get_clock (server->loop)) != NULL &&
      r_clock_is_synthetic (clock))
    return r_clock_get_time (clock);

  return r_time_get_ts_wallclock ();
}

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
  r_store_be64 (&plain[6], (ruint64)r_tls_server_now (server));
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
      n = r_tls_hello_ext_ec_point_format_count (&ext);
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
      n = r_tls_hello_ext_supported_groups_count (&ext);
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

/* Pull the SNI host_name out of the ClientHello into server->sni, before
 * negotiation, so a server_name callback can select the cert (and per-host
 * cipher preference) it drives. RFC 6066: ServerNameList<1..> of
 * { NameType(1), HostName<1..> }; keep the first host_name entry. SNI is
 * advisory, so a malformed list is ignored rather than fatal (bounds checked). */
static void
r_tls_server_parse_sni (RTLSServer * server)
{
  RTLSHelloExt hsext = R_TLS_HELLO_EXT_INIT;
  RTLSError r;

  for (r = r_tls_hello_msg_extension_first (&server->hello, &hsext);
      r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (&server->hello, &hsext)) {
    ruint16 listlen, namelen;

    if (hsext.type != R_TLS_EXT_TYPE_SERVER_NAME)
      continue;
    if (hsext.len < 2)
      break;
    listlen = r_load_be16 (hsext.data);
    if ((rsize) listlen + 2 <= hsext.len && listlen >= 3 &&
        hsext.data[2] == 0 /* host_name */) {
      namelen = r_load_be16 (hsext.data + 3);
      if ((rsize) namelen + 3 <= (rsize) listlen) {
        r_free (server->sni);
        server->sni = r_strndup ((const rchar *) (hsext.data + 5), namelen);
      }
    }
    break;
  }
}

/* ---- TLS 1.3 (RFC 8446) 1-RTT handshake ------------------------------- */

static rboolean
r_tls_server_find_ext (const RTLSServer * server, RTLSExtensionType type,
    RTLSHelloExt * out)
{
  RTLSHelloExt e = R_TLS_HELLO_EXT_INIT;
  RTLSError r;

  for (r = r_tls_hello_msg_extension_first (&server->hello, &e);
      r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (&server->hello, &e)) {
    if (e.type == (ruint16) type) {
      *out = e;
      return TRUE;
    }
  }
  return FALSE;
}

/* Whether the ClientHello's supported_groups lists @group. */
static rboolean
r_tls_server_client_offers_group (const RTLSServer * server,
    RTLSSupportedGroup group)
{
  RTLSHelloExt sg = R_TLS_HELLO_EXT_INIT;
  ruint16 n, i;

  if (!r_tls_server_find_ext (server, R_TLS_EXT_TYPE_SUPPORTED_GROUPS, &sg))
    return FALSE;
  n = r_tls_hello_ext_supported_groups_count (&sg);
  for (i = 0; i < n; i++)
    if (r_tls_hello_ext_supported_group (&sg, i) == group)
      return TRUE;
  return FALSE;
}

/* Read the client's key_share for @group (on @curve) into a public key, or NULL
 * when the client offered no share for that group. */
static RCryptoKey *
r_tls_server_read_key_share (const RTLSServer * server,
    RTLSSupportedGroup group, REcurveID curve)
{
  RTLSHelloExt ks = R_TLS_HELLO_EXT_INIT;
  RTLSKeyShareEntry entry = R_TLS_KEY_SHARE_ENTRY_INIT;
  RTLSError r;

  if (!r_tls_server_find_ext (server, R_TLS_EXT_TYPE_KEY_SHARE, &ks))
    return NULL;
  for (r = r_tls_hello_ext_key_share_first (&ks, &entry); r == R_TLS_ERROR_OK;
      r = r_tls_hello_ext_key_share_next (&ks, &entry)) {
    if (entry.group == group)
      return r_tls_ecdhe_point_read (curve, entry.key, entry.len);
  }
  return NULL;
}

/* Session state sealed inside a TLS 1.3 resumption ticket (format version 3):
 *   version(1) | cipher_suite(2) | issued_at(8) | nonce_len(1) | nonce |
 *   resumption_master_secret(HashLen)
 * The nonce and res_master together yield the PSK; issued_at bounds expiry and
 * cipher_suite fixes the hash (so HashLen). Distinct from the 1.2 layout. */
#define R_TLS_TICKET13_STATE_VERSION  3
#define R_TLS_TICKET13_NONCE_SIZE     4
#define R_TLS_TICKET13_STATE_MAX      (1 + 2 + 8 + 1 + \
    R_TLS_TICKET13_NONCE_SIZE + R_TLS13_SECRET_MAX)

/* Cap on rejected 0-RTT ciphertext discarded before we stop trial-decrypting
 * and fail the record (bounds a peer that streams undecryptable data). */
#define R_TLS13_EARLY_DATA_SKIP_MAX   16384

/* Seal the resumption state (res_master + @nonce, keyed to the negotiated
 * suite) into an opaque ticket under the shared key store. */
static RTLSError
r_tls_server_create_session_ticket13 (RTLSServer * server,
    const ruint8 * nonce, ruint8 noncelen)
{
  ruint8 plain[R_TLS_TICKET13_STATE_MAX];
  ruint8 * ticket;
  rsize ticketsize, n = 0, hlen = r_msg_digest_type_size (server->cs13_hash);

  plain[n++] = R_TLS_TICKET13_STATE_VERSION;
  r_store_be16 (&plain[n], (ruint16) server->cs13_suite); n += 2;
  r_store_be64 (&plain[n], (ruint64) r_tls_server_now (server)); n += 8;
  plain[n++] = noncelen;
  r_memcpy (&plain[n], nonce, noncelen); n += noncelen;
  r_memcpy (&plain[n], server->sched13.res_master, hlen); n += hlen;

  if (!r_tls_session_ticket_keys_seal (server->ticket_keys, plain, n,
        &ticket, &ticketsize)) {
    r_memclear_secure (plain, sizeof (plain));
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }
  r_memclear_secure (plain, sizeof (plain));
  if (ticketsize > RUINT16_MAX) {
    r_free (ticket);
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }

  r_free (server->ticket);
  server->ticket = ticket;
  server->ticketsize = (ruint16) ticketsize;
  return R_TLS_ERROR_OK;
}

/* Compute the pre_shared_key binder over the truncated ClientHello (RFC 8446
 * 4.2.11.2): a fresh transcript from the handshake-message start up to the
 * binders-list length field, with the given PSK's binder key. */
static rboolean
r_tls_server_psk_binder (RTLSServer * server, const RTLSHelloExt * psk,
    const ruint8 * chstart, ruint8 * out)
{
  RTLS13Schedule sched;
  ruint8 bhash[R_TLS13_SECRET_MAX], bk[R_TLS13_SECRET_MAX], finkey[R_TLS13_SECRET_MAX];
  rsize hlen = r_msg_digest_type_size (server->cs13_hash);
  const ruint8 * binders = r_tls_hello_ext_psk_binders_start (psk);
  RMsgDigest * md;
  rboolean ok;

  if (binders == NULL || chstart == NULL || binders < chstart)
    return FALSE;

  if ((md = r_msg_digest_new (server->cs13_hash)) == NULL)
    return FALSE;
  ok = r_msg_digest_update (md, chstart,
          RPOINTER_TO_SIZE (binders) - RPOINTER_TO_SIZE (chstart)) &&
       r_msg_digest_get_data (md, bhash, hlen, NULL);
  r_msg_digest_free (md);
  if (!ok)
    return FALSE;

  ok = r_tls13_schedule_init_psk (&sched, server->cs13_hash,
          server->psk13, server->psk13_len) &&
       r_tls13_binder_key (&sched, bk) &&
       r_tls13_finished_key (server->cs13_hash, bk, finkey) &&
       r_tls13_verify_data (server->cs13_hash, finkey, bhash, out);
  r_memclear_secure (&sched, sizeof (sched));
  return ok;
}

/* Accept a 1.3 PSK resumption offer. Requires psk_key_exchange_modes offering
 * psk_dhe_ke and a pre_shared_key whose first identity opens under our key
 * store; the ticket's suite must match and it must be unexpired, and the binder
 * must verify. Sets server->resumed13 / psk13 / selected_identity13 on success.
 * Returns NOT_NEEDED to decline (fall back to a full handshake), OK to resume,
 * or a fatal error if a valid identity carries a bad binder. */
static RTLSError
r_tls_server_try_resume13 (RTLSServer * server)
{
  RTLSHelloExt modes = R_TLS_HELLO_EXT_INIT, psk = R_TLS_HELLO_EXT_INIT;
  RTLSPskIdentity ident = R_TLS_PSK_IDENTITY_INIT;
  ruint8 plain[R_TLS_TICKET13_STATE_MAX], expect[R_TLS13_SECRET_MAX];
  const ruint8 * nonce, * binder;
  ruint8 noncelen, binderlen;
  rsize plainlen, hlen = r_msg_digest_type_size (server->cs13_hash);
  RTLSCipherSuite suite;
  RClockTime issued, now;

  server->resumed13 = FALSE;

  if (server->ticket_keys == NULL ||
      !r_tls_server_find_ext (server, R_TLS_EXT_TYPE_PSK_KEY_EXCHANGE_MODES, &modes) ||
      !r_tls_hello_ext_psk_ke_modes_contains (&modes, R_TLS_PSK_KE_MODE_PSK_DHE_KE) ||
      !r_tls_server_find_ext (server, R_TLS_EXT_TYPE_PRE_SHARED_KEY, &psk))
    return R_TLS_ERROR_NOT_NEEDED;

  /* Try the first offered identity (this cut offers a single ticket). */
  if (r_tls_hello_ext_psk_identity_first (&psk, &ident) != R_TLS_ERROR_OK ||
      !r_tls_session_ticket_keys_open (server->ticket_keys, ident.identity,
          ident.len, plain, sizeof (plain), &plainlen))
    return R_TLS_ERROR_NOT_NEEDED;   /* unknown / stale key: full handshake */

  /* version | suite | issued_at | nonce_len | nonce | res_master(hlen). */
  if (plainlen < 1 + 2 + 8 + 1 || plain[0] != R_TLS_TICKET13_STATE_VERSION)
    goto decline;
  suite = (RTLSCipherSuite) r_load_be16 (&plain[1]);
  issued = (RClockTime) r_load_be64 (&plain[3]);
  noncelen = plain[11];
  if ((rsize) 12 + noncelen + hlen != plainlen || suite != server->cs13_suite)
    goto decline;
  nonce = &plain[12];

  now = r_tls_server_now (server);
  if (now < issued ||
      now - issued > (RClockTime) R_TLS_SESSION_TICKET_LIFETIME * R_SECOND)
    goto decline;

  /* PSK = HKDF-Expand-Label(res_master, "resumption", nonce). */
  if (!r_tls13_resumption_psk (server->cs13_hash, &plain[12 + noncelen],
        nonce, noncelen, server->psk13))
    goto decline;
  server->psk13_len = hlen;
  r_memclear_secure (plain, sizeof (plain));

  /* The binder proves the client holds the PSK: a valid ticket with a bad
   * binder is an attack, so fail fatally rather than falling back. */
  if (r_tls_hello_ext_psk_binder (&psk, 0, &binder, &binderlen) != R_TLS_ERROR_OK ||
      !r_tls_server_psk_binder (server, &psk, server->hello.random - 6, expect))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (binderlen != hlen || r_memcmp_ct (binder, expect, hlen) != 0)
    return R_TLS_ERROR_HS_VERIFICATION_FAILED;

  server->resumed13 = TRUE;
  server->selected_identity13 = 0;

  /* 0-RTT is accepted only for the first identity (this cut offers one), only
   * when configured (max_early_data13), and only when the ClientHello carries
   * the early_data extension. */
  {
    RTLSHelloExt ed = R_TLS_HELLO_EXT_INIT;
    if (server->max_early_data13 > 0 &&
        r_tls_server_find_ext (server, R_TLS_EXT_TYPE_EARLY_DATA, &ed))
      server->early13_accepted = TRUE;
  }
  return R_TLS_ERROR_OK;

decline:
  r_memclear_secure (plain, sizeof (plain));
  return R_TLS_ERROR_NOT_NEEDED;
}

/* Detect and negotiate TLS 1.3 from the parsed ClientHello. Returns
 * R_TLS_ERROR_NOT_NEEDED when 1.3 is not selected, so the caller falls through
 * to the <=1.2 negotiation; otherwise it commits to 1.3 (or fails). */
static RTLSError
r_tls_server_nego_hello13 (RTLSServer * server)
{
  RTLSHelloExt sv = R_TLS_HELLO_EXT_INIT, ks = R_TLS_HELLO_EXT_INIT;
  RTLSKeyShareEntry entry = R_TLS_KEY_SHARE_ENTRY_INIT;
  RTLSCipherSuite cs13 = R_TLS_CS_NONE;
  RCryptoAlgorithm certalgo;
  RTLSError r;
  REcurveID curve;
  ruint16 i, ncs;

  if (!r_tls_server_find_ext (server, R_TLS_EXT_TYPE_SUPPORTED_VERSIONS, &sv) ||
      !r_tls_hello_ext_supported_versions_contains (&sv, R_TLS_VERSION_TLS_1_3))
    return R_TLS_ERROR_NOT_NEEDED;

  /* Committed to 1.3: this cut needs a server certificate (no PSK). */
  if (R_UNLIKELY (server->privkey == NULL || server->cert == NULL))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* Cipher suite: the first 1.3 suite the client offered that we support. */
  ncs = (ruint16) (server->hello.cslen / sizeof (ruint16));
  for (i = 0; i < ncs; i++) {
    RTLSCipherSuite c =
        (RTLSCipherSuite) r_load_be16 (server->hello.cs + i * sizeof (ruint16));
    if (c == R_TLS_CS_AES_128_GCM_SHA256 || c == R_TLS_CS_AES_256_GCM_SHA384) {
      cs13 = c;
      break;
    }
  }
  /* The 1.3 suites carry a table entry (key_exchange NULL, the AEAD cipher and
   * the HKDF/transcript hash); record it as the negotiated suite so the public
   * accessors report it, and take the cipher and hash from it. */
  if ((server->csinfo = r_tls_cipher_suite_get_info (cs13)) == NULL ||
      server->csinfo->cipher == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  server->cs13_suite = cs13;
  server->cs13_cipher = server->csinfo->cipher;
  server->cs13_hash = server->csinfo->prf;

  /* key_share / group selection. A configured preferred group is required of
   * the client: use the client's share for it, or leave ks_peer_pub NULL to
   * signal a HelloRetryRequest if the client lists the group (supported_groups)
   * without a share. With no preference, pick the first offered share on a
   * curve we support. */
  if (server->ks_pref_group != 0) {
    if (!r_tls_ecdhe_group_to_curve (server->ks_pref_group, &curve))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    server->ks_group = server->ks_pref_group;
    server->ecdhe_curve = curve;
    server->ks_peer_pub = r_tls_server_read_key_share (server, server->ks_group, curve);
    if (server->ks_peer_pub == NULL &&
        !r_tls_server_client_offers_group (server, server->ks_group))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;   /* client cannot do the group */
  } else {
    if (!r_tls_server_find_ext (server, R_TLS_EXT_TYPE_KEY_SHARE, &ks))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    for (r = r_tls_hello_ext_key_share_first (&ks, &entry); r == R_TLS_ERROR_OK;
        r = r_tls_hello_ext_key_share_next (&ks, &entry)) {
      if (r_tls_ecdhe_group_to_curve (entry.group, &curve)) {
        server->ks_group = entry.group;
        server->ecdhe_curve = curve;
        server->ks_peer_pub = r_tls_ecdhe_point_read (curve, entry.key, entry.len);
        break;
      }
    }
    if (server->ks_peer_pub == NULL)
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }

  /* CertificateVerify scheme follows the certificate key (both hash SHA-256). */
  certalgo = r_crypto_key_get_algo (server->privkey);
  if (certalgo == R_CRYPTO_ALGO_ECDSA)
    server->cv_scheme = R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256;
  else if (certalgo == R_CRYPTO_ALGO_RSA)
    server->cv_scheme = R_TLS_SIGN_SCHEME_RSA_PSS_SHA256;
  else
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* Echo the client's legacy_session_id in the ServerHello. */
  server->session_id_len =
      MIN (server->hello.sidlen, (ruint8) sizeof (server->session_id));
  if (server->session_id_len > 0)
    r_memcpy (server->session_id, server->hello.sid, server->session_id_len);

  if ((server->hshash = r_msg_digest_new (server->cs13_hash)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* Whether the client supports (EC)DHE resumption, so we know to issue a
   * ticket after the handshake. */
  {
    RTLSHelloExt m = R_TLS_HELLO_EXT_INIT;
    server->psk_dhe_ke13 =
        r_tls_server_find_ext (server, R_TLS_EXT_TYPE_PSK_KEY_EXCHANGE_MODES, &m) &&
        r_tls_hello_ext_psk_ke_modes_contains (&m, R_TLS_PSK_KE_MODE_PSK_DHE_KE);
  }

  /* Session resumption via pre_shared_key (psk_dhe_ke): accept the ticket and
   * validate the binder, or decline (NOT_NEEDED) for a full handshake. A fatal
   * error (bad binder on a valid ticket) aborts. */
  {
    RTLSError rr = r_tls_server_try_resume13 (server);
    if (rr != R_TLS_ERROR_OK && rr != R_TLS_ERROR_NOT_NEEDED)
      return rr;
  }

  /* A client that offered early_data we did not accept has already put its
   * 0-RTT records on the wire; they must be discarded rather than fed to the
   * handshake-key AEAD (RFC 8446 4.2.10). */
  {
    RTLSHelloExt ed = R_TLS_HELLO_EXT_INIT;
    if (!server->early13_accepted &&
        r_tls_server_find_ext (server, R_TLS_EXT_TYPE_EARLY_DATA, &ed))
      server->early13_skip = TRUE;
  }

  /* ALPN: pick the first configured protocol the client also offered (server
   * preference), echoed later in EncryptedExtensions. The <=1.2 negotiation
   * runs the same selection in nego_hello, but the 1.3 cut returns before it.
   * An offer with no overlap aborts the handshake (RFC 7301 3.2). */
  {
    RTLSHelloExt a = R_TLS_HELLO_EXT_INIT;
    if (r_tls_server_find_ext (server,
          R_TLS_EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, &a)) {
      rsize k;
      for (k = 0; k < server->alpn_count && server->alpn_selected == NULL; k++) {
        rsize plen = r_strlen (server->alpn_protocols[k]);
        if (r_tls_hello_ext_alpn_contains (&a,
              (const ruint8 *) server->alpn_protocols[k], (ruint8) plen)) {
          server->alpn_selected = server->alpn_protocols[k];
          server->alpn_selected_len = plen;
        }
      }
      if (server->alpn_count > 0 && server->alpn_selected == NULL)
        return R_TLS_ERROR_NO_APPLICATION_PROTOCOL;
    }
  }

  server->comp = R_TLS_COMPRESSION_NULL;
  server->version = R_TLS_VERSION_TLS_1_3;
  server->tls13 = TRUE;
  return R_TLS_ERROR_OK;
}

/* ServerHello supported_versions: selects 0x0304. */
static ruint16
r_tls_server_write_ext13_supported_versions (ruint8 * p)
{
  r_store_be16 (p, R_TLS_EXT_TYPE_SUPPORTED_VERSIONS);
  r_store_be16 (p + 2, sizeof (ruint16));
  r_store_be16 (p + 4, R_TLS_VERSION_TLS_1_3);
  return 6;
}

/* ServerHello key_share: the single server KeyShareEntry. */
static ruint16
r_tls_server_write_ext13_key_share (RTLSServer * server, ruint8 * p)
{
  ruint8 point[256], plen = 0;

  if (!r_tls_ecdhe_point_write (server->ecdhe_key, server->ecdhe_curve,
        point, sizeof (point), &plen))
    return 0;
  r_store_be16 (p, R_TLS_EXT_TYPE_KEY_SHARE);
  r_store_be16 (p + 2, (ruint16) (2 * sizeof (ruint16) + plen));
  r_store_be16 (p + 4, (ruint16) server->ks_group);
  r_store_be16 (p + 6, plen);
  r_memcpy (p + 8, point, plen);
  return (ruint16) (8 + plen);
}

/* HelloRetryRequest key_share: the selected group only, no key_exchange. */
static ruint16
r_tls_server_write_ext13_key_share_hrr (RTLSServer * server, ruint8 * p)
{
  r_store_be16 (p, R_TLS_EXT_TYPE_KEY_SHARE);
  r_store_be16 (p + 2, sizeof (ruint16));
  r_store_be16 (p + 4, (ruint16) server->ks_group);
  return 6;
}

/* ServerHello pre_shared_key: the selected_identity (RFC 8446 4.2.11). */
static ruint16
r_tls_server_write_ext13_pre_shared_key (RTLSServer * server, ruint8 * p)
{
  r_store_be16 (p, R_TLS_EXT_TYPE_PRE_SHARED_KEY);
  r_store_be16 (p + 2, sizeof (ruint16));
  r_store_be16 (p + 4, server->selected_identity13);
  return 6;
}

/* cookie extension carrying the server-issued cookie (RFC 8446 4.2.2). */
static ruint16
r_tls_server_write_ext13_cookie (RTLSServer * server, ruint8 * p)
{
  r_store_be16 (p, R_TLS_EXT_TYPE_COOKIE);
  r_store_be16 (p + 2, (ruint16) (sizeof (ruint16) + server->cookielen));
  r_store_be16 (p + 4, server->cookielen);
  r_memcpy (p + 6, server->cookie, server->cookielen);
  return (ruint16) (6 + server->cookielen);
}

/* Write a HelloRetryRequest: a ServerHello with the HRR-sentinel random asking
 * the client to retry with a key_share for server->ks_group, plus a cookie. */
static RTLSError
r_tls_server_write_hrr (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    ruint8 * ptr;
    rsize hssize, size = 0;
    ruint16 extsize = 0;
    ruint8 hrr_random[R_TLS_HELLO_RANDOM_BYTES];

    r_tls13_hello_retry_random (hrr_random);
    ret = r_tls_write_handshake (info.data, info.size, &hssize,
        R_TLS_VERSION_TLS_1_2, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO, 0);
    ptr = info.data + hssize;
    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_write_hs_server_hello (ptr, info.size - hssize, &size,
          R_TLS_VERSION_TLS_1_2, hrr_random,
          server->session_id, server->session_id_len,
          server->cs13_suite, server->comp);
    ptr += size;

    extsize += r_tls_server_write_ext13_supported_versions (ptr + 2 + extsize);
    extsize += r_tls_server_write_ext13_key_share_hrr (server, ptr + 2 + extsize);
    extsize += r_tls_server_write_ext13_cookie (server, ptr + 2 + extsize);
    r_store_be16 (ptr, extsize);
    ptr += extsize + 2;

    size = RPOINTER_TO_SIZE (ptr) - RPOINTER_TO_SIZE (info.data);
    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_update_handshake_len (info.data, info.size,
          (ruint16) (size - hssize));
    if (ret == R_TLS_ERROR_OK)
      r_msg_digest_update (server->hshash, info.data + R_TLS_RECORD_HDR_SIZE,
          size - R_TLS_RECORD_HDR_SIZE);
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

/* Validate the second ClientHello after a HelloRetryRequest: it must echo our
 * cookie and now carry a key_share for the group we asked for. */
static RTLSError
r_tls_server_nego_hello13_retry (RTLSServer * server)
{
  RTLSHelloExt ck = R_TLS_HELLO_EXT_INIT;
  REcurveID curve;

  if (server->cookielen > 0) {
    const ruint8 * cookie;
    ruint16 cookielen;
    if (!r_tls_server_find_ext (server, R_TLS_EXT_TYPE_COOKIE, &ck))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    cookie = r_tls_hello_ext_cookie (&ck, &cookielen);
    if (cookie == NULL || cookielen != server->cookielen ||
        r_memcmp (cookie, server->cookie, cookielen) != 0)
      return R_TLS_ERROR_ILLEGAL_PARAMETER;
  }

  if (!r_tls_ecdhe_group_to_curve (server->ks_group, &curve))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  server->ks_peer_pub = r_tls_server_read_key_share (server, server->ks_group, curve);
  if (server->ks_peer_pub == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;   /* still no usable share: no second HRR */

  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_server_write_hello13 (RTLSServer * server)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;

  if ((buf = r_tls_server_alloc_buffer (server)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    ruint8 * ptr;
    rsize hssize, size = 0;
    ruint16 extsize = 0;

    if (!server->servrandompinned) {
      r_tls_generate_hello_random (server->servrandom, server->prng);
      server->servrandompinned = TRUE;
    }

    /* legacy_record_version / legacy_version stay 0x0303; the real version is
     * carried by the supported_versions extension below. */
    ret = r_tls_write_handshake (info.data, info.size, &hssize,
        R_TLS_VERSION_TLS_1_2, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO, 0);
    ptr = info.data + hssize;
    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_write_hs_server_hello (ptr, info.size - hssize, &size,
          R_TLS_VERSION_TLS_1_2, server->servrandom,
          server->session_id, server->session_id_len,
          server->cs13_suite, server->comp);
    ptr += size;

    extsize += r_tls_server_write_ext13_supported_versions (ptr + 2 + extsize);
    extsize += r_tls_server_write_ext13_key_share (server, ptr + 2 + extsize);
    if (server->resumed13)
      extsize += r_tls_server_write_ext13_pre_shared_key (server, ptr + 2 + extsize);
    r_store_be16 (ptr, extsize);
    ptr += extsize + 2;

    size = RPOINTER_TO_SIZE (ptr) - RPOINTER_TO_SIZE (info.data);
    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_update_handshake_len (info.data, info.size,
          (ruint16) (size - hssize));
    if (ret == R_TLS_ERROR_OK)
      r_msg_digest_update (server->hshash, info.data + R_TLS_RECORD_HDR_SIZE,
          size - R_TLS_RECORD_HDR_SIZE);
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

/* AEAD-protect @plain[@plainlen] (real content type @ct) under the current
 * write key and queue the application_data record. */
static RTLSError
r_tls_server_protect_record13 (RTLSServer * server, RTLSContentType ct,
    const ruint8 * plain, rsize plainlen)
{
  RBuffer * rec;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize cap = R_TLS_RECORD_HDR_SIZE + plainlen + 1 + R_TLS13_AEAD_TAG_SIZE;
  rsize enclen = 0;
  RTLSError ret = R_TLS_ERROR_OOM;

  if ((rec = r_buffer_new_alloc (NULL, cap, NULL)) == NULL)
    return R_TLS_ERROR_OOM;
  if (r_buffer_map (rec, &info, R_MEM_MAP_WRITE)) {
    ruint8 * p = info.data;
    if (r_tls13_record_protect (server->rk_write.cipher,
            server->rk_write.iv, server->rk_write.ivlen, server->rk_write.seq,
            ct, plain, plainlen,
            p + R_TLS_RECORD_HDR_SIZE, info.size - R_TLS_RECORD_HDR_SIZE, &enclen)) {
      p[0] = (ruint8) R_TLS_CONTENT_TYPE_APPLICATION_DATA;
      r_store_be16 (p + 1, R_TLS_VERSION_TLS_1_2);
      r_store_be16 (p + 3, (ruint16) enclen);
      r_buffer_unmap (rec, &info);
      r_buffer_set_size (rec, R_TLS_RECORD_HDR_SIZE + enclen);
      if (r_queue_push (&server->qsend, rec) != NULL) {
        server->rk_write.seq++;
        rec = NULL;   /* queue owns it now */
        ret = R_TLS_ERROR_OK;
      } else {
        ret = R_TLS_ERROR_QUEUE_FULL;
      }
    } else {
      r_buffer_unmap (rec, &info);
      ret = R_TLS_ERROR_ENCRYPTION_FAILED;
    }
  }

  if (rec != NULL)
    r_buffer_unref (rec);
  return ret;
}

/* Frame @body[@bodylen] as a handshake message, fold it into the transcript,
 * and send it protected with the current write key. */
static RTLSError
r_tls_server_send_hs13 (RTLSServer * server, RTLSHandshakeType type,
    const ruint8 * body, rsize bodylen)
{
  rsize msglen = R_TLS_HS_HDR_SIZE + bodylen;
  ruint8 * msg;
  RTLSError ret;

  if ((msg = r_malloc (msglen)) == NULL)
    return R_TLS_ERROR_OOM;
  msg[0] = (ruint8) type;
  msg[1] = (ruint8) ((bodylen >> 16) & 0xff);
  msg[2] = (ruint8) ((bodylen >>  8) & 0xff);
  msg[3] = (ruint8) ((bodylen      ) & 0xff);
  r_memcpy (msg + R_TLS_HS_HDR_SIZE, body, bodylen);

  r_msg_digest_update (server->hshash, msg, msglen);
  ret = r_tls_server_protect_record13 (server, R_TLS_CONTENT_TYPE_HANDSHAKE,
      msg, msglen);

  r_free (msg);
  return ret;
}

/* Install a fresh traffic key, releasing any previously installed cipher. */
static rboolean
r_tls_server_install_keys13 (RTLSServer * server, RTLS13RecordKeys * rk,
    const ruint8 * secret)
{
  if (rk->cipher != NULL) {
    r_crypto_cipher_unref (rk->cipher);
    rk->cipher = NULL;
  }
  return r_tls13_traffic_keys (server->cs13_hash, secret, server->cs13_cipher, rk);
}

/* Sign the CertificateVerify content with the negotiated scheme. */
static RTLSError
r_tls_server_sign_certificate_verify13 (RTLSServer * server,
    const ruint8 * th, rsize hlen, ruint8 * sig, rsize * siglen)
{
  ruint8 tbs[R_TLS13_CERT_VERIFY_TBS_MAX], digest[R_TLS13_SECRET_MAX];
  rsize tbslen = 0, dlen;
  RMsgDigest * md;
  rboolean ok;

  if (!r_tls13_cert_verify_tbs (TRUE, th, hlen, tbs, sizeof (tbs), &tbslen))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* Both ecdsa_secp256r1_sha256 and rsa_pss_rsae_sha256 hash with SHA-256,
   * independent of the cipher-suite hash. */
  if ((md = r_msg_digest_new (R_MSG_DIGEST_TYPE_SHA256)) == NULL)
    return R_TLS_ERROR_OOM;
  dlen = r_msg_digest_size (md);
  ok = r_msg_digest_update (md, tbs, tbslen) &&
       r_msg_digest_get_data (md, digest, dlen, NULL);
  r_msg_digest_free (md);
  if (!ok)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  if (server->cv_scheme == R_TLS_SIGN_SCHEME_RSA_PSS_SHA256)
    r_rsa_priv_key_set_padding (server->privkey, R_RSA_PADDING_PKCS1_V21);
  if (r_crypto_key_sign (server->privkey, server->prng, R_MSG_DIGEST_TYPE_SHA256,
        digest, dlen, sig, siglen) != R_CRYPTO_OK)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  return R_TLS_ERROR_OK;
}

/* Send the encrypted server flight (EncryptedExtensions, Certificate,
 * CertificateVerify, Finished) and derive the application secrets. The
 * ServerHello goes out in the clear first. */
static RTLSError
r_tls_server_write_flight13 (RTLSServer * server)
{
  ruint8 ecdhe[64], th[R_TLS13_SECRET_MAX];
  ruint8 sig[512], finkey[R_TLS13_SECRET_MAX], vd[R_TLS13_SECRET_MAX];
  ruint8 body[4096];
  rsize ecdhelen = 0, siglen = sizeof (sig), bodylen = 0;
  rsize hlen = r_msg_digest_type_size (server->cs13_hash);
  RBuffer * certbuf;
  RMemMapInfo certinfo = R_MEM_MAP_INFO_INIT;
  RTLSError ret;

  /* 0. Accepted 0-RTT: the client early-traffic secret is bound to the
   * ClientHello alone, so derive it and install the early read key now, before
   * the ServerHello is folded. The client's 0-RTT records then decrypt under it
   * until the EndOfEarlyData switches the read key to the handshake secret. */
  if (server->early13_accepted) {
    if (!r_msg_digest_get_data (server->hshash, th, hlen, NULL))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    if (!r_tls13_schedule_init_psk (&server->sched13, server->cs13_hash,
            server->psk13, server->psk13_len) ||
        !r_tls13_schedule_early (&server->sched13, th) ||
        !r_tls_server_install_keys13 (server, &server->rk_read, server->sched13.cet))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    server->early13_draining = TRUE;
  }

  /* 1. ServerHello (plaintext); generate the server ephemeral first. */
  if ((server->ecdhe_key = r_tls_ecdhe_keygen (server->ecdhe_curve, server->prng)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if ((ret = r_tls_server_write_hello13 (server)) != R_TLS_ERROR_OK)
    return ret;

  /* 2. Handshake secrets, bound to Transcript-Hash(ClientHello..ServerHello). */
  if (!r_msg_digest_get_data (server->hshash, th, hlen, NULL))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!r_tls_ecdhe_compute (server->ecdhe_key, server->ks_peer_pub,
        ecdhe, sizeof (ecdhe), &ecdhelen))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  /* Resumption is psk_dhe_ke: the Early Secret comes from the ticket PSK
   * instead of zero, then the Handshake Secret still mixes in the ECDHE. */
  if (!(server->resumed13 ?
          r_tls13_schedule_init_psk (&server->sched13, server->cs13_hash,
              server->psk13, server->psk13_len) :
          r_tls13_schedule_init (&server->sched13, server->cs13_hash)) ||
      !r_tls13_schedule_handshake (&server->sched13, ecdhe, ecdhelen, th)) {
    r_memclear_secure (ecdhe, sizeof (ecdhe));
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }
  r_memclear_secure (ecdhe, sizeof (ecdhe));

  /* 3. Install handshake-traffic keys (server writes shs, reads chs). While
   * draining 0-RTT the read key stays the early-traffic key -- it switches to
   * chs only once the EndOfEarlyData arrives. */
  if (!r_tls_server_install_keys13 (server, &server->rk_write, server->sched13.shs))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!server->early13_draining &&
      !r_tls_server_install_keys13 (server, &server->rk_read, server->sched13.chs))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* 4. EncryptedExtensions: echo the server's decisions -- early-data
   * acceptance (empty extension) and the negotiated ALPN protocol -- otherwise
   * an empty list. */
  {
    ruint8 ee[4 + 7 + 255];   /* early_data(4) + ALPN(7 + name<=255>) */
    ruint16 eelen = 0;
    if (server->early13_accepted) {
      r_store_be16 (ee, (ruint16)R_TLS_EXT_TYPE_EARLY_DATA);
      r_store_be16 (ee + 2, 0);
      eelen = 4;
    }
    eelen += r_tls_server_write_hs_ext_alpn (server, ee + eelen);
    if ((ret = r_tls_write_hs_encrypted_extensions (body, sizeof (body),
            &bodylen, eelen ? ee : NULL, eelen)) != R_TLS_ERROR_OK)
      return ret;
  }
  if ((ret = r_tls_server_send_hs13 (server,
          R_TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, body, bodylen)) != R_TLS_ERROR_OK)
    return ret;

  /* 5. + 6. Certificate and CertificateVerify: authenticated by the PSK on a
   * resumed handshake, so both are skipped (RFC 8446 2.2). */
  if (!server->resumed13) {
    /* Certificate (single leaf). */
    if ((certbuf = r_crypto_cert_get_data_buffer (server->cert)) == NULL)
      return R_TLS_ERROR_NO_CERTIFICATE;
    if (!r_buffer_map (certbuf, &certinfo, R_MEM_MAP_READ)) {
      r_buffer_unref (certbuf);
      return R_TLS_ERROR_OOM;
    }
    ret = r_tls_write_hs_certificate13 (body, sizeof (body), &bodylen,
        certinfo.data, certinfo.size);
    r_buffer_unmap (certbuf, &certinfo);
    r_buffer_unref (certbuf);
    if (ret != R_TLS_ERROR_OK)
      return ret;
    if ((ret = r_tls_server_send_hs13 (server,
            R_TLS_HANDSHAKE_TYPE_CERTIFICATE, body, bodylen)) != R_TLS_ERROR_OK)
      return ret;

    /* CertificateVerify over Transcript-Hash(ClientHello..Certificate). */
    if (!r_msg_digest_get_data (server->hshash, th, hlen, NULL))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    if ((ret = r_tls_server_sign_certificate_verify13 (server, th, hlen,
            sig, &siglen)) != R_TLS_ERROR_OK)
      return ret;
    if ((ret = r_tls_write_hs_certificate_verify (body, sizeof (body), &bodylen,
            server->cv_scheme, sig, (ruint16) siglen)) != R_TLS_ERROR_OK)
      return ret;
    if ((ret = r_tls_server_send_hs13 (server,
            R_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, body, bodylen)) != R_TLS_ERROR_OK)
      return ret;
  }

  /* 7. server Finished over Transcript-Hash(ClientHello..CertificateVerify). */
  if (!r_msg_digest_get_data (server->hshash, th, hlen, NULL))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!r_tls13_finished_key (server->cs13_hash, server->sched13.shs, finkey) ||
      !r_tls13_verify_data (server->cs13_hash, finkey, th, vd))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if ((ret = r_tls_write_hs_finished (body, sizeof (body), &bodylen,
          vd, hlen)) != R_TLS_ERROR_OK)
    return ret;
  if ((ret = r_tls_server_send_hs13 (server,
          R_TLS_HANDSHAKE_TYPE_FINISHED, body, bodylen)) != R_TLS_ERROR_OK)
    return ret;

  /* 8. Application secrets, bound to Transcript-Hash(..server Finished). The
   * client Finished still arrives under the client handshake-traffic key, so
   * the read key is not switched yet. */
  if (!r_msg_digest_get_data (server->hshash, th, hlen, NULL))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!r_tls13_schedule_master (&server->sched13, th))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  return R_TLS_ERROR_OK;
}

/* Verify the client Finished and switch to application-traffic keys. */
static RTLSError
r_tls_server_finished13 (RTLSServer * server, const RTLSParser * parser)
{
  const ruint8 * vd;
  rsize vdsize;
  ruint8 th[R_TLS13_SECRET_MAX], finkey[R_TLS13_SECRET_MAX], expect[R_TLS13_SECRET_MAX];
  rsize hlen = r_msg_digest_type_size (server->cs13_hash);
  RTLSHandshakeType type;
  RTLSError err;

  if ((err = r_tls_parser_parse_handshake_peek_type (parser, &type)) != R_TLS_ERROR_OK)
    return err;
  if (type != R_TLS_HANDSHAKE_TYPE_FINISHED)
    return R_TLS_ERROR_WRONG_TYPE;
  if ((err = r_tls_parser_parse_finished (parser, &vd, &vdsize)) != R_TLS_ERROR_OK)
    return err;

  /* The client Finished verify_data covers the transcript through the server
   * Finished -- the same hash the application secrets were bound to. */
  if (!r_msg_digest_get_data (server->hshash, th, hlen, NULL) ||
      !r_tls13_finished_key (server->cs13_hash, server->sched13.chs, finkey) ||
      !r_tls13_verify_data (server->cs13_hash, finkey, th, expect))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (vdsize != hlen || r_memcmp_ct (vd, expect, hlen) != 0)
    return R_TLS_ERROR_HS_VERIFICATION_FAILED;

  /* Switch to application-traffic keys (server writes sap, reads cap). */
  if (!r_tls_server_install_keys13 (server, &server->rk_write, server->sched13.sap) ||
      !r_tls_server_install_keys13 (server, &server->rk_read, server->sched13.cap))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* Fold the client Finished and derive the resumption master secret over
   * Transcript-Hash(ClientHello..client Finished) for any tickets we issue. */
  r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);
  if (!r_msg_digest_get_data (server->hshash, th, hlen, NULL) ||
      !r_tls13_schedule_resumption (&server->sched13, th))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  return R_TLS_ERROR_OK;
}

/* Issue a post-handshake NewSessionTicket (RFC 8446 4.6.1): mint an opaque
 * ticket around a per-ticket nonce and send it protected under the application
 * write key. Only when a key store is configured and the client offered
 * psk_dhe_ke. Not folded into any transcript (the handshake is complete). */
static RTLSError
r_tls_server_write_new_session_ticket13 (RTLSServer * server)
{
  ruint8 body[512], msg[512], nonce[R_TLS_TICKET13_NONCE_SIZE];
  ruint32 age_add;
  rsize bodylen = 0, msglen;
  RTLSError ret;

  if (server->ticket_keys == NULL || !server->psk_dhe_ke13)
    return R_TLS_ERROR_NOT_NEEDED;

  /* A per-connection counter nonce keeps each ticket's PSK distinct. */
  r_store_be32 (nonce, server->nst13_count++);
  if (!r_prng_fill (server->prng, (ruint8 *) &age_add, sizeof (age_add)))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if ((ret = r_tls_server_create_session_ticket13 (server,
          nonce, sizeof (nonce))) != R_TLS_ERROR_OK)
    return ret;

  if ((ret = r_tls_write_hs_new_session_ticket13 (body, sizeof (body), &bodylen,
          R_TLS_SESSION_TICKET_LIFETIME, age_add, nonce, sizeof (nonce),
          server->ticket, server->ticketsize,
          server->max_early_data13)) != R_TLS_ERROR_OK)
    return ret;

  msg[0] = (ruint8) R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET;
  msg[1] = (ruint8) ((bodylen >> 16) & 0xff);
  msg[2] = (ruint8) ((bodylen >>  8) & 0xff);
  msg[3] = (ruint8) ((bodylen      ) & 0xff);
  msglen = R_TLS_HS_HDR_SIZE + bodylen;
  if (R_UNLIKELY (msglen > sizeof (msg)))
    return R_TLS_ERROR_BUF_TOO_SMALL;
  r_memcpy (msg + R_TLS_HS_HDR_SIZE, body, bodylen);

  return r_tls_server_protect_record13 (server, R_TLS_CONTENT_TYPE_HANDSHAKE,
      msg, msglen);
}

/* ----------------------------------------------------------------------- */

static RTLSError
r_tls_server_nego_hello (RTLSServer * server, RTLSVersion verlo, RTLSVersion verhi)
{
  RTLSHelloExt hsext = R_TLS_HELLO_EXT_INIT;
  RTLSError r;
  ruint16 count, i;
  rboolean alpn_offered = FALSE;
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

  /* Detect a TLS 1.3 offer (supported_versions) before resolving SNI, so the
   * server_name callback sees the version that will actually be negotiated. The
   * full 1.3 negotiation runs after SNI (it needs the selected certificate). */
  if (!r_tls_version_is_dtls (server->version) &&
      server->max_version >= R_TLS_VERSION_TLS_1_3) {
    RTLSHelloExt sv = R_TLS_HELLO_EXT_INIT;
    if (r_tls_server_find_ext (server, R_TLS_EXT_TYPE_SUPPORTED_VERSIONS, &sv) &&
        r_tls_hello_ext_supported_versions_contains (&sv, R_TLS_VERSION_TLS_1_3))
      server->version = R_TLS_VERSION_TLS_1_3;
  }

  /* Resolve SNI and let the application select the certificate / policy for the
   * requested host now -- before cipher negotiation below -- so the chosen cert
   * key and any per-host cipher preference (the preferred_cipher_suites callback,
   * which sees the SNI from here on) drive suite selection. state is still
   * R_TLS_SERVER_HELLO, so the callback may call r_tls_server_set_cert /
   * _set_client_cert_mode. A callback error aborts the handshake. */
  r_tls_server_parse_sni (server);
  if (server->server_name_cb != NULL) {
    RTLSError snierr = server->server_name_cb (server->userdata, server->sni, server);
    if (snierr != R_TLS_ERROR_OK)
      return snierr;
  }

  /* A ClientHello selecting TLS 1.3 (supported_versions) takes the 1.3 path;
   * NOT_NEEDED means it did not, so fall through to the <=1.2 negotiation. The
   * range cap suppresses 1.3 entirely, making the server a genuine 1.2 peer. */
  if (!r_tls_version_is_dtls (server->version) &&
      server->max_version >= R_TLS_VERSION_TLS_1_3) {
    RTLSError r13 = r_tls_server_nego_hello13 (server);
    if (r13 != R_TLS_ERROR_NOT_NEEDED)
      return r13;
  }

  /* Falling through here means <=1.2 was negotiated; reject it if a higher
   * minimum was required. */
  if (!r_tls_version_is_dtls (server->version) &&
      server->version < server->min_version)
    return R_TLS_ERROR_VERSION;

  /* RFC 7507: TLS_FALLBACK_SCSV marks a ClientHello as a deliberate downgrade
   * of the client's own retry. Having landed below the highest version we
   * support, that fallback was forced by a meddler -- refuse it. Pairs with the
   * RFC 8446 4.1.3 ServerHello.random sentinel, which guards the reverse path. */
  if (!r_tls_version_is_dtls (server->version) &&
      server->version < server->max_version &&
      r_tls_hello_msg_has_cipher_suite (&server->hello, R_TLS_CS_FALLBACK_SCSV))
    return R_TLS_ERROR_INAPPROPRIATE_FALLBACK;

  if (R_UNLIKELY (server->hello.cslen == 0 || (server->hello.cslen & 1)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  count = server->hello.cslen / sizeof (ruint16);
  incoming = r_mem_newa_n (RTLSCipherSuite, count);
  for (i = 0; i < count; i++)
    incoming[i] = (RTLSCipherSuite) r_load_be16 (server->hello.cs + i * sizeof (ruint16));

  /* Compression: we only support null, but the client MUST offer it
   * (RFC 5246 7.4.1.4). An empty list is malformed; a non-empty list without
   * null is a well-formed-but-illegal parameter. */
  {
    ruint16 ncomp = r_tls_hello_msg_compression_count (&server->hello), c;

    if (ncomp == 0)
      return R_TLS_ERROR_CORRUPT_RECORD;
    for (c = 0; c < ncomp; c++) {
      if (r_tls_hello_msg_compression_method (&server->hello, c) == R_TLS_COMPRESSION_NULL)
        break;
    }
    if (c == ncomp)
      return R_TLS_ERROR_ILLEGAL_PARAMETER;
  }
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
  server->alpn_selected = NULL;
  server->max_fragment = 0;

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
        count = r_tls_hello_ext_use_srtp_profile_count (&hsext);
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

          count = r_tls_hello_ext_sign_scheme_count (&hsext);
          for (i = 0; i < count; i++) {
            if (r_tls_hello_ext_sign_scheme (&hsext, i) == want) {
              ok = TRUE;
              break;
            }
          }
          if (!ok)
            return R_TLS_ERROR_HANDSHAKE_FAILURE;
        }
        break;
      case R_TLS_EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
        /* Select the first of our configured protocols the client also offered
         * (server preference). With nothing configured we do not participate. */
        alpn_offered = TRUE;
        for (i = 0; i < server->alpn_count && server->alpn_selected == NULL; i++) {
          rsize plen = r_strlen (server->alpn_protocols[i]);
          if (r_tls_hello_ext_alpn_contains (&hsext,
                (const ruint8 *) server->alpn_protocols[i], (ruint8) plen)) {
            server->alpn_selected = server->alpn_protocols[i];
            server->alpn_selected_len = plen;
          }
        }
        break;
      case R_TLS_EXT_TYPE_MAX_FRAGMENT_LENGTH:
        /* RFC 6066: a single byte, 1..4 -> 2^9..2^12. Any other value (or a
         * malformed length) is illegal. The cap is echoed in the ServerHello
         * and enforced on both directions. */
        if (hsext.len != 1 || hsext.data[0] < 1 || hsext.data[0] > 4)
          return R_TLS_ERROR_ILLEGAL_PARAMETER;
        server->max_fragment = hsext.data[0];
        break;
      /* server_name (SNI) is parsed earlier, in r_tls_server_parse_sni. */
      default:
        break;
    }
  }

  /* The client offered ALPN and we have protocols configured but none matched:
   * abort (RFC 7301 3.2). With no protocols configured we simply ignore it. */
  if (alpn_offered && server->alpn_count > 0 && server->alpn_selected == NULL)
    return R_TLS_ERROR_NO_APPLICATION_PROTOCOL;

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

  /* Idempotent: release any keys a prior call installed so a re-expansion
   * (e.g. a full handshake after a failed resume) never leaks them. */
  if (server->client.hmac != NULL) { r_hmac_free (server->client.hmac); server->client.hmac = NULL; }
  if (server->server.hmac != NULL) { r_hmac_free (server->server.hmac); server->server.hmac = NULL; }
  if (server->client.cipher != NULL) { r_crypto_cipher_unref (server->client.cipher); server->client.cipher = NULL; }
  if (server->server.cipher != NULL) { r_crypto_cipher_unref (server->server.cipher); server->server.cipher = NULL; }
  r_free (server->client.fixediv); server->client.fixediv = NULL;
  r_free (server->server.fixediv); server->server.fixediv = NULL;

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
        if (r_memcmp_ct (verify_calc, verify_data, size) != 0) {
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

  /* Once 1.3 write keys are installed, alerts are AEAD-protected as
   * application_data (RFC 8446 5); only the pre-key handshake alerts are
   * plaintext. */
  if (server->tls13 && server->rk_write.cipher != NULL) {
    ruint8 body[2] = { (ruint8) level, (ruint8) alert };
    return r_tls_server_protect_record13 (server, R_TLS_CONTENT_TYPE_ALERT,
        body, sizeof (body));
  }

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
    case R_TLS_ERROR_ILLEGAL_PARAMETER: /* field value out of range */
      return R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER;
    case R_TLS_ERROR_NO_APPLICATION_PROTOCOL: /* no ALPN protocol in common */
      return R_TLS_ALERT_TYPE_NO_APPLICATION_PROTOCOL;
    case R_TLS_ERROR_INAPPROPRIATE_FALLBACK:  /* RFC 7507 fallback SCSV */
      return R_TLS_ALERT_TYPE_INAPPROPRIATE_FALLBACK;
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

/* Once closed (close_notify exchanged) any further record is dropped. */
static RTLSError
r_tls_server_state_closed (RTLSServer * server, const RTLSParser * parser)
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
/* Attempt to resume from a session ticket. Returns R_TLS_ERROR_NOT_NEEDED when
 * the ClientHello is not resumable (no ticket, or a bad / expired / unusable
 * one) and no server state was touched -- the caller runs a full handshake.
 * R_TLS_ERROR_OK means the session was adopted. Any other (negative) result
 * means a commit step failed after state was mutated: the caller must abort the
 * handshake rather than fall back (a fallback would re-derive over half-adopted
 * state). */
static RTLSError
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
    return R_TLS_ERROR_NOT_NEEDED;

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
    return R_TLS_ERROR_NOT_NEEDED;

  if (!r_tls_session_ticket_keys_open (server->ticket_keys, ticket, ticketlen,
        plain, sizeof (plain), &plainlen))
    return R_TLS_ERROR_NOT_NEEDED;
  if (plainlen != sizeof (plain) || plain[0] != R_TLS_TICKET_STATE_VERSION) {
    r_memclear_secure (plain, sizeof (plain));
    return R_TLS_ERROR_NOT_NEEDED;
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
   * (RFC 7627 5.3). All these reject as "not resumable": no state mutated yet. */
  now = r_tls_server_now (server);
  if (ver != server->version ||
      now < issued_at ||
      now - issued_at > (RClockTime) R_TLS_SESSION_TICKET_LIFETIME * R_SECOND ||
      ems != server->support_ext_master_secret ||
      !r_tls_hello_msg_has_cipher_suite (&server->hello, cs) ||
      (csinfo = r_tls_cipher_suite_get_info (cs)) == NULL) {
    r_memclear_secure (plain, sizeof (plain));
    return R_TLS_ERROR_NOT_NEEDED;
  }

  /* --- Commit: server state is mutated past here. A failure now aborts the
   * handshake (returned to the caller), it does not fall back. --- */

  /* Adopt the resumed session: the suite comes from the ticket, not this
   * ClientHello's preference-ordered negotiation (RFC 7627 5.1). */
  server->csinfo = csinfo;
  r_memcpy (server->mastersecret, &plain[14], sizeof (server->mastersecret));
  r_memclear_secure (plain, sizeof (plain));

  /* Re-select the PRF and transcript hash for the recovered suite: nego_hello
   * derived them from the negotiated suite, which the ticket suite may differ
   * from. The ClientHello is fed to hshash only after this returns (state_hello),
   * so swapping the hash here is transcript-safe; free the old one first. */
  if (server->hshash != NULL)
    r_msg_digest_free (server->hshash);
  server->hshash = NULL;
  if (!r_tls_prf_and_hash_for (csinfo->prf, &server->prf, &server->hshash))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* A fresh session id signals the resumed session to the client. Pin the
   * server random now: key expansion below and the ServerHello both consume it,
   * and they must agree. */
  server->session_id_len = (ruint8) sizeof (server->session_id);
  r_prng_fill (server->prng, server->session_id, server->session_id_len);
  if (!server->servrandompinned) {
    r_tls_generate_hello_random (server->servrandom, server->prng);
    /* Resuming a <= 1.2 session still warrants the downgrade sentinel when the
     * server is 1.3-capable (RFC 8446 4.1.3), matching r_tls_server_write_hello. */
    if (!r_tls_version_is_dtls (server->version) &&
        server->max_version >= R_TLS_VERSION_TLS_1_3)
      r_tls13_downgrade_random (server->servrandom, server->version);
    server->servrandompinned = TRUE;
  }

  /* The master secret comes from the ticket, so expand the key block directly
   * (no derivation from a pre-master secret). */
  if ((r = r_tls_server_expand_master_secret (server)) != R_TLS_ERROR_OK)
    return r;

  server->resumed = TRUE;
  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_server_state_hello (RTLSServer * server, const RTLSParser * parser)
{
  RTLSError err;

  if ((err = r_tls_parser_parse_hello (parser, &server->hello)) == R_TLS_ERROR_OK &&
      server->hrr_sent) {
    /* Second ClientHello after our HelloRetryRequest. The transcript already
     * holds message_hash(CH1) || HelloRetryRequest, so validate the retry, fold
     * CH2 and run the 1.3 flight. */
    if ((err = r_tls_server_nego_hello13_retry (server)) == R_TLS_ERROR_OK) {
      r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);
      if ((err = r_tls_server_write_flight13 (server)) == R_TLS_ERROR_OK)
        err = r_tls_server_change_state (server, R_TLS_SERVER_FINISHED);
    }
    if (err != R_TLS_ERROR_OK)
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
    return err;
  }

  if (err == R_TLS_ERROR_OK) {
    R_LOG_DEBUG ("%p - client hello parsed record ver %.4x, hello ver %.4x",
        server, parser->version, server->hello.version);
    server->hellobuf = r_buffer_ref (parser->buf);

    /* nego_hello resolves SNI and fires the server_name callback (cert / policy
     * / per-host cipher selection) before choosing the cipher suite. */
    if ((err = r_tls_server_nego_hello (server, parser->version, server->hello.version)) == R_TLS_ERROR_OK) {
      if (server->tls13) {
        /* The 1.3 flight is written below, after the ClientHello is folded into
         * the transcript; state advances there. A pre_shared_key offer is
         * accepted (or declined to a full handshake) as part of writing it. */
      } else {
        RTLSError rr = r_tls_server_try_resume (server);
        if (rr == R_TLS_ERROR_OK)
          err = r_tls_server_change_state (server, R_TLS_SERVER_CHANGE_CIPHER);
        else if (rr == R_TLS_ERROR_NOT_NEEDED)
          err = r_tls_server_change_state (server, R_TLS_SERVER_CERTIFICATE);
        else
          err = rr;   /* resume committed then failed: abort, do not fall back */
      }
    }
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      if (server->tls13 && server->ks_peer_pub == NULL) {
        /* The client did not offer a key_share for the required group: answer
         * with a HelloRetryRequest. Per RFC 8446 4.4.1 the transcript replaces
         * the first ClientHello with message_hash(CH1); issue a cookie the
         * retry must echo. */
        ruint8 mh[4 + R_TLS13_SECRET_MAX];
        rsize mhlen = 0;
        server->cookielen = (ruint8) sizeof (server->cookie);
        if (!r_prng_fill (server->prng, server->cookie, server->cookielen) ||
            !r_tls13_message_hash (server->cs13_hash, parser->fragment.data,
                parser->fragment.size, mh, sizeof (mh), &mhlen)) {
          err = R_TLS_ERROR_HANDSHAKE_FAILURE;
        } else {
          r_msg_digest_update (server->hshash, mh, mhlen);
          if ((err = r_tls_server_write_hrr (server)) == R_TLS_ERROR_OK)
            server->server.msgseq++;
        }
        if (err == R_TLS_ERROR_OK)
          server->hrr_sent = TRUE;
        else
          r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
        break;
      }

      R_LOG_TRACE ("Updating HS hash with ClientHello %u bytes",
          (ruint)parser->fragment.size);
      r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);

      if (server->tls13) {
        /* Send ServerHello..Finished, then await the client Finished. */
        if ((err = r_tls_server_write_flight13 (server)) == R_TLS_ERROR_OK)
          err = r_tls_server_change_state (server, R_TLS_SERVER_FINISHED);
        if (err != R_TLS_ERROR_OK)
          r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
        break;
      }

      if (server->resumed) {
        /* Abbreviated flight: the server Finished is sent now, ahead of the
         * client's. A fresh NewSessionTicket is reissued to refresh the
         * lifetime (RFC 5077), before the ChangeCipherSpec so it is plaintext
         * and folded into the server Finished's transcript. The client answers
         * with its ChangeCipherSpec + Finished. */
        if (r_tls_server_write_hello (server) == R_TLS_ERROR_OK)
          server->server.msgseq++;
        if (r_tls_server_write_new_session_ticket (server) == R_TLS_ERROR_OK)
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

  if (server->tls13) {
    /* While draining accepted 0-RTT (before the EndOfEarlyData), the client's
     * records arrive under the early-traffic key: application_data is delivered
     * as early data, and EndOfEarlyData ends the flow and switches the read key
     * to the client handshake-traffic secret for the client Finished. */
    if (server->early13_draining) {
      if (parser->content == R_TLS_CONTENT_TYPE_APPLICATION_DATA) {
        RBuffer * buf;
        /* Reject a client that streams more 0-RTT than the max_early_data_size
         * we advertised in the ticket (RFC 8446 4.2.10). */
        if ((server->early13_received += parser->fragment.size) >
            server->max_early_data13) {
          r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
          return R_TLS_ERROR_WRONG_TYPE;
        }
        buf = r_buffer_view (parser->buf, parser->offset, parser->fragment.size);
        if (buf != NULL) {
          server->cb.appdata (server->userdata, buf, server);
          r_buffer_unref (buf);
        }
        return R_TLS_ERROR_OK;
      }
      if (parser->content == R_TLS_CONTENT_TYPE_HANDSHAKE) {
        RTLSHandshakeType type;
        if ((err = r_tls_parser_parse_handshake_peek_type (parser, &type)) != R_TLS_ERROR_OK ||
            type != R_TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA) {
          r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
          return R_TLS_ERROR_WRONG_TYPE;
        }
        r_msg_digest_update (server->hshash, parser->fragment.data, parser->fragment.size);
        server->early13_draining = FALSE;
        if (!r_tls_server_install_keys13 (server, &server->rk_read, server->sched13.chs)) {
          r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
          return R_TLS_ERROR_HANDSHAKE_FAILURE;
        }
        return R_TLS_ERROR_OK;
      }
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
      return R_TLS_ERROR_WRONG_TYPE;
    }

    if ((err = r_tls_server_finished13 (server, parser)) == R_TLS_ERROR_OK)
      err = r_tls_server_change_state (server, R_TLS_SERVER_APPDATA);
    if (err == R_TLS_ERROR_OK) {
      r_msg_digest_free (server->hshash);
      server->hshash = NULL;
      /* Offer a resumption ticket now that the handshake (and the resumption
       * master secret) is complete. A failure here does not fail the session. */
      r_tls_server_write_new_session_ticket13 (server);
      if (server->cb.handshake_done != NULL)
        server->cb.handshake_done (server->userdata, server);
    } else {
      r_tls_server_send_alert (server, r_tls_server_alert_for_error (err));
    }
    return err;
  }

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

/* Send a post-handshake KeyUpdate (RFC 8446 4.6.3) and rotate our sending key.
 * Unlike handshake-phase messages it is framed but not folded into the
 * transcript. It goes out under the current write key; every record after it
 * uses the advanced key, so the rotation follows the queued record. */
static RTLSError
r_tls_server_send_key_update13 (RTLSServer * server, rboolean request_peer_update)
{
  ruint8 msg[R_TLS_HS_HDR_SIZE + 1];
  RTLSError ret;

  msg[0] = (ruint8) R_TLS_HANDSHAKE_TYPE_KEY_UPDATE;
  msg[1] = 0x00;
  msg[2] = 0x00;
  msg[3] = 0x01;
  msg[4] = (ruint8) (request_peer_update ? R_TLS_KEY_UPDATE_REQUESTED
                                         : R_TLS_KEY_UPDATE_NOT_REQUESTED);

  if ((ret = r_tls_server_protect_record13 (server, R_TLS_CONTENT_TYPE_HANDSHAKE,
          msg, sizeof (msg))) != R_TLS_ERROR_OK)
    return ret;

  if (!r_tls13_traffic_update (server->cs13_hash, server->sched13.sap,
          server->sched13.sap) ||
      !r_tls_server_install_keys13 (server, &server->rk_write, server->sched13.sap))
    return R_TLS_ERROR_ENCRYPTION_FAILED;
  return R_TLS_ERROR_OK;
}

/* Handle a peer KeyUpdate (RFC 8446 4.6.3): advance our receiving key to the
 * peer's next generation and, when asked, answer with our own KeyUpdate --
 * never itself update_requested, so the exchange cannot loop. The queued reply
 * is flushed by the incoming_data send_out once dispatch returns. */
static RTLSError
r_tls_server_recv_key_update13 (RTLSServer * server, const RTLSParser * parser)
{
  ruint8 request;

  if (r_tls_parser_parse_key_update (parser, &request) != R_TLS_ERROR_OK ||
      request > R_TLS_KEY_UPDATE_REQUESTED) {
    r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
    return R_TLS_ERROR_ILLEGAL_PARAMETER;
  }

  if (!r_tls13_traffic_update (server->cs13_hash, server->sched13.cap,
          server->sched13.cap) ||
      !r_tls_server_install_keys13 (server, &server->rk_read, server->sched13.cap)) {
    r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
    return R_TLS_ERROR_ENCRYPTION_FAILED;
  }

  if (request == R_TLS_KEY_UPDATE_REQUESTED)
    return r_tls_server_send_key_update13 (server, FALSE);
  return R_TLS_ERROR_OK;
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
  } else if (parser->content == R_TLS_CONTENT_TYPE_HANDSHAKE) {
    RTLSHandshakeType hstype;

    if (r_tls_parser_parse_handshake_peek_type (parser, &hstype) != R_TLS_ERROR_OK)
      R_LOG_WARNING ("Received non-app-data record");
    else if (server->tls13 && hstype == R_TLS_HANDSHAKE_TYPE_KEY_UPDATE)
      return r_tls_server_recv_key_update13 (server, parser);
    else if (hstype == R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
      /* A post-handshake ClientHello is a renegotiation attempt. We do not
       * renegotiate; decline with a warning and keep the session running
       * (RFC 5246 7.2.1). The caller flushes via send_out after dispatch. */
      r_tls_server_emit_alert (server, R_TLS_ALERT_LEVEL_WARNING,
          R_TLS_ALERT_TYPE_NO_RENEGOTIATION);
    else
      R_LOG_WARNING ("Received non-app-data record");
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
    r_tls_server_state_closed,

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

    if (server->tls13) {
      /* TLS 1.3: a middlebox-compat ChangeCipherSpec is ignored entirely
       * (RFC 8446 5). Once read keys are installed, the peer's records are
       * AEAD-protected application_data; the ClientHello before that is
       * plaintext and passes through to the state handler. */
      if (parser.content == R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC)
        continue;
      if (server->rk_read.cipher != NULL &&
          parser.content == R_TLS_CONTENT_TYPE_APPLICATION_DATA) {
        if ((err = r_tls_parser_unprotect13 (&parser, server->rk_read.cipher,
                server->rk_read.iv, server->rk_read.ivlen,
                server->rk_read.seq)) != R_TLS_ERROR_OK) {
          /* Rejected 0-RTT: the client's early-data records fail under the
           * handshake key. Discard them (no alert) up to a bound, until the
           * client Finished decrypts (RFC 8446 4.2.10). */
          if (server->early13_skip &&
              (server->early13_skipped += parser.fragment.size) <=
                  R_TLS13_EARLY_DATA_SKIP_MAX)
            continue;
          R_LOG_WARNING ("1.3 record unprotect returned: %d", err);
          r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_BAD_RECORD_MAC);
          continue;
        }
        server->early13_skip = FALSE;   /* a record decrypted: early data is over */
        server->rk_read.seq++;
      } else if (server->early13_skip &&
          parser.content == R_TLS_CONTENT_TYPE_APPLICATION_DATA) {
        /* Rejected 0-RTT with no read key yet installed (e.g. after a
         * HelloRetryRequest): the early-data records are undecryptable, so
         * discard them up to the same bound. */
        if ((server->early13_skipped += parser.fragment.size) <=
                R_TLS13_EARLY_DATA_SKIP_MAX)
          continue;
        r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_BAD_RECORD_MAC);
        continue;
      }
    } else {
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
    }

    /* Honour a negotiated max_fragment_length: a plaintext fragment larger than
     * the cap is a fatal record_overflow (RFC 6066). */
    if (server->max_fragment != 0 &&
        parser.fragment.size > ((rsize) 1u << (8 + server->max_fragment))) {
      r_tls_server_send_alert (server, R_TLS_ALERT_TYPE_RECORD_OVERFLOW);
      err = R_TLS_ERROR_RECORD_OVERFLOW;
      break;
    }

    /* Count the accepted record. A ChangeCipherSpec resets the read counter
     * to 0 for the new read state in its handler below, so increment first. */
    server->client.seqno++;

    if (parser.content == R_TLS_CONTENT_TYPE_ALERT) {
      RTLSAlertLevel alevel;
      RTLSAlertType atype;

      if ((err = r_tls_parser_parse_alert (&parser, &alevel, &atype)) == R_TLS_ERROR_OK) {
        R_LOG_WARNING ("Received Alert, %.2x %.2x", alevel, atype);

        if (alevel == R_TLS_ALERT_LEVEL_FATAL) {
          err = r_tls_server_change_state (server, R_TLS_SERVER_ERROR);
        } else if (atype == R_TLS_ALERT_TYPE_CLOSE_NOTIFY &&
            server->state < R_TLS_SERVER_CLOSED) {
          /* Respond with our own close_notify (RFC 5246 7.2.1) and surface
           * the orderly close to the application. */
          if (r_tls_server_emit_alert (server, R_TLS_ALERT_LEVEL_WARNING,
                R_TLS_ALERT_TYPE_CLOSE_NOTIFY) == R_TLS_ERROR_OK)
            r_tls_server_send_out (server);
          r_tls_server_change_state (server, R_TLS_SERVER_CLOSED);
          if (server->cb.closed != NULL)
            server->cb.closed (server->userdata, server);
        }
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

  if (server->tls13) {
    ret = r_tls_server_protect_record13 (server,
        R_TLS_CONTENT_TYPE_APPLICATION_DATA, in.data, in.size);
    r_buffer_unmap (buffer, &in);
    if (ret != R_TLS_ERROR_OK)
      return FALSE;
    r_tls_server_send_out (server);
    return TRUE;
  }

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

rboolean
r_tls_server_key_update (RTLSServer * server, rboolean request_peer_update)
{
  if (R_UNLIKELY (server == NULL)) return FALSE;
  /* KeyUpdate is a TLS 1.3 post-handshake message; the record keys must be
   * installed, i.e. the session established. */
  if (R_UNLIKELY (!server->tls13 || server->state != R_TLS_SERVER_APPDATA))
    return FALSE;

  if (r_tls_server_send_key_update13 (server, request_peer_update) != R_TLS_ERROR_OK)
    return FALSE;

  r_tls_server_send_out (server);
  return TRUE;
}

rboolean
r_tls_server_close (RTLSServer * server)
{
  if (R_UNLIKELY (server == NULL)) return FALSE;
  /* Only an established session can be cleanly closed; a second call is a
   * no-op (the state has already advanced past APPDATA). */
  if (server->state != R_TLS_SERVER_APPDATA) return FALSE;

  if (r_tls_server_emit_alert (server, R_TLS_ALERT_LEVEL_WARNING,
        R_TLS_ALERT_TYPE_CLOSE_NOTIFY) != R_TLS_ERROR_OK)
    return FALSE;

  r_tls_server_send_out (server);
  r_tls_server_change_state (server, R_TLS_SERVER_CLOSED);
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

const rchar *
r_tls_server_get_alpn_selected (const RTLSServer * server, rsize * len)
{
  if (len != NULL)
    *len = (server != NULL) ? server->alpn_selected_len : 0;

  return (server != NULL) ? server->alpn_selected : NULL;
}

