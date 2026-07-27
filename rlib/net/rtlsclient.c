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
#include <rlib/net/proto/rtls13.h>

#include <rlib/crypto/rx509.h>
#include <rlib/crypto/rrsa.h>

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
  R_TLS_CLIENT_CLOSED,
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
  RTLSVersion min_version;      /* lowest TLS version the client will offer / accept */
  RTLSVersion max_version;      /* highest offered; == version at start, then negotiated */
  rboolean version_range_set;   /* an explicit range was configured before start */
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

  rchar * server_name;         /* SNI host to offer in the ClientHello, or NULL */

  rboolean ecdhe;                  /* an ECDHE suite was negotiated */
  REcurveID ecdhe_curve;           /* the server-selected named group */
  RCryptoKey * ecdhe_key;          /* client ephemeral ECDH private key */
  RCryptoKey * ecdhe_server_pub;   /* server's ephemeral public point */

  /* TLS 1.3 state (see proto/rtls13). */
  rboolean tls13;                       /* TLS 1.3 was negotiated */
  RTLS13Schedule sched13;               /* 1-RTT key schedule */
  RTLS13RecordKeys rk_write, rk_read;   /* installed 1.3 record keys */
  const RCryptoCipherInfo * cs13_cipher;/* AEAD for the 1.3 suite */
  RTLSCipherSuite cs13_suite;           /* 0x1301 / 0x1302 */
  RMsgDigestType cs13_hash;             /* SHA-256 / SHA-384 */
  RTLSSupportedGroup ks_group;          /* offered key_share group */
  ruint8 flight13_step;                 /* sub-step within the encrypted flight */
  rboolean hrr_received;                /* a HelloRetryRequest was processed */
  rboolean hrr_just_sent;              /* the retry ClientHello was just sent */
  ruint8 cookie[256];                   /* cookie echoed in the retry ClientHello */
  ruint16 cookielen;
  RTLSClientSession * resume;           /* session to offer for resumption, or NULL */
  RTLSClientSession * new_session;      /* session from a received NewSessionTicket */
  rboolean resumed13;                   /* server accepted our pre_shared_key */
  RBuffer * early_data;                 /* 0-RTT payload to offer, or NULL */
  rboolean early13_sent;                /* early_data offered and records emitted */
  rboolean early13_accepted;            /* server echoed early_data in EncryptedExtensions */

  RBuffer * inbuf;
  RQueue qsend;
};

/* A stored TLS 1.3 resumption session: the server's ticket, the PSK derived
 * from it, and the parameters needed to offer it again (RFC 8446 4.6.1). */
struct RTLSClientSession {
  RRef ref;
  ruint8 * ticket;              /* opaque NewSessionTicket identity */
  rsize ticketlen;
  ruint8 psk[R_TLS13_SECRET_MAX];
  rsize psklen;
  RTLSCipherSuite suite;
  RMsgDigestType hash;
  ruint32 age_add;
  ruint32 max_early_data;       /* early_data max_early_data_size, 0 if no 0-RTT */
  RClockTime obtained;          /* when the ticket arrived, for obfuscated age */
};

static void
r_tls_client_session_free (RTLSClientSession * s)
{
  r_free (s->ticket);
  r_memclear_secure (s->psk, sizeof (s->psk));
  r_free (s);
}

/* Wall-clock 'now' for ticket age bookkeeping; a synthetic loop clock drives it
 * deterministically in tests (mirrors r_tls_server_now). */
static RClockTime
r_tls_client_now (const RTLSClient * client)
{
  RClock * clock;

  if (client->loop != NULL &&
      (clock = r_ev_loop_get_clock (client->loop)) != NULL &&
      r_clock_is_synthetic (clock))
    return r_clock_get_time (clock);

  return r_time_get_ts_wallclock ();
}

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
  r_free (client->server_name);
  if (client->ecdhe_key != NULL)
    r_crypto_key_unref (client->ecdhe_key);
  if (client->ecdhe_server_pub != NULL)
    r_crypto_key_unref (client->ecdhe_server_pub);
  if (client->rk_write.cipher != NULL)
    r_crypto_cipher_unref (client->rk_write.cipher);
  if (client->rk_read.cipher != NULL)
    r_crypto_cipher_unref (client->rk_read.cipher);
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
  if (client->resume != NULL)
    r_tls_client_session_unref (client->resume);
  if (client->new_session != NULL)
    r_tls_client_session_unref (client->new_session);
  if (client->early_data != NULL)
    r_buffer_unref (client->early_data);

  if (client->inbuf != NULL)
    r_buffer_unref (client->inbuf);
  r_queue_clear (&client->qsend, r_buffer_unref);
  r_memclear_secure (client->mastersecret, sizeof (client->mastersecret));
  r_memclear_secure (&client->sched13, sizeof (client->sched13));
  r_free (client);
}

RTLSError
r_tls_client_set_session (RTLSClient * client, RTLSClientSession * session)
{
  if (R_UNLIKELY (client == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (client->loop != NULL)) return R_TLS_ERROR_WRONG_STATE;

  if (client->resume != NULL)
    r_tls_client_session_unref (client->resume);
  client->resume = (session != NULL) ? r_tls_client_session_ref (session) : NULL;
  return R_TLS_ERROR_OK;
}

RTLSClientSession *
r_tls_client_get_session (const RTLSClient * client)
{
  if (R_UNLIKELY (client == NULL) || client->new_session == NULL)
    return NULL;
  return r_tls_client_session_ref (client->new_session);
}

RTLSError
r_tls_client_set_early_data (RTLSClient * client, RBuffer * buffer)
{
  if (R_UNLIKELY (client == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (client->loop != NULL)) return R_TLS_ERROR_WRONG_STATE;

  if (client->early_data != NULL)
    r_buffer_unref (client->early_data);
  client->early_data = (buffer != NULL) ? r_buffer_ref (buffer) : NULL;
  return R_TLS_ERROR_OK;
}

rboolean
r_tls_client_get_early_data_accepted (const RTLSClient * client)
{
  return client != NULL && client->early13_accepted;
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
    ret->min_version = R_TLS_VERSION_TLS_1_2;
    ret->max_version = R_TLS_VERSION_TLS_1_3;
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
r_tls_client_set_server_name (RTLSClient * client, const rchar * host)
{
  if (R_UNLIKELY (client == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (client->state != R_TLS_CLIENT_INITIAL)) return R_TLS_ERROR_WRONG_STATE;
  /* The name is copied verbatim into one ClientHello record; a DNS host name is
   * at most 255 bytes (RFC 1035). Reject anything longer rather than risk the
   * record buffer / overflow the 16-bit extension length fields. */
  if (R_UNLIKELY (host != NULL && r_strlen (host) > 255)) return R_TLS_ERROR_INVAL;

  r_free (client->server_name);
  client->server_name = (host != NULL) ? r_strdup (host) : NULL;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_client_set_version_range (RTLSClient * client,
    RTLSVersion min, RTLSVersion max)
{
  if (R_UNLIKELY (client == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (client->state != R_TLS_CLIENT_INITIAL)) return R_TLS_ERROR_WRONG_STATE;
  /* Only the TLS 1.2..1.3 window is configurable; DTLS is fixed at 1.2. */
  if (R_UNLIKELY (min < R_TLS_VERSION_TLS_1_2 || max > R_TLS_VERSION_TLS_1_3 ||
        min > max))
    return R_TLS_ERROR_VERSION;

  client->min_version = min;
  client->max_version = max;
  client->version_range_set = TRUE;
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

static RTLSError r_tls_client_protect_record13 (RTLSClient * client,
    RTLSContentType ct, const ruint8 * plain, rsize plainlen);
static rboolean r_tls_client_install_keys13 (RTLSClient * client,
    RTLS13RecordKeys * rk, const ruint8 * secret);
static rboolean r_tls_client_setup_early_keys13 (RTLSClient * client);
static RTLSError r_tls_client_send_early_data13 (RTLSClient * client);

/* Build an alert record and queue it for sending; the caller flushes. */
static RTLSError
r_tls_client_emit_alert (RTLSClient * client, RTLSAlertLevel level,
    RTLSAlertType alert)
{
  RBuffer * buf;
  RTLSError ret = R_TLS_ERROR_OOM;
  RTLSVersion ver = (client->version != 0) ? client->version : client->recordver;

  /* Once 1.3 write keys are installed, alerts are AEAD-protected as
   * application_data (RFC 8446 5); only the pre-key handshake alerts are
   * plaintext. */
  if (client->tls13 && client->rk_write.cipher != NULL) {
    ruint8 body[2] = { (ruint8) level, (ruint8) alert };
    return r_tls_client_protect_record13 (client, R_TLS_CONTENT_TYPE_ALERT,
        body, sizeof (body));
  }

  if ((buf = r_tls_client_alloc_buffer (client)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
      rsize sz = 0;

      if (r_tls_version_is_dtls (ver))
        ret = r_dtls_write_alert (info.data, info.size, &sz, ver,
            client->client.epoch, client->client.seqno, level, alert);
      else
        ret = r_tls_write_alert (info.data, info.size, &sz, ver, level, alert);
      r_buffer_unmap (buf, &info);

      if (ret == R_TLS_ERROR_OK) {
        r_buffer_set_size (buf, sz);
        ret = r_tls_client_send_record (client, buf);
      }
    }
    r_buffer_unref (buf);
  }

  return ret;
}

static void
r_tls_client_send_alert (RTLSClient * client, RTLSAlertType alert)
{
  R_LOG_WARNING ("Sending alert: 0x%.2x in state (%d)", alert, client->state);

  if (r_tls_client_emit_alert (client, R_TLS_ALERT_LEVEL_FATAL, alert)
      == R_TLS_ERROR_OK)
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
r_tls_client_write_hs_ext_signature_algorithms (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_SIGNATURE_ALGORITHMS);
  r_store_be16 (&ptr[2], 2 + 2 * sizeof (ruint16));   /* list length + 2 schemes */
  r_store_be16 (&ptr[4], 2 * sizeof (ruint16));       /* scheme list length */
  r_store_be16 (&ptr[6], (ruint16)R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256);
  r_store_be16 (&ptr[8], (ruint16)R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA256);
  return 10;
}

/* server_name (SNI, RFC 6066): a ServerNameList with one host_name entry.
 * Offered only when a name was set via r_tls_client_set_server_name. */
static ruint16
r_tls_client_write_hs_ext_server_name (ruint8 * ptr, const rchar * name)
{
  rsize namelen = r_strlen (name);
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_SERVER_NAME);
  r_store_be16 (&ptr[2], (ruint16)(5 + namelen));    /* extension_data length */
  r_store_be16 (&ptr[4], (ruint16)(3 + namelen));    /* ServerNameList length */
  ptr[6] = 0;                                         /* NameType: host_name */
  r_store_be16 (&ptr[7], (ruint16)namelen);          /* HostName length */
  r_memcpy (&ptr[9], name, namelen);
  return (ruint16)(9 + namelen);
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
  const RTLSCipherSuite preferred[] = { R_TLS_DEFAULT_CIPHER_SUITES };

  (void) ctx; (void) ver;

  *count = MIN (*count, R_N_ELEMENTS (preferred));
  r_memcpy (cs, preferred, *count * sizeof (RTLSCipherSuite));

  return TRUE;
}

/* signature_algorithms for 1.3: offer ecdsa_secp256r1_sha256 and
 * rsa_pss_rsae_sha256 (the schemes valid for a 1.3 CertificateVerify), plus
 * rsa_pkcs1_sha256 for certificate signatures. */
static ruint16
r_tls_client_write_hs_ext_signature_algorithms13 (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_SIGNATURE_ALGORITHMS);
  r_store_be16 (&ptr[2], 2 + 3 * sizeof (ruint16));
  r_store_be16 (&ptr[4], 3 * sizeof (ruint16));
  r_store_be16 (&ptr[6], (ruint16)R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256);
  r_store_be16 (&ptr[8], (ruint16)R_TLS_SIGN_SCHEME_RSA_PSS_SHA256);
  r_store_be16 (&ptr[10], (ruint16)R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA256);
  return 12;
}

/* ClientHello supported_versions offering TLS 1.3 first, then 1.2 when it is
 * within the configured range, so a 1.3-capable server picks 1.3 while a
 * 1.2-only server can still match the hybrid offer. */
static ruint16
r_tls_client_write_hs_ext_supported_versions13 (ruint8 * ptr, rboolean include_tls12)
{
  ruint8 n = include_tls12 ? 2 : 1;
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_SUPPORTED_VERSIONS);
  r_store_be16 (&ptr[2], sizeof (ruint8) + n * sizeof (ruint16));
  ptr[4] = n * sizeof (ruint16);                      /* ProtocolVersion list length */
  r_store_be16 (&ptr[5], (ruint16)R_TLS_VERSION_TLS_1_3);
  if (include_tls12)
    r_store_be16 (&ptr[7], (ruint16)R_TLS_VERSION_TLS_1_2);
  return 5 + n * sizeof (ruint16);
}

/* ClientHello key_share with a single KeyShareEntry for the offered group. */
static ruint16
r_tls_client_write_hs_ext_key_share13 (RTLSClient * client, ruint8 * ptr)
{
  ruint8 point[256], plen = 0;
  ruint16 entrylen;

  if (!r_tls_ecdhe_point_write (client->ecdhe_key, client->ecdhe_curve,
        point, sizeof (point), &plen))
    return 0;
  entrylen = (ruint16) (2 * sizeof (ruint16) + plen);     /* group + klen + key */
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_KEY_SHARE);
  r_store_be16 (&ptr[2], (ruint16) (sizeof (ruint16) + entrylen));
  r_store_be16 (&ptr[4], entrylen);                       /* client_shares length */
  r_store_be16 (&ptr[6], (ruint16)client->ks_group);
  r_store_be16 (&ptr[8], plen);
  r_memcpy (&ptr[10], point, plen);
  return (ruint16) (10 + plen);
}

/* ClientHello cookie echo: returns the HelloRetryRequest's cookie verbatim. */
static ruint16
r_tls_client_write_hs_ext_cookie (RTLSClient * client, ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_COOKIE);
  r_store_be16 (&ptr[2], (ruint16) (sizeof (ruint16) + client->cookielen));
  r_store_be16 (&ptr[4], client->cookielen);
  r_memcpy (&ptr[6], client->cookie, client->cookielen);
  return (ruint16) (6 + client->cookielen);
}

/* psk_key_exchange_modes offering psk_dhe_ke (RFC 8446 4.2.9). */
static ruint16
r_tls_client_write_hs_ext_psk_key_exchange_modes (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_PSK_KEY_EXCHANGE_MODES);
  r_store_be16 (&ptr[2], 2);
  ptr[4] = 1;                                     /* ke_modes<1..255> length */
  ptr[5] = (ruint8) R_TLS_PSK_KE_MODE_PSK_DHE_KE;
  return 6;
}

/* Empty early_data extension: signals a 0-RTT offer in the ClientHello
 * (RFC 8446 4.2.10). */
static ruint16
r_tls_client_write_hs_ext_early_data (ruint8 * ptr)
{
  r_store_be16 (&ptr[0], (ruint16)R_TLS_EXT_TYPE_EARLY_DATA);
  r_store_be16 (&ptr[2], 0);
  return 4;
}

/* Whether an EncryptedExtensions handshake message (a full message: 4-byte
 * header then a uint16-prefixed extension list) carries an early_data
 * extension, i.e. the server accepted 0-RTT. */
static rboolean
r_tls_client_ee_has_early_data (const ruint8 * msg, rsize msglen)
{
  const ruint8 * p, * end;
  ruint16 extslen;

  if (msglen < R_TLS_HS_HDR_SIZE + sizeof (ruint16))
    return FALSE;
  p = msg + R_TLS_HS_HDR_SIZE;
  extslen = r_load_be16 (p);
  p += sizeof (ruint16);
  end = p + extslen;
  if (RPOINTER_TO_SIZE (end) > RPOINTER_TO_SIZE (msg + msglen))
    return FALSE;
  while (p + 2 * sizeof (ruint16) <= end) {
    ruint16 etype = r_load_be16 (p);
    ruint16 elen = r_load_be16 (p + sizeof (ruint16));
    p += 2 * sizeof (ruint16);
    if (p + elen > end)
      return FALSE;
    if (etype == R_TLS_EXT_TYPE_EARLY_DATA)
      return TRUE;
    p += elen;
  }
  return FALSE;
}

/* pre_shared_key offer with a single identity and a zeroed binder placeholder
 * (RFC 8446 4.2.11). Returns bytes written and, via @binder_off, the offset of
 * the binder value within @ptr so the caller can patch it after computing it
 * over the truncated ClientHello. */
static ruint16
r_tls_client_write_hs_ext_pre_shared_key (RTLSClient * client, ruint8 * ptr,
    ruint8 binderlen, rsize * binder_off)
{
  RTLSClientSession * s = client->resume;
  ruint16 idlen = (ruint16) s->ticketlen;
  ruint16 idslen = (ruint16) (sizeof (ruint16) + idlen + sizeof (ruint32));
  ruint16 bslen = (ruint16) (1 + binderlen);
  ruint32 age;
  rsize n = 0;

  /* obfuscated_ticket_age = elapsed_ms + ticket_age_add (RFC 8446 4.2.11.1). */
  age = (ruint32) ((r_tls_client_now (client) - s->obtained) / R_MSECOND) + s->age_add;

  r_store_be16 (&ptr[n], (ruint16)R_TLS_EXT_TYPE_PRE_SHARED_KEY); n += 2;
  r_store_be16 (&ptr[n], (ruint16) (sizeof (ruint16) + idslen +
        sizeof (ruint16) + bslen)); n += 2;
  r_store_be16 (&ptr[n], idslen); n += 2;         /* identities<7..> length */
  r_store_be16 (&ptr[n], idlen); n += 2;
  r_memcpy (&ptr[n], s->ticket, idlen); n += idlen;
  r_store_be32 (&ptr[n], age); n += 4;
  r_store_be16 (&ptr[n], bslen); n += 2;          /* binders<33..> length */
  ptr[n++] = binderlen;
  *binder_off = n;
  r_memset (&ptr[n], 0, binderlen); n += binderlen;
  return (ruint16) n;
}

/* Compute the pre_shared_key binder over the truncated ClientHello
 * [@chstart, @binders) with the resumption PSK's binder key (RFC 8446
 * 4.2.11.2). Assumes an empty prior transcript (the non-retry offer). */
static rboolean
r_tls_client_psk_binder (RTLSClient * client, const ruint8 * chstart,
    const ruint8 * binders, ruint8 * out)
{
  RTLSClientSession * s = client->resume;
  RTLS13Schedule sched;
  ruint8 bhash[R_TLS13_SECRET_MAX], bk[R_TLS13_SECRET_MAX], finkey[R_TLS13_SECRET_MAX];
  rsize hlen = r_msg_digest_type_size (s->hash);
  RMsgDigest * md;
  rboolean ok;

  if ((md = r_msg_digest_new (s->hash)) == NULL)
    return FALSE;
  ok = r_msg_digest_update (md, chstart,
          RPOINTER_TO_SIZE (binders) - RPOINTER_TO_SIZE (chstart)) &&
       r_msg_digest_get_data (md, bhash, hlen, NULL);
  r_msg_digest_free (md);
  if (!ok)
    return FALSE;

  ok = r_tls13_schedule_init_psk (&sched, s->hash, s->psk, s->psklen) &&
       r_tls13_binder_key (&sched, bk) &&
       r_tls13_finished_key (s->hash, bk, finkey) &&
       r_tls13_verify_data (s->hash, finkey, bhash, out);
  r_memclear_secure (&sched, sizeof (sched));
  return ok;
}

static RTLSError
r_tls_client_send_hello (RTLSClient * client, rboolean retry)
{
  RBuffer * buf;
  RTLSError ret;
  RMemMapInfo info;
  RTLSCipherSuite cs[24];
  rsize ncs = R_N_ELEMENTS (cs);
  rboolean dtls = r_tls_version_is_dtls (client->version);
  /* Offer 0-RTT when a resumption session that permits early data is set and
   * the application queued a payload that fits the ticket's max_early_data_size
   * (never on a retry); an oversized payload is sent as 1-RTT instead. */
  rboolean offer_early = !retry && client->resume != NULL &&
      client->resume->max_early_data > 0 && client->early_data != NULL &&
      r_buffer_get_size (client->early_data) <= client->resume->max_early_data;
  /* TLS 1.3 keeps the legacy_version fields at 0x0303; the real version is
   * carried in the supported_versions extension. */
  RTLSVersion wire = (client->version == R_TLS_VERSION_TLS_1_3) ?
      R_TLS_VERSION_TLS_1_2 : client->version;

  R_LOG_DEBUG ("%p - client hello", client);

  if (!client->clirandompinned) {
    r_tls_generate_hello_random (client->clirandom, client->prng);
    client->clirandompinned = TRUE;
  }

  if (client->version == R_TLS_VERSION_TLS_1_3) {
    /* Offer the 1.3 AEAD suites (honouring an application preference that names
     * them) and generate the key_share ephemeral. */
    RTLSCipherSuite want[24];
    rsize nwant = R_N_ELEMENTS (want), i;

    ncs = 0;
    if (client->cb.preferred_cipher_suites != NULL &&
        client->cb.preferred_cipher_suites (client->userdata, client->version, want, &nwant)) {
      for (i = 0; i < nwant && ncs < R_N_ELEMENTS (cs); i++) {
        if (want[i] == R_TLS_CS_AES_128_GCM_SHA256 ||
            want[i] == R_TLS_CS_AES_256_GCM_SHA384)
          cs[ncs++] = want[i];
      }
    }
    if (ncs == 0) {
      cs[0] = R_TLS_CS_AES_128_GCM_SHA256;
      cs[1] = R_TLS_CS_AES_256_GCM_SHA384;
      ncs = 2;
    }
    /* When 1.2 is within range, also offer the 1.2 suites so a server may
     * negotiate 1.2 from this same ClientHello (RFC 8446 hybrid); a 1.3 server
     * ignores them. */
    if (client->min_version <= R_TLS_VERSION_TLS_1_2) {
      rsize n12 = R_N_ELEMENTS (cs) - ncs;
      if (client->cb.preferred_cipher_suites == NULL ||
          !client->cb.preferred_cipher_suites (client->userdata,
            R_TLS_VERSION_TLS_1_2, cs + ncs, &n12))
        r_tls_client_default_cipher_suites (client->userdata,
            R_TLS_VERSION_TLS_1_2, cs + ncs, &n12);
      ncs += n12;
    }
    /* On a retry the group + ephemeral were re-selected for the
     * HelloRetryRequest's group; keep them. */
    if (!retry) {
      client->ks_group = R_TLS_SUPPORTED_GROUP_X25519;
      if (!r_tls_ecdhe_group_to_curve (client->ks_group, &client->ecdhe_curve))
        return R_TLS_ERROR_HANDSHAKE_FAILURE;
    }
    if (client->ecdhe_key == NULL &&
        (client->ecdhe_key = r_tls_ecdhe_keygen (client->ecdhe_curve, client->prng)) == NULL)
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
  } else if (client->cb.preferred_cipher_suites == NULL ||
      !client->cb.preferred_cipher_suites (client->userdata, client->version, cs, &ncs)) {
    ncs = R_N_ELEMENTS (cs);
    r_tls_client_default_cipher_suites (client->userdata, client->version, cs, &ncs);
  }

  if ((buf = r_tls_client_alloc_buffer (client)) == NULL)
    return R_TLS_ERROR_OOM;

  if (r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    ruint8 * ptr, * psk_binder_ptr = NULL;
    rsize hssize, size = 0;
    ruint16 extsize;
    ruint8 hdrsize, psk_binderlen = 0;

    if (dtls) {
      ret = r_dtls_write_handshake (info.data, info.size, &hssize,
          wire, R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO, 0,
          client->client.epoch, client->client.seqno, client->client.msgseq, 0, 0);
      hdrsize = R_DTLS_RECORD_HDR_SIZE;
    } else {
      ret = r_tls_write_handshake (info.data, info.size, &hssize,
          wire, R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO, 0);
      hdrsize = R_TLS_RECORD_HDR_SIZE;
    }
    ptr = info.data + hssize;
    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_write_hs_client_hello (ptr, info.size - hssize, &size,
          wire, client->clirandom, NULL, 0, NULL, 0,
          cs, (ruint16)ncs, client->comp);
    ptr += size;

    extsize = 0;
    if (client->version == R_TLS_VERSION_TLS_1_3) {
      rboolean include12 = client->min_version <= R_TLS_VERSION_TLS_1_2;
      /* When 1.2 is within range, the 1.2-compatible extensions go first so the
       * same ClientHello completes a 1.2 handshake if the server negotiates it
       * (the 1.3 signature_algorithms is a superset, so it serves both). */
      if (include12) {
        extsize += r_tls_client_write_hs_ext_renegotiation (ptr + 2 + extsize);
        extsize += r_tls_client_write_hs_ext_extended_ms (ptr + 2 + extsize);
        extsize += r_tls_client_write_hs_ext_encrypt_then_mac (ptr + 2 + extsize);
      }
      extsize += r_tls_client_write_hs_ext_supported_groups (ptr + 2 + extsize);
      if (include12)
        extsize += r_tls_client_write_hs_ext_ec_point_formats (ptr + 2 + extsize);
      extsize += r_tls_client_write_hs_ext_signature_algorithms13 (ptr + 2 + extsize);
      extsize += r_tls_client_write_hs_ext_supported_versions13 (ptr + 2 + extsize, include12);
      extsize += r_tls_client_write_hs_ext_key_share13 (client, ptr + 2 + extsize);
      if (retry && client->cookielen > 0)
        extsize += r_tls_client_write_hs_ext_cookie (client, ptr + 2 + extsize);
      if (client->server_name != NULL)
        extsize += r_tls_client_write_hs_ext_server_name (ptr + 2 + extsize, client->server_name);
      /* Advertise (EC)DHE resumption support so the server issues tickets. */
      extsize += r_tls_client_write_hs_ext_psk_key_exchange_modes (ptr + 2 + extsize);
      /* early_data (0-RTT) sits before pre_shared_key, which stays last. */
      if (offer_early)
        extsize += r_tls_client_write_hs_ext_early_data (ptr + 2 + extsize);
      /* pre_shared_key MUST be the last extension. Offered only on the initial
       * ClientHello (the binder transcript assumes an empty prior transcript). */
      if (client->resume != NULL && !retry) {
        ruint8 * pskptr = ptr + 2 + extsize;
        rsize boff;
        psk_binderlen = (ruint8) r_msg_digest_type_size (client->resume->hash);
        extsize += r_tls_client_write_hs_ext_pre_shared_key (client, pskptr,
            psk_binderlen, &boff);
        psk_binder_ptr = pskptr + boff;
      }
    } else {
      extsize += r_tls_client_write_hs_ext_renegotiation (ptr + 2 + extsize);
      extsize += r_tls_client_write_hs_ext_extended_ms (ptr + 2 + extsize);
      extsize += r_tls_client_write_hs_ext_encrypt_then_mac (ptr + 2 + extsize);
      extsize += r_tls_client_write_hs_ext_supported_groups (ptr + 2 + extsize);
      extsize += r_tls_client_write_hs_ext_ec_point_formats (ptr + 2 + extsize);
      extsize += r_tls_client_write_hs_ext_signature_algorithms (ptr + 2 + extsize);
      if (client->server_name != NULL)
        extsize += r_tls_client_write_hs_ext_server_name (ptr + 2 + extsize, client->server_name);
      if (dtls)
        extsize += r_tls_client_write_hs_ext_use_srtp (ptr + 2 + extsize);
    }
    r_store_be16 (ptr, extsize);
    ptr += extsize + 2;

    size = RPOINTER_TO_SIZE (ptr) - RPOINTER_TO_SIZE (info.data);
    if (ret == R_TLS_ERROR_OK) {
      if (dtls)
        ret = r_dtls_update_handshake_len (info.data, info.size,
            (ruint16)(size - hssize), 0, (ruint32)(size - hssize));
      else
        ret = r_tls_update_handshake_len (info.data, info.size, (ruint16)(size - hssize));

      /* Now that the header length covers the full ClientHello, compute the
       * binder over the message truncated before the binders list and patch it
       * in, so the folded transcript carries the real binder. */
      if (ret == R_TLS_ERROR_OK && psk_binder_ptr != NULL) {
        ruint8 binder[R_TLS13_SECRET_MAX];
        if (!r_tls_client_psk_binder (client, info.data + hdrsize,
              psk_binder_ptr - 3, binder))
          ret = R_TLS_ERROR_HANDSHAKE_FAILURE;
        else
          r_memcpy (psk_binder_ptr, binder, psk_binderlen);
      }

      if (ret == R_TLS_ERROR_OK) {
        if (retry) {
          /* The retry ClientHello is folded straight into the live transcript
           * (which already holds message_hash(CH1) || HelloRetryRequest). */
          r_msg_digest_update (client->hshash, info.data + hdrsize, size - hdrsize);
        } else {
          /* Buffer the first ClientHello; it is folded once the ServerHello
           * picks the suite (hence the hash). */
          client->clienthellolen = size - hdrsize;
          if ((client->clienthello = r_memdup (info.data + hdrsize, client->clienthellolen)) == NULL)
            ret = R_TLS_ERROR_OOM;
        }
      }

      /* Install the client early-traffic key (bound to the ClientHello just
       * buffered) so the 0-RTT records can go out right behind the hello. */
      if (ret == R_TLS_ERROR_OK && offer_early) {
        if (r_tls_client_setup_early_keys13 (client))
          client->early13_sent = TRUE;
        else
          ret = R_TLS_ERROR_HANDSHAKE_FAILURE;
      }
    }
    r_buffer_unmap (buf, &info);
    r_buffer_set_size (buf, size);

    if (ret == R_TLS_ERROR_OK)
      ret = r_tls_client_send_record (client, buf);
    /* 0-RTT data follows the ClientHello, encrypted under the early key. */
    if (ret == R_TLS_ERROR_OK && client->early13_sent)
      ret = r_tls_client_send_early_data13 (client);
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
        version != R_TLS_VERSION_TLS_1_3 &&
        version != R_TLS_VERSION_DTLS_1_2))
    return R_TLS_ERROR_VERSION;

  R_LOG_DEBUG ("%p - start (ver %.4x)", client, version);

  if (prng != NULL) r_prng_ref (prng);
  client->loop = r_ev_loop_ref (loop);
  client->prng = prng;
  client->comp = R_TLS_COMPRESSION_NULL;

  /* Resolve the offered version range. DTLS is fixed at 1.2. For TLS the range
   * is the one configured with r_tls_client_set_version_range, or [1.2, version]
   * by default so start(1.3) offers both versions and start(1.2) offers 1.2. */
  if (r_tls_version_is_dtls (version)) {
    client->min_version = client->max_version = version;
  } else if (!client->version_range_set) {
    client->min_version = R_TLS_VERSION_TLS_1_2;
    client->max_version = version;
  }
  /* version carries the highest offered version now and the negotiated one once
   * the ServerHello lands (a 1.2 fallback pins it down). */
  client->version = client->max_version;

  /* The PRF and transcript hash depend on the suite the server selects, which
   * is not known until its ServerHello. The ClientHello is buffered and the
   * transcript started in nego_server_hello. */

  r_tls_client_change_state (client, R_TLS_CLIENT_SERVER_HELLO);

  if (r_tls_client_send_hello (client, FALSE) != R_TLS_ERROR_OK)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  client->client.msgseq++;
  r_tls_client_send_out (client);

  return R_TLS_ERROR_OK;
}

/* ---- TLS 1.3 (RFC 8446) 1-RTT handshake ------------------------------- */

static rboolean
r_tls_client_install_keys13 (RTLSClient * client, RTLS13RecordKeys * rk,
    const ruint8 * secret)
{
  if (rk->cipher != NULL) {
    r_crypto_cipher_unref (rk->cipher);
    rk->cipher = NULL;
  }
  return r_tls13_traffic_keys (client->cs13_hash, secret, client->cs13_cipher, rk);
}

/* AEAD-protect @plain[@plainlen] (real content type @ct) under the current
 * write key and queue the application_data record. */
static RTLSError
r_tls_client_protect_record13 (RTLSClient * client, RTLSContentType ct,
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
    if (r_tls13_record_protect (client->rk_write.cipher,
            client->rk_write.iv, client->rk_write.ivlen, client->rk_write.seq,
            ct, plain, plainlen,
            p + R_TLS_RECORD_HDR_SIZE, info.size - R_TLS_RECORD_HDR_SIZE, &enclen)) {
      p[0] = (ruint8) R_TLS_CONTENT_TYPE_APPLICATION_DATA;
      r_store_be16 (p + 1, R_TLS_VERSION_TLS_1_2);
      r_store_be16 (p + 3, (ruint16) enclen);
      r_buffer_unmap (rec, &info);
      r_buffer_set_size (rec, R_TLS_RECORD_HDR_SIZE + enclen);
      if (r_queue_push (&client->qsend, rec) != NULL) {
        client->rk_write.seq++;
        rec = NULL;
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

/* Derive the client early-traffic secret (bound to the just-built ClientHello)
 * from the resumption PSK and install it as the write key, so 0-RTT data and
 * the later EndOfEarlyData go out under it. The suite is the ticket's -- 0-RTT
 * commits to it before the ServerHello confirms it. */
static rboolean
r_tls_client_setup_early_keys13 (RTLSClient * client)
{
  RTLSClientSession * s = client->resume;
  const RTLSCipherSuiteInfo * info = r_tls_cipher_suite_get_info (s->suite);
  ruint8 th[R_TLS13_SECRET_MAX];
  rsize hlen = r_msg_digest_type_size (s->hash);
  RMsgDigest * md;
  rboolean ok;

  if (info == NULL || info->cipher == NULL)
    return FALSE;
  if ((md = r_msg_digest_new (s->hash)) == NULL)
    return FALSE;
  ok = r_msg_digest_update (md, client->clienthello, client->clienthellolen) &&
       r_msg_digest_get_data (md, th, hlen, NULL);
  r_msg_digest_free (md);
  if (!ok)
    return FALSE;

  client->cs13_hash = s->hash;
  client->cs13_cipher = info->cipher;
  return r_tls13_schedule_init_psk (&client->sched13, s->hash, s->psk, s->psklen) &&
      r_tls13_schedule_early (&client->sched13, th) &&
      r_tls_client_install_keys13 (client, &client->rk_write, client->sched13.cet);
}

/* Encrypt and queue the queued 0-RTT payload under the early write key. */
static RTLSError
r_tls_client_send_early_data13 (RTLSClient * client)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RTLSError ret = R_TLS_ERROR_OK;

  if (client->early_data == NULL)
    return R_TLS_ERROR_OK;
  if (!r_buffer_map (client->early_data, &info, R_MEM_MAP_READ))
    return R_TLS_ERROR_OOM;
  if (info.size > 0)
    ret = r_tls_client_protect_record13 (client,
        R_TLS_CONTENT_TYPE_APPLICATION_DATA, info.data, info.size);
  r_buffer_unmap (client->early_data, &info);
  return ret;
}

/* Frame, transcript-fold and send a handshake message under the write key. */
static RTLSError
r_tls_client_send_hs13 (RTLSClient * client, RTLSHandshakeType type,
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
  if (bodylen > 0)
    r_memcpy (msg + R_TLS_HS_HDR_SIZE, body, bodylen);

  r_msg_digest_update (client->hshash, msg, msglen);
  ret = r_tls_client_protect_record13 (client, R_TLS_CONTENT_TYPE_HANDSHAKE,
      msg, msglen);

  r_free (msg);
  return ret;
}

/* Detect and validate a TLS 1.3 ServerHello. Returns R_TLS_ERROR_NOT_NEEDED
 * when the ServerHello does not select 1.3 (the caller then runs the <=1.2
 * path). On success it starts the transcript and stores the negotiated suite,
 * group and server key_share; the handshake secrets are derived once the
 * ServerHello has been folded (see r_tls_client_setup_keys13). */
static RTLSError
r_tls_client_nego_server_hello13 (RTLSClient * client, const RTLSHelloMsg * hello)
{
  RTLSHelloExt ext, sv = R_TLS_HELLO_EXT_INIT, ks = R_TLS_HELLO_EXT_INIT;
  RTLSHelloExt psk = R_TLS_HELLO_EXT_INIT;
  RTLSKeyShareEntry entry = R_TLS_KEY_SHARE_ENTRY_INIT;
  rboolean have_sv = FALSE, have_ks = FALSE, have_psk = FALSE;
  RTLSCipherSuite cs;
  REcurveID curve;
  RTLSError r;

  for (r = r_tls_hello_msg_extension_first (hello, &ext); r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (hello, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_SUPPORTED_VERSIONS) { sv = ext; have_sv = TRUE; }
    else if (ext.type == R_TLS_EXT_TYPE_KEY_SHARE) { ks = ext; have_ks = TRUE; }
    else if (ext.type == R_TLS_EXT_TYPE_PRE_SHARED_KEY) { psk = ext; have_psk = TRUE; }
  }
  if (!have_sv ||
      r_tls_hello_ext_selected_version (&sv) != R_TLS_VERSION_TLS_1_3)
    return R_TLS_ERROR_NOT_NEEDED;

  /* The server accepts resumption by echoing pre_shared_key with the identity
   * it selected; it must be one we offered (we offer a single identity, 0). */
  if (have_psk && client->resume != NULL) {
    if (psk.len != sizeof (ruint16) || r_load_be16 (psk.data) != 0)
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    client->resumed13 = TRUE;
  }

  /* Committed to 1.3. */
  if (hello->cslen != sizeof (ruint16))
    return R_TLS_ERROR_CORRUPT_RECORD;
  cs = (RTLSCipherSuite) r_load_be16 (hello->cs);
  /* After a HelloRetryRequest the ServerHello must keep the suite the HRR
   * committed to (RFC 8446 4.1.4); a changed suite is illegal_parameter. */
  if (client->hrr_received && cs != client->cs13_suite)
    return R_TLS_ERROR_ILLEGAL_PARAMETER;
  /* The 1.3 suites carry a table entry (key_exchange NULL, the AEAD cipher and
   * the HKDF/transcript hash); record it as the negotiated suite so the public
   * accessors report it, and take the cipher and hash from it. */
  if ((client->csinfo = r_tls_cipher_suite_get_info (cs)) == NULL ||
      client->csinfo->cipher == NULL ||
      (cs != R_TLS_CS_AES_128_GCM_SHA256 && cs != R_TLS_CS_AES_256_GCM_SHA384))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  client->cs13_suite = cs;
  client->cs13_cipher = client->csinfo->cipher;
  client->cs13_hash = client->csinfo->prf;

  /* The server key_share must be on the group we offered. */
  if (!have_ks || r_tls_hello_ext_key_share_server (&ks, &entry) != R_TLS_ERROR_OK)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!r_tls_ecdhe_group_to_curve (entry.group, &curve) ||
      curve != client->ecdhe_curve)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if ((client->ecdhe_server_pub =
          r_tls_ecdhe_point_read (curve, entry.key, entry.len)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  r_memcpy (client->servrandom, hello->random, R_TLS_HELLO_RANDOM_BYTES);

  /* Start the transcript on the suite hash and fold the buffered ClientHello;
   * the caller folds the ServerHello right after this returns. After a
   * HelloRetryRequest the transcript (message_hash(CH1) || HRR || CH2) is
   * already established, so leave it. */
  if (!client->hrr_received) {
    if (R_UNLIKELY (client->hshash != NULL || client->clienthello == NULL))
      return R_TLS_ERROR_WRONG_STATE;
    if ((client->hshash = r_msg_digest_new (client->cs13_hash)) == NULL)
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    r_msg_digest_update (client->hshash, client->clienthello, client->clienthellolen);
    r_free (client->clienthello);
    client->clienthello = NULL;
    client->clienthellolen = 0;
  }

  client->flight13_step = 0;
  client->tls13 = TRUE;
  return R_TLS_ERROR_OK;
}

/* After the ServerHello is folded into the transcript, derive the handshake
 * secrets and install the handshake-traffic keys. */
static RTLSError
r_tls_client_setup_keys13 (RTLSClient * client)
{
  ruint8 ecdhe[64], th[R_TLS13_SECRET_MAX];
  rsize ecdhelen = 0, hlen = r_msg_digest_type_size (client->cs13_hash);

  if (!r_msg_digest_get_data (client->hshash, th, hlen, NULL))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!r_tls_ecdhe_compute (client->ecdhe_key, client->ecdhe_server_pub,
        ecdhe, sizeof (ecdhe), &ecdhelen))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  /* On an accepted resumption the Early Secret comes from the ticket PSK
   * (psk_dhe_ke); otherwise it is the PSK-less zero value. */
  if (!(client->resumed13 ?
          r_tls13_schedule_init_psk (&client->sched13, client->cs13_hash,
              client->resume->psk, client->resume->psklen) :
          r_tls13_schedule_init (&client->sched13, client->cs13_hash)) ||
      !r_tls13_schedule_handshake (&client->sched13, ecdhe, ecdhelen, th)) {
    r_memclear_secure (ecdhe, sizeof (ecdhe));
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  }
  r_memclear_secure (ecdhe, sizeof (ecdhe));

  /* Client reads the server (shs) and writes as the client (chs). While 0-RTT
   * is in flight the write key stays the early-traffic key -- it switches to
   * chs only once we know the server's decision (EncryptedExtensions), so the
   * EndOfEarlyData (on accept) is still protected under the early key. */
  if (!r_tls_client_install_keys13 (client, &client->rk_read, client->sched13.shs))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!client->early13_sent &&
      !r_tls_client_install_keys13 (client, &client->rk_write, client->sched13.chs))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  return R_TLS_ERROR_OK;
}

/* Handle a HelloRetryRequest (a ServerHello carrying the HRR-sentinel random):
 * rewrite the transcript to message_hash(CH1) || HRR, regenerate the key_share
 * for the group the server selected, and send the second ClientHello. */
static RTLSError
r_tls_client_handle_hrr (RTLSClient * client, const RTLSHelloMsg * hello,
    const RTLSParser * parser)
{
  RTLSHelloExt ext, sv = R_TLS_HELLO_EXT_INIT, ks = R_TLS_HELLO_EXT_INIT,
      ck = R_TLS_HELLO_EXT_INIT;
  rboolean have_sv = FALSE, have_ks = FALSE, have_ck = FALSE;
  RTLSSupportedGroup selected;
  RTLSCipherSuite cs;
  REcurveID curve;
  ruint8 mh[4 + R_TLS13_SECRET_MAX];
  rsize mhlen = 0;
  RTLSError r;

  /* Only one HelloRetryRequest is permitted (RFC 8446 4.1.4). */
  if (client->hrr_received)
    return R_TLS_ERROR_WRONG_TYPE;

  for (r = r_tls_hello_msg_extension_first (hello, &ext); r == R_TLS_ERROR_OK;
      r = r_tls_hello_msg_extension_next (hello, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_SUPPORTED_VERSIONS) { sv = ext; have_sv = TRUE; }
    else if (ext.type == R_TLS_EXT_TYPE_KEY_SHARE) { ks = ext; have_ks = TRUE; }
    else if (ext.type == R_TLS_EXT_TYPE_COOKIE) { ck = ext; have_ck = TRUE; }
  }
  if (!have_sv || r_tls_hello_ext_selected_version (&sv) != R_TLS_VERSION_TLS_1_3)
    return R_TLS_ERROR_VERSION;
  if (!have_ks)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* The selected group must be one we support and must differ from the one we
   * already sent a share for (otherwise the server should not have retried). */
  selected = r_tls_hello_ext_key_share_group (&ks);
  if (!r_tls_ecdhe_group_to_curve (selected, &curve) || selected == client->ks_group)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* Cipher suite from the HelloRetryRequest. */
  if (hello->cslen != sizeof (ruint16))
    return R_TLS_ERROR_CORRUPT_RECORD;
  cs = (RTLSCipherSuite) r_load_be16 (hello->cs);
  if ((client->csinfo = r_tls_cipher_suite_get_info (cs)) == NULL ||
      client->csinfo->cipher == NULL ||
      (cs != R_TLS_CS_AES_128_GCM_SHA256 && cs != R_TLS_CS_AES_256_GCM_SHA384))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  client->cs13_suite = cs;
  client->cs13_cipher = client->csinfo->cipher;
  client->cs13_hash = client->csinfo->prf;

  /* Stash the cookie to echo in the retry. */
  if (have_ck) {
    ruint16 clen;
    const ruint8 * c = r_tls_hello_ext_cookie (&ck, &clen);
    if (c == NULL || clen > sizeof (client->cookie))
      return R_TLS_ERROR_HANDSHAKE_FAILURE;
    r_memcpy (client->cookie, c, clen);
    client->cookielen = clen;
  }

  /* Regenerate the (EC)DHE share for the selected group. */
  client->ks_group = selected;
  client->ecdhe_curve = curve;
  if (client->ecdhe_key != NULL) {
    r_crypto_key_unref (client->ecdhe_key);
    client->ecdhe_key = NULL;
  }
  if ((client->ecdhe_key = r_tls_ecdhe_keygen (curve, client->prng)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* Transcript rewrite (RFC 8446 4.4.1): the first ClientHello is replaced by
   * message_hash(CH1), then the HelloRetryRequest is folded. */
  if (R_UNLIKELY (client->hshash != NULL || client->clienthello == NULL))
    return R_TLS_ERROR_WRONG_STATE;
  if ((client->hshash = r_msg_digest_new (client->cs13_hash)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (!r_tls13_message_hash (client->cs13_hash, client->clienthello,
        client->clienthellolen, mh, sizeof (mh), &mhlen))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  r_msg_digest_update (client->hshash, mh, mhlen);
  r_free (client->clienthello);
  client->clienthello = NULL;
  client->clienthellolen = 0;
  r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);

  client->tls13 = TRUE;
  client->hrr_received = TRUE;

  /* Send the second ClientHello; it folds itself into the live transcript. */
  if ((r = r_tls_client_send_hello (client, TRUE)) != R_TLS_ERROR_OK)
    return r;
  client->client.msgseq++;
  client->hrr_just_sent = TRUE;
  return R_TLS_ERROR_OK;
}

/* Verify the server's CertificateVerify against the peer certificate. */
static RTLSError
r_tls_client_verify_certificate_verify13 (RTLSClient * client,
    RTLSSignatureScheme scheme, const ruint8 * sig, ruint16 sigsize)
{
  ruint8 th[R_TLS13_SECRET_MAX], tbs[R_TLS13_CERT_VERIFY_TBS_MAX], digest[R_TLS13_SECRET_MAX];
  rsize hlen = r_msg_digest_type_size (client->cs13_hash), tbslen = 0, dlen;
  RMsgDigest * md;
  RCryptoKey * pub;
  rboolean ok;
  RTLSError err;

  if (scheme != R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 &&
      scheme != R_TLS_SIGN_SCHEME_RSA_PSS_SHA256)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  /* The signature covers the content over Transcript-Hash(..Certificate). */
  if (!r_msg_digest_get_data (client->hshash, th, hlen, NULL) ||
      !r_tls13_cert_verify_tbs (TRUE, th, hlen, tbs, sizeof (tbs), &tbslen))
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  if ((md = r_msg_digest_new (R_MSG_DIGEST_TYPE_SHA256)) == NULL)
    return R_TLS_ERROR_OOM;
  dlen = r_msg_digest_size (md);
  ok = r_msg_digest_update (md, tbs, tbslen) &&
       r_msg_digest_get_data (md, digest, dlen, NULL);
  r_msg_digest_free (md);
  if (!ok)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;

  if ((pub = r_crypto_cert_get_public_key (client->peer_cert)) == NULL)
    return R_TLS_ERROR_HANDSHAKE_FAILURE;
  if (scheme == R_TLS_SIGN_SCHEME_RSA_PSS_SHA256)
    r_rsa_pub_key_set_padding (pub, R_RSA_PADDING_PKCS1_V21);
  err = (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256, digest, dlen,
            sig, sigsize) == R_CRYPTO_OK) ?
      R_TLS_ERROR_OK : R_TLS_ERROR_HS_VERIFICATION_FAILED;
  r_crypto_key_unref (pub);
  return err;
}

/* Process one message of the encrypted server flight (EncryptedExtensions,
 * Certificate, CertificateVerify, Finished). On the Finished it sends the
 * client Finished and switches to the application keys; flight13_step reaches 4
 * to signal completion to the caller. */
static RTLSError
r_tls_client_flight13 (RTLSClient * client, const RTLSParser * parser)
{
  RTLSHandshakeType type;
  rsize hlen = r_msg_digest_type_size (client->cs13_hash);
  ruint8 th[R_TLS13_SECRET_MAX];
  RTLSError err;

  if ((err = r_tls_parser_parse_handshake_peek_type (parser, &type)) != R_TLS_ERROR_OK)
    return err;

  switch (client->flight13_step) {
    case 0:
      if (type != R_TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS)
        return R_TLS_ERROR_WRONG_TYPE;
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      /* EncryptedExtensions carries the server's 0-RTT decision. On acceptance
       * the write key stays the early-traffic key until the EndOfEarlyData; on
       * rejection switch to the handshake key now and let the queued early data
       * be resent as 1-RTT once the handshake completes. */
      if (client->early13_sent) {
        client->early13_accepted = r_tls_client_ee_has_early_data (
            parser->fragment.data, parser->fragment.size);
        if (!client->early13_accepted) {
          client->early13_sent = FALSE;
          if (!r_tls_client_install_keys13 (client, &client->rk_write,
                client->sched13.chs))
            return R_TLS_ERROR_HANDSHAKE_FAILURE;
        }
      }
      /* A resumed handshake authenticates via the PSK, so no Certificate /
       * CertificateVerify follow: jump straight to the server Finished. */
      client->flight13_step = client->resumed13 ? 3 : 1;
      return R_TLS_ERROR_OK;

    case 1: {
      RTLSCertificate tlscert = R_TLS_CERTIFICATE_INIT;
      RCryptoCert * chain[R_TLS_CLIENT_MAX_CHAIN];
      ruint n = 0, i;

      if (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE)
        return R_TLS_ERROR_WRONG_TYPE;
      err = r_tls_parser_parse_certificate13_first (parser, &tlscert);
      while (n < R_TLS_CLIENT_MAX_CHAIN && err == R_TLS_ERROR_OK) {
        if ((chain[n] = r_tls_certificate_get_cert (&tlscert)) != NULL)
          n++;
        err = r_tls_parser_parse_certificate13_next (parser, &tlscert);
      }
      if (n == 0)
        return R_TLS_ERROR_NO_CERTIFICATE;
      if (client->cb.verify_cert != NULL &&
          !client->cb.verify_cert (client->userdata, chain, n))
        err = R_TLS_ERROR_CORRUPT_CERTIFICATE;
      else {
        client->peer_cert = r_crypto_cert_ref (chain[0]);
        err = R_TLS_ERROR_OK;
      }
      for (i = 0; i < n; i++)
        r_crypto_cert_unref (chain[i]);
      if (err != R_TLS_ERROR_OK)
        return err;
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      client->flight13_step = 2;
      return R_TLS_ERROR_OK;
    }

    case 2: {
      RTLSSignatureScheme scheme;
      const ruint8 * sig;
      ruint16 sigsize;

      if (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY)
        return R_TLS_ERROR_WRONG_TYPE;
      if ((err = r_tls_parser_parse_certificate_verify (parser, &scheme,
              &sig, &sigsize)) != R_TLS_ERROR_OK)
        return err;
      if ((err = r_tls_client_verify_certificate_verify13 (client, scheme,
              sig, sigsize)) != R_TLS_ERROR_OK)
        return err;
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      client->flight13_step = 3;
      return R_TLS_ERROR_OK;
    }

    case 3: {
      const ruint8 * vd;
      rsize vdsize;
      ruint8 finkey[R_TLS13_SECRET_MAX], expect[R_TLS13_SECRET_MAX], cvd[R_TLS13_SECRET_MAX];
      ruint8 body[64];
      rsize bodylen = 0;

      if (type != R_TLS_HANDSHAKE_TYPE_FINISHED)
        return R_TLS_ERROR_WRONG_TYPE;
      if ((err = r_tls_parser_parse_finished (parser, &vd, &vdsize)) != R_TLS_ERROR_OK)
        return err;

      /* Verify the server Finished over Transcript-Hash(..CertificateVerify). */
      if (!r_msg_digest_get_data (client->hshash, th, hlen, NULL) ||
          !r_tls13_finished_key (client->cs13_hash, client->sched13.shs, finkey) ||
          !r_tls13_verify_data (client->cs13_hash, finkey, th, expect))
        return R_TLS_ERROR_HANDSHAKE_FAILURE;
      if (vdsize != hlen || r_memcmp_ct (vd, expect, hlen) != 0)
        return R_TLS_ERROR_HS_VERIFICATION_FAILED;

      /* Fold the server Finished, then derive the application secrets over
       * Transcript-Hash(..server Finished). */
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      if (!r_msg_digest_get_data (client->hshash, th, hlen, NULL) ||
          !r_tls13_schedule_master (&client->sched13, th))
        return R_TLS_ERROR_HANDSHAKE_FAILURE;

      /* On accepted 0-RTT, close the early-data flow with an EndOfEarlyData
       * (still under the early write key), fold it, then switch the write key to
       * the client handshake-traffic secret. The client Finished then covers the
       * transcript through EndOfEarlyData. */
      if (client->early13_accepted) {
        if ((err = r_tls_client_send_hs13 (client,
                R_TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA, NULL, 0)) != R_TLS_ERROR_OK)
          return err;
        client->early13_sent = FALSE;
        if (!r_tls_client_install_keys13 (client, &client->rk_write, client->sched13.chs) ||
            !r_msg_digest_get_data (client->hshash, th, hlen, NULL))
          return R_TLS_ERROR_HANDSHAKE_FAILURE;
      }

      /* Client Finished under the client handshake-traffic key. */
      if (!r_tls13_finished_key (client->cs13_hash, client->sched13.chs, finkey) ||
          !r_tls13_verify_data (client->cs13_hash, finkey, th, cvd))
        return R_TLS_ERROR_HANDSHAKE_FAILURE;
      if ((err = r_tls_write_hs_finished (body, sizeof (body), &bodylen,
              cvd, hlen)) != R_TLS_ERROR_OK)
        return err;
      if ((err = r_tls_client_send_hs13 (client,
              R_TLS_HANDSHAKE_TYPE_FINISHED, body, bodylen)) != R_TLS_ERROR_OK)
        return err;

      /* Derive the resumption master secret over the transcript through the
       * client Finished (send_hs13 just folded it), for tickets received later. */
      if (!r_msg_digest_get_data (client->hshash, th, hlen, NULL) ||
          !r_tls13_schedule_resumption (&client->sched13, th))
        return R_TLS_ERROR_HANDSHAKE_FAILURE;

      /* Switch to application keys: client writes cap, reads sap. */
      if (!r_tls_client_install_keys13 (client, &client->rk_write, client->sched13.cap) ||
          !r_tls_client_install_keys13 (client, &client->rk_read, client->sched13.sap))
        return R_TLS_ERROR_HANDSHAKE_FAILURE;

      client->flight13_step = 4;   /* flight complete */
      return R_TLS_ERROR_OK;
    }

    default:
      return R_TLS_ERROR_WRONG_STATE;
  }
}

/* ----------------------------------------------------------------------- */

static RTLSError
r_tls_client_nego_server_hello (RTLSClient * client, const RTLSParser * parser)
{
  RTLSHelloMsg hello;
  RTLSHelloExt ext;
  RTLSError r;

  if ((r = r_tls_parser_parse_hello (parser, &hello)) != R_TLS_ERROR_OK)
    return r;

  /* A ServerHello carrying the HelloRetryRequest sentinel random is a retry
   * request: rewrite the transcript and send a second ClientHello. */
  if (client->version == R_TLS_VERSION_TLS_1_3 &&
      r_tls13_random_is_hrr (hello.random))
    return r_tls_client_handle_hrr (client, &hello, parser);

  /* A 1.3-capable client checks supported_versions before the legacy version,
   * which a 1.3 ServerHello pins to 0x0303. */
  if (client->version == R_TLS_VERSION_TLS_1_3) {
    RTLSError r13 = r_tls_client_nego_server_hello13 (client, &hello);
    if (r13 != R_TLS_ERROR_NOT_NEEDED)
      return r13;
    /* Offered 1.3 but the server selected a lower version: a downgrade sentinel
     * in the random is a forced downgrade and must abort (RFC 8446 4.1.3). */
    if (r_tls13_random_is_downgrade (hello.random))
      return R_TLS_ERROR_ILLEGAL_PARAMETER;
    /* No sentinel: the server negotiated a lower version. Accept it only if it
     * is within our offered range (a hybrid ClientHello also offers 1.2), then
     * fall back to a full 1.2 handshake -- pin the negotiated version (it frames
     * records and the RSA premaster) and drop the 1.3 key_share ephemeral so the
     * 1.2 ECDHE exchange keys itself from the server-selected curve. A 1.3-only
     * client leaves version unchanged and the check below rejects the mismatch. */
    if (hello.version == R_TLS_VERSION_TLS_1_2 &&
        client->min_version <= R_TLS_VERSION_TLS_1_2) {
      client->version = R_TLS_VERSION_TLS_1_2;
      if (client->ecdhe_key != NULL) {
        r_crypto_key_unref (client->ecdhe_key);
        client->ecdhe_key = NULL;
      }
    }
  }

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
  client->ecdhe = (client->csinfo->key_exchange == R_KEY_EXCHANGE_ECDHE_RSA ||
      client->csinfo->key_exchange == R_KEY_EXCHANGE_ECDHE_ECDSA);

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
  RTLSSignatureScheme sigscheme = r_tls_sign_scheme_for_key (client->privkey);

  /* Sign the transcript through ClientKeyExchange (current hshash); the scheme
   * follows the client cert key (RSA or ECDSA), both SHA-256. */
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
            &bodylen, sigscheme, sig, (ruint16)sigsize)) == R_TLS_ERROR_OK) {
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
        if (r_memcmp_ct (verify_calc, verify_data, size) != 0) {
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

/* Once closed (close_notify exchanged) any further record is dropped. */
static RTLSError
r_tls_client_state_closed (RTLSClient * client, const RTLSParser * parser)
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
    else if ((err = r_tls_client_nego_server_hello (client, parser)) == R_TLS_ERROR_OK &&
             !client->hrr_just_sent)
      err = r_tls_client_change_state (client, R_TLS_CLIENT_CERTIFICATE);
  }

  switch (err) {
    case R_TLS_ERROR_OK:
      if (client->hrr_just_sent) {
        /* A HelloRetryRequest was processed and the second ClientHello sent;
         * the transcript was rewritten there. Stay in this state to await the
         * real ServerHello. */
        client->hrr_just_sent = FALSE;
        break;
      }
      r_msg_digest_update (client->hshash, parser->fragment.data, parser->fragment.size);
      /* With the ServerHello folded, the 1.3 handshake secrets can be derived
       * and the handshake-traffic keys installed. */
      if (client->tls13 &&
          (err = r_tls_client_setup_keys13 (client)) != R_TLS_ERROR_OK)
        r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
      break;
    case R_TLS_ERROR_WRONG_TYPE:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
      break;
    case R_TLS_ERROR_VERSION:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_PROTOCOL_VERSION);
      break;
    case R_TLS_ERROR_ILLEGAL_PARAMETER:
      r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
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

  /* In TLS 1.3 this state drives the whole encrypted flight (EncryptedExtensions
   * .. Finished); each protected record decrypts to one handshake message. */
  if (client->tls13) {
    err = r_tls_client_flight13 (client, parser);
    if (err == R_TLS_ERROR_OK && client->flight13_step >= 4) {
      err = r_tls_client_change_state (client, R_TLS_CLIENT_APPDATA);
      r_msg_digest_free (client->hshash);
      client->hshash = NULL;
      /* Deliver the 0-RTT payload as ordinary application data when the server
       * did not accept it (declined 0-RTT, or the session never permitted it),
       * so it is sent either way. */
      if (client->early_data != NULL) {
        if (!client->early13_accepted)
          r_tls_client_send_appdata (client, client->early_data);
        r_buffer_unref (client->early_data);
        client->early_data = NULL;
      }
      if (client->cb.handshake_done != NULL)
        client->cb.handshake_done (client->userdata, client);
    } else if (err != R_TLS_ERROR_OK) {
      r_tls_client_send_alert (client,
          (err == R_TLS_ERROR_HS_VERIFICATION_FAILED) ?
          R_TLS_ALERT_TYPE_DECRYPT_ERROR :
          (err == R_TLS_ERROR_CORRUPT_CERTIFICATE) ?
          R_TLS_ALERT_TYPE_BAD_CERTIFICATE : R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
    }
    return err;
  }

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

/* Store a post-handshake NewSessionTicket (RFC 8446 4.6.1) as a resumption
 * session: keep the ticket and derive its PSK from our resumption master
 * secret and the ticket nonce. A malformed ticket or allocation failure is
 * ignored (resumption is best-effort). */
static void
r_tls_client_store_ticket13 (RTLSClient * client, const RTLSParser * parser)
{
  ruint32 lifetime, age_add, max_early_data;
  const ruint8 * nonce, * ticket;
  ruint8 noncelen;
  ruint16 ticketsize;
  RTLSClientSession * s;

  if (r_tls_parser_parse_new_session_ticket13 (parser, &lifetime, &age_add,
        &nonce, &noncelen, &ticket, &ticketsize, &max_early_data) != R_TLS_ERROR_OK)
    return;
  if ((s = r_mem_new0 (RTLSClientSession)) == NULL)
    return;
  if ((s->ticket = r_memdup (ticket, ticketsize)) == NULL) {
    r_free (s);
    return;
  }
  s->ticketlen = ticketsize;
  s->suite = client->cs13_suite;
  s->hash = client->cs13_hash;
  s->age_add = age_add;
  s->max_early_data = max_early_data;
  s->obtained = r_tls_client_now (client);
  if (!r_tls13_resumption_psk (client->cs13_hash, client->sched13.res_master,
        nonce, noncelen, s->psk)) {
    r_memclear_secure (s->psk, sizeof (s->psk));
    r_free (s->ticket);
    r_free (s);
    return;
  }
  s->psklen = r_msg_digest_type_size (client->cs13_hash);
  r_ref_init (s, r_tls_client_session_free);

  if (client->new_session != NULL)
    r_tls_client_session_unref (client->new_session);
  client->new_session = s;
}

/* Send a post-handshake KeyUpdate (RFC 8446 4.6.3) and rotate our sending key.
 * Unlike handshake-phase messages it is framed but not folded into the
 * transcript. It goes out under the current write key; every record after it
 * uses the advanced key, so the rotation follows the queued record. */
static RTLSError
r_tls_client_send_key_update13 (RTLSClient * client, rboolean request_peer_update)
{
  ruint8 msg[R_TLS_HS_HDR_SIZE + 1];
  RTLSError ret;

  msg[0] = (ruint8) R_TLS_HANDSHAKE_TYPE_KEY_UPDATE;
  msg[1] = 0x00;
  msg[2] = 0x00;
  msg[3] = 0x01;
  msg[4] = (ruint8) (request_peer_update ? R_TLS_KEY_UPDATE_REQUESTED
                                         : R_TLS_KEY_UPDATE_NOT_REQUESTED);

  if ((ret = r_tls_client_protect_record13 (client, R_TLS_CONTENT_TYPE_HANDSHAKE,
          msg, sizeof (msg))) != R_TLS_ERROR_OK)
    return ret;

  if (!r_tls13_traffic_update (client->cs13_hash, client->sched13.cap,
          client->sched13.cap) ||
      !r_tls_client_install_keys13 (client, &client->rk_write, client->sched13.cap))
    return R_TLS_ERROR_ENCRYPTION_FAILED;
  return R_TLS_ERROR_OK;
}

/* Handle a peer KeyUpdate (RFC 8446 4.6.3): advance our receiving key to the
 * peer's next generation and, when asked, answer with our own KeyUpdate --
 * never itself update_requested, so the exchange cannot loop. The queued reply
 * is flushed by the incoming_data send_out once dispatch returns. */
static RTLSError
r_tls_client_recv_key_update13 (RTLSClient * client, const RTLSParser * parser)
{
  ruint8 request;

  if (r_tls_parser_parse_key_update (parser, &request) != R_TLS_ERROR_OK ||
      request > R_TLS_KEY_UPDATE_REQUESTED) {
    r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
    return R_TLS_ERROR_ILLEGAL_PARAMETER;
  }

  if (!r_tls13_traffic_update (client->cs13_hash, client->sched13.sap,
          client->sched13.sap) ||
      !r_tls_client_install_keys13 (client, &client->rk_read, client->sched13.sap)) {
    r_tls_client_send_alert (client, R_TLS_ALERT_TYPE_INTERNAL_ERROR);
    return R_TLS_ERROR_ENCRYPTION_FAILED;
  }

  if (request == R_TLS_KEY_UPDATE_REQUESTED)
    return r_tls_client_send_key_update13 (client, FALSE);
  return R_TLS_ERROR_OK;
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
  } else if (parser->content == R_TLS_CONTENT_TYPE_HANDSHAKE) {
    /* Post-handshake messages (1.3): store a NewSessionTicket for resumption,
     * rekey on a KeyUpdate, ignore the rest. */
    RTLSHandshakeType type;
    if (client->tls13 &&
        r_tls_parser_parse_handshake_peek_type (parser, &type) == R_TLS_ERROR_OK) {
      if (type == R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET)
        r_tls_client_store_ticket13 (client, parser);
      else if (type == R_TLS_HANDSHAKE_TYPE_KEY_UPDATE)
        return r_tls_client_recv_key_update13 (client, parser);
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
    r_tls_client_state_closed,
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

    if (client->tls13) {
      /* TLS 1.3: ignore middlebox-compat ChangeCipherSpec; protected records
       * arrive as application_data once read keys are installed. */
      if (parser.content == R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC)
        continue;
      if (client->rk_read.cipher != NULL &&
          parser.content == R_TLS_CONTENT_TYPE_APPLICATION_DATA) {
        if ((err = r_tls_parser_unprotect13 (&parser, client->rk_read.cipher,
                client->rk_read.iv, client->rk_read.ivlen,
                client->rk_read.seq)) != R_TLS_ERROR_OK) {
          R_LOG_WARNING ("1.3 record unprotect returned: %d", err);
          continue;
        }
        client->rk_read.seq++;
      }
    } else {
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
        } else if (atype == R_TLS_ALERT_TYPE_CLOSE_NOTIFY &&
            client->state < R_TLS_CLIENT_CLOSED) {
          /* Respond with our own close_notify (RFC 5246 7.2.1) and surface
           * the orderly close to the application. */
          if (r_tls_client_emit_alert (client, R_TLS_ALERT_LEVEL_WARNING,
                R_TLS_ALERT_TYPE_CLOSE_NOTIFY) == R_TLS_ERROR_OK)
            r_tls_client_send_out (client);
          r_tls_client_change_state (client, R_TLS_CLIENT_CLOSED);
          if (client->cb.closed != NULL)
            client->cb.closed (client->userdata, client);
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

  if (client->tls13) {
    ret = r_tls_client_protect_record13 (client,
        R_TLS_CONTENT_TYPE_APPLICATION_DATA, in.data, in.size);
    r_buffer_unmap (buffer, &in);
    if (ret != R_TLS_ERROR_OK)
      return FALSE;
    r_tls_client_send_out (client);
    return TRUE;
  }

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

rboolean
r_tls_client_key_update (RTLSClient * client, rboolean request_peer_update)
{
  if (R_UNLIKELY (client == NULL)) return FALSE;
  /* KeyUpdate is a TLS 1.3 post-handshake message; the record keys must be
   * installed, i.e. the session established. */
  if (R_UNLIKELY (!client->tls13 || client->state != R_TLS_CLIENT_APPDATA))
    return FALSE;

  if (r_tls_client_send_key_update13 (client, request_peer_update) != R_TLS_ERROR_OK)
    return FALSE;

  r_tls_client_send_out (client);
  return TRUE;
}

rboolean
r_tls_client_close (RTLSClient * client)
{
  if (R_UNLIKELY (client == NULL)) return FALSE;
  /* Only an established session can be cleanly closed; a second call is a
   * no-op (the state has already advanced past APPDATA). */
  if (client->state != R_TLS_CLIENT_APPDATA) return FALSE;

  if (r_tls_client_emit_alert (client, R_TLS_ALERT_LEVEL_WARNING,
        R_TLS_ALERT_TYPE_CLOSE_NOTIFY) != R_TLS_ERROR_OK)
    return FALSE;

  r_tls_client_send_out (client);
  r_tls_client_change_state (client, R_TLS_CLIENT_CLOSED);
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
