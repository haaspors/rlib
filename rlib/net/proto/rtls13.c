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
#include <rlib/net/proto/rtls13.h>

#include <rlib/crypto/rkdf.h>
#include <rlib/crypto/rhmac.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

/* TLSCiphertext record header used as the AEAD additional_data (RFC 8446 5.2):
 * opaque_type=application_data | legacy_record_version=0x0303 | length. */
#define R_TLS13_RECORD_AAD_SIZE   5

#define R_TLS13_LABEL_PREFIX      "tls13 "
#define R_TLS13_LABEL_PREFIX_LEN  6

rboolean
r_tls13_expand_label (RMsgDigestType hash, const ruint8 * secret,
    const rchar * label, rsize labellen, const ruint8 * context, rsize ctxlen,
    ruint8 * out, rsize outlen)
{
  /* HkdfLabel: uint16 length | opaque label<7..255> | opaque context<0..255>.
   * Max = 2 + 1 + (6 + 249) + 1 + 255. */
  ruint8 info[2 + 1 + (R_TLS13_LABEL_PREFIX_LEN + 249) + 1 + 255];
  rsize n = 0, hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (secret == NULL || label == NULL || out == NULL ||
        hlen == 0 || outlen == 0 || outlen > 0xffff ||
        labellen == 0 || labellen > 255 - R_TLS13_LABEL_PREFIX_LEN ||
        ctxlen > 255 || (context == NULL && ctxlen != 0)))
    return FALSE;

  info[n++] = (ruint8) (outlen >> 8);
  info[n++] = (ruint8) outlen;
  info[n++] = (ruint8) (R_TLS13_LABEL_PREFIX_LEN + labellen);
  r_memcpy (info + n, R_TLS13_LABEL_PREFIX, R_TLS13_LABEL_PREFIX_LEN);
  n += R_TLS13_LABEL_PREFIX_LEN;
  r_memcpy (info + n, label, labellen);
  n += labellen;
  info[n++] = (ruint8) ctxlen;
  if (ctxlen != 0) {
    r_memcpy (info + n, context, ctxlen);
    n += ctxlen;
  }

  return r_hkdf_expand (hash, secret, hlen, info, n, out, outlen);
}

rboolean
r_tls13_derive_secret (RMsgDigestType hash, const ruint8 * secret,
    const rchar * label, rsize labellen, const ruint8 * transcript_hash,
    ruint8 * out)
{
  rsize hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (transcript_hash == NULL || hlen == 0))
    return FALSE;

  /* Derive-Secret(Secret, Label, Messages) =
   *   HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), HashLen). */
  return r_tls13_expand_label (hash, secret, label, labellen,
      transcript_hash, hlen, out, hlen);
}

rboolean
r_tls13_aead_nonce (const ruint8 * iv, rsize ivlen, ruint64 seq, ruint8 * nonce)
{
  rsize i;

  if (R_UNLIKELY (iv == NULL || nonce == NULL ||
        ivlen == 0 || ivlen > R_TLS13_AEAD_NONCE_MAX))
    return FALSE;

  /* nonce = iv XOR left-zero-padded big-endian seq, over the low 8 octets. */
  r_memcpy (nonce, iv, ivlen);
  for (i = 0; i < sizeof (ruint64) && i < ivlen; i++)
    nonce[ivlen - 1 - i] ^= (ruint8) (seq >> (8 * i));

  return TRUE;
}

/* Fill the 5-byte TLSCiphertext header / AEAD additional_data for an
 * encrypted_record of @reclen bytes. */
static void
r_tls13_record_aad (ruint8 * aad, rsize reclen)
{
  aad[0] = (ruint8) R_TLS_CONTENT_TYPE_APPLICATION_DATA;
  aad[1] = 0x03;  /* legacy_record_version = 0x0303 (TLS 1.2) */
  aad[2] = 0x03;
  aad[3] = (ruint8) (reclen >> 8);
  aad[4] = (ruint8) reclen;
}

rboolean
r_tls13_record_protect (const RCryptoCipher * cipher,
    const ruint8 * iv, rsize ivlen, ruint64 seq,
    RTLSContentType type, const ruint8 * content, rsize contentlen,
    ruint8 * out, rsize outsize, rsize * outlen)
{
  ruint8 nonce[R_TLS13_AEAD_NONCE_MAX];
  ruint8 aad[R_TLS13_RECORD_AAD_SIZE];
  rsize innerlen = contentlen + 1;        /* content || inner content type */
  rsize reclen = innerlen + R_TLS13_AEAD_TAG_SIZE;

  if (R_UNLIKELY (cipher == NULL || out == NULL || outlen == NULL ||
        (content == NULL && contentlen != 0) || outsize < reclen))
    return FALSE;
  if (R_UNLIKELY (!r_tls13_aead_nonce (iv, ivlen, seq, nonce)))
    return FALSE;

  /* TLSInnerPlaintext: assemble in place (the AEAD may encrypt in place). */
  if (contentlen != 0)
    r_memmove (out, content, contentlen);
  out[contentlen] = (ruint8) type;
  r_tls13_record_aad (aad, reclen);

  if (R_UNLIKELY (r_crypto_cipher_encrypt_aead (cipher, out, innerlen, out,
          aad, sizeof (aad), nonce, ivlen,
          out + innerlen, R_TLS13_AEAD_TAG_SIZE) != R_CRYPTO_CIPHER_OK))
    return FALSE;

  *outlen = reclen;
  return TRUE;
}

rboolean
r_tls13_record_unprotect (const RCryptoCipher * cipher,
    const ruint8 * iv, rsize ivlen, ruint64 seq,
    const ruint8 * record, rsize reclen,
    ruint8 * out, rsize outsize, rsize * outlen, RTLSContentType * type)
{
  ruint8 nonce[R_TLS13_AEAD_NONCE_MAX];
  ruint8 aad[R_TLS13_RECORD_AAD_SIZE];
  ruint8 tag[R_TLS13_AEAD_TAG_SIZE];
  rsize innerlen;
  rssize i;

  if (R_UNLIKELY (cipher == NULL || record == NULL || out == NULL ||
        outlen == NULL || type == NULL || reclen <= R_TLS13_AEAD_TAG_SIZE))
    return FALSE;
  innerlen = reclen - R_TLS13_AEAD_TAG_SIZE;
  if (R_UNLIKELY (outsize < innerlen))
    return FALSE;
  if (R_UNLIKELY (!r_tls13_aead_nonce (iv, ivlen, seq, nonce)))
    return FALSE;

  r_tls13_record_aad (aad, reclen);
  r_memcpy (tag, record + innerlen, R_TLS13_AEAD_TAG_SIZE);
  if (R_UNLIKELY (r_crypto_cipher_decrypt_aead (cipher, out, innerlen, record,
          aad, sizeof (aad), nonce, ivlen,
          tag, R_TLS13_AEAD_TAG_SIZE) != R_CRYPTO_CIPHER_OK))
    return FALSE;

  /* Strip the optional trailing zero padding; the last non-zero octet is the
   * real content type (RFC 8446 5.4). An all-zero plaintext is malformed. */
  for (i = (rssize) innerlen - 1; i >= 0 && out[i] == 0; i--)
    ;
  if (R_UNLIKELY (i < 0))
    return FALSE;

  *type = (RTLSContentType) out[i];
  *outlen = (rsize) i;
  return TRUE;
}

/* Transcript-Hash("") = Hash of the empty message, the context Derive-Secret
 * binds the "derived" step to. */
static rboolean
r_tls13_empty_transcript (RMsgDigestType hash, ruint8 * out, rsize hlen)
{
  RMsgDigest * md;
  rboolean ok;

  if ((md = r_msg_digest_new (hash)) == NULL)
    return FALSE;
  ok = r_msg_digest_get_data (md, out, hlen, NULL);
  r_msg_digest_free (md);
  return ok;
}

rboolean
r_tls13_schedule_init (RTLS13Schedule * sched, RMsgDigestType hash)
{
  ruint8 zero[R_TLS13_SECRET_MAX];
  rsize hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (sched == NULL || hlen == 0 || hlen > R_TLS13_SECRET_MAX))
    return FALSE;

  sched->hash = hash;
  sched->hlen = hlen;

  /* Early Secret = HKDF-Extract(0, 0^HashLen): no PSK. */
  r_memset (zero, 0, hlen);
  return r_hkdf_extract (hash, NULL, 0, zero, hlen, sched->early);
}

rboolean
r_tls13_schedule_init_psk (RTLS13Schedule * sched, RMsgDigestType hash,
    const ruint8 * psk, rsize psklen)
{
  rsize hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (sched == NULL || psk == NULL || psklen == 0 ||
        hlen == 0 || hlen > R_TLS13_SECRET_MAX))
    return FALSE;

  sched->hash = hash;
  sched->hlen = hlen;

  /* Early Secret = HKDF-Extract(0, PSK). */
  return r_hkdf_extract (hash, NULL, 0, psk, psklen, sched->early);
}

rboolean
r_tls13_binder_key (const RTLS13Schedule * sched, ruint8 * out)
{
  ruint8 emptyhash[R_TLS13_SECRET_MAX];

  if (R_UNLIKELY (sched == NULL || out == NULL))
    return FALSE;

  /* binder_key = Derive-Secret(Early, "res binder", ""). */
  return r_tls13_empty_transcript (sched->hash, emptyhash, sched->hlen) &&
      r_tls13_derive_secret (sched->hash, sched->early,
          R_STR_WITH_SIZE_ARGS ("res binder"), emptyhash, out);
}

rboolean
r_tls13_schedule_early (RTLS13Schedule * sched, const ruint8 * transcript_hash)
{
  if (R_UNLIKELY (sched == NULL || transcript_hash == NULL))
    return FALSE;

  /* client_early_traffic_secret = Derive-Secret(Early, "c e traffic",
   *   Transcript-Hash(ClientHello)). */
  return r_tls13_derive_secret (sched->hash, sched->early,
      R_STR_WITH_SIZE_ARGS ("c e traffic"), transcript_hash, sched->cet);
}

rboolean
r_tls13_schedule_handshake (RTLS13Schedule * sched, const ruint8 * ecdhe,
    rsize ecdhelen, const ruint8 * transcript_hash)
{
  ruint8 emptyhash[R_TLS13_SECRET_MAX], derived[R_TLS13_SECRET_MAX];

  if (R_UNLIKELY (sched == NULL || ecdhe == NULL || ecdhelen == 0 ||
        transcript_hash == NULL))
    return FALSE;

  /* derived = Derive-Secret(Early, "derived", ""). */
  if (!r_tls13_empty_transcript (sched->hash, emptyhash, sched->hlen) ||
      !r_tls13_derive_secret (sched->hash, sched->early,
          R_STR_WITH_SIZE_ARGS ("derived"), emptyhash, derived))
    return FALSE;

  /* Handshake Secret = HKDF-Extract(derived, ECDHE). */
  if (!r_hkdf_extract (sched->hash, derived, sched->hlen, ecdhe, ecdhelen,
        sched->handshake))
    return FALSE;

  return r_tls13_derive_secret (sched->hash, sched->handshake,
            R_STR_WITH_SIZE_ARGS ("c hs traffic"), transcript_hash, sched->chs) &&
         r_tls13_derive_secret (sched->hash, sched->handshake,
            R_STR_WITH_SIZE_ARGS ("s hs traffic"), transcript_hash, sched->shs);
}

rboolean
r_tls13_schedule_master (RTLS13Schedule * sched, const ruint8 * transcript_hash)
{
  ruint8 emptyhash[R_TLS13_SECRET_MAX], derived[R_TLS13_SECRET_MAX];
  ruint8 zero[R_TLS13_SECRET_MAX];

  if (R_UNLIKELY (sched == NULL || transcript_hash == NULL))
    return FALSE;

  /* Master Secret = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0). */
  if (!r_tls13_empty_transcript (sched->hash, emptyhash, sched->hlen) ||
      !r_tls13_derive_secret (sched->hash, sched->handshake,
          R_STR_WITH_SIZE_ARGS ("derived"), emptyhash, derived))
    return FALSE;

  r_memset (zero, 0, sched->hlen);
  if (!r_hkdf_extract (sched->hash, derived, sched->hlen, zero, sched->hlen,
        sched->master))
    return FALSE;

  return r_tls13_derive_secret (sched->hash, sched->master,
            R_STR_WITH_SIZE_ARGS ("c ap traffic"), transcript_hash, sched->cap) &&
         r_tls13_derive_secret (sched->hash, sched->master,
            R_STR_WITH_SIZE_ARGS ("s ap traffic"), transcript_hash, sched->sap);
}

rboolean
r_tls13_schedule_resumption (RTLS13Schedule * sched,
    const ruint8 * transcript_hash)
{
  if (R_UNLIKELY (sched == NULL || transcript_hash == NULL))
    return FALSE;

  /* resumption_master_secret = Derive-Secret(Master, "res master",
   *   Transcript-Hash(ClientHello..client Finished)). */
  return r_tls13_derive_secret (sched->hash, sched->master,
      R_STR_WITH_SIZE_ARGS ("res master"), transcript_hash, sched->res_master);
}

rboolean
r_tls13_resumption_psk (RMsgDigestType hash, const ruint8 * res_master,
    const ruint8 * nonce, rsize noncelen, ruint8 * out)
{
  rsize hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (res_master == NULL || out == NULL || hlen == 0))
    return FALSE;

  /* PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
   *   ticket_nonce, HashLen). */
  return r_tls13_expand_label (hash, res_master,
      R_STR_WITH_SIZE_ARGS ("resumption"), nonce, noncelen, out, hlen);
}

rboolean
r_tls13_traffic_keys (RMsgDigestType hash, const ruint8 * secret,
    const RCryptoCipherInfo * info, RTLS13RecordKeys * out)
{
  ruint8 key[32];
  rsize keylen;

  if (R_UNLIKELY (secret == NULL || info == NULL || out == NULL))
    return FALSE;
  keylen = info->keybits / 8;
  if (R_UNLIKELY (keylen == 0 || keylen > sizeof (key) ||
        info->ivsize == 0 || info->ivsize > R_TLS13_AEAD_NONCE_MAX))
    return FALSE;

  if (!r_tls13_expand_label (hash, secret, R_STR_WITH_SIZE_ARGS ("key"),
          NULL, 0, key, keylen) ||
      !r_tls13_expand_label (hash, secret, R_STR_WITH_SIZE_ARGS ("iv"),
          NULL, 0, out->iv, info->ivsize)) {
    r_memclear (key, sizeof (key));
    return FALSE;
  }

  out->cipher = r_crypto_cipher_new (info, key);
  r_memclear (key, sizeof (key));
  if (R_UNLIKELY (out->cipher == NULL))
    return FALSE;
  out->ivlen = info->ivsize;
  out->seq = 0;
  return TRUE;
}

rboolean
r_tls13_traffic_update (RMsgDigestType hash, const ruint8 * secret, ruint8 * out)
{
  ruint8 next[R_TLS13_SECRET_MAX];
  rsize hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (secret == NULL || out == NULL ||
        hlen == 0 || hlen > R_TLS13_SECRET_MAX))
    return FALSE;

  /* application_traffic_secret_N+1 = HKDF-Expand-Label(
   *   application_traffic_secret_N, "traffic upd", "", Hash.length). A temporary
   * keeps this correct when @out aliases @secret for an in-place advance. */
  if (!r_tls13_expand_label (hash, secret, R_STR_WITH_SIZE_ARGS ("traffic upd"),
        NULL, 0, next, hlen))
    return FALSE;
  r_memcpy (out, next, hlen);
  r_memclear (next, sizeof (next));
  return TRUE;
}

rboolean
r_tls13_finished_key (RMsgDigestType hash, const ruint8 * secret, ruint8 * out)
{
  rsize hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (secret == NULL || out == NULL || hlen == 0))
    return FALSE;

  return r_tls13_expand_label (hash, secret, R_STR_WITH_SIZE_ARGS ("finished"),
      NULL, 0, out, hlen);
}

rboolean
r_tls13_verify_data (RMsgDigestType hash, const ruint8 * finished_key,
    const ruint8 * transcript_hash, ruint8 * out)
{
  RHmac * hmac;
  rsize hlen = r_msg_digest_type_size (hash);
  rboolean ok;

  if (R_UNLIKELY (finished_key == NULL || transcript_hash == NULL ||
        out == NULL || hlen == 0))
    return FALSE;

  if ((hmac = r_hmac_new (hash, finished_key, hlen)) == NULL)
    return FALSE;
  ok = r_hmac_update (hmac, transcript_hash, hlen) &&
       r_hmac_get_data (hmac, out, hlen, NULL);
  r_hmac_free (hmac);
  return ok;
}

rboolean
r_tls13_cert_verify_tbs (rboolean server, const ruint8 * transcript_hash,
    rsize thlen, ruint8 * out, rsize outsize, rsize * outlen)
{
  /* RFC 8446 4.4.3: 64 octets of 0x20, the context string, a single 0x00, and
   * the transcript hash. The two context strings are both 33 bytes. */
  static const rchar ctx_server[] = "TLS 1.3, server CertificateVerify";
  static const rchar ctx_client[] = "TLS 1.3, client CertificateVerify";
  const rchar * ctx = server ? ctx_server : ctx_client;
  rsize ctxlen = 33;  /* sizeof - 1, both strings */
  rsize n = 64 + ctxlen + 1 + thlen;

  if (R_UNLIKELY (transcript_hash == NULL || out == NULL || outlen == NULL ||
        thlen == 0 || outsize < n))
    return FALSE;

  r_memset (out, 0x20, 64);
  r_memcpy (out + 64, ctx, ctxlen);
  out[64 + ctxlen] = 0x00;
  r_memcpy (out + 64 + ctxlen + 1, transcript_hash, thlen);
  *outlen = n;
  return TRUE;
}

/* SHA-256("HelloRetryRequest"), the ServerHello.random of a HelloRetryRequest. */
static const ruint8 r_tls13_hrr_random[32] = {
  0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
  0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
  0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

void
r_tls13_hello_retry_random (ruint8 * out)
{
  if (R_LIKELY (out != NULL))
    r_memcpy (out, r_tls13_hrr_random, sizeof (r_tls13_hrr_random));
}

rboolean
r_tls13_random_is_hrr (const ruint8 * random)
{
  return random != NULL &&
      r_memcmp (random, r_tls13_hrr_random, sizeof (r_tls13_hrr_random)) == 0;
}

/* RFC 8446 4.1.3 downgrade-protection sentinels, stamped into the last 8 bytes
 * of ServerHello.random by a 1.3-capable server that negotiates a lower
 * version: "DOWNGRD\x01" for TLS 1.2, "DOWNGRD\x00" for TLS 1.1 or below. */
static const ruint8 r_tls13_downgrade_tls12[8] = {
  0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01
};
static const ruint8 r_tls13_downgrade_tls11[8] = {
  0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00
};

void
r_tls13_downgrade_random (ruint8 * random, RTLSVersion negotiated)
{
  if (R_UNLIKELY (random == NULL))
    return;
  if (negotiated == R_TLS_VERSION_TLS_1_2)
    r_memcpy (random + R_TLS_HELLO_RANDOM_BYTES - 8, r_tls13_downgrade_tls12, 8);
  else if (negotiated >= R_TLS_VERSION_TLS_1_0 && negotiated < R_TLS_VERSION_TLS_1_2)
    r_memcpy (random + R_TLS_HELLO_RANDOM_BYTES - 8, r_tls13_downgrade_tls11, 8);
}

rboolean
r_tls13_random_is_downgrade (const ruint8 * random)
{
  if (R_UNLIKELY (random == NULL))
    return FALSE;
  return r_memcmp (random + R_TLS_HELLO_RANDOM_BYTES - 8,
          r_tls13_downgrade_tls12, 8) == 0 ||
      r_memcmp (random + R_TLS_HELLO_RANDOM_BYTES - 8,
          r_tls13_downgrade_tls11, 8) == 0;
}

rboolean
r_tls13_message_hash (RMsgDigestType hash, const ruint8 * msg, rsize msglen,
    ruint8 * out, rsize outsize, rsize * outlen)
{
  RMsgDigest * md;
  rsize hlen = r_msg_digest_type_size (hash);
  rboolean ok;

  if (R_UNLIKELY (msg == NULL || out == NULL || outlen == NULL ||
        hlen == 0 || outsize < 4 + hlen))
    return FALSE;

  /* Handshake header: message_hash type, then a 3-byte length of HashLen. */
  out[0] = (ruint8) R_TLS_HANDSHAKE_TYPE_MESSAGE_HASH;
  out[1] = 0x00;
  out[2] = 0x00;
  out[3] = (ruint8) hlen;

  if ((md = r_msg_digest_new (hash)) == NULL)
    return FALSE;
  ok = r_msg_digest_update (md, msg, msglen) &&
       r_msg_digest_get_data (md, out + 4, hlen, NULL);
  r_msg_digest_free (md);
  if (!ok)
    return FALSE;

  *outlen = 4 + hlen;
  return TRUE;
}
