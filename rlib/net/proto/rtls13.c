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
