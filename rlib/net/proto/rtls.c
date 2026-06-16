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
#include <rlib/net/proto/rtls.h>
#include "rtls-private.h"

#include <rlib/rtime.h>

#include <rlib/crypto/rx509.h>
#include <rlib/crypto/recc.h>
#include <rlib/crypto/rxdh.h>

static inline ruint32
_r_parse_u24 (const ruint8 * ptr)
{
  return ((ruint32)ptr[0] << 16) | ((ruint32)ptr[1] <<  8) | ((ruint32)ptr[2]);
}

static inline ruint64
_r_parse_u48 (const ruint8 * ptr)
{
  return ((ruint64)ptr[0] << 40) | ((ruint64)ptr[1] << 32) | ((ruint64)ptr[2] << 24) |
         ((ruint64)ptr[3] << 16) | ((ruint64)ptr[4] <<  8) | ((ruint64)ptr[5]);
}

rboolean
r_tls_sign_scheme_to_md (RTLSSignatureScheme scheme, RMsgDigestType * md)
{
  switch (scheme) {
    case R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA256:
    case R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256:
      *md = R_MSG_DIGEST_TYPE_SHA256;
      return TRUE;
    default:
      return FALSE;
  }
}

RTLSSignatureScheme
r_tls_sign_scheme_for_key (const RCryptoKey * key)
{
  return (r_crypto_key_get_algo (key) == R_CRYPTO_ALGO_ECDSA) ?
      R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256 :
      R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA256;
}

rboolean
r_tls_ecdhe_group_to_curve (RTLSSupportedGroup group, REcurveID * curve)
{
  switch (group) {
    case R_TLS_SUPPORTED_GROUP_SECP256R1: *curve = R_ECURVE_ID_SECP256R1; return TRUE;
    case R_TLS_SUPPORTED_GROUP_X25519:    *curve = R_ECURVE_ID_X25519;    return TRUE;
    default: return FALSE;
  }
}

rboolean
r_tls_ecdhe_curve_is_montgomery (REcurveID curve)
{
  return curve == R_ECURVE_ID_X25519 || curve == R_ECURVE_ID_X448;
}

RCryptoKey *
r_tls_ecdhe_keygen (REcurveID curve, RPrng * prng)
{
  if (r_tls_ecdhe_curve_is_montgomery (curve))
    return r_xdh_priv_key_new_gen (curve, prng);
  return r_ecdh_priv_key_new_gen (curve, prng);
}

rboolean
r_tls_ecdhe_point_write (const RCryptoKey * key, REcurveID curve,
    ruint8 * out, rsize cap, ruint8 * len)
{
  rsize sz = cap;

  if (r_tls_ecdhe_curve_is_montgomery (curve)) {
    const ruint8 * u;
    rsize usize;
    if (!r_xdh_key_get_pub_u (key, &u, &usize)) return FALSE;
    if (usize > cap) return FALSE;
    r_memcpy (out, u, usize);
    *len = (ruint8)usize;
    return TRUE;
  } else {
    REcurveAffinePoint q;
    REcurve params;
    rboolean ok;

    r_ecurve_point_init (&q);
    if (!r_ecc_key_get_q (key, &q)) { r_ecurve_point_clear (&q); return FALSE; }
    if (!r_ecurve_init (&params, curve)) { r_ecurve_point_clear (&q); return FALSE; }
    ok = r_ecurve_point_to_uncompressed (&q, &params, out, &sz);
    r_ecurve_clear (&params);
    r_ecurve_point_clear (&q);
    if (!ok) return FALSE;
    *len = (ruint8)sz;
    return TRUE;
  }
}

RCryptoKey *
r_tls_ecdhe_point_read (REcurveID curve, const ruint8 * point, rsize len)
{
  if (r_tls_ecdhe_curve_is_montgomery (curve))
    return r_xdh_pub_key_new (curve, point, len);
  return r_ecdh_pub_key_new (curve, point, len);
}

rboolean
r_tls_ecdhe_compute (const RCryptoKey * priv, const RCryptoKey * peer,
    ruint8 * out, rsize cap, rsize * len)
{
  rsize sz = cap;
  RCryptoResult res;

  if (r_xdh_key_get_curve (priv) != R_ECURVE_ID_NONE)
    res = r_xdh_compute_shared (priv, peer, out, &sz);
  else
    res = r_ecdh_compute_shared (priv, peer, out, &sz);

  if (res != R_CRYPTO_OK) return FALSE;
  *len = sz;
  return TRUE;
}

void
r_tls_parser_clear (RTLSParser * parser)
{
  if (R_LIKELY (parser->buf != NULL)) {
    if (R_LIKELY (parser->fragment.data != NULL))
      r_buffer_unmap (parser->buf, &parser->fragment);
    r_buffer_unref (parser->buf);
    r_memclear (parser, sizeof (RTLSParser));
  }
}

RTLSVersion
r_tls_parse_data_shallow (rconstpointer buf, rsize size)
{
  RTLSVersion ret = R_TLS_VERSION_UNKNOWN;
  const ruint8 * data;

  if ((data = buf) != NULL && size > 5) {
    RTLSContentType content = (RTLSContentType)data[0];
    RTLSVersion ver;

    if (content < R_TLS_CONTENT_TYPE_FIRST ||
        content > R_TLS_CONTENT_TYPE_LAST) {
      goto beach;
    }

    ver = (RTLSVersion)r_load_be16 (&data[1]);
    switch (ver) {
      case R_TLS_VERSION_SSL_1_0:
      case R_TLS_VERSION_SSL_2_0:
      case R_TLS_VERSION_SSL_3_0:
      case R_TLS_VERSION_TLS_1_0:
      case R_TLS_VERSION_TLS_1_1:
      case R_TLS_VERSION_TLS_1_2:
      case R_TLS_VERSION_TLS_1_3:
      case R_TLS_VERSION_DTLS_1_0:
      case R_TLS_VERSION_DTLS_1_2:
      case R_TLS_VERSION_DTLS_1_3:
        ret = ver;
      default:
        break;
    }
  }

beach:
  return ret;
}

RTLSError
r_tls_parser_init (RTLSParser * parser, rconstpointer buf, rsize size)
{
  RBuffer * buffer;
  RTLSError ret;

  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size == 0)) return R_TLS_ERROR_BUF_TOO_SMALL;

  if ((buffer = r_buffer_new_take (r_memdup (buf, size), size)) != NULL) {
    ret = r_tls_parser_init_buffer (parser, buffer);
    r_buffer_unref (buffer);
  } else {
    ret = R_TLS_ERROR_INVAL;
  }

  return ret;
}

RTLSError
r_tls_parser_init_buffer (RTLSParser * parser, RBuffer * buf)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RTLSError ret;
  ruint16 fraglen;

  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_TLS_ERROR_INVAL;

  if (!r_buffer_map_byte_range (buf, 0, 5, &info, R_MEM_MAP_READ))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  parser->content = (RTLSContentType)info.data[0];
  if (parser->content < R_TLS_CONTENT_TYPE_FIRST ||
      parser->content > R_TLS_CONTENT_TYPE_LAST) {
    ret = R_TLS_ERROR_INVALID_RECORD;
    goto beach;
  }

  parser->version = (RTLSVersion)r_load_be16 (&info.data[1]);

  if (!r_tls_parser_is_dtls (parser)) {
    if (R_UNLIKELY (parser->version < R_TLS_VERSION_TLS_1_0 ||
          parser->version > R_TLS_VERSION_TLS_1_3)) {
      ret = R_TLS_ERROR_VERSION;
      goto beach;
    }

    parser->epoch = 0;
    parser->seqno = 0;
    parser->offset = 5;
    fraglen = r_load_be16 (&info.data[3]);
  } else {
    RMemMapInfo dtlsext = R_MEM_MAP_INFO_INIT;

    if (R_UNLIKELY (parser->version > R_TLS_VERSION_DTLS_1_0 ||
        parser->version < R_TLS_VERSION_DTLS_1_3)) {
      ret = R_TLS_ERROR_VERSION;
      goto beach;
    }

    if (!r_buffer_map_byte_range (buf, 5, 6 + 2, &dtlsext, R_MEM_MAP_READ)) {
      ret = R_TLS_ERROR_BUF_TOO_SMALL;
      goto beach;
    }

    parser->epoch = r_load_be16 (&info.data[3]);
    parser->seqno = _r_parse_u48 (&dtlsext.data[0]);
    parser->offset = 13;
    fraglen = r_load_be16 (&dtlsext.data[6]);
    r_buffer_unmap (buf, &dtlsext);
  }

  if ((fraglen & 0xc000) > 0) {
    ret = R_TLS_ERROR_RECORD_OVERFLOW;
    goto beach;
  }
  if (!r_buffer_map_byte_range (buf, parser->offset, (rssize)fraglen,
        &parser->fragment, R_MEM_MAP_READ)) {
    ret = R_TLS_ERROR_BUF_TOO_SMALL;
    goto beach;
  }

  ret = R_TLS_ERROR_OK;
  parser->buf = r_buffer_ref (buf);
  parser->recsize = parser->offset + fraglen;

beach:
  r_buffer_unmap (buf, &info);
  return ret;
}

RTLSError
r_tls_parser_init_next (RTLSParser * parser, RBuffer ** buf)
{
  RBuffer * next;
  RTLSError ret;

  if ((next = r_tls_parser_next (parser)) != NULL) {
    r_tls_parser_clear (parser);
    ret = r_tls_parser_init_buffer (parser, next);
    if (buf != NULL)
      *buf = next;
    else
      r_buffer_unref (next);
  } else {
    r_tls_parser_clear (parser);
    ret = R_TLS_ERROR_EOB;
    if (buf != NULL)
      *buf = NULL;
  }

  return ret;
}

RBuffer *
r_tls_parser_next (RTLSParser * parser)
{
  RBuffer * ret;

  if ((ret = r_buffer_new ()) != NULL) {
    if (!r_buffer_append_view (ret, parser->buf, parser->recsize, -1)) {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

/* TLS 1.2 AEAD record framing (RFC 5246 6.2.3.3 / RFC 5288 3): the 12-byte GCM
 * nonce is a 4-byte fixed salt (write-IV from key expansion) concatenated with
 * the 8-byte R_TLS_AEAD_EXPLICIT_NONCE_SIZE nonce carried on the wire ahead of
 * the ciphertext. */
#define R_TLS_AEAD_NONCE_SIZE_MAX        12
/* additional_data = seq_num(8) || type(1) || version(2) || length(2) */
#define R_TLS_AEAD_AAD_SIZE              13

/* Fill the 13-byte MAC seed prefix: seq_num (epoch+seqno for DTLS) +
 * content type + version + length, where length is the IV+ciphertext size
 * for encrypt-then-MAC (RFC 7366) or the plaintext size for MAC-then-encrypt. */
static void
r_tls_mac_seed (const RTLSParser * parser, ruint8 scratch[13], rsize length)
{
  if (r_tls_parser_is_dtls (parser)) {
    scratch[0x00] = (parser->epoch   >>  8) & 0xff;
    scratch[0x01] = (parser->epoch        ) & 0xff;
  } else {
    scratch[0x00] = (parser->seqno   >> 56) & 0xff;
    scratch[0x01] = (parser->seqno   >> 48) & 0xff;
  }
  scratch[0x02] = (parser->seqno   >> 40) & 0xff;
  scratch[0x03] = (parser->seqno   >> 32) & 0xff;
  scratch[0x04] = (parser->seqno   >> 24) & 0xff;
  scratch[0x05] = (parser->seqno   >> 16) & 0xff;
  scratch[0x06] = (parser->seqno   >>  8) & 0xff;
  scratch[0x07] = (parser->seqno        ) & 0xff;
  scratch[0x08] = (parser->content      ) & 0xff;
  scratch[0x09] = (parser->version >>  8) & 0xff;
  scratch[0x0a] = (parser->version      ) & 0xff;
  scratch[0x0b] = (length          >>  8) & 0xff;
  scratch[0x0c] = (length               ) & 0xff;
}

/* RFC 7366 encrypt-then-MAC decrypt: the fragment is IV || ciphertext || MAC.
 * Verify the MAC over the IV and ciphertext first, then decrypt and strip
 * the CBC padding. */
static RTLSError
r_tls_parser_decrypt_etm (RTLSParser * parser,
    const RCryptoCipher * cipher, RHmac * mac)
{
  RBuffer * buf, * replace;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize ivsize = cipher->info->ivsize;
  rsize macsize = r_hmac_size (mac);
  rsize ctlen, contentsize, padding;
  ruint8 scratch[sizeof (ruint64) + sizeof (ruint8) + 2 * sizeof (ruint16)];
  ruint8 * iv;

  if (parser->fragment.size < ivsize + ivsize + macsize)
    return R_TLS_ERROR_CORRUPT_RECORD;
  ctlen = parser->fragment.size - ivsize - macsize;
  if ((ctlen % ivsize) != 0)
    return R_TLS_ERROR_CORRUPT_RECORD;

  r_tls_mac_seed (parser, scratch, ivsize + ctlen);
  r_hmac_reset (mac);
  r_hmac_update (mac, scratch, sizeof (scratch));
  r_hmac_update (mac, parser->fragment.data, ivsize + ctlen);
  if (!r_hmac_verify (mac, parser->fragment.data + ivsize + ctlen, macsize))
    return R_TLS_ERROR_INVALID_MAC;

  if ((buf = r_buffer_new_alloc (NULL, ctlen, NULL)) == NULL)
    return R_TLS_ERROR_OOM;
  if (!r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    r_buffer_unref (buf);
    return R_TLS_ERROR_OOM;
  }

  iv = r_alloca (ivsize);
  r_memcpy (iv, parser->fragment.data, ivsize);
  if (r_crypto_cipher_decrypt (cipher, info.data, info.size,
        parser->fragment.data + ivsize, iv, ivsize) != R_CRYPTO_CIPHER_OK) {
    r_buffer_unmap (buf, &info);
    r_buffer_unref (buf);
    return R_TLS_ERROR_CORRUPT_RECORD;
  }

  padding = 1 + info.data[info.size - 1];
  if (padding > ctlen) {
    r_buffer_unmap (buf, &info);
    r_buffer_unref (buf);
    return R_TLS_ERROR_CORRUPT_RECORD;
  }
  contentsize = ctlen - padding;
  r_buffer_unmap (buf, &info);
  r_buffer_resize (buf, 0, contentsize);

  replace = r_buffer_replace_byte_range (parser->buf,
      parser->offset, parser->fragment.size, buf);
  r_buffer_unref (buf);
  r_buffer_unmap (parser->buf, &parser->fragment);
  r_buffer_unref (parser->buf);
  parser->buf = replace;
  parser->recsize = parser->offset + contentsize;

  if (!r_buffer_map_byte_range (parser->buf, parser->offset, (rssize)contentsize,
        &parser->fragment, R_MEM_MAP_READ))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  return R_TLS_ERROR_OK;
}

/* AEAD (e.g. AES-GCM) decrypt: the fragment is explicit_nonce(8) ||
 * ciphertext || tag(16). The 12-byte GCM nonce is salt(4) || explicit_nonce;
 * the additional data is the 13-byte seq_num||type||version||plainlen seed.
 * On a tag mismatch the AEAD reports R_CRYPTO_CIPHER_AUTH_FAILED and the
 * decrypted buffer is dropped without reaching the caller, so a forged record
 * never exposes data; the failure maps to R_TLS_ERROR_INVALID_MAC
 * (-> bad_record_mac). */
static RTLSError
r_tls_parser_decrypt_aead (RTLSParser * parser, const RCryptoCipher * cipher,
    const ruint8 * salt)
{
  RBuffer * buf, * replace;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize tagsize = cipher->info->blocksize;   /* 16 for GCM */
  rsize saltsize = cipher->info->ivsize - R_TLS_AEAD_EXPLICIT_NONCE_SIZE; /* 4 */
  rsize ctlen;
  ruint8 nonce[R_TLS_AEAD_NONCE_SIZE_MAX];
  ruint8 aad[R_TLS_AEAD_AAD_SIZE];
  const ruint8 * ct, * tag;
  RCryptoCipherResult res;

  if (R_UNLIKELY (salt == NULL)) return R_TLS_ERROR_INVAL;
  /* The nonce buffer is sized for a 12-byte AEAD nonce (salt + 8). */
  if (R_UNLIKELY (cipher->info->ivsize != R_TLS_AEAD_NONCE_SIZE_MAX))
    return R_TLS_ERROR_INVAL;
  if (parser->fragment.size < R_TLS_AEAD_EXPLICIT_NONCE_SIZE + tagsize)
    return R_TLS_ERROR_CORRUPT_RECORD;

  ctlen = parser->fragment.size - R_TLS_AEAD_EXPLICIT_NONCE_SIZE - tagsize;
  ct = parser->fragment.data + R_TLS_AEAD_EXPLICIT_NONCE_SIZE;
  tag = ct + ctlen;

  /* GCM nonce = salt || explicit-nonce (the latter taken off the wire) */
  r_memcpy (nonce, salt, saltsize);
  r_memcpy (nonce + saltsize, parser->fragment.data, R_TLS_AEAD_EXPLICIT_NONCE_SIZE);
  /* AAD seq_num is the LOCAL expected receive seqno, length is the plaintext */
  r_tls_mac_seed (parser, aad, ctlen);

  if ((buf = r_buffer_new_alloc (NULL, ctlen, NULL)) == NULL)
    return R_TLS_ERROR_OOM;
  if (!r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    r_buffer_unref (buf);
    return R_TLS_ERROR_OOM;
  }

  res = r_crypto_cipher_decrypt_aead (cipher, info.data, ctlen, ct,
      aad, sizeof (aad), nonce, saltsize + R_TLS_AEAD_EXPLICIT_NONCE_SIZE,
      (ruint8 *) tag, tagsize);
  r_buffer_unmap (buf, &info);
  if (res != R_CRYPTO_CIPHER_OK) {
    r_buffer_unref (buf);
    return (res == R_CRYPTO_CIPHER_AUTH_FAILED) ?
        R_TLS_ERROR_INVALID_MAC : R_TLS_ERROR_CORRUPT_RECORD;
  }

  replace = r_buffer_replace_byte_range (parser->buf,
      parser->offset, parser->fragment.size, buf);
  r_buffer_unref (buf);
  r_buffer_unmap (parser->buf, &parser->fragment);
  r_buffer_unref (parser->buf);
  parser->buf = replace;
  parser->recsize = parser->offset + ctlen;

  if (!r_buffer_map_byte_range (parser->buf, parser->offset, (rssize)ctlen,
        &parser->fragment, R_MEM_MAP_READ))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_decrypt (RTLSParser * parser,
    const RCryptoCipher * cipher, RHmac * mac, rboolean etm, const ruint8 * salt)
{
  RBuffer * buf, * replace;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize ivsize, contentsize;
  ruint8 * iv;

  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (cipher == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (cipher->info->type == R_CRYPTO_CIPHER_ALGO_NULL))
    return R_TLS_ERROR_OK;

  if (cipher->info->mode == R_CRYPTO_CIPHER_MODE_GCM)
    return r_tls_parser_decrypt_aead (parser, cipher, salt);

  if (etm && mac != NULL && cipher->info->mode == R_CRYPTO_CIPHER_MODE_CBC)
    return r_tls_parser_decrypt_etm (parser, cipher, mac);

  ivsize = cipher->info->ivsize;
  if (R_UNLIKELY (parser->fragment.size < ivsize))
    return R_TLS_ERROR_CORRUPT_RECORD;
  contentsize = parser->fragment.size - ivsize;
  if ((buf = r_buffer_new_alloc (NULL, contentsize, NULL)) == NULL)
    return R_TLS_ERROR_OOM;

  if (!r_buffer_map (buf, &info, R_MEM_MAP_WRITE)) {
    r_buffer_unref (buf);
    return R_TLS_ERROR_OOM;
  }

  iv = r_alloca (ivsize);
  r_memcpy (iv, parser->fragment.data, ivsize);
  if (r_crypto_cipher_decrypt (cipher, info.data, info.size,
        parser->fragment.data + ivsize, iv, ivsize) != R_CRYPTO_CIPHER_OK) {
    r_buffer_unmap (buf, &info);
    r_buffer_unref (buf);
    return R_TLS_ERROR_CORRUPT_RECORD;
  }

  if (cipher->info->mode == R_CRYPTO_CIPHER_MODE_CBC) {
    rsize padding;   /* 1 + pad-length byte; widened so a 0xff trailing
                      * byte (256) can't truncate to 0 in ruint8 */
    rsize macsize = (mac != NULL) ? r_hmac_size (mac) : 0;

    if (info.size < macsize + 1) {
      r_buffer_unmap (buf, &info);
      r_buffer_unref (buf);
      return R_TLS_ERROR_CORRUPT_RECORD;
    }
    contentsize -= macsize;
    if ((padding = 1 + info.data[info.size - 1]) < contentsize) {
      contentsize -= padding;

      if (mac != NULL) {
        ruint8 scratch[sizeof (ruint64) + sizeof (ruint8) + sizeof (ruint16) + sizeof (ruint16)];

        r_hmac_reset (mac);
        if (r_tls_parser_is_dtls (parser)) {
          scratch[0x00] = (parser->epoch  >> 8) & 0xff;
          scratch[0x01] = (parser->epoch      ) & 0xff;
        } else {
          scratch[0x00] = (parser->seqno >> 56) & 0xff;
          scratch[0x01] = (parser->seqno >> 48) & 0xff;
        }
        scratch[0x02] = (parser->seqno   >> 40) & 0xff;
        scratch[0x03] = (parser->seqno   >> 32) & 0xff;
        scratch[0x04] = (parser->seqno   >> 24) & 0xff;
        scratch[0x05] = (parser->seqno   >> 16) & 0xff;
        scratch[0x06] = (parser->seqno   >>  8) & 0xff;
        scratch[0x07] = (parser->seqno        ) & 0xff;
        scratch[0x08] = (parser->content      ) & 0xff;
        scratch[0x09] = (parser->version >>  8) & 0xff;
        scratch[0x0a] = (parser->version      ) & 0xff;
        scratch[0x0b] = (contentsize     >>  8) & 0xff;
        scratch[0x0c] = (contentsize          ) & 0xff;

        r_hmac_update (mac, &scratch, sizeof (scratch));
        r_hmac_update (mac, info.data, contentsize);

        if (!r_hmac_verify (mac, &info.data[contentsize], macsize)) {
          r_buffer_unmap (buf, &info);
          r_buffer_unref (buf);
          return R_TLS_ERROR_INVALID_MAC;
        }
      }

      r_buffer_unmap (buf, &info);
      r_buffer_resize (buf, 0, contentsize);
    } else {
      r_buffer_unmap (buf, &info);
      r_buffer_unref (buf);
      return R_TLS_ERROR_CORRUPT_RECORD;
    }
  } else if (cipher->info->mode == R_CRYPTO_CIPHER_MODE_STREAM) {
    r_buffer_unmap (buf, &info);
  } else {
    r_buffer_unmap (buf, &info);
  }

  replace = r_buffer_replace_byte_range (parser->buf,
      parser->offset, parser->fragment.size, buf);
  r_buffer_unref (buf);
  r_buffer_unmap (parser->buf, &parser->fragment);
  r_buffer_unref (parser->buf);
  parser->buf = replace;
  parser->recsize = parser->offset + contentsize;

  if (!r_buffer_map_byte_range (parser->buf, parser->offset, (rssize)contentsize,
        &parser->fragment, R_MEM_MAP_READ))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  return R_TLS_ERROR_OK;
}

static RBuffer *
_r_tls_encrypt_buffer (const ruint8 * buf, rsize bufsize, rsize hdrsize,
    const RCryptoCipher * cipher, const ruint8 * iv,
    const ruint8 * mac, rsize macsize)
{
  RBuffer * ret = NULL;
  rsize ivsize, size;
  ruint8 padding;

  ivsize = cipher->info->ivsize;
  size = ivsize + (bufsize - hdrsize) + macsize;
  padding = (ruint8)(ivsize - (size % ivsize));
  size += padding;

  if ((ret = r_buffer_new_alloc (NULL, hdrsize + size, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;
    RCryptoCipherResult res;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      ruint8 * ivtmp = r_alloca (ivsize);
      ruint8 * p = info.data;

      /* record hdr */
      r_memcpy (p, buf, hdrsize - 2);
      p += hdrsize - 2;
      *p++ = (size >> 8) & 0xff;
      *p++ = (size     ) & 0xff;

      /* IV */
      r_memcpy (ivtmp, iv, ivsize);
      r_memcpy (p, iv, ivsize);
      p += ivsize;

      /* TLSCompressed data */
      r_memcpy (p, buf + hdrsize, bufsize - hdrsize);
      p += bufsize - hdrsize;

      /* MAC */
      r_memcpy (p, mac, macsize);
      p += macsize;

      /* padding */
      r_memset (p, padding - 1, padding);

      p = info.data + hdrsize + ivsize;
      res = r_crypto_cipher_encrypt (cipher, p, size - ivsize, p, ivtmp, ivsize);

      r_buffer_unmap (ret, &info);
    } else {
      res = R_CRYPTO_CIPHER_INVAL;
    }

    if (res != R_CRYPTO_CIPHER_OK) {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

/* RFC 7366 encrypt-then-MAC: emit record hdr + IV + ENC(fragment||padding),
 * then the MAC over @aad (seq + type + version), the IV+ciphertext length and
 * the IV+ciphertext. @aad is the 11-byte seq+type+version prefix the wrapper
 * assembled (the length is appended here since it depends on the ciphertext). */
static RBuffer *
_r_tls_encrypt_buffer_etm (const ruint8 * buf, rsize bufsize, rsize hdrsize,
    const RCryptoCipher * cipher, const ruint8 * iv, RHmac * hmac,
    const ruint8 * aad)
{
  RBuffer * ret = NULL;
  rsize ivsize = cipher->info->ivsize;
  rsize fragsize = bufsize - hdrsize;
  rsize macsize = r_hmac_size (hmac);
  ruint8 padding = (ruint8)(ivsize - (fragsize % ivsize));
  rsize ctlen = fragsize + padding;
  rsize reclen = ivsize + ctlen + macsize;

  if ((ret = r_buffer_new_alloc (NULL, hdrsize + reclen, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;
    RCryptoCipherResult res;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      ruint8 * ivtmp = r_alloca (ivsize);
      ruint8 * p = info.data;
      ruint8 lenbe[sizeof (ruint16)];

      /* record hdr with the IV+ciphertext+MAC length */
      r_memcpy (p, buf, hdrsize - 2);
      p += hdrsize - 2;
      *p++ = (reclen >> 8) & 0xff;
      *p++ = (reclen     ) & 0xff;

      /* IV (in the clear), then fragment + padding to encrypt */
      r_memcpy (ivtmp, iv, ivsize);
      r_memcpy (p, iv, ivsize);
      r_memcpy (p + ivsize, buf + hdrsize, fragsize);
      r_memset (p + ivsize + fragsize, padding - 1, padding);

      res = r_crypto_cipher_encrypt (cipher, p + ivsize, ctlen, p + ivsize, ivtmp, ivsize);

      if (res == R_CRYPTO_CIPHER_OK) {
        /* MAC over seq + type + version + length + IV + ciphertext */
        lenbe[0] = ((ivsize + ctlen) >> 8) & 0xff;
        lenbe[1] = ((ivsize + ctlen)     ) & 0xff;
        r_hmac_reset (hmac);
        r_hmac_update (hmac, aad, sizeof (ruint64) + sizeof (ruint8) + sizeof (ruint16));
        r_hmac_update (hmac, lenbe, sizeof (lenbe));
        r_hmac_update (hmac, p, ivsize + ctlen);
        if (!r_hmac_get_data (hmac, p + ivsize + ctlen, macsize, &macsize))
          res = R_CRYPTO_CIPHER_INVAL;
      }

      r_buffer_unmap (ret, &info);
    } else {
      res = R_CRYPTO_CIPHER_INVAL;
    }

    if (res != R_CRYPTO_CIPHER_OK) {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

RBuffer *
r_dtls_encrypt_buffer (RBuffer * buf, const RCryptoCipher * cipher,
    const ruint8 * iv, RHmac * hmac, rboolean etm)
{
  RBuffer * ret;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  if (R_UNLIKELY (buf == NULL)) return NULL;
  if (R_UNLIKELY (cipher == NULL)) return NULL;
  if (R_UNLIKELY (hmac == NULL)) return NULL;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    ruint16 hdrsize = R_DTLS_RECORD_HDR_SIZE;

    if (etm && cipher->info->mode == R_CRYPTO_CIPHER_MODE_CBC) {
      ruint8 aad[sizeof (ruint64) + sizeof (ruint8) + sizeof (ruint16)];
      r_memcpy (aad, info.data + 3, sizeof (ruint64)); /* epoch + seqno */
      aad[8] = info.data[0];                           /* type */
      aad[9] = info.data[1]; aad[10] = info.data[2];   /* version */
      ret = _r_tls_encrypt_buffer_etm (info.data, info.size, hdrsize,
          cipher, iv, hmac, aad);
    } else {
      rsize macsize = r_hmac_size (hmac);
      ruint8 * macbuf = r_alloca (macsize);
      ruint16 fraglen = RUINT16_TO_BE ((ruint16)(info.size - R_DTLS_RECORD_HDR_SIZE));

      r_hmac_reset (hmac);
      r_hmac_update (hmac, info.data + 3, sizeof (ruint64)); /* epoch + seqno */
      r_hmac_update (hmac, info.data, 1 + sizeof (ruint16)); /* type + version */
      r_hmac_update (hmac, &fraglen, sizeof (ruint16)); /* length */
      r_hmac_update (hmac, info.data + hdrsize, info.size - hdrsize); /* fragment */

      if (r_hmac_get_data (hmac, macbuf, macsize, &macsize)) {
        ret = _r_tls_encrypt_buffer (info.data, info.size, hdrsize,
            cipher, iv, macbuf, macsize);
      } else {
        ret = NULL;
      }
    }
    r_buffer_unmap (buf, &info);
  } else {
    ret = NULL;
  }

  return ret;
}

RBuffer *
r_tls_encrypt_buffer (RBuffer * buf, ruint64 seqno,
    const RCryptoCipher * cipher, const ruint8 * iv, RHmac * hmac, rboolean etm)
{
  RBuffer * ret;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  if (R_UNLIKELY (buf == NULL)) return NULL;
  if (R_UNLIKELY (cipher == NULL)) return NULL;
  if (R_UNLIKELY (hmac == NULL)) return NULL;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    ruint16 hdrsize = R_TLS_RECORD_HDR_SIZE;

    seqno = RUINT64_TO_BE (seqno);
    if (etm && cipher->info->mode == R_CRYPTO_CIPHER_MODE_CBC) {
      ruint8 aad[sizeof (ruint64) + sizeof (ruint8) + sizeof (ruint16)];
      r_memcpy (aad, &seqno, sizeof (ruint64));        /* seqno */
      aad[8] = info.data[0];                           /* type */
      aad[9] = info.data[1]; aad[10] = info.data[2];   /* version */
      ret = _r_tls_encrypt_buffer_etm (info.data, info.size, hdrsize,
          cipher, iv, hmac, aad);
    } else {
      rsize macsize = r_hmac_size (hmac);
      ruint8 * macbuf = r_alloca (macsize);

      r_hmac_reset (hmac);
      r_hmac_update (hmac, &seqno, sizeof (ruint64)); /* seqno */
      r_hmac_update (hmac, info.data, 5); /* type + version + length */
      r_hmac_update (hmac, info.data + hdrsize, info.size - hdrsize); /* fragment */

      if (r_hmac_get_data (hmac, macbuf, macsize, &macsize)) {
        ret = _r_tls_encrypt_buffer (info.data, info.size, hdrsize,
            cipher, iv, macbuf, macsize);
      } else {
        ret = NULL;
      }
    }
    r_buffer_unmap (buf, &info);
  } else {
    ret = NULL;
  }

  return ret;
}

/* AEAD record builder: emit record hdr || explicit_nonce(8) || ciphertext ||
 * tag. The 12-byte GCM nonce is @salt(4) || @nonce_explicit(8); @aad is the
 * 13-byte seq_num||type||version||plainlen seed. */
static RBuffer *
_r_tls_encrypt_buffer_aead (const ruint8 * buf, rsize bufsize, rsize hdrsize,
    const RCryptoCipher * cipher, const ruint8 * salt,
    const ruint8 * nonce_explicit, const ruint8 * aad)
{
  RBuffer * ret = NULL;
  rsize fraglen = bufsize - hdrsize;
  rsize tagsize = cipher->info->blocksize;   /* 16 for GCM */
  rsize saltsize = cipher->info->ivsize - R_TLS_AEAD_EXPLICIT_NONCE_SIZE; /* 4 */
  rsize reclen = R_TLS_AEAD_EXPLICIT_NONCE_SIZE + fraglen + tagsize;

  /* The nonce buffer is sized for a 12-byte AEAD nonce (salt + 8). */
  if (R_UNLIKELY (cipher->info->ivsize != R_TLS_AEAD_NONCE_SIZE_MAX))
    return NULL;

  if ((ret = r_buffer_new_alloc (NULL, hdrsize + reclen, NULL)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;
    RCryptoCipherResult res;

    if (r_buffer_map (ret, &info, R_MEM_MAP_WRITE)) {
      ruint8 nonce[R_TLS_AEAD_NONCE_SIZE_MAX];
      ruint8 * p = info.data;

      /* record hdr with the AEAD record length */
      r_memcpy (p, buf, hdrsize - 2);
      p += hdrsize - 2;
      *p++ = (reclen >> 8) & 0xff;
      *p++ = (reclen     ) & 0xff;

      /* explicit nonce on the wire, then ciphertext + tag */
      r_memcpy (p, nonce_explicit, R_TLS_AEAD_EXPLICIT_NONCE_SIZE);
      p += R_TLS_AEAD_EXPLICIT_NONCE_SIZE;

      r_memcpy (nonce, salt, saltsize);
      r_memcpy (nonce + saltsize, nonce_explicit, R_TLS_AEAD_EXPLICIT_NONCE_SIZE);

      res = r_crypto_cipher_encrypt_aead (cipher, p, fraglen, buf + hdrsize,
          aad, R_TLS_AEAD_AAD_SIZE, nonce, saltsize + R_TLS_AEAD_EXPLICIT_NONCE_SIZE,
          p + fraglen, tagsize);

      r_buffer_unmap (ret, &info);
    } else {
      res = R_CRYPTO_CIPHER_INVAL;
    }

    if (res != R_CRYPTO_CIPHER_OK) {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

/* Build the 13-byte AEAD additional_data: seq_num(8) || type(1) || version(2)
 * || plainlen(2). @seqnum is the 8-byte big-endian sequence (TLS) or
 * epoch||seqno (DTLS); @rec points at the record header (type, version). */
static void
r_tls_aead_aad (ruint8 aad[R_TLS_AEAD_AAD_SIZE], const ruint8 * seqnum, const ruint8 * rec,
    rsize plainlen)
{
  r_memcpy (aad, seqnum, sizeof (ruint64));
  aad[0x08] = rec[0];                          /* type */
  aad[0x09] = rec[1]; aad[0x0a] = rec[2];      /* version */
  aad[0x0b] = (plainlen >> 8) & 0xff;
  aad[0x0c] = (plainlen     ) & 0xff;
}

RBuffer *
r_tls_encrypt_buffer_aead (RBuffer * buf, ruint64 seqno,
    const RCryptoCipher * cipher, const ruint8 * salt)
{
  RBuffer * ret;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  if (R_UNLIKELY (buf == NULL || cipher == NULL || salt == NULL)) return NULL;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    ruint8 nonce_explicit[R_TLS_AEAD_EXPLICIT_NONCE_SIZE];
    ruint8 aad[R_TLS_AEAD_AAD_SIZE];
    ruint64 seqbe = RUINT64_TO_BE (seqno);

    r_memcpy (nonce_explicit, &seqbe, sizeof (ruint64));
    r_tls_aead_aad (aad, nonce_explicit, info.data,
        info.size - R_TLS_RECORD_HDR_SIZE);
    ret = _r_tls_encrypt_buffer_aead (info.data, info.size, R_TLS_RECORD_HDR_SIZE,
        cipher, salt, nonce_explicit, aad);
    r_buffer_unmap (buf, &info);
  } else {
    ret = NULL;
  }

  return ret;
}

RBuffer *
r_dtls_encrypt_buffer_aead (RBuffer * buf, const RCryptoCipher * cipher,
    const ruint8 * salt)
{
  RBuffer * ret;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  if (R_UNLIKELY (buf == NULL || cipher == NULL || salt == NULL)) return NULL;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    ruint8 aad[R_TLS_AEAD_AAD_SIZE];

    /* DTLS explicit nonce and AAD seq_num are both the record's epoch||seqno
     * (info.data + 3). */
    r_tls_aead_aad (aad, info.data + 3, info.data,
        info.size - R_DTLS_RECORD_HDR_SIZE);
    ret = _r_tls_encrypt_buffer_aead (info.data, info.size, R_DTLS_RECORD_HDR_SIZE,
        cipher, salt, info.data + 3, aad);
    r_buffer_unmap (buf, &info);
  } else {
    ret = NULL;
  }

  return ret;
}

static RTLSError
r_tls_parser_parse_handshake_internal (const RTLSParser * parser,
    RTLSHandshakeType * type, const ruint8 ** body, const ruint8 ** end)
{
  if (R_UNLIKELY (parser->content != R_TLS_CONTENT_TYPE_HANDSHAKE))
    return R_TLS_ERROR_WRONG_TYPE;
  if (R_UNLIKELY (parser->fragment.size < 1))
    return R_TLS_ERROR_CORRUPT_RECORD;
  *type = (RTLSHandshakeType)parser->fragment.data[0];

  *end = parser->fragment.data + parser->fragment.size;
  *body = parser->fragment.data + (8 + 24) / 8;
  if (r_tls_parser_is_dtls (parser))
    *body += (16 + 24 + 24) / 8;

  if (R_UNLIKELY (*body > *end)) return R_TLS_ERROR_CORRUPT_RECORD;
  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_handshake_peek_type (const RTLSParser * parser,
    RTLSHandshakeType * type)
{
  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (type == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (parser->content != R_TLS_CONTENT_TYPE_HANDSHAKE))
    return R_TLS_ERROR_WRONG_TYPE;

  *type = (RTLSHandshakeType)parser->fragment.data[0];
  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_handshake_full (const RTLSParser * parser,
    RTLSHandshakeType * type, ruint32 * length, ruint16 * msgseq,
    ruint32 * fragoff, ruint32 * fraglen)
{
  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (parser->content != R_TLS_CONTENT_TYPE_HANDSHAKE))
    return R_TLS_ERROR_WRONG_TYPE;
  if (R_UNLIKELY (parser->fragment.size < 4)) return R_TLS_ERROR_BUF_TOO_SMALL;

  if (type != NULL)
    *type = (RTLSHandshakeType)parser->fragment.data[0];
  if (length != NULL)
    *length = _r_parse_u24 (&parser->fragment.data[1]);
  if (r_tls_parser_is_dtls (parser)) {
    if (R_UNLIKELY (parser->fragment.size < 12)) return R_TLS_ERROR_BUF_TOO_SMALL;
    if (msgseq != NULL)
      *msgseq = r_load_be16 (&parser->fragment.data[4]);
    if (fragoff != NULL)
      *fragoff = _r_parse_u24 (&parser->fragment.data[6]);
    if (fraglen != NULL)
      *fraglen = _r_parse_u24 (&parser->fragment.data[9]);
  } else {
    if (msgseq != NULL)   *msgseq = 0;
    if (fragoff != NULL)  *fragoff = 0;
    if (fraglen != NULL)  *fraglen = 0;
  }

  return R_TLS_ERROR_OK;
}

rboolean
r_tls_parser_dtls_is_complete_handshake_fragment (const RTLSParser * parser)
{
  ruint32 len, foff, flen;
  if (r_tls_parser_parse_handshake_full (parser, NULL, &len, NULL, &foff, &flen) == R_TLS_ERROR_OK)
    return foff == 0 && len == flen;

  return FALSE;
}

RTLSError
r_tls_parser_parse_hello (const RTLSParser * parser, RTLSHelloMsg * msg)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO &&
        type != R_TLS_HANDSHAKE_TYPE_SERVER_HELLO))
    return R_TLS_ERROR_WRONG_TYPE;

  msg->version = (RTLSVersion)r_load_be16 (ptr);
  ptr += sizeof (ruint16);

  /* Random */
  if (ptr + R_TLS_HELLO_RANDOM_BYTES + 1 > end) return R_TLS_ERROR_CORRUPT_RECORD;
  msg->random = ptr;
  ptr += R_TLS_HELLO_RANDOM_BYTES;
  /* Session ID */
  msg->sidlen = *ptr++;
  if (ptr + msg->sidlen + 2 > end) return R_TLS_ERROR_CORRUPT_RECORD;
  msg->sid = ptr;
  ptr += msg->sidlen;

  if (type == R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
    /* Cookie */
    if (r_tls_parser_is_dtls (parser)) {
      msg->cookielen = *ptr++;
      if (ptr + msg->cookielen + 2 > end) return R_TLS_ERROR_CORRUPT_RECORD;
      msg->cookie = ptr;
      ptr += msg->cookielen;
    } else {
      msg->cookielen = 0;
      msg->cookie = NULL;
    }
    /* Cipher suites */
    msg->cslen = r_load_be16 (ptr);
    if (ptr + msg->cslen + sizeof (ruint16) + sizeof (ruint8) > end)
      return R_TLS_ERROR_CORRUPT_RECORD;
    msg->cs = &ptr[sizeof (ruint16)];
    ptr += msg->cslen + sizeof (ruint16);
    /* Compression methods */
    msg->complen = *ptr++;
    if (ptr + msg->complen > end) return R_TLS_ERROR_CORRUPT_RECORD;
    msg->compression = ptr;
    ptr += msg->complen;
  } else {
    msg->cookielen = 0;
    msg->cookie = NULL;
    if (ptr + sizeof (ruint16) + sizeof (ruint8) > end)
      return R_TLS_ERROR_CORRUPT_RECORD;
    /* Cipher suite */
    msg->cslen = sizeof (ruint16);
    msg->cs = ptr;
    ptr += sizeof (ruint16);
    /* Compression methods */
    msg->complen = 1;
    msg->compression = ptr++;
  }

  /* Extensions */
  if (ptr + sizeof (ruint16) > end) {
    msg->extlen = 0;
    msg->ext = NULL;
  } else {
    msg->extlen = r_load_be16 (ptr);
    ptr += sizeof (ruint16);
    if (ptr + msg->extlen > end) return R_TLS_ERROR_CORRUPT_RECORD;
    msg->ext = ptr;
  }

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_certificate_next (const RTLSParser * parser,
    RTLSCertificate * cert)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  ruint32 totallen;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + (24 / 8)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if ((totallen = _r_parse_u24 (ptr)) > 0) {
    ptr = (cert->start != NULL) ? cert->cert + cert->len : ptr + (24 / 8);
    if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + (24 / 8)) <= RPOINTER_TO_SIZE (end))) {
      cert->start = ptr;
      cert->len = _r_parse_u24 (cert->start);
      cert->cert = cert->start + (24 / 8);

      if (R_UNLIKELY (RPOINTER_TO_SIZE (cert->cert + cert->len) > RPOINTER_TO_SIZE (end)))
        return R_TLS_ERROR_CORRUPT_RECORD;
      else
        return R_TLS_ERROR_OK;
    }
  }

  return R_TLS_ERROR_EOB;
}

RTLSError
r_tls_parser_parse_certificate_request (const RTLSParser * parser,
    RTLSCertReq * req)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  ruint16 len;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint8)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  req->certtypecount = *ptr++;
  req->certtype = ptr;
  ptr += req->certtypecount;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  len = r_load_be16 (ptr);
  req->signschemecount = len / sizeof (ruint16);
  req->signscheme = ptr + sizeof (ruint16);
  ptr += sizeof (ruint16) + len;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  len = r_load_be16 (ptr);
  req->cacount = len / sizeof (ruint16);
  req->ca = ptr + sizeof (ruint16);
  ptr += sizeof (ruint16) + len;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  else
    return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_new_session_ticket (const RTLSParser * parser,
    ruint32 * lifetime, const ruint8 ** ticket, ruint16 * ticketsize)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint32) + sizeof (ruint16)) >
        RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if (lifetime != NULL)
    *lifetime = r_load_be32 (ptr);
  ptr += sizeof (ruint32);
  /* The ticket bytes themselves must fit, not just the length field. */
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16) + r_load_be16 (ptr)) >
        RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  if (ticketsize != NULL)
    *ticketsize = r_load_be16 (ptr);
  if (ticket != NULL)
    *ticket = ptr + sizeof (ruint16);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_certificate_verify (const RTLSParser * parser,
    RTLSSignatureScheme * sigscheme, const ruint8 ** sig, ruint16 * sigsize)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16) + sizeof (ruint16)) >
        RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if (sigscheme != NULL)
    *sigscheme = (RTLSSignatureScheme)r_load_be16 (ptr);
  ptr += sizeof (ruint16);
  /* The declared signature length must fit the record, or a verify would read
   * past the fragment. */
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16) + r_load_be16 (ptr)) >
        RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  if (sigsize != NULL)
    *sigsize = r_load_be16 (ptr);
  if (sig != NULL)
    *sig = ptr + sizeof (ruint16);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_client_key_exchange_rsa (const RTLSParser * parser,
    const ruint8 ** encprems, rsize * size)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;
  rsize s;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE))
    return R_TLS_ERROR_WRONG_TYPE;

  s = RPOINTER_TO_SIZE (end - ptr);
  if ((s & 0b11) == 0b10 && RSIZE_POPCOUNT (s) == 2) {
    ruint16 v16 = r_load_be16 (ptr);
    if (R_UNLIKELY ((rsize)v16 > s))
      return R_TLS_ERROR_CORRUPT_RECORD;

    s = (rsize)v16;
    ptr += sizeof (ruint16);
  }

  if (encprems != NULL)
    *encprems = ptr;
  if (size != NULL)
    *size = s;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_client_key_exchange_ecdhe (const RTLSParser * parser,
    const ruint8 ** point, ruint8 * pointlen)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;
  ruint8 len;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint8)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  len = *ptr++;
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + len) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if (point != NULL)    *point = ptr;
  if (pointlen != NULL) *pointlen = len;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_server_key_exchange_ecdhe (const RTLSParser * parser,
    RTLSEcCurveType * curve_type, RTLSSupportedGroup * named_curve,
    const ruint8 ** point, ruint8 * pointlen,
    RTLSSignatureScheme * sigscheme, const ruint8 ** sig, ruint16 * sigsize,
    const ruint8 ** signed_params, rsize * signed_params_len)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end, * params, * pt, * sg;
  RTLSError ret;
  RTLSEcCurveType ct;
  RTLSSupportedGroup nc;
  RTLSSignatureScheme ss;
  ruint8 plen;
  ruint16 slen;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE))
    return R_TLS_ERROR_WRONG_TYPE;

  params = ptr;
  /* ECParameters: curve_type(1) + named_curve(2); then ECPoint: len(1) + point */
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint8) + sizeof (ruint16) +
          sizeof (ruint8)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  ct = (RTLSEcCurveType)*ptr;
  ptr += sizeof (ruint8);
  nc = (RTLSSupportedGroup)r_load_be16 (ptr);
  ptr += sizeof (ruint16);
  plen = *ptr++;
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + plen) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  pt = ptr;
  ptr += plen;

  /* Signature: scheme(2) + len(2) + sig */
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16) + sizeof (ruint16)) >
        RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  ss = (RTLSSignatureScheme)r_load_be16 (ptr);
  ptr += sizeof (ruint16);
  slen = r_load_be16 (ptr);
  ptr += sizeof (ruint16);
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + slen) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  sg = ptr;

  if (curve_type != NULL)        *curve_type = ct;
  if (named_curve != NULL)       *named_curve = nc;
  if (point != NULL)             *point = pt;
  if (pointlen != NULL)          *pointlen = plen;
  if (sigscheme != NULL)         *sigscheme = ss;
  if (sig != NULL)               *sig = sg;
  if (sigsize != NULL)           *sigsize = slen;
  if (signed_params != NULL)     *signed_params = params;
  if (signed_params_len != NULL) *signed_params_len = RPOINTER_TO_SIZE (pt + plen - params);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_finished (const RTLSParser * parser,
    const ruint8 ** verify_data, rsize * size)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_FINISHED))
    return R_TLS_ERROR_WRONG_TYPE;

  if (verify_data != NULL)
    *verify_data = ptr;
  if (size != NULL)
    *size = RPOINTER_TO_SIZE (end - ptr);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_alert (const RTLSParser * parser,
    RTLSAlertLevel * level, RTLSAlertType * type)
{
  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (type == NULL)) return R_TLS_ERROR_INVAL;

  if (R_UNLIKELY (parser->content != R_TLS_CONTENT_TYPE_ALERT))
    return R_TLS_ERROR_WRONG_TYPE;
  if (R_UNLIKELY (parser->fragment.size != 2))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if (level != NULL)
    *level = parser->fragment.data[0];
  *type = parser->fragment.data[1];
  return R_TLS_ERROR_OK;
}

rboolean
r_tls_hello_msg_has_cipher_suite (const RTLSHelloMsg * msg, RTLSCipherSuite cs)
{
  ruint16 i, count;
  count = r_tls_hello_msg_cipher_suite_count (msg);
  for (i = 0; i < count; i++) {
    if (r_tls_hello_msg_cipher_suite (msg, i) == cs)
      return TRUE;
  }
  return FALSE;
}

RTLSError
r_tls_hello_msg_extension_first (const RTLSHelloMsg * msg, RTLSHelloExt * ext)
{
  if (R_UNLIKELY (msg == NULL || ext == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (msg->extlen < R_TLS_HELLO_EXT_HDR_SIZE)) return R_TLS_ERROR_EOB;

  ext->start = msg->ext;
  ext->type = r_load_be16 (&ext->start[0]);
  ext->len = r_load_be16 (&ext->start[2]);
  ext->data = ext->start + R_TLS_HELLO_EXT_HDR_SIZE;
  /* The extension body must fit within the declared extensions length. */
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ext->data + ext->len) >
        RPOINTER_TO_SIZE (msg->ext + msg->extlen)))
    return R_TLS_ERROR_EOB;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_hello_msg_extension_next (const RTLSHelloMsg * msg, RTLSHelloExt * ext)
{
  if (R_UNLIKELY (msg == NULL || ext == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (ext->start == NULL || ext->data == NULL))
    return r_tls_hello_msg_extension_first (msg, ext);
  if (R_UNLIKELY (ext->data + ext->len + R_TLS_HELLO_EXT_HDR_SIZE > msg->ext + msg->extlen))
    return R_TLS_ERROR_EOB;

  ext->start = ext->data + ext->len;
  ext->type = r_load_be16 (&ext->start[0]);
  ext->len = r_load_be16 (&ext->start[2]);
  ext->data = ext->start + R_TLS_HELLO_EXT_HDR_SIZE;
  /* The extension body must fit within the declared extensions length
   * (mirrors the check in _first; a truncated trailing extension would
   * otherwise leave data+len past the block and over-read it). */
  if (R_UNLIKELY (RPOINTER_TO_SIZE (ext->data + ext->len) >
        RPOINTER_TO_SIZE (msg->ext + msg->extlen)))
    return R_TLS_ERROR_EOB;

  return R_TLS_ERROR_OK;
}

rboolean
r_tls_hello_ext_alpn_contains (const RTLSHelloExt * ext,
    const ruint8 * name, ruint8 len)
{
  const ruint8 * p, * end;
  ruint16 listlen;

  if (R_UNLIKELY (ext == NULL || name == NULL || len == 0))
    return FALSE;
  /* ProtocolNameList: uint16 list_len, then { uint8 name_len, name }*.
   * Keep every step inside the declared extension length. */
  if (ext->len < sizeof (ruint16))
    return FALSE;
  listlen = r_load_be16 (ext->data);
  if ((rsize) listlen + sizeof (ruint16) > ext->len)
    return FALSE;

  p = ext->data + sizeof (ruint16);
  end = p + listlen;
  while (p < end) {
    ruint8 nlen = *p++;
    if (nlen == 0 || p + nlen > end)
      return FALSE;
    if (nlen == len && r_memcmp (p, name, len) == 0)
      return TRUE;
    p += nlen;
  }

  return FALSE;
}

RCryptoCert *
r_tls_certificate_get_cert (const RTLSCertificate * cert)
{
  if (R_UNLIKELY (cert == NULL)) return NULL;
  return r_crypto_x509_cert_new (cert->cert, cert->len);
}

RTLSError
r_tls_write_handshake (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, RTLSHandshakeType type, ruint16 len)
{
  ruint hdrlen;
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 9)) return R_TLS_ERROR_BUF_TOO_SMALL;

  hdrlen = len + R_TLS_HS_HDR_SIZE;
  p = data;
  p[0] = R_TLS_CONTENT_TYPE_HANDSHAKE;
  p[1] = (ver     >> 8) & 0xff;
  p[2] = (ver         ) & 0xff;
  p[3] = (hdrlen  >> 8) & 0xff;
  p[4] = (hdrlen      ) & 0xff;
  p[5] = type;
  p[6] = 0x00;
  p[7] = (len     >> 8) & 0xff;
  p[8] = (len         ) & 0xff;

  if (out != NULL)
    *out = R_TLS_RECORD_HDR_SIZE + R_TLS_HS_HDR_SIZE;

  return R_TLS_ERROR_OK;
}

RTLSError
r_dtls_write_handshake (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, RTLSHandshakeType type, ruint16 len,
    ruint16 epoch, ruint64 seqno, ruint16 msgseq,
    ruint32 foff, ruint32 flen)
{
  ruint hdrlen;
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 25)) return R_TLS_ERROR_BUF_TOO_SMALL;

  hdrlen = len + R_DTLS_HS_HDR_SIZE;
  p = data;
  p[ 0] = R_TLS_CONTENT_TYPE_HANDSHAKE;
  p[ 1] = (ver     >>  8) & 0xff;
  p[ 2] = (ver          ) & 0xff;
  p[ 3] = (epoch   >>  8) & 0xff;
  p[ 4] = (epoch        ) & 0xff;
  p[ 5] = (seqno   >> 40) & 0xff;
  p[ 6] = (seqno   >> 32) & 0xff;
  p[ 7] = (seqno   >> 24) & 0xff;
  p[ 8] = (seqno   >> 16) & 0xff;
  p[ 9] = (seqno   >>  8) & 0xff;
  p[10] = (seqno        ) & 0xff;
  p[11] = (hdrlen  >>  8) & 0xff;
  p[12] = (hdrlen       ) & 0xff;
  p[13] = type;
  p[14] = 0x00;
  p[15] = (len      >> 8) & 0xff;
  p[16] = (len          ) & 0xff;
  p[17] = (msgseq  >>  8) & 0xff;
  p[18] = (msgseq       ) & 0xff;
  p[19] = (foff    >> 16) & 0xff;
  p[20] = (foff    >>  8) & 0xff;
  p[21] = (foff         ) & 0xff;
  p[22] = (flen    >> 16) & 0xff;
  p[23] = (flen    >>  8) & 0xff;
  p[24] = (flen         ) & 0xff;

  if (out != NULL)
    *out = R_DTLS_RECORD_HDR_SIZE + R_DTLS_HS_HDR_SIZE;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_update_handshake_len (rpointer data, rsize size, ruint16 len)
{
  ruint hdrlen;
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 9)) return R_TLS_ERROR_BUF_TOO_SMALL;

  hdrlen = len + R_TLS_HS_HDR_SIZE;
  p = data;
  p[3] = (hdrlen  >> 8) & 0xff;
  p[4] = (hdrlen      ) & 0xff;
  p[7] = (len     >> 8) & 0xff;
  p[8] = (len         ) & 0xff;

  return R_TLS_ERROR_OK;
}

RTLSError
r_dtls_update_handshake_len (rpointer data, rsize size, ruint16 len,
    ruint32 foff, ruint32 flen)
{
  ruint hdrlen;
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 25)) return R_TLS_ERROR_BUF_TOO_SMALL;

  hdrlen = len + R_DTLS_HS_HDR_SIZE;
  p = data;
  p[11] = (hdrlen  >>  8) & 0xff;
  p[12] = (hdrlen       ) & 0xff;
  p[15] = (len      >> 8) & 0xff;
  p[16] = (len          ) & 0xff;
  p[19] = (foff    >> 16) & 0xff;
  p[20] = (foff    >>  8) & 0xff;
  p[21] = (foff         ) & 0xff;
  p[22] = (flen    >> 16) & 0xff;
  p[23] = (flen    >>  8) & 0xff;
  p[24] = (flen         ) & 0xff;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_generate_hello_random (ruint8 random[R_TLS_HELLO_RANDOM_BYTES],
    RPrng * prng)
{
  ruint8 * p;
  ruint32 ts;

  if (R_UNLIKELY (random == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (prng == NULL)) return R_TLS_ERROR_INVAL;

  ts = (ruint32)(r_time_get_unix_time () & RUINT32_MAX);
  p = random;
  *p++ = (ts      >> 24) & 0xff;
  *p++ = (ts      >> 16) & 0xff;
  *p++ = (ts      >>  8) & 0xff;
  *p++ = (ts           ) & 0xff;
  r_prng_fill (prng, p, 28);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_hs_server_hello (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, const ruint8 srvrand[R_TLS_HELLO_RANDOM_BYTES],
    const ruint8 * sid, ruint8 sidsize,
    RTLSCipherSuite cs, RTLSCompressionMethod comp)
{
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < (rsize)(2 + 4 + 28 + 1 + sidsize + 2 + 1)))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;

  *p++ = (ver     >>  8) & 0xff;
  *p++ = (ver          ) & 0xff;
  r_memcpy (p, srvrand, R_TLS_HELLO_RANDOM_BYTES);
  p += R_TLS_HELLO_RANDOM_BYTES;
  *p++ = sidsize;
  r_memcpy (p, sid, sidsize); p += sidsize;
  *p++ = (cs      >>  8) & 0xff;
  *p++ = (cs           ) & 0xff;
  *p++ = (comp         ) & 0xff;

  if (out != NULL)
    *out = (2 + 4 + 28 + 1 + sidsize + 2 + 1);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_hs_client_hello (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, const ruint8 clirand[R_TLS_HELLO_RANDOM_BYTES],
    const ruint8 * sid, ruint8 sidsize, const ruint8 * cookie, ruint8 cookiesize,
    const RTLSCipherSuite * cs, ruint16 ncs, RTLSCompressionMethod comp)
{
  ruint8 * p;
  rboolean dtls = r_tls_version_is_dtls (ver);
  ruint16 i;
  rsize need = 2 + R_TLS_HELLO_RANDOM_BYTES + 1 + sidsize +
      (dtls ? (rsize)(1 + cookiesize) : 0) + 2 + (rsize)ncs * sizeof (ruint16) + 1 + 1;

  if (R_UNLIKELY (data == NULL || cs == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < need)) return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;
  *p++ = (ver >> 8) & 0xff;
  *p++ = (ver     ) & 0xff;
  r_memcpy (p, clirand, R_TLS_HELLO_RANDOM_BYTES); p += R_TLS_HELLO_RANDOM_BYTES;
  *p++ = sidsize;
  if (sidsize > 0) { r_memcpy (p, sid, sidsize); p += sidsize; }
  if (dtls) {
    *p++ = cookiesize;
    if (cookiesize > 0) { r_memcpy (p, cookie, cookiesize); p += cookiesize; }
  }
  r_store_be16 (p, (ruint16)(ncs * sizeof (ruint16))); p += 2;
  for (i = 0; i < ncs; i++) {
    r_store_be16 (p, (ruint16)cs[i]); p += 2;
  }
  *p++ = 1;                  /* one compression method follows */
  *p++ = (comp) & 0xff;

  if (out != NULL)
    *out = need;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_hs_new_session_ticket (rpointer data, rsize size, rsize * out,
    ruint32 lifetime, const ruint8 * ticket, ruint16 tsize)
{
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (size < (rsize)tsize + sizeof (ruint32) + sizeof (ruint16))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;

  *p++ = (lifetime  >> 24) & 0xff;
  *p++ = (lifetime  >> 16) & 0xff;
  *p++ = (lifetime  >>  8) & 0xff;
  *p++ = (lifetime       ) & 0xff;
  *p++ = (tsize     >>  8) & 0xff;
  *p++ = (tsize          ) & 0xff;
  r_memcpy (p, ticket, tsize);

  if (out != NULL)
    *out = sizeof (ruint32) + sizeof (ruint16) + tsize;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_hs_certificate_request (rpointer data, rsize size, rsize * out,
    const ruint8 * certtypes, ruint8 ncerttypes,
    const RTLSSignatureScheme * signschemes, ruint16 nsignschemes,
    const ruint8 * ca, ruint16 casize)
{
  ruint8 * p = data;
  rsize need = sizeof (ruint8) + (rsize)ncerttypes +
      sizeof (ruint16) + (rsize)nsignschemes * sizeof (ruint16) +
      sizeof (ruint16) + (rsize)casize;
  ruint16 i;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < need)) return R_TLS_ERROR_BUF_TOO_SMALL;

  *p++ = ncerttypes;
  if (ncerttypes > 0) { r_memcpy (p, certtypes, ncerttypes); p += ncerttypes; }

  r_store_be16 (p, (ruint16)(nsignschemes * sizeof (ruint16))); p += sizeof (ruint16);
  for (i = 0; i < nsignschemes; i++) {
    r_store_be16 (p, (ruint16)signschemes[i]); p += sizeof (ruint16);
  }

  r_store_be16 (p, casize); p += sizeof (ruint16);
  if (casize > 0) { r_memcpy (p, ca, casize); p += casize; }

  if (out != NULL)
    *out = need;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_hs_certificate_verify (rpointer data, rsize size, rsize * out,
    RTLSSignatureScheme sigscheme, const ruint8 * sig, ruint16 sigsize)
{
  ruint8 * p = data;
  rsize need = sizeof (ruint16) + sizeof (ruint16) + (rsize)sigsize;

  if (R_UNLIKELY (data == NULL || sig == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < need)) return R_TLS_ERROR_BUF_TOO_SMALL;

  r_store_be16 (p, (ruint16)sigscheme); p += sizeof (ruint16);
  r_store_be16 (p, sigsize); p += sizeof (ruint16);
  r_memcpy (p, sig, sigsize);

  if (out != NULL)
    *out = need;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_hs_certificate (rpointer data, rsize size, rsize * out,
    const ruint8 * der, rsize dersize)
{
  ruint8 * p = data;
  rsize entrylen = (der != NULL && dersize > 0) ? (3 + dersize) : 0;
  rsize need = 3 + entrylen;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < need)) return R_TLS_ERROR_BUF_TOO_SMALL;

  /* certificate_list<0..2^24-1> */
  *p++ = (ruint8)((entrylen >> 16) & 0xff);
  *p++ = (ruint8)((entrylen >>  8) & 0xff);
  *p++ = (ruint8)((entrylen      ) & 0xff);
  if (entrylen > 0) {
    *p++ = (ruint8)((dersize >> 16) & 0xff);
    *p++ = (ruint8)((dersize >>  8) & 0xff);
    *p++ = (ruint8)((dersize      ) & 0xff);
    r_memcpy (p, der, dersize);
  }

  if (out != NULL)
    *out = need;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_hs_server_key_exchange_ecdhe (rpointer data, rsize size, rsize * out,
    RTLSEcCurveType curve_type, RTLSSupportedGroup named_curve,
    const ruint8 * point, ruint8 pointlen,
    RTLSSignatureScheme sigscheme, const ruint8 * sig, ruint16 sigsize)
{
  ruint8 * p = data;
  rsize need = sizeof (ruint8) + sizeof (ruint16) + sizeof (ruint8) +
      (rsize)pointlen + sizeof (ruint16) + sizeof (ruint16) + (rsize)sigsize;

  if (R_UNLIKELY (data == NULL || point == NULL || sig == NULL))
    return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < need)) return R_TLS_ERROR_BUF_TOO_SMALL;

  /* ECParameters */
  *p++ = (ruint8)curve_type;
  r_store_be16 (p, (ruint16)named_curve); p += sizeof (ruint16);
  /* ECPoint */
  *p++ = pointlen;
  r_memcpy (p, point, pointlen); p += pointlen;
  /* Signature */
  r_store_be16 (p, (ruint16)sigscheme); p += sizeof (ruint16);
  r_store_be16 (p, sigsize); p += sizeof (ruint16);
  r_memcpy (p, sig, sigsize);

  if (out != NULL)
    *out = need;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_change_cipher (rpointer data, rsize size,
    rsize * out, RTLSVersion ver)
{
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < (rsize)(R_TLS_RECORD_HDR_SIZE + 1)))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;
  p[0x00] = R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
  p[0x01] = (ver     >>  8) & 0xff;
  p[0x02] = (ver          ) & 0xff;
  p[0x03] = 0;
  p[0x04] = 1;
  p[0x05] = 1;

  if (out != NULL)
    *out = R_TLS_RECORD_HDR_SIZE + 1;

  return R_TLS_ERROR_OK;
}

RTLSError
r_dtls_write_change_cipher (rpointer data, rsize size,
    rsize * out, RTLSVersion ver, ruint16 epoch, ruint64 seqno)
{
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < (rsize)(R_DTLS_RECORD_HDR_SIZE + 1)))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;
  p[0x00] = R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC;
  p[0x01] = (ver     >>  8) & 0xff;
  p[0x02] = (ver          ) & 0xff;
  p[0x03] = (epoch   >>  8) & 0xff;
  p[0x04] = (epoch        ) & 0xff;
  p[0x05] = (seqno   >> 40) & 0xff;
  p[0x06] = (seqno   >> 32) & 0xff;
  p[0x07] = (seqno   >> 24) & 0xff;
  p[0x08] = (seqno   >> 16) & 0xff;
  p[0x09] = (seqno   >>  8) & 0xff;
  p[0x0a] = (seqno        ) & 0xff;
  p[0x0b] = 0;
  p[0x0c] = 1;
  p[0x0d] = 1;

  if (out != NULL)
    *out = R_DTLS_RECORD_HDR_SIZE + 1;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_application_data (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, const ruint8 * payload, rsize plen)
{
  ruint8 * p;

  if (R_UNLIKELY (data == NULL || payload == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < (rsize)R_TLS_RECORD_HDR_SIZE + plen))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;
  p[0x00] = R_TLS_CONTENT_TYPE_APPLICATION_DATA;
  p[0x01] = (ver  >>  8) & 0xff;
  p[0x02] = (ver       ) & 0xff;
  p[0x03] = (plen >>  8) & 0xff;
  p[0x04] = (plen      ) & 0xff;
  r_memcpy (p + R_TLS_RECORD_HDR_SIZE, payload, plen);

  if (out != NULL)
    *out = R_TLS_RECORD_HDR_SIZE + plen;

  return R_TLS_ERROR_OK;
}

RTLSError
r_dtls_write_application_data (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, ruint16 epoch, ruint64 seqno,
    const ruint8 * payload, rsize plen)
{
  ruint8 * p;

  if (R_UNLIKELY (data == NULL || payload == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < (rsize)R_DTLS_RECORD_HDR_SIZE + plen))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;
  p[0x00] = R_TLS_CONTENT_TYPE_APPLICATION_DATA;
  p[0x01] = (ver   >>  8) & 0xff;
  p[0x02] = (ver        ) & 0xff;
  p[0x03] = (epoch >>  8) & 0xff;
  p[0x04] = (epoch      ) & 0xff;
  p[0x05] = (seqno >> 40) & 0xff;
  p[0x06] = (seqno >> 32) & 0xff;
  p[0x07] = (seqno >> 24) & 0xff;
  p[0x08] = (seqno >> 16) & 0xff;
  p[0x09] = (seqno >>  8) & 0xff;
  p[0x0a] = (seqno      ) & 0xff;
  p[0x0b] = (plen  >>  8) & 0xff;
  p[0x0c] = (plen       ) & 0xff;
  r_memcpy (p + R_DTLS_RECORD_HDR_SIZE, payload, plen);

  if (out != NULL)
    *out = R_DTLS_RECORD_HDR_SIZE + plen;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_alert (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, RTLSAlertLevel level, RTLSAlertType type)
{
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < (rsize)(R_TLS_RECORD_HDR_SIZE + 2)))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;
  p[0x00] = R_TLS_CONTENT_TYPE_ALERT;
  p[0x01] = (ver     >>  8) & 0xff;
  p[0x02] = (ver          ) & 0xff;
  p[0x03] = 0;
  p[0x04] = 2;
  p[0x05] = (ruint8) level;
  p[0x06] = (ruint8) type;

  if (out != NULL)
    *out = R_TLS_RECORD_HDR_SIZE + 2;

  return R_TLS_ERROR_OK;
}

RTLSError
r_dtls_write_alert (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, ruint16 epoch, ruint64 seqno,
    RTLSAlertLevel level, RTLSAlertType type)
{
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < (rsize)(R_DTLS_RECORD_HDR_SIZE + 2)))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;
  p[0x00] = R_TLS_CONTENT_TYPE_ALERT;
  p[0x01] = (ver     >>  8) & 0xff;
  p[0x02] = (ver          ) & 0xff;
  p[0x03] = (epoch   >>  8) & 0xff;
  p[0x04] = (epoch        ) & 0xff;
  p[0x05] = (seqno   >> 40) & 0xff;
  p[0x06] = (seqno   >> 32) & 0xff;
  p[0x07] = (seqno   >> 24) & 0xff;
  p[0x08] = (seqno   >> 16) & 0xff;
  p[0x09] = (seqno   >>  8) & 0xff;
  p[0x0a] = (seqno        ) & 0xff;
  p[0x0b] = 0;
  p[0x0c] = 2;
  p[0x0d] = (ruint8) level;
  p[0x0e] = (ruint8) type;

  if (out != NULL)
    *out = R_DTLS_RECORD_HDR_SIZE + 2;

  return R_TLS_ERROR_OK;
}

