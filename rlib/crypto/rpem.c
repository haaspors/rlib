/* RLIB - Convenience library for useful things
 * Copyright (C) 2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/crypto/rpem.h>

#include <rlib/crypto/raes.h>
#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rdsa.h>
#include <rlib/crypto/rrsa.h>
#include <rlib/crypto/rx509.h>

#include <rlib/charset/rascii.h>

#include <rlib/rmem.h>
#include <rlib/rmsgdigest.h>
#include <rlib/rstr.h>
#include <rlib/rbase64.h>

#define R_PEM_BEGIN_START     "-----BEGIN "
#define R_PEM_BEGIN_END       "-----"
#define R_PEM_END_START       "-----END "
#define R_PEM_END_END         "-----"

#define R_PEM_CERTIFICATE     "CERTIFICATE"
#define R_PEM_CRL             "X509 CRL"
#define R_PEM_CSR             "CERTIFICATE REQUEST"
#define R_PEM_PUBKEY          "PUBLIC KEY"
#define R_PEM_PRIVKEY         "PRIVATE KEY"
#define R_PEM_DSAPRIVKEY      "DSA PRIVATE KEY"
#define R_PEM_RSAPRIVKEY      "RSA PRIVATE KEY"
#define R_PEM_ENCPRIVKEY      "ENCRYPTED PRIVATE KEY"

#define R_PEM_BEGIN_PUBKEY    R_PEM_BEGIN_START R_PEM_PUBKEY R_PEM_BEGIN_END "\n"
#define R_PEM_END_PUBKEY      R_PEM_END_START   R_PEM_PUBKEY R_PEM_END_END   "\n"
#define R_PEM_BEGIN_CERT      R_PEM_BEGIN_START R_PEM_CERTIFICATE R_PEM_BEGIN_END "\n"
#define R_PEM_END_CERT        R_PEM_END_START   R_PEM_CERTIFICATE R_PEM_END_END   "\n"

struct _RPemParser {
  RRef ref;

  RMemFile * file;
  const rchar * data;
  rsize size;

  rsize offset;
};

typedef enum {
  R_PEM_LEGACY_CIPHER_NONE = 0,
  R_PEM_LEGACY_CIPHER_AES_128_CBC,
  R_PEM_LEGACY_CIPHER_AES_192_CBC,
  R_PEM_LEGACY_CIPHER_AES_256_CBC
} RPemLegacyCipher;

struct _RPemBlock {
  RRef ref;

  RPemParser * parser;
  const rchar * begline, * blob, * base64, * endline, * eob;
  RPemType type;
  rchar * label;

  /* RFC 1421-style legacy headers ("Proc-Type: 4,ENCRYPTED" +
   * "DEK-Info: <cipher>,<hex-iv>") parsed from between the BEGIN line
   * and the base64 blob. */
  RPemLegacyCipher legacy_cipher;
  ruint8 iv[16];
  rsize iv_size;
};


RPemParser *
r_pem_parser_new_from_file (const rchar * filename)
{
  RPemParser * ret;
  RMemFile * file;

  if ((file = r_mem_file_new (filename, R_MEM_PROT_READ, FALSE)) != NULL) {
    ret = r_pem_parser_new_from_memfile (file);
    r_mem_file_unref (file);
  } else {
    ret = NULL;
  }

  return ret;
}

static void
r_pem_parser_free (RPemParser * parser)
{
  if (parser->file != NULL)
    r_mem_file_unref (parser->file);

  r_free (parser);
}

RPemParser *
r_pem_parser_new_from_memfile (RMemFile * file)
{
  RPemParser * ret;

  if (R_UNLIKELY (file == NULL))
    return NULL;

  if ((ret = r_mem_new (RPemParser))) {
    r_ref_init (ret, r_pem_parser_free);
    ret->file = r_mem_file_ref (file);
    ret->data = (const rchar *)r_mem_file_get_mem (file);
    ret->size = r_mem_file_get_size (file);
    ret->offset = 0;
  }

  return ret;
}

RPemParser *
r_pem_parser_new (const rchar * data, rssize size)
{
  RPemParser * ret;

  if (R_UNLIKELY (data == NULL)) return NULL;
  if (size < 0) size = r_strlen (data);
  if (R_UNLIKELY (size < 32)) return NULL;

  if ((ret = r_mem_new (RPemParser))) {
    r_ref_init (ret, r_pem_parser_free);
    ret->file = NULL;
    ret->data = data;
    ret->size = (rsize)size;
    ret->offset = 0;
  }

  return ret;
}

void
r_pem_parser_reset (RPemParser * parser)
{
  parser->offset = 0;
}

static RPemType
r_pem_type_from_label (const rchar * label)
{
  if (r_str_equals (label, R_PEM_CERTIFICATE))
    return R_PEM_TYPE_CERTIFICATE;
  else if (r_str_equals (label, R_PEM_CRL))
    return R_PEM_TYPE_CERTIFICATE_LIST;
  else if (r_str_equals (label, R_PEM_CSR))
    return R_PEM_TYPE_CERTIFICATE_REQUEST;
  else if (r_str_equals (label, R_PEM_PUBKEY))
    return R_PEM_TYPE_PUBLIC_KEY;
  else if (r_str_equals (label, R_PEM_DSAPRIVKEY))
    return R_PEM_TYPE_DSA_PRIVATE_KEY;
  else if (r_str_equals (label, R_PEM_RSAPRIVKEY))
    return R_PEM_TYPE_RSA_PRIVATE_KEY;
  else if (r_str_equals (label, R_PEM_PRIVKEY))
    return R_PEM_TYPE_PRIVATE_KEY;
  else if (r_str_equals (label, R_PEM_ENCPRIVKEY))
    return R_PEM_TYPE_ENCRYPTED_PRIVATE_KEY;

  return R_PEM_TYPE_UNKNOWN;
}

static void
r_pem_block_free (RPemBlock * block)
{
  r_pem_parser_unref (block->parser);
  r_free (block->label);
  r_free (block);
}

static RPemLegacyCipher
r_pem_legacy_cipher_from_str (const rchar * s, rsize size)
{
  if (size == 11 && r_memcmp (s, "AES-128-CBC", 11) == 0)
    return R_PEM_LEGACY_CIPHER_AES_128_CBC;
  if (size == 11 && r_memcmp (s, "AES-192-CBC", 11) == 0)
    return R_PEM_LEGACY_CIPHER_AES_192_CBC;
  if (size == 11 && r_memcmp (s, "AES-256-CBC", 11) == 0)
    return R_PEM_LEGACY_CIPHER_AES_256_CBC;
  return R_PEM_LEGACY_CIPHER_NONE;
}

static rsize
r_pem_legacy_cipher_keysize (RPemLegacyCipher c)
{
  switch (c) {
    case R_PEM_LEGACY_CIPHER_AES_128_CBC: return 16;
    case R_PEM_LEGACY_CIPHER_AES_192_CBC: return 24;
    case R_PEM_LEGACY_CIPHER_AES_256_CBC: return 32;
    default: return 0;
  }
}

/* Parse the optional "Proc-Type: 4,ENCRYPTED" + "DEK-Info: <cipher>,<hex IV>"
 * headers immediately following the BEGIN line.  Advances `*blob` past the
 * headers (including the blank separator line) on success. */
static void
r_pem_parse_legacy_headers (RPemBlock * block, const rchar ** blob,
    const rchar * end)
{
  const rchar * p = *blob, * eol;
  rboolean is_encrypted = FALSE;

  block->legacy_cipher = R_PEM_LEGACY_CIPHER_NONE;
  block->iv_size = 0;

  /* "Proc-Type: 4,ENCRYPTED" */
  if (end - p < 22 || r_memcmp (p, "Proc-Type:", 10) != 0)
    return;
  p += 10;
  while (p < end && (*p == ' ' || *p == '\t')) p++;
  if (end - p < 11 || r_memcmp (p, "4,ENCRYPTED", 11) != 0)
    return;
  p += 11;
  if (p >= end || *p != '\n')
    return;
  p++;
  is_encrypted = TRUE;

  /* "DEK-Info: AES-NNN-CBC,<hex IV>" */
  if (end - p < 10 || r_memcmp (p, "DEK-Info:", 9) != 0)
    return;
  p += 9;
  while (p < end && (*p == ' ' || *p == '\t')) p++;
  if ((eol = r_strnchr (p, '\n', end - p)) == NULL)
    return;
  {
    const rchar * comma;
    RPemLegacyCipher cipher;
    rsize hex_size, raw_size, i;

    if ((comma = r_strnchr (p, ',', eol - p)) == NULL)
      return;
    if ((cipher = r_pem_legacy_cipher_from_str (p, comma - p)) ==
        R_PEM_LEGACY_CIPHER_NONE)
      return;
    hex_size = (rsize) (eol - (comma + 1));
    if ((hex_size & 1) != 0 || hex_size / 2 > sizeof (block->iv))
      return;
    raw_size = hex_size / 2;
    for (i = 0; i < raw_size; i++) {
      rint8 hi = r_ascii_xdigit_value (comma[1 + i * 2]);
      rint8 lo = r_ascii_xdigit_value (comma[1 + i * 2 + 1]);
      if (hi < 0 || lo < 0) return;
      block->iv[i] = (ruint8) ((hi << 4) | lo);
    }
    block->iv_size = raw_size;
    block->legacy_cipher = cipher;
  }
  p = eol + 1;

  /* Blank separator line. */
  if (p >= end || *p != '\n') {
    if (is_encrypted) {
      block->legacy_cipher = R_PEM_LEGACY_CIPHER_NONE;
      block->iv_size = 0;
    }
    return;
  }
  p++;

  *blob = p;
}

RPemBlock *
r_pem_parser_next_block (RPemParser * parser)
{
  RPemBlock * ret = NULL;

  const rchar * data, * beg, * lbl, * begend, * end;
  rsize size;
  rchar * label, * endstr;

  if (parser->offset >= parser->size)
    return NULL;

  data = &parser->data[parser->offset];
  size = parser->size - parser->offset;
  if ((beg = r_str_ptr_of_str (data, size,
          R_PEM_BEGIN_START, sizeof (R_PEM_BEGIN_START) - 1)) == NULL)
    return NULL;
  lbl = beg + sizeof (R_PEM_BEGIN_START) - 1;
  if ((begend = r_str_ptr_of_str (lbl, size - (lbl - data),
          R_PEM_BEGIN_END, sizeof (R_PEM_BEGIN_END) - 1)) == NULL)
    return NULL;

  label = r_strndup (lbl, begend - lbl);
  endstr = r_strprintf (R_PEM_END_START"%s"R_PEM_END_END, label);
  end = r_str_ptr_of_str (begend, size - (begend - data), endstr, -1);
  r_free (endstr);

  if (end != NULL) {
    parser->offset = RPOINTER_TO_SIZE (end - parser->data) +
      sizeof (R_PEM_END_START)-1 + (begend - lbl) + sizeof (R_PEM_END_END)-1;
    if ((ret = r_mem_new (RPemBlock)) != NULL) {
      r_ref_init (ret, r_pem_block_free);
      ret->parser = r_pem_parser_ref (parser);
      ret->label = label;
      ret->type = r_pem_type_from_label (label);
      ret->begline = beg;
      ret->endline = end;
      ret->eob = &parser->data[parser->offset];

      ret->blob = begend + sizeof (R_PEM_BEGIN_END) - 1;
      while (r_ascii_isspace (*ret->blob)) ret->blob++;

      ret->base64 = ret->blob;
      r_pem_parse_legacy_headers (ret, &ret->base64, ret->endline);
    } else {
      r_free (label);
    }

    while (parser->offset < parser->size &&
        r_ascii_isspace (parser->data[parser->offset])) {
      parser->offset++;
    }
  } else {
    parser->offset = parser->size;
    r_free (label);
  }

  return ret;
}

RPemType
r_pem_block_get_type (RPemBlock * block)
{
  return block->type;
}

rboolean
r_pem_block_is_encrypted (RPemBlock * block)
{
  if (R_UNLIKELY (block == NULL)) return FALSE;
  return block->type == R_PEM_TYPE_ENCRYPTED_PRIVATE_KEY ||
      block->legacy_cipher != R_PEM_LEGACY_CIPHER_NONE;
}

rboolean
r_pem_block_is_key (RPemBlock * block)
{
  return block->type >= R_PEM_TYPE_KEY_START
      && block->type <= R_PEM_TYPE_KEY_END;
}

rsize
r_pem_block_get_blob_size (RPemBlock * block)
{
  return block->endline - block->blob;
}

rsize
r_pem_block_get_base64_size (RPemBlock * block)
{
  return block->endline - block->base64;
}

rchar *
r_pem_block_get_base64 (RPemBlock * block, rsize * size)
{
  rsize s = r_pem_block_get_base64_size (block);

  if (size != NULL)
    *size = s;
  return r_strndup (block->base64, s);
}

ruint8 *
r_pem_block_decode_base64 (RPemBlock * block, rsize * size)
{
  rsize s = r_pem_block_get_base64_size (block);
  return r_base64_decode_dup (block->base64, s, size);
}

RAsn1BinDecoder *
r_pem_block_get_asn1_decoder (RPemBlock * block)
{
  RAsn1BinDecoder * ret = NULL;
  ruint8 * data;
  rsize size;

  if ((data = r_pem_block_decode_base64 (block, &size)) != NULL) {
    if ((ret = r_asn1_bin_decoder_new_with_data (R_ASN1_BER, data, size)) == NULL)
      r_free (data);
  }

  return ret;
}

/* OpenSSL's EVP_BytesToKey with count=1 and MD5 -- the KDF used by
 * "Proc-Type/DEK-Info" encrypted PEM keys.  Salt is the first 8 bytes
 * of the IV from the DEK-Info header. */
static rboolean
r_pem_legacy_bytes_to_key (const ruint8 * passphrase, rsize ppsize,
    const ruint8 * salt, ruint8 * key, rsize keysize)
{
  RMsgDigest * md;
  ruint8 d[16];           /* MD5 produces 16 bytes per round */
  rsize off = 0, used;

  if (R_UNLIKELY (passphrase == NULL || salt == NULL || key == NULL))
    return FALSE;

  while (off < keysize) {
    if ((md = r_md5_new ()) == NULL)
      return FALSE;
    if (off > 0 && !r_msg_digest_update (md, d, sizeof (d))) {
      r_msg_digest_free (md);
      return FALSE;
    }
    if (!r_msg_digest_update (md, passphrase, ppsize) ||
        !r_msg_digest_update (md, salt, 8) ||
        !r_msg_digest_get_data (md, d, sizeof (d), NULL)) {
      r_msg_digest_free (md);
      return FALSE;
    }
    r_msg_digest_free (md);
    used = MIN (sizeof (d), keysize - off);
    r_memcpy (key + off, d, used);
    off += used;
  }
  r_memclear (d, sizeof (d));
  return TRUE;
}

static ruint8 *
r_pem_decrypt_legacy (RPemBlock * block, const ruint8 * passphrase, rsize ppsize,
    ruint8 * cipherbuf, rsize cipherbufsize, rsize * out_size)
{
  ruint8 key[32];
  ruint8 iv[16];
  RCryptoCipher * cipher;
  ruint8 pad;
  rsize keysize;

  if (block->legacy_cipher == R_PEM_LEGACY_CIPHER_NONE)
    return NULL;
  if (block->iv_size != 16)            /* AES block size; salt = iv[0..7] */
    return NULL;
  if (cipherbufsize == 0 || (cipherbufsize & 0xf) != 0)
    return NULL;                       /* must be a multiple of 16 */

  keysize = r_pem_legacy_cipher_keysize (block->legacy_cipher);
  if (!r_pem_legacy_bytes_to_key (passphrase, ppsize, block->iv, key, keysize))
    return NULL;

  r_memcpy (iv, block->iv, sizeof (iv));
  cipher = r_cipher_aes_new (R_CRYPTO_CIPHER_MODE_CBC,
      (ruint) keysize * 8, key);
  r_memclear (key, sizeof (key));
  if (cipher == NULL)
    return NULL;

  if (r_crypto_cipher_decrypt (cipher, cipherbuf, cipherbufsize,
        cipherbuf, iv, sizeof (iv)) != R_CRYPTO_CIPHER_OK) {
    r_crypto_cipher_unref (cipher);
    return NULL;
  }
  r_crypto_cipher_unref (cipher);

  /* PKCS#5/PKCS#7 padding: last byte is the pad length (1..16). */
  pad = cipherbuf[cipherbufsize - 1];
  if (pad == 0 || pad > 16 || pad > cipherbufsize)
    return NULL;
  /* Verify all padding bytes equal pad (constant-time isn't critical here:
   * a wrong passphrase yields random plaintext, the ASN.1 parser fails too). */
  {
    rsize i;
    for (i = cipherbufsize - pad; i < cipherbufsize; i++) {
      if (cipherbuf[i] != pad)
        return NULL;
    }
  }
  *out_size = cipherbufsize - pad;
  return cipherbuf;
}

RCryptoKey *
r_pem_block_get_key (RPemBlock * block, const rchar * passphrase, rsize ppsize)
{
  RCryptoKey * ret;
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;

  if (R_UNLIKELY (block == NULL))
    return NULL;
  if (R_UNLIKELY (!r_pem_block_is_key (block)))
    return NULL;

  if (block->legacy_cipher != R_PEM_LEGACY_CIPHER_NONE) {
    ruint8 * decoded;
    rsize decoded_size, plain_size;

    if (passphrase == NULL)
      return NULL;
    if ((decoded = r_pem_block_decode_base64 (block, &decoded_size)) == NULL)
      return NULL;
    if (r_pem_decrypt_legacy (block, (const ruint8 *) passphrase, ppsize,
            decoded, decoded_size, &plain_size) == NULL) {
      r_free (decoded);
      return NULL;
    }
    if ((dec = r_asn1_bin_decoder_new_with_data (R_ASN1_BER, decoded,
            plain_size)) == NULL) {
      r_free (decoded);
      return NULL;
    }
  } else if ((dec = r_pem_block_get_asn1_decoder (block)) == NULL) {
    return NULL;
  }

  if (r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK) {
    r_asn1_bin_decoder_unref (dec);
    return NULL;
  }
  switch (r_pem_block_get_type (block)) {
    case R_PEM_TYPE_PUBLIC_KEY:
      ret = r_crypto_key_from_asn1_public_key (dec, &tlv);
      break;
    case R_PEM_TYPE_RSA_PRIVATE_KEY:
      ret = r_rsa_priv_key_new_from_asn1 (dec, &tlv);
      break;
    case R_PEM_TYPE_DSA_PRIVATE_KEY:
      ret = r_dsa_priv_key_new_from_asn1 (dec, &tlv);
      break;
    case R_PEM_TYPE_PRIVATE_KEY:
      ret = r_crypto_key_from_asn1_private_key (dec, &tlv);
      break;
    /* TODO: PKCS#8 EncryptedPrivateKeyInfo */
    default:
      ret = NULL;
  }
  r_asn1_bin_decoder_unref (dec);

  return ret;
}

RCryptoCert *
r_pem_block_get_cert (RPemBlock * block)
{
  RCryptoCert * ret;
  ruint8 * data;
  rsize size;

  if (R_UNLIKELY (block == NULL)) return NULL;
  if (R_UNLIKELY (r_pem_block_get_type (block) != R_PEM_TYPE_CERTIFICATE))
    return NULL;

  if ((data = r_pem_block_decode_base64 (block, &size)) != NULL) {
    if ((ret = r_crypto_x509_cert_new_take (data, size)) == NULL)
      r_free (data);
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_pem_write_public_key_dup (const RCryptoKey * key, rsize linesize, rsize * out)
{
  rchar * ret;
  rsize asn1_size, b64_size, size;

  if (R_UNLIKELY (key == NULL)) return NULL;

  /* Upper bound on the SubjectPublicKeyInfo size: covers RSA (modulus +
   * exponent), DSA (p, q, g, y), and EC (uncompressed point) with room
   * for AlgorithmIdentifier, OIDs, and DER overhead. */
  asn1_size = (rsize) (r_crypto_key_get_bitsize (key) / 8) * 4 + 512;
  b64_size = ((asn1_size + 2) / 3) * 4;
  if (linesize > 0)
    b64_size += b64_size / ((linesize + 3) & ~(rsize)3) + 1;
  size = sizeof (R_PEM_BEGIN_PUBKEY) - 1 + b64_size + 1 + sizeof (R_PEM_END_PUBKEY);

  if ((ret = r_malloc (size)) != NULL) {
    if (R_UNLIKELY (!r_pem_write_public_key (key, ret, size, linesize, out))) {
      r_free (ret);
      ret = NULL;
    }
  }

  return ret;
}

rboolean
r_pem_write_public_key (const RCryptoKey * key,
    rpointer data, rsize size, rsize linesize, rsize * out)
{
  rchar * p;
  RAsn1BinEncoder * enc;
  rboolean ret = FALSE;

  if (R_UNLIKELY (key == NULL)) return FALSE;
  if (R_UNLIKELY (data == NULL)) return FALSE;

  if (R_UNLIKELY ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)) == NULL))
    return FALSE;

  p = data;

  if (r_crypto_key_to_asn1 (key, enc) == R_CRYPTO_OK) {
    ruint8 * asn1buf;
    rsize asn1bufsize;

    /* FIXME: Use RBuffer instead!!! */
    if ((asn1buf = r_asn1_bin_encoder_get_data (enc, &asn1bufsize)) != NULL) {
      rchar * b64;
      rsize b64size;

      if ((b64 = r_base64_encode_dup_full (asn1buf, asn1bufsize, linesize, &b64size)) != NULL) {
        /* Reserve room for: BEGIN + b64 + optional newline + END +
         * trailing NUL. The END copy uses sizeof (not sizeof - 1)
         * so callers can treat the output as a C string. */
        if (size >= sizeof (R_PEM_BEGIN_PUBKEY) - 1 + b64size + 1 + sizeof (R_PEM_END_PUBKEY)) {
          p = r_stpncpy (p, R_PEM_BEGIN_PUBKEY, sizeof (R_PEM_BEGIN_PUBKEY) - 1);
          p = r_stpncpy (p, b64, b64size);
          if (p[-1] != '\n')
            *p++ = '\n';
          p = r_stpncpy (p, R_PEM_END_PUBKEY, sizeof (R_PEM_END_PUBKEY));

          ret = TRUE;
          if (out)
            *out = RPOINTER_TO_SIZE (p) - RPOINTER_TO_SIZE (data);
        }

        r_free (b64);
      }

      r_free (asn1buf);
    }
  }

  r_asn1_bin_encoder_unref (enc);

  return ret;
}

rchar *
r_pem_write_cert_dup (const RCryptoCert * cert, rsize linesize, rsize * out)
{
  RBuffer * buf;
  rchar * ret = NULL;

  if (R_UNLIKELY (cert == NULL)) return NULL;

  if ((buf = r_crypto_cert_get_data_buffer ((RCryptoCert *) cert)) != NULL) {
    rsize bin_size = r_buffer_get_size (buf);
    rsize b64_size = ((bin_size + 2) / 3) * 4;
    rsize size;

    if (linesize > 0)
      b64_size += b64_size / ((linesize + 3) & ~(rsize)3) + 1;
    size = sizeof (R_PEM_BEGIN_CERT) - 1 + b64_size + 1 + sizeof (R_PEM_END_CERT);

    if ((ret = r_malloc (size)) != NULL) {
      if (R_UNLIKELY (!r_pem_write_cert (cert, ret, size, linesize, out))) {
        r_free (ret);
        ret = NULL;
      }
    }
    r_buffer_unref (buf);
  }

  return ret;
}

rboolean
r_pem_write_cert (const RCryptoCert * cert, rpointer data, rsize size,
    rsize linesize, rsize * out)
{
  RBuffer * buf;
  rboolean ret = FALSE;

  if ((buf = r_crypto_cert_get_data_buffer (cert)) != NULL) {
    RMemMapInfo info = R_MEM_MAP_INFO_INIT;

    if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
      rchar * b64;
      rsize b64size;

      if ((b64 = r_base64_encode_dup_full (info.data, info.size, linesize, &b64size)) != NULL) {
        if (size >= sizeof (R_PEM_BEGIN_CERT) - 1 + b64size + 1 + sizeof (R_PEM_END_CERT)) {
          rchar * p = data;

          p = r_stpncpy (p, R_PEM_BEGIN_CERT, sizeof (R_PEM_BEGIN_CERT) - 1);
          p = r_stpncpy (p, b64, b64size);
          if (p[-1] != '\n')
            *p++ = '\n';
          p = r_stpncpy (p, R_PEM_END_CERT, sizeof (R_PEM_END_CERT));

          ret = TRUE;
          if (out)
            *out = RPOINTER_TO_SIZE (p) - RPOINTER_TO_SIZE (data);
        }

        r_free (b64);
      }
      r_buffer_unmap (buf, &info);
    }
    r_buffer_unref (buf);
  }

  return ret;
}

RCryptoKey *
r_pem_parse_key_from_data (const rchar * data, rssize size,
    const rchar * passphrase, rsize ppsize)
{
  RPemParser * parser;
  RCryptoKey * ret = NULL;

  if ((parser = r_pem_parser_new (data, size)) != NULL) {
    RPemBlock * block;
    if ((block = r_pem_parser_next_block (parser)) != NULL) {
      ret = r_pem_block_get_key (block, passphrase, ppsize);
      r_pem_block_unref (block);
    }
    r_pem_parser_unref (parser);
  }

  return ret;
}

RCryptoCert *
r_pem_parse_cert_from_data (const rchar * data, rssize size)
{
  RPemParser * parser;
  RCryptoCert * ret = NULL;

  if ((parser = r_pem_parser_new (data, size)) != NULL) {
    RPemBlock * block;
    if ((block = r_pem_parser_next_block (parser)) != NULL) {
      ret = r_pem_block_get_cert (block);
      r_pem_block_unref (block);
    }
    r_pem_parser_unref (parser);
  }

  return ret;
}

