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
#include <rlib/crypto/rrsa.h>
#include <rlib/crypto/rdsa.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>
#include <rlib/rascii.h>
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

struct _RPemParser {
  RRef ref;

  RMemFile * file;
  const rchar * data;
  rsize size;

  rsize offset;
};

struct _RPemBlock {
  RRef ref;

  RPemParser * parser;
  const rchar * begline, * blob, * base64, * endline, * eob;
  RPemType type;
  rchar * label;
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

      /* FIXME: Check if non standard encryption params is used!!! */
      ret->base64 = ret->blob;
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
  /* FIXME: Check if non standard encryption params is used!!! */
  return block->type == R_PEM_TYPE_ENCRYPTED_PRIVATE_KEY;
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
  return r_base64_decode (block->base64, s, size);
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

  /* TODO: If encrypted key, use passphrase */
  (void) passphrase;
  (void) ppsize;

  if ((dec = r_pem_block_get_asn1_decoder (block)) != NULL &&
      r_asn1_bin_decoder_next (dec, &tlv) == R_ASN1_DECODER_OK) {
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
      /* TODO: ecnrypted PRIVATE keys */
      default:
        ret = NULL;
    }
    r_asn1_bin_decoder_unref (dec);
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_pem_write_public_key_dup (const RCryptoKey * key, rsize linesize, rsize * out)
{
  rchar * ret;
  rsize size;

  if (R_UNLIKELY (key == NULL)) return NULL;

  size = 4096; /* FIXME: Calculate max size! */

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

      if ((b64 = r_base64_encode_full (asn1buf, asn1bufsize, linesize, &b64size)) != NULL) {
        if (size >= sizeof (R_PEM_BEGIN_PUBKEY) - 1 + b64size + sizeof (R_PEM_END_PUBKEY) - 1) {
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

