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
#include "rcrypto-private.h"

#include <rlib/crypto/rtlsciphersuite.h>

#include <rlib/rstr.h>

/* This list should be sorted on preference! */
static const RTLSCipherSuiteInfo g__r_cipher_suites[] = {
  /* AEAD (AES-GCM) first: no padding/MAC-oracle surface, preferred over CBC.
   * ECDSA ahead of RSA within each tier; the server selects per its cert. */
  { R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
    R_KEY_EXCHANGE_ECDHE_ECDSA, &g__r_crypto_cipher_aes_128_gcm, R_MSG_DIGEST_TYPE_NONE, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",
    R_KEY_EXCHANGE_ECDHE_ECDSA, &g__r_crypto_cipher_aes_256_gcm, R_MSG_DIGEST_TYPE_NONE, R_MSG_DIGEST_TYPE_SHA384 },
  { R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
    R_KEY_EXCHANGE_ECDHE_RSA, &g__r_crypto_cipher_aes_128_gcm, R_MSG_DIGEST_TYPE_NONE, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
    R_KEY_EXCHANGE_ECDHE_RSA, &g__r_crypto_cipher_aes_256_gcm, R_MSG_DIGEST_TYPE_NONE, R_MSG_DIGEST_TYPE_SHA384 },
  { R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256, "TLS-RSA-WITH-AES-128-GCM-SHA256",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_cipher_aes_128_gcm, R_MSG_DIGEST_TYPE_NONE, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384, "TLS-RSA-WITH-AES-256-GCM-SHA384",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_cipher_aes_256_gcm, R_MSG_DIGEST_TYPE_NONE, R_MSG_DIGEST_TYPE_SHA384 },

  { R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",
    R_KEY_EXCHANGE_ECDHE_ECDSA, &g__r_crypto_cipher_aes_128_cbc, R_MSG_DIGEST_TYPE_SHA256, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA",
    R_KEY_EXCHANGE_ECDHE_ECDSA, &g__r_crypto_cipher_aes_128_cbc, R_MSG_DIGEST_TYPE_SHA1, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA",
    R_KEY_EXCHANGE_ECDHE_ECDSA, &g__r_crypto_cipher_aes_256_cbc, R_MSG_DIGEST_TYPE_SHA1, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256",
    R_KEY_EXCHANGE_ECDHE_RSA, &g__r_crypto_cipher_aes_128_cbc, R_MSG_DIGEST_TYPE_SHA256, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA",
    R_KEY_EXCHANGE_ECDHE_RSA, &g__r_crypto_cipher_aes_128_cbc, R_MSG_DIGEST_TYPE_SHA1, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA",
    R_KEY_EXCHANGE_ECDHE_RSA, &g__r_crypto_cipher_aes_256_cbc, R_MSG_DIGEST_TYPE_SHA1, R_MSG_DIGEST_TYPE_SHA256 },

  { R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256, "TLS-RSA-WITH-AES-128-CBC-SHA256",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_cipher_aes_128_cbc, R_MSG_DIGEST_TYPE_SHA256, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_RSA_WITH_AES_256_CBC_SHA256, "TLS-RSA-WITH-AES-256-CBC-SHA256",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_cipher_aes_256_cbc, R_MSG_DIGEST_TYPE_SHA256, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_RSA_WITH_AES_128_CBC_SHA, "TLS-RSA-WITH-AES-128-CBC-SHA",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_cipher_aes_128_cbc, R_MSG_DIGEST_TYPE_SHA1, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_RSA_WITH_AES_256_CBC_SHA, "TLS-RSA-WITH-AES-256-CBC-SHA",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_cipher_aes_256_cbc, R_MSG_DIGEST_TYPE_SHA1, R_MSG_DIGEST_TYPE_SHA256 },

  { R_TLS_CS_RSA_WITH_NULL_SHA, "TLS-RSA-WITH-NULL-SHA",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_null_cipher, R_MSG_DIGEST_TYPE_SHA1, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_RSA_WITH_NULL_SHA256, "TLS-RSA-WITH-NULL-SHA256",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_null_cipher, R_MSG_DIGEST_TYPE_SHA256, R_MSG_DIGEST_TYPE_SHA256 },
  { R_TLS_CS_RSA_WITH_NULL_MD5, "TLS-RSA-WITH-NULL-MD5",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_null_cipher, R_MSG_DIGEST_TYPE_MD5, R_MSG_DIGEST_TYPE_SHA256 },

  /* Should be the last in our list */
  { R_TLS_CS_NULL_WITH_NULL_NULL, "TLS-NULL-WITH-NULL-NULL",
    R_KEY_EXCHANGE_NULL, &g__r_crypto_null_cipher, R_MSG_DIGEST_TYPE_NONE, R_MSG_DIGEST_TYPE_SHA256 },
};

rboolean
r_tls_cipher_suite_is_supported (RTLSCipherSuite suite)
{
  return r_tls_cipher_suite_get_info (suite) != NULL;
}

RTLSCipherSuite
r_tls_cipher_suite_filter (const RTLSCipherSuite * incoming, ruint ilen,
    const RTLSCipherSuite * preferred, ruint plen)
{
  RTLSCipherSuite ret = R_TLS_CS_NONE;
  ruint i, p;

  for (p = plen; p > 0;) {
    if (!r_tls_cipher_suite_is_supported (preferred[--p]))
      continue;
    for (i = 0; i < ilen; i++) {
      if (incoming[i] == preferred[p]) {
        ret = incoming[i];
        break;
      }
    }
  }

  return ret;
}

const RTLSCipherSuiteInfo *
r_tls_cipher_suite_get_info (RTLSCipherSuite suite)
{
  rsize i;

  for (i = 0; i < R_N_ELEMENTS (g__r_cipher_suites); i++) {
    if (g__r_cipher_suites[i].suite == suite)
      return &g__r_cipher_suites[i];
  }

  return NULL;
}

const RTLSCipherSuiteInfo *
r_tls_cipher_suite_get_info_from_str (const rchar * str)
{
  rsize i;

  for (i = 0; i < R_N_ELEMENTS (g__r_cipher_suites); i++) {
    if (r_str_equals (g__r_cipher_suites[i].str, str))
      return &g__r_cipher_suites[i];
  }

  return NULL;
}

