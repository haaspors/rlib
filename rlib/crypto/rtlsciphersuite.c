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
#include <rlib/crypto/rcrypto-private.h>

#include <rlib/crypto/rtlsciphersuite.h>

#include <rlib/rstr.h>

/* This list should be sorted on preference! */
static const RTLSCipherSuiteInfo g__r_cipher_suites[] = {
  { R_TLS_CS_RSA_WITH_AES_128_CBC_SHA, "TLS-RSA-WITH-AES-128-CBC-SHA",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_cipher_aes_128_cbc, R_HASH_TYPE_SHA1 },
  { R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256, "TLS-RSA-WITH-AES-128-CBC-SHA256",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_cipher_aes_128_cbc, R_HASH_TYPE_SHA256 },

  { R_TLS_CS_RSA_WITH_NULL_SHA, "TLS-RSA-WITH-NULL-SHA",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_null_cipher, R_HASH_TYPE_SHA1 },
  { R_TLS_CS_RSA_WITH_NULL_SHA256, "TLS-RSA-WITH-NULL-SHA256",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_null_cipher, R_HASH_TYPE_SHA256 },
  { R_TLS_CS_RSA_WITH_NULL_MD5, "TLS-RSA-WITH-NULL-MD5",
    R_KEY_EXCHANGE_RSA, &g__r_crypto_null_cipher, R_HASH_TYPE_MD5 },

  /* Should be the last in our list */
  { R_TLS_CS_NULL_WITH_NULL_NULL, "TLS-NULL-WITH-NULL-NULL",
    R_KEY_EXCHANGE_NULL, &g__r_crypto_null_cipher, R_HASH_TYPE_NONE },
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

