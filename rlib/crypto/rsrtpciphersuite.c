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

#include <rlib/crypto/rsrtpciphersuite.h>

#include <rlib/rstr.h>

/* This list should be sorted on preference! */
static const RSRTPCipherSuiteInfo g__r_srtp_cipher_suites[] = {
  { R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, "SRTP-AES-128-CM-HMAC-SHA1-80",
    &g__r_crypto_cipher_aes_128_ctr, 112, R_MSG_DIGEST_TYPE_SHA1, 0, 80, 80,
    &g__r_crypto_cipher_aes_128_ctr },
  { R_SRTP_CS_AES_128_CM_HMAC_SHA1_32, "SRTP-AES-128-CM-HMAC-SHA1-32",
    &g__r_crypto_cipher_aes_128_ctr, 112, R_MSG_DIGEST_TYPE_SHA1, 0, 32, 80,
    &g__r_crypto_cipher_aes_128_ctr },

  { R_SRTP_CS_NULL_HMAC_SHA1_80, "SRTP-NULL-HMAC-SHA1-80",
    &g__r_crypto_null_cipher, 0, R_MSG_DIGEST_TYPE_SHA1, 0, 80, 80,
    &g__r_crypto_cipher_aes_128_ctr },
  { R_SRTP_CS_NULL_HMAC_SHA1_32, "SRTP-NULL-HMAC-SHA1-32",
    &g__r_crypto_null_cipher, 0, R_MSG_DIGEST_TYPE_SHA1, 0, 32, 80,
    &g__r_crypto_cipher_aes_128_ctr },

  /* Should be the last in our list */
  { R_SRTP_CS_NULL_NULL, "SRTP-NULL-NULL",
    &g__r_crypto_null_cipher, 0, R_MSG_DIGEST_TYPE_NONE, 0, 0, 0,
    &g__r_crypto_cipher_aes_128_ctr /* ?? */ },
};

rboolean
r_srtp_cipher_suite_is_supported (RSRTPCipherSuite suite)
{
  return r_srtp_cipher_suite_get_info (suite) != NULL;
}

RSRTPCipherSuite
r_srtp_cipher_suite_filter (const RSRTPCipherSuite * incoming, ruint ilen,
    const RSRTPCipherSuite * preferred, ruint plen)
{
  RSRTPCipherSuite ret = R_SRTP_CS_NONE;
  ruint i, p;

  for (p = plen; p > 0;) {
    if (!r_srtp_cipher_suite_is_supported (preferred[--p]))
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

const RSRTPCipherSuiteInfo *
r_srtp_cipher_suite_get_info (RSRTPCipherSuite suite)
{
  rsize i;

  for (i = 0; i < R_N_ELEMENTS (g__r_srtp_cipher_suites); i++) {
    if (g__r_srtp_cipher_suites[i].suite == suite)
      return &g__r_srtp_cipher_suites[i];
  }

  return NULL;
}

const RSRTPCipherSuiteInfo *
r_srtp_cipher_suite_get_info_from_str (const rchar * str)
{
  rsize i;

  for (i = 0; i < R_N_ELEMENTS (g__r_srtp_cipher_suites); i++) {
    if (r_str_equals (g__r_srtp_cipher_suites[i].str, str))
      return &g__r_srtp_cipher_suites[i];
  }

  return NULL;
}

