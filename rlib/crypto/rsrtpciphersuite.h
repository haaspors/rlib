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
#ifndef __R_CRYPTO_SRTP_CIPHER_SUITE_H__
#define __R_CRYPTO_SRTP_CIPHER_SUITE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/crypto/rcipher.h>
#include <rlib/rhash.h>

R_BEGIN_DECLS

/* https://www.iana.org/assignments/sdp-security-descriptions/sdp-security-descriptions.xhtml#sdp-security-descriptions-3 */
/* https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml#srtp-protection-1 */
typedef enum {
  R_SRTP_CS_NONE                                      = -1,
  R_SRTP_CS_NULL_NULL                                 = 0x0000,
  R_SRTP_CS_AES_128_CM_HMAC_SHA1_80                   = 0x0001, /* [RFC4568], [RFC5764] */
  R_SRTP_CS_AES_128_CM_HMAC_SHA1_32                   = 0x0002, /* [RFC4568], [RFC5764] */
  R_SRTP_CS_F8_128_HMAC_SHA1_80                       = 0x0003, /* [RFC4568] */

  R_SRTP_CS_NULL_HMAC_SHA1_80                         = 0x0005, /* [RFC5764] */
  R_SRTP_CS_NULL_HMAC_SHA1_32                         = 0x0006, /* [RFC5764] */
  R_SRTP_CS_AEAD_AES_128_GCM                          = 0x0007, /* [RFC7714] */
  R_SRTP_CS_AEAD_AES_256_GCM                          = 0x0008, /* [RFC7714] */

  R_SRTP_CS_SEED_CTR_128_HMAC_SHA1_80                 = 0x0011, /* [RFC5669] */
  R_SRTP_CS_SEED_128_CCM_80                           = 0x0012, /* [RFC5669] */
  R_SRTP_CS_SEED_128_GCM_96                           = 0x0013, /* [RFC5669] */
  R_SRTP_CS_AES_192_CM_HMAC_SHA1_80                   = 0x0021, /* [RFC6188] */
  R_SRTP_CS_AES_192_CM_HMAC_SHA1_32                   = 0x0022, /* [RFC6188] */
  R_SRTP_CS_AES_256_CM_HMAC_SHA1_80                   = 0x0023, /* [RFC6188] */
  R_SRTP_CS_AES_256_CM_HMAC_SHA1_32                   = 0x0024, /* [RFC6188] */
} RSRTPCipherSuite;

typedef struct {
  RSRTPCipherSuite suite;
  const rchar * str;

  const RCryptoCipherInfo * cipher;
  rsize saltbits;

  RHashType auth;
  rsize authprefixlen;
  rsize srtp_tagbits;
  rsize srtcp_tagbits;

  const RCryptoCipherInfo * kdprf;
} RSRTPCipherSuiteInfo;

R_API rboolean r_srtp_cipher_suite_is_supported (RSRTPCipherSuite suite);
R_API RSRTPCipherSuite r_srtp_cipher_suite_filter (
    const RSRTPCipherSuite * incoming, ruint ilen,
    const RSRTPCipherSuite * preferred, ruint plen);
R_API const RSRTPCipherSuiteInfo * r_srtp_cipher_suite_get_info (RSRTPCipherSuite suite);
R_API const RSRTPCipherSuiteInfo * r_srtp_cipher_suite_get_info_from_str (const rchar * str);

R_END_DECLS

#endif /* __R_CRYPTO_SRTP_CIPHER_SUITE_H__ */

