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
#ifndef __R_CRYPTO_CIPHER_SUITE_H__
#define __R_CRYPTO_CIPHER_SUITE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/crypto/rcipher.h>
#include <rlib/rhash.h>

R_BEGIN_DECLS

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-4 */
typedef enum {
  R_TLS_CS_NONE                                           = -1,
  R_TLS_CS_NULL_WITH_NULL_NULL                            = 0x0000, /* TLS & DTLS [RFC5247] */
  R_TLS_CS_RSA_WITH_NULL_MD5                              = 0x0001, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_RSA_WITH_NULL_SHA                              = 0x0002, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_RSA_EXPORT_WITH_RC4_40_MD5                     = 0x0003, /* TLS only [RFC4346][RFC6347] */
  R_TLS_CS_RSA_WITH_RC4_128_MD5                           = 0x0004, /* TLS only [RFC5246][RFC6347] */
  R_TLS_CS_RSA_WITH_RC4_128_SHA                           = 0x0005, /* TLS only [RFC5246][RFC6347] */
  R_TLS_CS_RSA_EXPORT_WITH_RC2_CBC_40_MD5                 = 0x0006, /* TLS & DTLS [RFC4346] */
  R_TLS_CS_RSA_WITH_IDEA_CBC_SHA                          = 0x0007, /* TLS & DTLS [RFC5469] */
  R_TLS_CS_RSA_EXPORT_WITH_DES40_CBC_SHA                  = 0x0008, /* TLS & DTLS [RFC4346] */
  R_TLS_CS_RSA_WITH_DES_CBC_SHA                           = 0x0009, /* TLS & DTLS [RFC5469] */
  R_TLS_CS_RSA_WITH_3DES_EDE_CBC_SHA                      = 0x000a, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA               = 0x000b, /* TLS & DTLS [RFC4346] */
  R_TLS_CS_DH_DSS_WITH_DES_CBC_SHA                        = 0x000c, /* TLS & DTLS [RFC5469] */
  R_TLS_CS_DH_DSS_WITH_3DES_EDE_CBC_SHA                   = 0x000d, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA               = 0x000e, /* TLS & DTLS [RFC4346] */
  R_TLS_CS_DH_RSA_WITH_DES_CBC_SHA                        = 0x000f, /* TLS & DTLS [RFC5469] */
  R_TLS_CS_DH_RSA_WITH_3DES_EDE_CBC_SHA                   = 0x0010, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA              = 0x0011, /* TLS & DTLS [RFC4346] */
  R_TLS_CS_DHE_DSS_WITH_DES_CBC_SHA                       = 0x0012, /* TLS & DTLS [RFC5469] */
  R_TLS_CS_DHE_DSS_WITH_3DES_EDE_CBC_SHA                  = 0x0013, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA              = 0x0014, /* TLS & DTLS [RFC4346] */
  R_TLS_CS_DHE_RSA_WITH_DES_CBC_SHA                       = 0x0015, /* TLS & DTLS [RFC5469] */
  R_TLS_CS_DHE_RSA_WITH_3DES_EDE_CBC_SHA                  = 0x0016, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_anon_EXPORT_WITH_RC4_40_MD5                 = 0x0017, /* TLS only [RFC4346][RFC6347] */
  R_TLS_CS_DH_anon_WITH_RC4_128_MD5                       = 0x0018, /* TLS only [RFC5246][RFC6347] */
  R_TLS_CS_DH_anon_EXPORT_WITH_DES40_CBC_SHA              = 0x0019, /* TLS & DTLS [RFC4346] */
  R_TLS_CS_DH_anon_WITH_DES_CBC_SHA                       = 0x001a, /* TLS & DTLS [RFC5469] */
  R_TLS_CS_DH_anon_WITH_3DES_EDE_CBC_SHA                  = 0x001b, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_KRB5_WITH_DES_CBC_SHA                          = 0x001e, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_WITH_3DES_EDE_CBC_SHA                     = 0x001f, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_WITH_RC4_128_SHA                          = 0x0020, /* TLS only [RFC2712][RFC6347] */
  R_TLS_CS_KRB5_WITH_IDEA_CBC_SHA                         = 0x0021, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_WITH_DES_CBC_MD5                          = 0x0022, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_WITH_3DES_EDE_CBC_MD5                     = 0x0023, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_WITH_RC4_128_MD5                          = 0x0024, /* TLS only [RFC2712][RFC6347] */
  R_TLS_CS_KRB5_WITH_IDEA_CBC_MD5                         = 0x0025, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_EXPORT_WITH_DES_CBC_40_SHA                = 0x0026, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA                = 0x0027, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_EXPORT_WITH_RC4_40_SHA                    = 0x0028, /* TLS only [RFC2712][RFC6347] */
  R_TLS_CS_KRB5_EXPORT_WITH_DES_CBC_40_MD5                = 0x0029, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5                = 0x002a, /* TLS & DTLS [RFC2712] */
  R_TLS_CS_KRB5_EXPORT_WITH_RC4_40_MD5                    = 0x002b, /* TLS only [RFC2712][RFC6347] */
  R_TLS_CS_PSK_WITH_NULL_SHA                              = 0x002c, /* TLS & DTLS [RFC4785] */
  R_TLS_CS_DHE_PSK_WITH_NULL_SHA                          = 0x002d, /* TLS & DTLS [RFC4785] */
  R_TLS_CS_RSA_PSK_WITH_NULL_SHA                          = 0x002e, /* TLS & DTLS [RFC4785] */
  R_TLS_CS_RSA_WITH_AES_128_CBC_SHA                       = 0x002f, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_DSS_WITH_AES_128_CBC_SHA                    = 0x0030, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_RSA_WITH_AES_128_CBC_SHA                    = 0x0031, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_DSS_WITH_AES_128_CBC_SHA                   = 0x0032, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_RSA_WITH_AES_128_CBC_SHA                   = 0x0033, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_anon_WITH_AES_128_CBC_SHA                   = 0x0034, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_RSA_WITH_AES_256_CBC_SHA                       = 0x0035, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_DSS_WITH_AES_256_CBC_SHA                    = 0x0036, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_RSA_WITH_AES_256_CBC_SHA                    = 0x0037, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_DSS_WITH_AES_256_CBC_SHA                   = 0x0038, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_RSA_WITH_AES_256_CBC_SHA                   = 0x0039, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_anon_WITH_AES_256_CBC_SHA                   = 0x003a, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_RSA_WITH_NULL_SHA256                           = 0x003b, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256                    = 0x003c, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_RSA_WITH_AES_256_CBC_SHA256                    = 0x003d, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_DSS_WITH_AES_128_CBC_SHA256                 = 0x003e, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_RSA_WITH_AES_128_CBC_SHA256                 = 0x003f, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_DSS_WITH_AES_128_CBC_SHA256                = 0x0040, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_RSA_WITH_CAMELLIA_128_CBC_SHA                  = 0x0041, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA               = 0x0042, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA               = 0x0043, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA              = 0x0044, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA              = 0x0045, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_anon_WITH_CAMELLIA_128_CBC_SHA              = 0x0046, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_RSA_WITH_AES_128_CBC_SHA256                = 0x0067, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_DSS_WITH_AES_256_CBC_SHA256                 = 0x0068, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_RSA_WITH_AES_256_CBC_SHA256                 = 0x0069, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_DSS_WITH_AES_256_CBC_SHA256                = 0x006a, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DHE_RSA_WITH_AES_256_CBC_SHA256                = 0x006b, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_anon_WITH_AES_128_CBC_SHA256                = 0x006c, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_DH_anon_WITH_AES_256_CBC_SHA256                = 0x006d, /* TLS & DTLS [RFC5246] */
  R_TLS_CS_RSA_WITH_CAMELLIA_256_CBC_SHA                  = 0x0084, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA               = 0x0085, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA               = 0x0086, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA              = 0x0087, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA              = 0x0088, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_anon_WITH_CAMELLIA_256_CBC_SHA              = 0x0089, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_PSK_WITH_RC4_128_SHA                           = 0x008a, /* TLS only [RFC4279][RFC6347] */
  R_TLS_CS_PSK_WITH_3DES_EDE_CBC_SHA                      = 0x008b, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_PSK_WITH_AES_128_CBC_SHA                       = 0x008c, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_PSK_WITH_AES_256_CBC_SHA                       = 0x008d, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_DHE_PSK_WITH_RC4_128_SHA                       = 0x008e, /* TLS only [RFC4279][RFC6347] */
  R_TLS_CS_DHE_PSK_WITH_3DES_EDE_CBC_SHA                  = 0x008f, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_DHE_PSK_WITH_AES_128_CBC_SHA                   = 0x0090, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_DHE_PSK_WITH_AES_256_CBC_SHA                   = 0x0091, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_RSA_PSK_WITH_RC4_128_SHA                       = 0x0092, /* TLS only [RFC4279][RFC6347] */
  R_TLS_CS_RSA_PSK_WITH_3DES_EDE_CBC_SHA                  = 0x0093, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_RSA_PSK_WITH_AES_128_CBC_SHA                   = 0x0094, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_RSA_PSK_WITH_AES_256_CBC_SHA                   = 0x0095, /* TLS & DTLS [RFC4279] */
  R_TLS_CS_RSA_WITH_SEED_CBC_SHA                          = 0x0096, /* TLS & DTLS [RFC4162] */
  R_TLS_CS_DH_DSS_WITH_SEED_CBC_SHA                       = 0x0097, /* TLS & DTLS [RFC4162] */
  R_TLS_CS_DH_RSA_WITH_SEED_CBC_SHA                       = 0x0098, /* TLS & DTLS [RFC4162] */
  R_TLS_CS_DHE_DSS_WITH_SEED_CBC_SHA                      = 0x0099, /* TLS & DTLS [RFC4162] */
  R_TLS_CS_DHE_RSA_WITH_SEED_CBC_SHA                      = 0x009a, /* TLS & DTLS [RFC4162] */
  R_TLS_CS_DH_anon_WITH_SEED_CBC_SHA                      = 0x009b, /* TLS & DTLS [RFC4162] */
  R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256                    = 0x009c, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384                    = 0x009d, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DHE_RSA_WITH_AES_128_GCM_SHA256                = 0x009e, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DHE_RSA_WITH_AES_256_GCM_SHA384                = 0x009f, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DH_RSA_WITH_AES_128_GCM_SHA256                 = 0x00a0, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DH_RSA_WITH_AES_256_GCM_SHA384                 = 0x00a1, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DHE_DSS_WITH_AES_128_GCM_SHA256                = 0x00a2, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DHE_DSS_WITH_AES_256_GCM_SHA384                = 0x00a3, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DH_DSS_WITH_AES_128_GCM_SHA256                 = 0x00a4, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DH_DSS_WITH_AES_256_GCM_SHA384                 = 0x00a5, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DH_anon_WITH_AES_128_GCM_SHA256                = 0x00a6, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_DH_anon_WITH_AES_256_GCM_SHA384                = 0x00a7, /* TLS & DTLS [RFC5288] */
  R_TLS_CS_PSK_WITH_AES_128_GCM_SHA256                    = 0x00a8, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_PSK_WITH_AES_256_GCM_SHA384                    = 0x00a9, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_DHE_PSK_WITH_AES_128_GCM_SHA256                = 0x00aa, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_DHE_PSK_WITH_AES_256_GCM_SHA384                = 0x00ab, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_RSA_PSK_WITH_AES_128_GCM_SHA256                = 0x00ac, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_RSA_PSK_WITH_AES_256_GCM_SHA384                = 0x00ad, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_PSK_WITH_AES_128_CBC_SHA256                    = 0x00ae, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_PSK_WITH_AES_256_CBC_SHA384                    = 0x00af, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_PSK_WITH_NULL_SHA256                           = 0x00b0, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_PSK_WITH_NULL_SHA384                           = 0x00b1, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_DHE_PSK_WITH_AES_128_CBC_SHA256                = 0x00b2, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_DHE_PSK_WITH_AES_256_CBC_SHA384                = 0x00b3, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_DHE_PSK_WITH_NULL_SHA256                       = 0x00b4, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_DHE_PSK_WITH_NULL_SHA384                       = 0x00b5, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_RSA_PSK_WITH_AES_128_CBC_SHA256                = 0x00b6, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_RSA_PSK_WITH_AES_256_CBC_SHA384                = 0x00b7, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_RSA_PSK_WITH_NULL_SHA256                       = 0x00b8, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_RSA_PSK_WITH_NULL_SHA384                       = 0x00b9, /* TLS & DTLS [RFC5487] */
  R_TLS_CS_RSA_WITH_CAMELLIA_128_CBC_SHA256               = 0x00ba, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256            = 0x00bb, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256            = 0x00bc, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256           = 0x00bd, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256           = 0x00be, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256           = 0x00bf, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_RSA_WITH_CAMELLIA_256_CBC_SHA256               = 0x00c0, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256            = 0x00c1, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256            = 0x00c2, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256           = 0x00c3, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256           = 0x00c4, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256           = 0x00c5, /* TLS & DTLS [RFC5932] */
  R_TLS_CS_EMPTY_RENEGOTIATION_INFO_SCSV                  = 0x00ff, /* TLS & DTLS [RFC5746] */
  R_TLS_CS_FALLBACK_SCSV                                  = 0x5600, /* TLS & DTLS [RFC7507] */
  R_TLS_CS_ECDH_ECDSA_WITH_NULL_SHA                       = 0xc001, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_ECDSA_WITH_RC4_128_SHA                    = 0xc002, /* TLS only [RFC4492][RFC6347] */
  R_TLS_CS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA               = 0xc003, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_ECDSA_WITH_AES_128_CBC_SHA                = 0xc004, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_ECDSA_WITH_AES_256_CBC_SHA                = 0xc005, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDHE_ECDSA_WITH_NULL_SHA                      = 0xc006, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDHE_ECDSA_WITH_RC4_128_SHA                   = 0xc007, /* TLS only [RFC4492][RFC6347] */
  R_TLS_CS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA              = 0xc008, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               = 0xc009, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               = 0xc00a, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_RSA_WITH_NULL_SHA                         = 0xc00b, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_RSA_WITH_RC4_128_SHA                      = 0xc00c, /* TLS only [RFC4492][RFC6347] */
  R_TLS_CS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA                 = 0xc00d, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_RSA_WITH_AES_128_CBC_SHA                  = 0xc00e, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_RSA_WITH_AES_256_CBC_SHA                  = 0xc00f, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDHE_RSA_WITH_NULL_SHA                        = 0xc010, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDHE_RSA_WITH_RC4_128_SHA                     = 0xc011, /* TLS only [RFC4492][RFC6347] */
  R_TLS_CS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA                = 0xc012, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA                 = 0xc013, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA                 = 0xc014, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_anon_WITH_NULL_SHA                        = 0xc015, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_anon_WITH_RC4_128_SHA                     = 0xc016, /* TLS only [RFC4492][RFC6347] */
  R_TLS_CS_ECDH_anon_WITH_3DES_EDE_CBC_SHA                = 0xc017, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_anon_WITH_AES_128_CBC_SHA                 = 0xc018, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_ECDH_anon_WITH_AES_256_CBC_SHA                 = 0xc019, /* TLS & DTLS [RFC4492] */
  R_TLS_CS_SRP_SHA_WITH_3DES_EDE_CBC_SHA                  = 0xc01a, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA              = 0xc01b, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA              = 0xc01c, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_SRP_SHA_WITH_AES_128_CBC_SHA                   = 0xc01d, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA               = 0xc01e, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA               = 0xc01f, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_SRP_SHA_WITH_AES_256_CBC_SHA                   = 0xc020, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA               = 0xc021, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA               = 0xc022, /* TLS & DTLS [RFC5054] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256            = 0xc023, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384            = 0xc024, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256             = 0xc025, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384             = 0xc026, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256              = 0xc027, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA384              = 0xc028, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDH_RSA_WITH_AES_128_CBC_SHA256               = 0xc029, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDH_RSA_WITH_AES_256_CBC_SHA384               = 0xc02a, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            = 0xc02b, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            = 0xc02c, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256             = 0xc02d, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384             = 0xc02e, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256              = 0xc02f, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384              = 0xc030, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDH_RSA_WITH_AES_128_GCM_SHA256               = 0xc031, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDH_RSA_WITH_AES_256_GCM_SHA384               = 0xc032, /* TLS & DTLS [RFC5289] */
  R_TLS_CS_ECDHE_PSK_WITH_RC4_128_SHA                     = 0xc033, /* TLS only [RFC5489][RFC6347] */
  R_TLS_CS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA                = 0xc034, /* TLS & DTLS [RFC5489] */
  R_TLS_CS_ECDHE_PSK_WITH_AES_128_CBC_SHA                 = 0xc035, /* TLS & DTLS [RFC5489] */
  R_TLS_CS_ECDHE_PSK_WITH_AES_256_CBC_SHA                 = 0xc036, /* TLS & DTLS [RFC5489] */
  R_TLS_CS_ECDHE_PSK_WITH_AES_128_CBC_SHA256              = 0xc037, /* TLS & DTLS [RFC5489] */
  R_TLS_CS_ECDHE_PSK_WITH_AES_256_CBC_SHA384              = 0xc038, /* TLS & DTLS [RFC5489] */
  R_TLS_CS_ECDHE_PSK_WITH_NULL_SHA                        = 0xc039, /* TLS & DTLS [RFC5489] */
  R_TLS_CS_ECDHE_PSK_WITH_NULL_SHA256                     = 0xc03a, /* TLS & DTLS [RFC5489] */
  R_TLS_CS_ECDHE_PSK_WITH_NULL_SHA384                     = 0xc03b, /* TLS & DTLS [RFC5489] */
  R_TLS_CS_RSA_WITH_ARIA_128_CBC_SHA256                   = 0xc03c, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_RSA_WITH_ARIA_256_CBC_SHA384                   = 0xc03d, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_DSS_WITH_ARIA_128_CBC_SHA256                = 0xc03e, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_DSS_WITH_ARIA_256_CBC_SHA384                = 0xc03f, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_RSA_WITH_ARIA_128_CBC_SHA256                = 0xc040, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_RSA_WITH_ARIA_256_CBC_SHA384                = 0xc041, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_DSS_WITH_ARIA_128_CBC_SHA256               = 0xc042, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_DSS_WITH_ARIA_256_CBC_SHA384               = 0xc043, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_RSA_WITH_ARIA_128_CBC_SHA256               = 0xc044, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_RSA_WITH_ARIA_256_CBC_SHA384               = 0xc045, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_anon_WITH_ARIA_128_CBC_SHA256               = 0xc046, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_anon_WITH_ARIA_256_CBC_SHA384               = 0xc047, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256           = 0xc048, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384           = 0xc049, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256            = 0xc04a, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384            = 0xc04b, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256             = 0xc04c, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384             = 0xc04d, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256              = 0xc04e, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384              = 0xc04f, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_RSA_WITH_ARIA_128_GCM_SHA256                   = 0xc050, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_RSA_WITH_ARIA_256_GCM_SHA384                   = 0xc051, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_RSA_WITH_ARIA_128_GCM_SHA256               = 0xc052, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_RSA_WITH_ARIA_256_GCM_SHA384               = 0xc053, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_RSA_WITH_ARIA_128_GCM_SHA256                = 0xc054, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_RSA_WITH_ARIA_256_GCM_SHA384                = 0xc055, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_DSS_WITH_ARIA_128_GCM_SHA256               = 0xc056, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_DSS_WITH_ARIA_256_GCM_SHA384               = 0xc057, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_DSS_WITH_ARIA_128_GCM_SHA256                = 0xc058, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_DSS_WITH_ARIA_256_GCM_SHA384                = 0xc059, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_anon_WITH_ARIA_128_GCM_SHA256               = 0xc05a, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DH_anon_WITH_ARIA_256_GCM_SHA384               = 0xc05b, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256           = 0xc05c, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384           = 0xc05d, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256            = 0xc05e, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384            = 0xc05f, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256             = 0xc060, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384             = 0xc061, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256              = 0xc062, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384              = 0xc063, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_PSK_WITH_ARIA_128_CBC_SHA256                   = 0xc064, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_PSK_WITH_ARIA_256_CBC_SHA384                   = 0xc065, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_PSK_WITH_ARIA_128_CBC_SHA256               = 0xc066, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_PSK_WITH_ARIA_256_CBC_SHA384               = 0xc067, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_RSA_PSK_WITH_ARIA_128_CBC_SHA256               = 0xc068, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_RSA_PSK_WITH_ARIA_256_CBC_SHA384               = 0xc069, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_PSK_WITH_ARIA_128_GCM_SHA256                   = 0xc06a, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_PSK_WITH_ARIA_256_GCM_SHA384                   = 0xc06b, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_PSK_WITH_ARIA_128_GCM_SHA256               = 0xc06c, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_DHE_PSK_WITH_ARIA_256_GCM_SHA384               = 0xc06d, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_RSA_PSK_WITH_ARIA_128_GCM_SHA256               = 0xc06e, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_RSA_PSK_WITH_ARIA_256_GCM_SHA384               = 0xc06f, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256             = 0xc070, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384             = 0xc071, /* TLS & DTLS [RFC6209] */
  R_TLS_CS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256       = 0xc072, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384       = 0xc073, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256        = 0xc074, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384        = 0xc075, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256         = 0xc076, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384         = 0xc077, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256          = 0xc078, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384          = 0xc079, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_RSA_WITH_CAMELLIA_128_GCM_SHA256               = 0xc07a, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_RSA_WITH_CAMELLIA_256_GCM_SHA384               = 0xc07b, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256           = 0xc07c, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384           = 0xc07d, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256            = 0xc07e, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384            = 0xc07f, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256           = 0xc080, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384           = 0xc081, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256            = 0xc082, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384            = 0xc083, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256           = 0xc084, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384           = 0xc085, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256       = 0xc086, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384       = 0xc087, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256        = 0xc088, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384        = 0xc089, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256         = 0xc08a, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384         = 0xc08b, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256          = 0xc08c, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384          = 0xc08d, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_PSK_WITH_CAMELLIA_128_GCM_SHA256               = 0xc08e, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_PSK_WITH_CAMELLIA_256_GCM_SHA384               = 0xc08f, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256           = 0xc090, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384           = 0xc091, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256           = 0xc092, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384           = 0xc093, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_PSK_WITH_CAMELLIA_128_CBC_SHA256               = 0xc094, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_PSK_WITH_CAMELLIA_256_CBC_SHA384               = 0xc095, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256           = 0xc096, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384           = 0xc097, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256           = 0xc098, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384           = 0xc099, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256         = 0xc09a, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384         = 0xc09b, /* TLS & DTLS [RFC6367] */
  R_TLS_CS_RSA_WITH_AES_128_CCM                           = 0xc09c, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_RSA_WITH_AES_256_CCM                           = 0xc09d, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_DHE_RSA_WITH_AES_128_CCM                       = 0xc09e, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_DHE_RSA_WITH_AES_256_CCM                       = 0xc09f, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_RSA_WITH_AES_128_CCM_8                         = 0xc0a0, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_RSA_WITH_AES_256_CCM_8                         = 0xc0a1, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_DHE_RSA_WITH_AES_128_CCM_8                     = 0xc0a2, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_DHE_RSA_WITH_AES_256_CCM_8                     = 0xc0a3, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_PSK_WITH_AES_128_CCM                           = 0xc0a4, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_PSK_WITH_AES_256_CCM                           = 0xc0a5, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_DHE_PSK_WITH_AES_128_CCM                       = 0xc0a6, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_DHE_PSK_WITH_AES_256_CCM                       = 0xc0a7, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_PSK_WITH_AES_128_CCM_8                         = 0xc0a8, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_PSK_WITH_AES_256_CCM_8                         = 0xc0a9, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_PSK_DHE_WITH_AES_128_CCM_8                     = 0xc0aa, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_PSK_DHE_WITH_AES_256_CCM_8                     = 0xc0ab, /* TLS & DTLS [RFC6655] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CCM                   = 0xc0ac, /* TLS & DTLS [RFC7251] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CCM                   = 0xc0ad, /* TLS & DTLS [RFC7251] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CCM_8                 = 0xc0ae, /* TLS & DTLS [RFC7251] */
  R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CCM_8                 = 0xc0af, /* TLS & DTLS [RFC7251] */
  R_TLS_CS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD    = 0xcc13, /* TLS & DTLS [RFC7905] */
  R_TLS_CS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD  = 0xcc14, /* TLS & DTLS [RFC7905] */
  R_TLS_CS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256        = 0xcca8, /* TLS & DTLS [RFC7905] */
  R_TLS_CS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      = 0xcca9, /* TLS & DTLS [RFC7905] */
  R_TLS_CS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256          = 0xccaa, /* TLS & DTLS [RFC7905] */
  R_TLS_CS_PSK_WITH_CHACHA20_POLY1305_SHA256              = 0xccab, /* TLS & DTLS [RFC7905] */
  R_TLS_CS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256        = 0xccac, /* TLS & DTLS [RFC7905] */
  R_TLS_CS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256          = 0xccad, /* TLS & DTLS [RFC7905] */
  R_TLS_CS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256          = 0xccae, /* TLS & DTLS [RFC7905] */
} RTLSCipherSuite;

typedef enum {
  R_KEY_EXCHANGE_NULL = 0,
  R_KEY_EXCHANGE_RSA,
  R_KEY_EXCHANGE_DH_DSS,
  R_KEY_EXCHANGE_DH_RSA,
  R_KEY_EXCHANGE_DH_anon,
  R_KEY_EXCHANGE_DHE_DSS,
  R_KEY_EXCHANGE_DHE_RSA,
  R_KEY_EXCHANGE_ECDH_RSA,
  R_KEY_EXCHANGE_ECDH_ECDSA,
  R_KEY_EXCHANGE_ECDH_anon,
  R_KEY_EXCHANGE_ECDHE_RSA,
  R_KEY_EXCHANGE_ECDHE_ECDSA,
  R_KEY_EXCHANGE_PSK,
  R_KEY_EXCHANGE_DHE_PSK,
  R_KEY_EXCHANGE_RSA_PSK,
  R_KEY_EXCHANGE_ECDHE_PSK,

  R_KEY_EXCHANGE_SRP_SHA,
  R_KEY_EXCHANGE_KRB5,
} RKeyExchangeType;

typedef struct {
  RTLSCipherSuite suite;
  const rchar * str;

  RKeyExchangeType key_exchange;
  const RCryptoCipherInfo * cipher;
  RHashType mac;
} RTLSCipherSuiteInfo;

R_API rboolean r_tls_cipher_suite_is_supported (RTLSCipherSuite suite);
R_API RTLSCipherSuite r_tls_cipher_suite_filter (
    const RTLSCipherSuite * incoming, ruint ilen,
    const RTLSCipherSuite * preferred, ruint plen);

R_API const RTLSCipherSuiteInfo * r_tls_cipher_suite_get_info (RTLSCipherSuite suite);
R_API const RTLSCipherSuiteInfo * r_tls_cipher_suite_get_info_from_str (const rchar * str);

R_END_DECLS

#endif /* __R_CRYPTO_CIPHER_SUITE_H__ */

