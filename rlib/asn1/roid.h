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
#ifndef __R_ASN1_OID_H__
#define __R_ASN1_OID_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

#define R_ASN1_OID_SIZEOF(oid)                      (sizeof (oid) - 1)
#define R_ASN1_OID_ARGS(oid)                        oid, R_ASN1_OID_SIZEOF (oid)
#define r_asn1_oid_bin_cmp_full(buf, bufsize, oid, oidsize) (bufsize == oidsize ?  \
    r_memcmp (buf, oid, bufsize) : ((int)bufsize - (int)oidsize))
#define r_asn1_oid_bin_cmp(buf, bufsize, oid) (bufsize == R_ASN1_OID_SIZEOF(oid) ?  \
    r_memcmp (buf, oid, bufsize) : ((int)bufsize - (int)R_ASN1_OID_SIZEOF(oid)))
#define r_asn1_oid_bin_equals_full(buf, bufsize, oid, oidsize)                \
    (r_asn1_oid_bin_cmp_full (buf, bufsize, oid, oidsize) == 0)
#define r_asn1_oid_bin_equals(buf, bufsize, oid)                              \
    (r_asn1_oid_bin_cmp (buf, bufsize, oid) == 0)

/* Top level OIDs in dot notation */
#define R_ASN1_OID_ITU_REC                          "\x00"    /* 0.0 */
#define R_ASN1_OID_ITU_QUESTION                     "\x01"    /* 0.1 */
#define R_ASN1_OID_ITU_ADM                          "\x02"    /* 0.2 */
#define R_ASN1_OID_ISO_NET_OP                       "\x03"    /* 0.3 */
#define R_ASN1_OID_ITU_ID_ORG                       "\x04"    /* 0.4 */
#define R_ASN1_OID_ITU_R_REC                        "\x05"    /* 0.5 */
#define R_ASN1_OID_ITU_DATA                         "\x09"    /* 0.9 */
#define R_ASN1_OID_ISO_STD                          "\x28"    /* 1.0 */
#define R_ASN1_OID_ISO_REG_AUTH                     "\x29"    /* 1.1 */
#define R_ASN1_OID_ISO_MEMBER_BODY                  "\x2a"    /* 1.2 */
#define R_ASN1_OID_ISO_ID_ORG                       "\x2b"    /* 1.3 */
#define R_ASN1_OID_ISOITU_PRES                      "\x50"    /* 2.0 */
#define R_ASN1_OID_ISOITU_ASN1                      "\x51"    /* 2.1 */
#define R_ASN1_OID_ISOITU_ASS_CTRL                  "\x52"    /* 2.2 */
#define R_ASN1_OID_ISOITU_REL_TX                    "\x53"    /* 2.3 */
#define R_ASN1_OID_ISOITU_REM_OP                    "\x54"    /* 2.4 */
#define R_ASN1_OID_ISOITU_DS                        "\x55"    /* 2.5 */
#define R_ASN1_OID_ISOITU_MHS                       "\x56"    /* 2.6 */
#define R_ASN1_OID_ISOITU_CCR                       "\x57"    /* 2.7 */
#define R_ASN1_OID_ISOITU_ODA                       "\x58"    /* 2.8 */
#define R_ASN1_OID_ISOITU_MS                        "\x59"    /* 2.9 */
#define R_ASN1_OID_ISOITU_TRANS_PROC                "\x5a"    /* 2.10 */
#define R_ASN1_OID_ISOITU_DOR                       "\x5b"    /* 2.11 */
#define R_ASN1_OID_ISOITU_REF_DATA_TX               "\x5c"    /* 2.12 */
#define R_ASN1_OID_ISOITU_NET_LAYER                 "\x5d"    /* 2.13 */
#define R_ASN1_OID_ISOITU_TRANS_LAYER               "\x5e"    /* 2.14 */
#define R_ASN1_OID_ISOITU_LINK_LAYER                "\x5f"    /* 2.15 */
#define R_ASN1_OID_ISOITU_COUNTRY                   "\x60"    /* 2.16 */
#define R_ASN1_OID_ISOITU_REG_PROC                  "\x61"    /* 2.17 */
#define R_ASN1_OID_ISOITU_PHY_LAYER                 "\x62"    /* 2.18 */
#define R_ASN1_OID_ISOITU_MHEG                      "\x63"    /* 2.19 */
#define R_ASN1_OID_ISOITU_GENERIC_ULS               "\x64"    /* 2.20 */
#define R_ASN1_OID_ISOITU_TRANS_LAYER_SEC_PROT      "\x65"    /* 2.21 */
#define R_ASN1_OID_ISOITU_NET_LAYER_SEC_PROT        "\x66"    /* 2.22 */
#define R_ASN1_OID_ISOITU_INT_ORG                   "\x67"    /* 2.23 */
#define R_ASN1_OID_ISOITU_SIOS                      "\x68"    /* 2.24 */
#define R_ASN1_OID_ISOITU_UUID                      "\x69"    /* 2.25 */
#define R_ASN1_OID_ISOITU_ODP                       "\x6a"    /* 2.26 */
#define R_ASN1_OID_ISOITU_TAG_BASED                 "\x6b"    /* 2.27 */
#define R_ASN1_OID_ISOITU_ITS                       "\x6c"    /* 2.28 */
#define R_ASN1_OID_ISOITU_UPU                       "\x78"    /* 2.40 */
#define R_ASN1_OID_ISOITU_BIP                       "\x79"    /* 2.41 */
#define R_ASN1_OID_ISOITU_TELEBIOMETRICS            "\x7a"    /* 2.42 */
#define R_ASN1_OID_ISOITU_CYBERSECURITY             "\x8100"  /* 2.48 */
#define R_ASN1_OID_ISOITU_ALERTING                  "\x8101"  /* 2.49 */
#define R_ASN1_OID_ISOITU_ORS                       "\x8102"  /* 2.50 */
#define R_ASN1_OID_ISOITU_GS1                       "\x8103"  /* 2.51 */
#define R_ASN1_OID_ISOITU_EXAMPLE                   "\x8837"  /* 2.999 */

/* ISO MEMBERS */
#define R_ASN1_OID_ISO_AU                       R_ASN1_OID_ISO_MEMBER_BODY"\x24"      /*  36 */
#define R_ASN1_OID_ISO_AT                       R_ASN1_OID_ISO_MEMBER_BODY"\x28"      /*  40 */
#define R_ASN1_OID_ISO_BE                       R_ASN1_OID_ISO_MEMBER_BODY"\x38"      /*  56 */
#define R_ASN1_OID_ISO_CN                       R_ASN1_OID_ISO_MEMBER_BODY"\x81\x1c"  /* 156 */
#define R_ASN1_OID_ISO_CZ                       R_ASN1_OID_ISO_MEMBER_BODY"\x81\x4b"  /* 203 */
#define R_ASN1_OID_ISO_DK                       R_ASN1_OID_ISO_MEMBER_BODY"\x81\x50"  /* 208 */
#define R_ASN1_OID_ISO_FI                       R_ASN1_OID_ISO_MEMBER_BODY"\x81\x76"  /* 246 */
#define R_ASN1_OID_ISO_FR                       R_ASN1_OID_ISO_MEMBER_BODY"\x81\x7a"  /* 250 */
#define R_ASN1_OID_ISO_DE                       R_ASN1_OID_ISO_MEMBER_BODY"\x82\x14"  /* 276 */
#define R_ASN1_OID_ISO_GR                       R_ASN1_OID_ISO_MEMBER_BODY"\x82\x26"  /* 300 */
#define R_ASN1_OID_ISO_HK                       R_ASN1_OID_ISO_MEMBER_BODY"\x82\x58"  /* 344 */
#define R_ASN1_OID_ISO_IE                       R_ASN1_OID_ISO_MEMBER_BODY"\x82\x74"  /* 372 */
#define R_ASN1_OID_ISO_JP                       R_ASN1_OID_ISO_MEMBER_BODY"\x83\x08"  /* 392 */
#define R_ASN1_OID_ISO_KZ                       R_ASN1_OID_ISO_MEMBER_BODY"\x83\x0e"  /* 398 */
#define R_ASN1_OID_ISO_KR                       R_ASN1_OID_ISO_MEMBER_BODY"\x83\x1a"  /* 410 */
#define R_ASN1_OID_ISO_MD                       R_ASN1_OID_ISO_MEMBER_BODY"\x83\x72"  /* 498 */
#define R_ASN1_OID_ISO_NL                       R_ASN1_OID_ISO_MEMBER_BODY"\x84\x10"  /* 528 */
#define R_ASN1_OID_ISO_NG                       R_ASN1_OID_ISO_MEMBER_BODY"\x84\x36"  /* 566 */
#define R_ASN1_OID_ISO_NO                       R_ASN1_OID_ISO_MEMBER_BODY"\x84\x42"  /* 578 */
#define R_ASN1_OID_ISO_PL                       R_ASN1_OID_ISO_MEMBER_BODY"\x84\x68"  /* 616 */
#define R_ASN1_OID_ISO_RU                       R_ASN1_OID_ISO_MEMBER_BODY"\x85\x03"  /* 643 */
#define R_ASN1_OID_ISO_SG                       R_ASN1_OID_ISO_MEMBER_BODY"\x85\x3e"  /* 702 */
#define R_ASN1_OID_ISO_VN                       R_ASN1_OID_ISO_MEMBER_BODY"\x85\x40"  /* 704 */
#define R_ASN1_OID_ISO_SE                       R_ASN1_OID_ISO_MEMBER_BODY"\x85\x72"  /* 752 */
#define R_ASN1_OID_ISO_UA                       R_ASN1_OID_ISO_MEMBER_BODY"\x86\x24"  /* 804 */
#define R_ASN1_OID_ISO_GB                       R_ASN1_OID_ISO_MEMBER_BODY"\x86\x3a"  /* 826 */
#define R_ASN1_OID_ISO_US                       R_ASN1_OID_ISO_MEMBER_BODY"\x86\x48"  /* 840 */
#define R_ASN1_OID_ISO_UZ                       R_ASN1_OID_ISO_MEMBER_BODY"\x86\x5c"  /* 860 */
#define R_ASN1_OID_ISO_VE                       R_ASN1_OID_ISO_MEMBER_BODY"\x86\x5e"  /* 862 */

R_API rchar * r_asn1_oid_to_dot (const ruint32 * oid, rsize oidlen) R_ATTR_MALLOC;
R_API ruint32 * r_asn1_oid_from_dot (const rchar * oid, rssize oidsize,
    rsize * outlen) R_ATTR_MALLOC;

R_API rboolean r_asn1_oid_is_dot (const ruint32 * oid, rsize oidlen,
    const rchar * dot, rssize dotsize);
R_API rboolean r_asn1_oid_has_dot_prefix (const ruint32 * oid, rsize oidlen,
    const rchar * dot, rssize dotsize);

#define R_RSA_OID_RSADSI                        R_ASN1_OID_ISO_US"\x86\xf7\x0d"
#define R_RSA_OID_PKCS_1                        R_RSA_OID_RSADSI"\x01\x01"
#define R_RSA_OID_PKCS_2                        R_RSA_OID_RSADSI"\x01\x02"
#define R_RSA_OID_PKCS_3                        R_RSA_OID_RSADSI"\x01\x03"
#define R_RSA_OID_PKCS_4                        R_RSA_OID_RSADSI"\x01\x04"
#define R_RSA_OID_PKCS_5                        R_RSA_OID_RSADSI"\x01\x05"
#define R_RSA_OID_PKCS_6                        R_RSA_OID_RSADSI"\x01\x06"
#define R_RSA_OID_PKCS_7                        R_RSA_OID_RSADSI"\x01\x07"
#define R_RSA_OID_PKCS_8                        R_RSA_OID_RSADSI"\x01\x08"
#define R_RSA_OID_PKCS_9                        R_RSA_OID_RSADSI"\x01\x09"
#define R_RSA_OID_PKCS_10                       R_RSA_OID_RSADSI"\x01\x0a"
#define R_RSA_OID_PKCS_11                       R_RSA_OID_RSADSI"\x01\x0b"
#define R_RSA_OID_PKCS_12                       R_RSA_OID_RSADSI"\x01\x0c"
#define R_RSA_OID_PKCS_13                       R_RSA_OID_RSADSI"\x01\x0d"
#define R_RSA_OID_PKCS_14                       R_RSA_OID_RSADSI"\x01\x0e"
#define R_RSA_OID_PKCS_15                       R_RSA_OID_RSADSI"\x01\x0f"

#define R_RSA_OID_RSA_ENCRYPTION                R_RSA_OID_PKCS_1"\x01"
#define R_RSA_OID_MD2_WITH_RSA                  R_RSA_OID_PKCS_1"\x02"
#define R_RSA_OID_MD4_WITH_RSA                  R_RSA_OID_PKCS_1"\x03"
#define R_RSA_OID_MD5_WITH_RSA                  R_RSA_OID_PKCS_1"\x04"
#define R_RSA_OID_SHA1_WITH_RSA                 R_RSA_OID_PKCS_1"\x05"
#define R_RSA_OID_OAEP_WITH_RSA                 R_RSA_OID_PKCS_1"\x06"
#define R_RSA_OID_OAEP_WITH_RSAES               R_RSA_OID_PKCS_1"\x07"
#define R_RSA_OID_MGF1_WITH_RSA                 R_RSA_OID_PKCS_1"\x08"
#define R_RSA_OID_PSPECIFIED                    R_RSA_OID_PKCS_1"\x09"
#define R_RSA_OID_RSASSA_PSS                    R_RSA_OID_PKCS_1"\x0a"
#define R_RSA_OID_SHA256_WITH_RSA               R_RSA_OID_PKCS_1"\x0b"
#define R_RSA_OID_SHA384_WITH_RSA               R_RSA_OID_PKCS_1"\x0c"
#define R_RSA_OID_SHA512_WITH_RSA               R_RSA_OID_PKCS_1"\x0d"
#define R_RSA_OID_SHA224_WITH_RSA               R_RSA_OID_PKCS_1"\x0e"
#define R_RSA_OID_DH_KEY_AGREEMENT              R_RSA_OID_PKCS_3"\x01"
#define R_RSA_OID_PBE_WITH_MD2_AND_DES          R_RSA_OID_PKCS_5"\x01"
#define R_RSA_OID_PBE_WITH_MD5_AND_DES          R_RSA_OID_PKCS_5"\x03"
#define R_RSA_OID_PBE_WITH_MD2_AND_RC2          R_RSA_OID_PKCS_5"\x04"
#define R_RSA_OID_PBE_WITH_MD5_AND_RC2          R_RSA_OID_PKCS_5"\x06"
#define R_RSA_OID_PBE_WITH_MD5_AND_XOR          R_RSA_OID_PKCS_5"\x09"
#define R_RSA_OID_PBE_WITH_SHA1_AND_DES         R_RSA_OID_PKCS_5"\x0a"
#define R_RSA_OID_PBE_WITH_SHA1_AND_RC2         R_RSA_OID_PKCS_5"\x0b"
#define R_RSA_OID_PBKDF2                        R_RSA_OID_PKCS_5"\x0c"
#define R_RSA_OID_PBES2                         R_RSA_OID_PKCS_5"\x0d"
#define R_RSA_OID_PBMAC1                        R_RSA_OID_PKCS_5"\x0e"

#define R_OIW_OID                               R_ASN1_OID_ISO_ID_ORG"\x0e"
#define R_OIW_SECSIG_OID                        R_OIW_OID"\x03"
#define R_OIW_SECSIG_OID_MD4_RSA                R_OIW_SECSIG_OID"\x02\x02"
#define R_OIW_SECSIG_OID_MD5_RSA                R_OIW_SECSIG_OID"\x02\x03"
#define R_OIW_SECSIG_OID_MD4_RSA2               R_OIW_SECSIG_OID"\x02\x04"
#define R_OIW_SECSIG_OID_MD2_RSA_SIG            R_OIW_SECSIG_OID"\x02\x18"
#define R_OIW_SECSIG_OID_MD5_RSA_SIG            R_OIW_SECSIG_OID"\x02\x19"
#define R_OIW_SECSIG_OID_SHA1_FIPS              R_OIW_SECSIG_OID"\x02\x1a"
#define R_OIW_SECSIG_OID_SHA1_DSA               R_OIW_SECSIG_OID"\x02\x1b"
#define R_OIW_SECSIG_OID_SHA1_RSA               R_OIW_SECSIG_OID"\x02\x1d"

#define R_X9CM_OID                              R_ASN1_OID_ISO_US"\xce\x38"

#define R_X9CM_OID_HOLD_INSTRUCTION             R_X9CM_OID"\x02"
#define R_X9CM_OID_HOLD_INSTRUCTION_NONE        R_OID_X9_HOLD_INSTRUCTION"\x01"
#define R_X9CM_OID_HOLD_INSTRUCTION_CALLISSUER  R_OID_X9_HOLD_INSTRUCTION"\x02"
#define R_X9CM_OID_HOLD_INSTRUCTION_REJECT      R_OID_X9_HOLD_INSTRUCTION"\x03"

#define R_X9CM_OID_DSA                          R_X9CM_OID"\x04\x01"
#define R_X9CM_OID_DSA_WITH_SHA1                R_X9CM_OID"\x04\x03"

#define R_X500_OID_ID_AT                        R_ASN1_OID_ISOITU_DS"\x04"
#define R_X509_OID_ID_CE                        R_ASN1_OID_ISOITU_DS"\x1d"
#define R_X509_OID_ID_PKIX                      R_ASN1_OID_ISO_ID_ORG"\x06\x01\x05\x05\x07"
#define R_X509_OID_ID_PE                        R_X509_OID_ID_PKIX"\x01"
#define R_X509_OID_ID_QT                        R_X509_OID_ID_PKIX"\x02"
#define R_X509_OID_ID_KP                        R_X509_OID_ID_PKIX"\x03"
#define R_X509_OID_ID_AD                        R_X509_OID_ID_PKIX"\x30"

#define R_ID_AT_OID_COMMON_NAME                 R_X500_OID_ID_AT"\x03"
#define R_ID_AT_OID_SURNAME                     R_X500_OID_ID_AT"\x04"
#define R_ID_AT_OID_SERIAL_NUMBER               R_X500_OID_ID_AT"\x05"
#define R_ID_AT_OID_CUNTRY_NAME                 R_X500_OID_ID_AT"\x06"
#define R_ID_AT_OID_LOCALITY_NAME               R_X500_OID_ID_AT"\x07"
#define R_ID_AT_OID_STATE_OR_PROVINCE_NAME      R_X500_OID_ID_AT"\x08"
#define R_ID_AT_OID_STREET_ADDRESS              R_X500_OID_ID_AT"\x09"
#define R_ID_AT_OID_ORGANIZATION_NAME           R_X500_OID_ID_AT"\x0a"
#define R_ID_AT_OID_ORGANIZATIONAL_UNIT_NAME    R_X500_OID_ID_AT"\x0b"
#define R_ID_AT_OID_TITLE                       R_X500_OID_ID_AT"\x0c"
#define R_ID_AT_OID_NAME                        R_X500_OID_ID_AT"\x29"
#define R_ID_AT_OID_GIVEN_NAME                  R_X500_OID_ID_AT"\x2a"
#define R_ID_AT_OID_INITIALS                    R_X500_OID_ID_AT"\x2b"
#define R_ID_AT_OID_GENERATION_QUALIFIER        R_X500_OID_ID_AT"\x2c"
#define R_ID_AT_OID_DN_QUALIFIER                R_X500_OID_ID_AT"\x2e"
#define R_ID_AT_OID_DN_PSEUDONYM                R_X500_OID_ID_AT"\x41"

#define R_PSS_OID_USER_ID                       R_ASN1_OID_ITU_DATA"\x92\x26\x89\x93\xf2\x2c\x64\x01\x01"
#define R_PSS_OID_DOMAIN_COMPONENT              R_ASN1_OID_ITU_DATA"\x92\x26\x89\x93\xf2\x2c\x64\x01\x19"

#define R_ID_CE_OID_SUBJECT_DIRECTORY_ATTRIBUTES R_X509_OID_ID_CE"\x09"
#define R_ID_CE_OID_SUBJECT_KEY_ID              R_X509_OID_ID_CE"\x0e"
#define R_ID_CE_OID_KEY_USAGE                   R_X509_OID_ID_CE"\x0f"
#define R_ID_CE_OID_PRIVATE_KEY_USAGE_PERIOD    R_X509_OID_ID_CE"\x10"
#define R_ID_CE_OID_SUBJECT_ALT_NAME            R_X509_OID_ID_CE"\x11"
#define R_ID_CE_OID_ISSUER_ALT_NAME             R_X509_OID_ID_CE"\x12"
#define R_ID_CE_OID_BASIC_CONSTRAINTS           R_X509_OID_ID_CE"\x13"
#define R_ID_CE_OID_CRL_NUMBER                  R_X509_OID_ID_CE"\x14"
#define R_ID_CE_OID_CRL_REASONS                 R_X509_OID_ID_CE"\x15"
#define R_ID_CE_OID_HOLD_INSTRUCTION_CODE       R_X509_OID_ID_CE"\x17"
#define R_ID_CE_OID_INVALIDITY_DATE             R_X509_OID_ID_CE"\x18"
#define R_ID_CE_OID_DELTA_CRL_INDICATOR         R_X509_OID_ID_CE"\x1b"
#define R_ID_CE_OID_ISSUING_DISTRIBUTION_POINT  R_X509_OID_ID_CE"\x1c"
#define R_ID_CE_OID_CERTIFICATE_ISSUER          R_X509_OID_ID_CE"\x1d"
#define R_ID_CE_OID_NAME_CONSTRAINTS            R_X509_OID_ID_CE"\x1e"
#define R_ID_CE_OID_CRL_DISTRIBUTION_POINTS     R_X509_OID_ID_CE"\x1f"
#define R_ID_CE_OID_CERTIFICATE_POLICIES        R_X509_OID_ID_CE"\x20"
#define R_ID_CE_OID_POLICY_MAPPINGS             R_X509_OID_ID_CE"\x21"
#define R_ID_CE_OID_AUTHORITY_KEY_ID            R_X509_OID_ID_CE"\x23"
#define R_ID_CE_OID_POLICY_CONSTRAINTS          R_X509_OID_ID_CE"\x24"
#define R_ID_CE_OID_EXT_KEY_USAGE               R_X509_OID_ID_CE"\x25"
#define R_ID_CE_OID_FRESHEST_CRL                R_X509_OID_ID_CE"\x2e"
#define R_ID_CE_OID_INHIBIT_ANY_POLICY          R_X509_OID_ID_CE"\x36"

#define R_ID_PE_OID_AUTHORITY_INFO_ACCESS       R_X509_OID_ID_PE"\x01"
#define R_ID_PE_OID_SUBJECT_INFO_ACCESS         R_X509_OID_ID_PE"\x0b"

#define R_ID_QT_OID_OCPS                        R_X509_OID_ID_QT"\x01"
#define R_ID_QT_OID_UNOTICE                     R_X509_OID_ID_QT"\x02"

#define R_ID_KP_OID_SERVER_AUTH                 R_X509_OID_ID_KP"\x01"
#define R_ID_KP_OID_CLIENT_AUTH                 R_X509_OID_ID_KP"\x02"
#define R_ID_KP_OID_CODE_SIGNING                R_X509_OID_ID_KP"\x03"
#define R_ID_KP_OID_EMAIL_PROTECTION            R_X509_OID_ID_KP"\x04"
#define R_ID_KP_OID_TIME_STAMPING               R_X509_OID_ID_KP"\x08"
#define R_ID_KP_OID_OCSP_SIGNING                R_X509_OID_ID_KP"\x09"

#define R_ID_AD_OID_OCSP                        R_X509_OID_ID_AD"\x01"
#define R_ID_AD_OID_CA_ISSUERS                  R_X509_OID_ID_AD"\x02"
#define R_ID_AD_OID_CA_TIME_STAMPING            R_X509_OID_ID_AD"\x03"
#define R_ID_AD_OID_CA_REPOSITORY               R_X509_OID_ID_AD"\x05"

R_END_DECLS

#endif /* __R_ASN1_OID_H__ */

