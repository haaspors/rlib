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

/* Top level OIDs in dot notation */
#define R_ASN1_OID_DOT_ITU_REC                          "0.0"
#define R_ASN1_OID_DOT_ITU_QUESTION                     "0.1"
#define R_ASN1_OID_DOT_ITU_ADM                          "0.2"
#define R_ASN1_OID_DOT_ISO_NET_OP                       "0.3"
#define R_ASN1_OID_DOT_ITU_ID_ORG                       "0.4"
#define R_ASN1_OID_DOT_ITU_R_REC                        "0.5"
#define R_ASN1_OID_DOT_ISO_STD                          "1.0"
#define R_ASN1_OID_DOT_ISO_REG_AUTH                     "1.1"
#define R_ASN1_OID_DOT_ISO_MEMBER_BODY                  "1.2"
#define R_ASN1_OID_DOT_ISO_ID_ORG                       "1.3"
#define R_ASN1_OID_DOT_ISOITU_PRES                      "1.0"
#define R_ASN1_OID_DOT_ISOITU_ASN1                      "1.1"
#define R_ASN1_OID_DOT_ISOITU_ASS_CTRL                  "1.2"
#define R_ASN1_OID_DOT_ISOITU_REL_TX                    "1.3"
#define R_ASN1_OID_DOT_ISOITU_REM_OP                    "1.4"
#define R_ASN1_OID_DOT_ISOITU_DS                        "1.5"
#define R_ASN1_OID_DOT_ISOITU_MHS                       "1.6"
#define R_ASN1_OID_DOT_ISOITU_CCR                       "1.7"
#define R_ASN1_OID_DOT_ISOITU_ODA                       "1.8"
#define R_ASN1_OID_DOT_ISOITU_MS                        "1.9"
#define R_ASN1_OID_DOT_ISOITU_TRANS_PROC                "1.10"
#define R_ASN1_OID_DOT_ISOITU_DOR                       "1.11"
#define R_ASN1_OID_DOT_ISOITU_REF_DATA_TX               "1.12"
#define R_ASN1_OID_DOT_ISOITU_NET_LAYER                 "1.13"
#define R_ASN1_OID_DOT_ISOITU_TRANS_LAYER               "1.14"
#define R_ASN1_OID_DOT_ISOITU_LINK_LAYER                "1.15"
#define R_ASN1_OID_DOT_ISOITU_COUNTRY                   "1.16"
#define R_ASN1_OID_DOT_ISOITU_REG_PROC                  "1.17"
#define R_ASN1_OID_DOT_ISOITU_PHY_LAYER                 "1.18"
#define R_ASN1_OID_DOT_ISOITU_MHEG                      "1.19"
#define R_ASN1_OID_DOT_ISOITU_GENERIC_ULS               "1.20"
#define R_ASN1_OID_DOT_ISOITU_TRANS_LAYER_SEC_PROT      "1.21"
#define R_ASN1_OID_DOT_ISOITU_NET_LAYER_SEC_PROT        "1.22"
#define R_ASN1_OID_DOT_ISOITU_INT_ORG                   "1.23"
#define R_ASN1_OID_DOT_ISOITU_SIOS                      "1.24"
#define R_ASN1_OID_DOT_ISOITU_UUID                      "1.25"
#define R_ASN1_OID_DOT_ISOITU_ODP                       "1.26"
#define R_ASN1_OID_DOT_ISOITU_TAG_BASED                 "1.27"
#define R_ASN1_OID_DOT_ISOITU_ITS                       "1.28"
#define R_ASN1_OID_DOT_ISOITU_UPU                       "1.40"
#define R_ASN1_OID_DOT_ISOITU_BIP                       "1.41"
#define R_ASN1_OID_DOT_ISOITU_TELEBIOMETRICS            "1.42"
#define R_ASN1_OID_DOT_ISOITU_CYBERSECURITY             "1.48"
#define R_ASN1_OID_DOT_ISOITU_ALERTING                  "1.49"
#define R_ASN1_OID_DOT_ISOITU_ORS                       "1.50"
#define R_ASN1_OID_DOT_ISOITU_GS1                       "1.51"
#define R_ASN1_OID_DOT_ISOITU_EXAMPLE                   "1.999"

/* ISO MEMBERS */
#define R_ASN_OID_DOT_ISO_AU            R_ASN1_OID_DOT_ISO_MEMBER_BODY".36"
#define R_ASN_OID_DOT_ISO_AT            R_ASN1_OID_DOT_ISO_MEMBER_BODY".40"
#define R_ASN_OID_DOT_ISO_BE            R_ASN1_OID_DOT_ISO_MEMBER_BODY".56"
#define R_ASN_OID_DOT_ISO_CN            R_ASN1_OID_DOT_ISO_MEMBER_BODY".156"
#define R_ASN_OID_DOT_ISO_CZ            R_ASN1_OID_DOT_ISO_MEMBER_BODY".203"
#define R_ASN_OID_DOT_ISO_DK            R_ASN1_OID_DOT_ISO_MEMBER_BODY".208"
#define R_ASN_OID_DOT_ISO_FI            R_ASN1_OID_DOT_ISO_MEMBER_BODY".246"
#define R_ASN_OID_DOT_ISO_FR            R_ASN1_OID_DOT_ISO_MEMBER_BODY".250"
#define R_ASN_OID_DOT_ISO_DE            R_ASN1_OID_DOT_ISO_MEMBER_BODY".276"
#define R_ASN_OID_DOT_ISO_GR            R_ASN1_OID_DOT_ISO_MEMBER_BODY".300"
#define R_ASN_OID_DOT_ISO_HK            R_ASN1_OID_DOT_ISO_MEMBER_BODY".344"
#define R_ASN_OID_DOT_ISO_IE            R_ASN1_OID_DOT_ISO_MEMBER_BODY".372"
#define R_ASN_OID_DOT_ISO_JP            R_ASN1_OID_DOT_ISO_MEMBER_BODY".392"
#define R_ASN_OID_DOT_ISO_KZ            R_ASN1_OID_DOT_ISO_MEMBER_BODY".398"
#define R_ASN_OID_DOT_ISO_KR            R_ASN1_OID_DOT_ISO_MEMBER_BODY".410"
#define R_ASN_OID_DOT_ISO_MD            R_ASN1_OID_DOT_ISO_MEMBER_BODY".498"
#define R_ASN_OID_DOT_ISO_NL            R_ASN1_OID_DOT_ISO_MEMBER_BODY".528"
#define R_ASN_OID_DOT_ISO_NG            R_ASN1_OID_DOT_ISO_MEMBER_BODY".566"
#define R_ASN_OID_DOT_ISO_NO            R_ASN1_OID_DOT_ISO_MEMBER_BODY".578"
#define R_ASN_OID_DOT_ISO_PL            R_ASN1_OID_DOT_ISO_MEMBER_BODY".616"
#define R_ASN_OID_DOT_ISO_RU            R_ASN1_OID_DOT_ISO_MEMBER_BODY".643"
#define R_ASN_OID_DOT_ISO_SG            R_ASN1_OID_DOT_ISO_MEMBER_BODY".702"
#define R_ASN_OID_DOT_ISO_VN            R_ASN1_OID_DOT_ISO_MEMBER_BODY".704"
#define R_ASN_OID_DOT_ISO_SE            R_ASN1_OID_DOT_ISO_MEMBER_BODY".752"
#define R_ASN_OID_DOT_ISO_UA            R_ASN1_OID_DOT_ISO_MEMBER_BODY".804"
#define R_ASN_OID_DOT_ISO_GB            R_ASN1_OID_DOT_ISO_MEMBER_BODY".826"
#define R_ASN_OID_DOT_ISO_US            R_ASN1_OID_DOT_ISO_MEMBER_BODY".840"
#define R_ASN_OID_DOT_ISO_UZ            R_ASN1_OID_DOT_ISO_MEMBER_BODY".860"
#define R_ASN_OID_DOT_ISO_VE            R_ASN1_OID_DOT_ISO_MEMBER_BODY".862"

R_BEGIN_DECLS

R_API rchar * r_asn1_oid_to_dot (const ruint32 * oid, rsize oidlen) R_ATTR_MALLOC;
R_API ruint32 * r_asn1_oid_from_dot (const rchar * oid, rssize oidsize,
    rsize * outlen) R_ATTR_MALLOC;

R_API rboolean r_asn1_oid_is_dot (const ruint32 * oid, rsize oidlen,
    const rchar * dot, rssize dotsize);
R_API rboolean r_asn1_oid_has_dot_prefix (const ruint32 * oid, rsize oidlen,
    const rchar * dot, rssize dotsize);

#define R_RSA_OID_RSADSI                    R_ASN_OID_DOT_ISO_US".113549"
#define R_RSA_OID_PKCS_1                    R_RSA_OID_RSADSI".1.1"
#define R_RSA_OID_PKCS_2                    R_RSA_OID_RSADSI".1.2"
#define R_RSA_OID_PKCS_3                    R_RSA_OID_RSADSI".1.3"
#define R_RSA_OID_PKCS_4                    R_RSA_OID_RSADSI".1.4"
#define R_RSA_OID_PKCS_5                    R_RSA_OID_RSADSI".1.5"
#define R_RSA_OID_PKCS_6                    R_RSA_OID_RSADSI".1.6"
#define R_RSA_OID_PKCS_7                    R_RSA_OID_RSADSI".1.7"
#define R_RSA_OID_PKCS_8                    R_RSA_OID_RSADSI".1.8"
#define R_RSA_OID_PKCS_9                    R_RSA_OID_RSADSI".1.9"
#define R_RSA_OID_PKCS_10                   R_RSA_OID_RSADSI".1.10"
#define R_RSA_OID_PKCS_11                   R_RSA_OID_RSADSI".1.11"
#define R_RSA_OID_PKCS_12                   R_RSA_OID_RSADSI".1.12"
#define R_RSA_OID_PKCS_13                   R_RSA_OID_RSADSI".1.13"
#define R_RSA_OID_PKCS_14                   R_RSA_OID_RSADSI".1.14"
#define R_RSA_OID_PKCS_15                   R_RSA_OID_RSADSI".1.15"

#define R_RSA_OID_RSA_ENCRYPTION            R_RSA_OID_PKCS_1".1"
#define R_RSA_OID_MD2_WITH_RSA              R_RSA_OID_PKCS_1".2"
#define R_RSA_OID_MD4_WITH_RSA              R_RSA_OID_PKCS_1".3"
#define R_RSA_OID_MD5_WITH_RSA              R_RSA_OID_PKCS_1".4"
#define R_RSA_OID_SHA1_WITH_RSA             R_RSA_OID_PKCS_1".5"
#define R_RSA_OID_OAEP_WITH_RSA             R_RSA_OID_PKCS_1".6"
#define R_RSA_OID_OAEP_WITH_RSAES           R_RSA_OID_PKCS_1".7"
#define R_RSA_OID_MGF1_WITH_RSA             R_RSA_OID_PKCS_1".8"
#define R_RSA_OID_PSPECIFIED                R_RSA_OID_PKCS_1".9"
#define R_RSA_OID_RSASSA_PSS                R_RSA_OID_PKCS_1".10"
#define R_RSA_OID_SHA256_WITH_RSA           R_RSA_OID_PKCS_1".11"
#define R_RSA_OID_SHA384_WITH_RSA           R_RSA_OID_PKCS_1".12"
#define R_RSA_OID_SHA512_WITH_RSA           R_RSA_OID_PKCS_1".13"
#define R_RSA_OID_SHA224_WITH_RSA           R_RSA_OID_PKCS_1".14"
#define R_RSA_OID_DH_KEY_AGREEMENT          R_RSA_OID_PKCS_3".1"
#define R_RSA_OID_PBE_WITH_MD2_AND_DES      R_RSA_OID_PKCS_5".1"
#define R_RSA_OID_PBE_WITH_MD5_AND_DES      R_RSA_OID_PKCS_5".3"
#define R_RSA_OID_PBE_WITH_MD2_AND_RC2      R_RSA_OID_PKCS_5".4"
#define R_RSA_OID_PBE_WITH_MD5_AND_RC2      R_RSA_OID_PKCS_5".6"
#define R_RSA_OID_PBE_WITH_MD5_AND_XOR      R_RSA_OID_PKCS_5".9"
#define R_RSA_OID_PBE_WITH_SHA1_AND_DES     R_RSA_OID_PKCS_5".10"
#define R_RSA_OID_PBE_WITH_SHA1_AND_RC2     R_RSA_OID_PKCS_5".11"
#define R_RSA_OID_PBKDF2                    R_RSA_OID_PKCS_5".12"
#define R_RSA_OID_PBES2                     R_RSA_OID_PKCS_5".13"
#define R_RSA_OID_PBMAC1                    R_RSA_OID_PKCS_5".14"

R_END_DECLS

#endif /* __R_ASN1_OID_H__ */

