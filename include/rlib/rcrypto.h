/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_H__
#define __R_CRYPTO_H__

/**
 * @defgroup r_crypto Cryptography
 *
 * @brief Symmetric and asymmetric primitives, message digests, MACs,
 * elliptic curves, certificates and the wire-format encodings (PEM,
 * ASN.1) that surround them.
 *
 * The crypto API breaks into the following sub-areas:
 *
 *   - @ref r_crypto_symmetric — block / stream cipher base, AES and ChaCha20.
 *   - @ref r_crypto_hash — message digests and HMAC.
 *   - @ref r_crypto_key — polymorphic asymmetric-key handle plus the
 *     concrete key kinds (RSA, DSA, DH) that plug into it.
 *   - @ref r_crypto_ec — elliptic-curve arithmetic and the EdDSA /
 *     X25519 / X448 primitives layered on top.
 *   - @ref r_crypto_cert — generic certificate handle plus X.509.
 *   - @ref r_crypto_encoding — PEM container framing. ASN.1 BER / DER
 *     lives under @ref r_format alongside the other structured-data
 *     codecs; the crypto headers consume it heavily.
 *   - @ref r_crypto_ciphersuite — SRTP and TLS ciphersuite tables.
 */

/**
 * @defgroup r_crypto_symmetric Symmetric ciphers
 * @ingroup r_crypto
 *
 * @brief Block / stream cipher base interface and the concrete
 * algorithm implementations that plug into it.
 */

/**
 * @defgroup r_crypto_hash Message digests and MACs
 * @ingroup r_crypto
 *
 * @brief Cryptographic hash functions plus the HMAC construction
 * that turns them into keyed message-authentication codes.
 */

/**
 * @defgroup r_crypto_ec Elliptic curves
 * @ingroup r_crypto
 *
 * @brief Curve arithmetic over GF(p) for the three families rlib
 * carries (short-Weierstrass, twisted Edwards, Montgomery) plus the
 * signature (Ed25519 / Ed448) and key-exchange (X25519 / X448)
 * primitives layered on top.
 */

/**
 * @defgroup r_crypto_encoding Wire-format encodings
 * @ingroup r_crypto
 *
 * @brief PEM container parsing / emission. ASN.1 BER and DER live
 * under @ref r_format alongside the other structured-data codecs;
 * the crypto headers consume them heavily, so they are listed here
 * as adjacent reading.
 */

/**
 * @defgroup r_crypto_cert Certificates
 * @ingroup r_crypto
 *
 * @brief Generic certificate handle (@c RCryptoCert) plus the X.509
 * concrete instantiation.
 */

/**
 * @defgroup r_crypto_ciphersuite Ciphersuite tables
 * @ingroup r_crypto
 *
 * @brief Lookup tables describing the parameters of SRTP and TLS
 * ciphersuites by their IANA / RFC identifier.
 */

#include <rlib/rlib.h>

#include <rlib/crypto/raes.h>
#include <rlib/crypto/rchacha20.h>
#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rdh.h>
#include <rlib/crypto/rdsa.h>
#include <rlib/crypto/recc.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/recurve-edwards.h>
#include <rlib/crypto/red25519.h>
#include <rlib/crypto/red448.h>
#include <rlib/crypto/recurve-montgomery.h>
#include <rlib/crypto/rhmac.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/crypto/rpem.h>
#include <rlib/crypto/rrsa.h>
#include <rlib/crypto/rxdh.h>
#include <rlib/crypto/rsrtpciphersuite.h>
#include <rlib/crypto/rtlsciphersuite.h>
#include <rlib/crypto/rx509.h>

#endif /* __R_CRYPTO_H__ */

