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
#ifndef __R_CRYPTO_AES_H__
#define __R_CRYPTO_AES_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rcipher.h>

R_BEGIN_DECLS

#define R_AES_STR           "AES"
#define R_AES_BLOCK_BYTES   16

R_API RCryptoCipher * r_cipher_aes_new (RCryptoCipherMode mode, ruint bits, const ruint8 * key) R_ATTR_MALLOC;
R_API RCryptoCipher * r_cipher_aes_new_from_hex (RCryptoCipherMode mode, const rchar * hexkey) R_ATTR_MALLOC;
R_API RCryptoCipher * r_cipher_aes_128_ecb_new (const ruint8 * key) R_ATTR_MALLOC;
R_API RCryptoCipher * r_cipher_aes_192_ecb_new (const ruint8 * key) R_ATTR_MALLOC;
R_API RCryptoCipher * r_cipher_aes_256_ecb_new (const ruint8 * key) R_ATTR_MALLOC;
R_API RCryptoCipher * r_cipher_aes_128_cbc_new (const ruint8 * key) R_ATTR_MALLOC;
R_API RCryptoCipher * r_cipher_aes_192_cbc_new (const ruint8 * key) R_ATTR_MALLOC;
R_API RCryptoCipher * r_cipher_aes_256_cbc_new (const ruint8 * key) R_ATTR_MALLOC;


R_API rboolean r_cipher_aes_ecb_encrypt_block (const RCryptoCipher * cipher,
    ruint8 ciphertxt[R_AES_BLOCK_BYTES], const ruint8 plaintxt[R_AES_BLOCK_BYTES]);
R_API rboolean r_cipher_aes_ecb_decrypt_block (const RCryptoCipher * cipher,
    ruint8 plaintxt[R_AES_BLOCK_BYTES], const ruint8 ciphertxt[R_AES_BLOCK_BYTES]);

R_API RCryptoCipherResult r_cipher_aes_ecb_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
R_API RCryptoCipherResult r_cipher_aes_ecb_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);

R_API RCryptoCipherResult r_cipher_aes_cbc_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
R_API RCryptoCipherResult r_cipher_aes_cbc_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);

R_END_DECLS

#endif /* __R_CRYPTO_AES_H__ */

