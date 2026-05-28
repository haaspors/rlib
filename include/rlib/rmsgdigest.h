/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2017  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_MSG_DIGEST_H__
#define __R_MSG_DIGEST_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

/**
 * @defgroup r_msg_digest Cryptographic message digests
 * @brief MD2 / MD4 / MD5 / SHA-1 / SHA-2 family hashes plus the
 * SHAKE256 extendable-output function (XOF).
 * @{
 */

/**
 * @file rlib/rmsgdigest.h
 * @brief Cryptographic message digests with a uniform absorb /
 * finalise / extract interface.
 *
 * The module surface is a single opaque @c RMsgDigest type
 * constructed via one of the per-algorithm @c r_msg_digest_new_*
 * helpers (or the type-dispatched @c r_msg_digest_new). Drive it
 * with one or more @c r_msg_digest_update calls and then extract
 * the result with @c r_msg_digest_get_data.
 *
 * Fixed-output digests (MD2 / MD4 / MD5 / SHA-1 / SHA-2 family)
 * write exactly @c r_msg_digest_size bytes on every extract. The
 * extendable-output function @c R_MSG_DIGEST_TYPE_SHAKE256 (FIPS
 * 202 §6.2) is driven through @c r_msg_digest_squeeze instead:
 * the output length is a caller-chosen per-call parameter and the
 * sponge can be squeezed incrementally across multiple calls.
 *
 * Free with @c r_msg_digest_free; the destructor wipes the
 * compression-variable state with @c r_memclear_secure since
 * mid-stream state can be key-dependent for HMAC / KDF callers.
 */

R_BEGIN_DECLS

/**
 * @brief Message-digest algorithm identifier.
 */
typedef enum {
  R_MSG_DIGEST_TYPE_NONE = -1,    /**< @brief Sentinel for "no algorithm". */
  R_MSG_DIGEST_TYPE_MD2,          /**< @brief RSA MD2 (RFC 1319). Deprecated for any new use. */
  R_MSG_DIGEST_TYPE_MD4,          /**< @brief RSA MD4 (RFC 1320). Deprecated. */
  R_MSG_DIGEST_TYPE_MD5,          /**< @brief RSA MD5 (RFC 1321). Broken; for legacy interop only. */
  R_MSG_DIGEST_TYPE_SHA1,         /**< @brief SHA-1 (FIPS 180-4). 160-bit output. */
  R_MSG_DIGEST_TYPE_SHA224,       /**< @brief SHA-224 (FIPS 180-4). 224-bit output. */
  R_MSG_DIGEST_TYPE_SHA256,       /**< @brief SHA-256 (FIPS 180-4). 256-bit output. */
  R_MSG_DIGEST_TYPE_SHA384,       /**< @brief SHA-384 (FIPS 180-4). 384-bit output. */
  R_MSG_DIGEST_TYPE_SHA512,       /**< @brief SHA-512 (FIPS 180-4). 512-bit output. */
  /**
   * @brief SHAKE256 extendable-output function (FIPS 202 §6.2).
   *
   * The output length is a caller-chosen per-squeeze parameter.
   * @c r_msg_digest_type_size returns @c 0 for this type; drive
   * extraction via @c r_msg_digest_squeeze rather than
   * @c r_msg_digest_get_data.
   */
  R_MSG_DIGEST_TYPE_SHAKE256,
  R_MSG_DIGEST_TYPE_COUNT,        /**< @brief Number of valid types. */
} RMsgDigestType;

/**
 * @brief Output size in bytes for the named algorithm.
 *
 * @return The fixed output length for Merkle-Damgård digests, or
 *         @c 0 for XOF / unknown types (for an XOF the per-squeeze
 *         length is the caller's choice).
 */
R_API rsize r_msg_digest_type_size (RMsgDigestType type);
/**
 * @brief Block size in bytes for the named algorithm.
 *
 * For Merkle-Damgård digests this is the compression-function
 * block size (e.g. @c 64 for SHA-256). For @c SHAKE256 it is the
 * sponge rate (136 bytes).
 *
 * @return Block / rate size, or @c 0 for unknown types.
 */
R_API rsize r_msg_digest_type_blocksize (RMsgDigestType type);
/**
 * @brief Canonical lowercase string name for the algorithm
 * (e.g. @c "sha-256").
 *
 * @return @c NULL for @c R_MSG_DIGEST_TYPE_NONE or unknown values.
 */
R_API const rchar * r_msg_digest_type_string (RMsgDigestType type);
/**
 * @brief Inverse of @c r_msg_digest_type_string: parse an algorithm
 * name.
 *
 * Comparison is case-insensitive. Pass @c size = @c -1 to use the
 * NUL-terminated length of @p str.
 *
 * @return The matching enum value, or @c R_MSG_DIGEST_TYPE_NONE.
 */
R_API RMsgDigestType r_msg_digest_type_from_str (const rchar * str, rssize size);

/** @brief Opaque message-digest state handle. */
typedef struct RMsgDigest RMsgDigest;

/**
 * @brief Allocate a fresh digest for the given algorithm.
 *
 * Dispatches to the per-algorithm constructor
 * (@c r_msg_digest_new_*). The returned object is owned by the
 * caller and freed with @c r_msg_digest_free.
 *
 * @return New digest handle, or @c NULL on unknown @p type or
 *         allocation failure.
 */
R_API RMsgDigest * r_msg_digest_new (RMsgDigestType type);

/**
 * @brief Free a digest and securely wipe its internal state.
 *
 * @param md  Digest to free; may be @c NULL.
 */
R_API void r_msg_digest_free (RMsgDigest * md);

R_API RMsgDigest * r_msg_digest_new_md2 (void);     /**< @brief Construct a fresh MD2 digest. */
R_API RMsgDigest * r_msg_digest_new_md4 (void);     /**< @brief Construct a fresh MD4 digest. */
R_API RMsgDigest * r_msg_digest_new_md5 (void);     /**< @brief Construct a fresh MD5 digest. */
R_API RMsgDigest * r_msg_digest_new_sha1 (void);    /**< @brief Construct a fresh SHA-1 digest. */
R_API RMsgDigest * r_msg_digest_new_sha224 (void);  /**< @brief Construct a fresh SHA-224 digest. */
R_API RMsgDigest * r_msg_digest_new_sha256 (void);  /**< @brief Construct a fresh SHA-256 digest. */
R_API RMsgDigest * r_msg_digest_new_sha384 (void);  /**< @brief Construct a fresh SHA-384 digest. */
R_API RMsgDigest * r_msg_digest_new_sha512 (void);  /**< @brief Construct a fresh SHA-512 digest. */
/**
 * @brief Construct a fresh SHAKE256 sponge.
 *
 * After zero or more @c r_msg_digest_update calls, extract output
 * via @c r_msg_digest_squeeze. @c r_msg_digest_get_data is not
 * supported for XOF types and will return @c FALSE.
 */
R_API RMsgDigest * r_msg_digest_new_shake256 (void);

#define r_md2_new r_msg_digest_new_md2          /**< @brief Short alias. */
#define r_md4_new r_msg_digest_new_md4          /**< @brief Short alias. */
#define r_md5_new r_msg_digest_new_md5          /**< @brief Short alias. */
#define r_sha1_new r_msg_digest_new_sha1        /**< @brief Short alias. */
#define r_sha224_new r_msg_digest_new_sha224    /**< @brief Short alias. */
#define r_sha256_new r_msg_digest_new_sha256    /**< @brief Short alias. */
#define r_sha384_new r_msg_digest_new_sha384    /**< @brief Short alias. */
#define r_sha512_new r_msg_digest_new_sha512    /**< @brief Short alias. */
#define r_shake256_new r_msg_digest_new_shake256 /**< @brief Short alias. */

/**
 * @brief Output size in bytes for @p md.
 *
 * @return The fixed output length, or @c 0 for XOFs (the size is
 *         per-squeeze and the caller picks).
 */
R_API rsize r_msg_digest_size (const RMsgDigest * md);
/** @brief Compression-function block size in bytes for @p md. */
R_API rsize r_msg_digest_blocksize (const RMsgDigest * md);

/** @brief Reset @p md to the post-construction state, dropping any
 *  accumulated input. */
R_API void r_msg_digest_reset (RMsgDigest * md);
/**
 * @brief Absorb @p size bytes from @p data into @p md.
 *
 * Returns @c FALSE if @p md has already been finalised (either via
 * @c r_msg_digest_finish or implicitly by the first squeeze of a
 * XOF).
 */
R_API rboolean r_msg_digest_update (RMsgDigest * md, rconstpointer data, rsize size);
/**
 * @brief Run the finalisation step (padding plus the
 * length-encoded final compression).
 *
 * @c r_msg_digest_get_data calls this implicitly via a cloned
 * state, so callers that only want to read the digest don't have to
 * invoke @c r_msg_digest_finish explicitly. After @c finish no
 * further @c update is allowed.
 */
R_API rboolean r_msg_digest_finish (RMsgDigest * md);

/**
 * @brief Extract the digest result into @p data.
 *
 * Internally clones @p md and finalises the clone so the caller can
 * continue updating the original; this works for fixed-output
 * digests only. For XOF types this returns @c FALSE - drive
 * extraction via @c r_msg_digest_squeeze instead.
 *
 * @param md    Digest to read from. Const because the caller-visible
 *              state is preserved.
 * @param data  Destination buffer.
 * @param size  Capacity of @p data.
 * @param out   Out-pointer for the bytes written.
 * @return @c TRUE on success.
 */
R_API rboolean r_msg_digest_get_data (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);

/**
 * @brief Pull @p size bytes of XOF output from @p md.
 *
 * Only valid for XOF types (@c R_MSG_DIGEST_TYPE_SHAKE256); returns
 * @c FALSE for fixed-output digests.
 *
 * Implicitly finalises on the first call, after which no further
 * @c r_msg_digest_update is allowed. Subsequent @c _squeeze calls
 * pull the next chunk of output from the sponge - so squeezing
 * @c n + @c m bytes in two calls of @c n then @c m produces the same
 * byte sequence as a single @c n + @c m -byte squeeze. Reset with
 * @c r_msg_digest_reset to absorb a fresh message.
 *
 * @param md    XOF digest.
 * @param data  Destination buffer.
 * @param size  Bytes to extract.
 * @return @c TRUE on success; @c FALSE on NULL inputs or non-XOF type.
 */
R_API rboolean r_msg_digest_squeeze (RMsgDigest * md, ruint8 * data, rsize size);
/**
 * @brief Return the digest result as a heap-allocated lowercase hex
 * string. Caller frees with @c r_free.
 */
R_API rchar * r_msg_digest_get_hex (const RMsgDigest * md);
/**
 * @brief Like @c r_msg_digest_get_hex but with @p divider inserted
 * between every @p interval bytes (useful for fingerprint-style
 * formatting like @c "01:23:45:..."). Caller frees with @c r_free.
 */
R_API rchar * r_msg_digest_get_hex_full (const RMsgDigest * md,
    const rchar * divider, rsize interval);

R_END_DECLS

/** @} */

#endif /* __R_MSG_DIGEST_H__ */
