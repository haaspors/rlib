/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_NET_PROTO_TLS13_H__
#define __R_NET_PROTO_TLS13_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/proto/rtls13.h
 * @brief TLS 1.3 (RFC 8446) key schedule primitives.
 */

#include <rlib/rtypes.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/crypto/rcipher.h>
#include <rlib/net/proto/rtls.h>

/**
 * @addtogroup r_tls_proto
 * @{
 */

R_BEGIN_DECLS

/**
 * @brief HKDF-Expand-Label (RFC 8446, section 7.1).
 *
 * Expand @p secret into @p outlen bytes under a TLS 1.3 @c HkdfLabel built from
 * @p label (automatically prefixed with @c "tls13 ") and @p context.
 *
 * @param hash     Digest of the cipher suite (e.g. @c R_MSG_DIGEST_TYPE_SHA256).
 * @param secret   The secret to expand; @c HashLen bytes.
 * @param label    Label without the @c "tls13 " prefix (e.g. @c "key",
 *                 @c "derived", @c "c hs traffic"); 1..249 bytes.
 * @param labellen Length of @p label in bytes.
 * @param context  Context bytes (e.g. a transcript hash); may be @c NULL when
 *                 @p ctxlen is 0.
 * @param ctxlen   Length of @p context, at most 255.
 * @param out      Destination for @p outlen bytes.
 * @param outlen   Number of bytes to derive; 1..65535.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_tls13_expand_label (RMsgDigestType hash,
    const ruint8 * secret, const rchar * label, rsize labellen,
    const ruint8 * context, rsize ctxlen, ruint8 * out, rsize outlen);

/**
 * @brief Derive-Secret (RFC 8446, section 7.1).
 *
 * @c HKDF-Expand-Label(secret, label, transcript_hash, HashLen): derive a new
 * @c HashLen-byte secret bound to a handshake-transcript hash.
 *
 * @param hash            Digest of the cipher suite.
 * @param secret          The input secret; @c HashLen bytes.
 * @param label           Label without the @c "tls13 " prefix.
 * @param labellen        Length of @p label in bytes.
 * @param transcript_hash @c Transcript-Hash(messages); @c HashLen bytes.
 * @param out             Destination for the @c HashLen-byte derived secret.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_tls13_derive_secret (RMsgDigestType hash,
    const ruint8 * secret, const rchar * label, rsize labellen,
    const ruint8 * transcript_hash, ruint8 * out);

/** @brief AEAD authentication tag size for the 1.3 cipher suites, in bytes. */
#define R_TLS13_AEAD_TAG_SIZE     16
/** @brief Maximum AEAD record-nonce length, in bytes. */
#define R_TLS13_AEAD_NONCE_MAX    16

/**
 * @brief Build the per-record AEAD nonce (RFC 8446, section 5.3).
 *
 * The 64-bit record @p seq is encoded big-endian, left-padded with zeros to
 * @p ivlen bytes, and XORed with the static write-IV @p iv.
 *
 * @param iv     Static write-IV from the key schedule; @p ivlen bytes.
 * @param ivlen  Nonce length (the AEAD's IV size); 1..@c R_TLS13_AEAD_NONCE_MAX.
 * @param seq    Record sequence number.
 * @param nonce  Destination for the @p ivlen-byte nonce.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_tls13_aead_nonce (const ruint8 * iv, rsize ivlen,
    ruint64 seq, ruint8 * nonce);

/**
 * @brief Protect a 1.3 record (RFC 8446, section 5.2).
 *
 * Appends the inner content type to @p content to form the @c TLSInnerPlaintext,
 * then AEAD-seals it with @p cipher under the nonce derived from @p iv and @p seq,
 * the @c additional_data being the @c TLSCiphertext record header. The resulting
 * @c encrypted_record (ciphertext followed by a @c R_TLS13_AEAD_TAG_SIZE tag) is
 * written to @p out; the caller frames it behind a 5-byte record header.
 *
 * @param cipher     AEAD cipher keyed with the write traffic key.
 * @param iv         Static write-IV; @p ivlen bytes.
 * @param ivlen      Nonce length.
 * @param seq        Record sequence number.
 * @param type       Real content type of @p content (@ref RTLSContentType).
 * @param content    Plaintext payload; @p contentlen bytes.
 * @param contentlen Payload length.
 * @param out        Destination for the @c encrypted_record.
 * @param outsize    Capacity of @p out in bytes.
 * @param outlen     Out: bytes written to @p out.
 * @return @c TRUE on success; @c FALSE on invalid arguments, too-small @p out,
 *  or a cipher failure.
 */
R_API rboolean r_tls13_record_protect (const RCryptoCipher * cipher,
    const ruint8 * iv, rsize ivlen, ruint64 seq,
    RTLSContentType type, const ruint8 * content, rsize contentlen,
    ruint8 * out, rsize outsize, rsize * outlen);

/**
 * @brief Unprotect a 1.3 record (RFC 8446, section 5.2).
 *
 * AEAD-opens @p record (the @c encrypted_record), strips the optional trailing
 * zero padding and the inner content-type byte, and yields the plaintext and its
 * real content type.
 *
 * @param cipher  AEAD cipher keyed with the read traffic key.
 * @param iv      Static read-IV; @p ivlen bytes.
 * @param ivlen   Nonce length.
 * @param seq     Record sequence number.
 * @param record  The @c encrypted_record (ciphertext + tag); @p reclen bytes.
 * @param reclen  Length of @p record.
 * @param out     Destination for the recovered plaintext.
 * @param outsize Capacity of @p out in bytes.
 * @param outlen  Out: plaintext length written to @p out.
 * @param type    Out: recovered content type (@ref RTLSContentType).
 * @return @c TRUE on success; @c FALSE on invalid arguments, authentication
 *  failure, an all-zero (typeless) plaintext, or too-small @p out.
 */
R_API rboolean r_tls13_record_unprotect (const RCryptoCipher * cipher,
    const ruint8 * iv, rsize ivlen, ruint64 seq,
    const ruint8 * record, rsize reclen,
    ruint8 * out, rsize outsize, rsize * outlen, RTLSContentType * type);

/** @brief Maximum DTLS 1.3 sequence-number length on the wire, in bytes. */
#define R_DTLS13_SN_MAX           2

/**
 * @brief Derive the DTLS 1.3 record-number protection key (RFC 9147, 4.2.3).
 *
 * @c sn_key = HKDF-Expand-Label(secret, "sn", "", key_length): a key, the same
 * length as the AEAD key, that masks the on-the-wire record sequence number.
 *
 * @param hash   Digest of the cipher suite.
 * @param secret The traffic secret to expand; @c HashLen bytes.
 * @param keylen Key length in bytes (the AEAD key length: 16 or 32).
 * @param sn_key Destination for @p keylen bytes.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_dtls13_sn_key (RMsgDigestType hash, const ruint8 * secret,
    rsize keylen, ruint8 * sn_key);

/**
 * @brief Compute the DTLS 1.3 sequence-number mask (RFC 9147, 4.2.3).
 *
 * Derives the mask that encrypts (or decrypts) the record sequence number from a
 * ciphertext sample. For an AES AEAD the mask is @c AES-ECB(sn_key,
 * Ciphertext[0..15]); for ChaCha20 it is the ChaCha20 block keystream with
 * @c Ciphertext[0..3] as the (little-endian) block counter and
 * @c Ciphertext[4..15] as the nonce. The caller XORs the @p masklen leading mask
 * bytes onto the on-the-wire sequence-number bytes.
 *
 * @param aead      AEAD algorithm family: @c R_CRYPTO_CIPHER_ALGO_AES or
 *                  @c R_CRYPTO_CIPHER_ALGO_CHACHA20.
 * @param sn_key    The sequence-number key from @ref r_dtls13_sn_key.
 * @param sn_keylen Key length in bytes (16 or 32 for AES; 32 for ChaCha20).
 * @param ciphertext The record ciphertext sample; @p ctlen bytes.
 * @param ctlen     Length of @p ciphertext; must be at least 16.
 * @param mask      Destination for @p masklen mask bytes.
 * @param masklen   Number of mask bytes to produce; 1..@ref R_DTLS13_SN_MAX.
 * @return @c TRUE on success; @c FALSE on invalid arguments, a too-short
 *  ciphertext, or a cipher failure.
 */
R_API rboolean r_dtls13_sn_mask (RCryptoCipherAlgorithm aead,
    const ruint8 * sn_key, rsize sn_keylen,
    const ruint8 * ciphertext, rsize ctlen, ruint8 * mask, rsize masklen);

/** @brief Largest TLS 1.3 secret / digest, in bytes (SHA-384). */
#define R_TLS13_SECRET_MAX        48

/**
 * @brief Per-direction installed TLS 1.3 record keys (RFC 8446, section 7.3).
 *
 * Holds the AEAD cipher keyed with a traffic key, its static IV, and the
 * record sequence number, which restarts at zero whenever a new traffic key is
 * installed (handshake then application).
 */
typedef struct {
  RCryptoCipher * cipher;             /**< @brief AEAD keyed with the traffic key. */
  ruint8 iv[R_TLS13_AEAD_NONCE_MAX];  /**< @brief Static write/read IV. */
  rsize ivlen;                        /**< @brief IV length in bytes. */
  ruint64 seq;                        /**< @brief Record counter; resets on rekey. */
} RTLS13RecordKeys;
/** @brief Static initialiser for an empty @ref RTLS13RecordKeys. */
#define R_TLS13_RECORD_KEYS_INIT    { NULL, { 0, }, 0, 0 }

/**
 * @brief TLS 1.3 1-RTT key schedule (RFC 8446, section 7.1).
 *
 * Carries the extract/derive secrets, hash-agnostic so the same struct serves
 * the SHA-256 (@c TLS_AES_128_GCM_SHA256) and SHA-384
 * (@c TLS_AES_256_GCM_SHA384) cipher suites. Drive it with
 * @ref r_tls13_schedule_init, then @ref r_tls13_schedule_handshake (after the
 * ServerHello) and @ref r_tls13_schedule_master (after the server Finished).
 */
typedef struct {
  RMsgDigestType hash;                /**< @brief Cipher-suite hash. */
  rsize hlen;                         /**< @brief @p hash output length. */
  ruint8 early[R_TLS13_SECRET_MAX];      /**< @brief Early Secret. */
  ruint8 handshake[R_TLS13_SECRET_MAX];  /**< @brief Handshake Secret. */
  ruint8 master[R_TLS13_SECRET_MAX];     /**< @brief Master Secret. */
  ruint8 chs[R_TLS13_SECRET_MAX];        /**< @brief client_handshake_traffic_secret. */
  ruint8 shs[R_TLS13_SECRET_MAX];        /**< @brief server_handshake_traffic_secret. */
  ruint8 cap[R_TLS13_SECRET_MAX];        /**< @brief client_application_traffic_secret_0. */
  ruint8 sap[R_TLS13_SECRET_MAX];        /**< @brief server_application_traffic_secret_0. */
  ruint8 res_master[R_TLS13_SECRET_MAX]; /**< @brief resumption_master_secret. */
  ruint8 cet[R_TLS13_SECRET_MAX];        /**< @brief client_early_traffic_secret. */
} RTLS13Schedule;

/**
 * @brief Initialise the key schedule and compute the Early Secret.
 *
 * With no PSK the Early Secret is @c HKDF-Extract(0, 0^HashLen).
 *
 * @param sched Schedule to initialise.
 * @param hash  Cipher-suite hash (SHA-256 / SHA-384).
 * @return @c TRUE on success; @c FALSE on an unsupported hash.
 */
R_API rboolean r_tls13_schedule_init (RTLS13Schedule * sched, RMsgDigestType hash);

/**
 * @brief Initialise the key schedule with a resumption PSK.
 *
 * The Early Secret becomes @c HKDF-Extract(0, PSK) instead of the PSK-less
 * @c HKDF-Extract(0, 0^HashLen); the caller drives the rest of the schedule
 * (@ref r_tls13_schedule_handshake, @ref r_tls13_schedule_master) exactly as in
 * the full handshake. The @p psk is the ticket-derived secret from
 * @ref r_tls13_resumption_psk and its length is the suite's @c HashLen.
 *
 * @param sched  Schedule to initialise.
 * @param hash   Cipher-suite hash (SHA-256 / SHA-384).
 * @param psk    The pre-shared key; @c HashLen bytes.
 * @param psklen Length of @p psk.
 * @return @c TRUE on success; @c FALSE on an unsupported hash or @c NULL @p psk.
 */
R_API rboolean r_tls13_schedule_init_psk (RTLS13Schedule * sched,
    RMsgDigestType hash, const ruint8 * psk, rsize psklen);

/**
 * @brief Derive the resumption binder key (RFC 8446, section 7.1).
 *
 * @c binder_key = Derive-Secret(Early, "res binder", ""). The caller expands it
 * into a Finished key with @ref r_tls13_finished_key and computes the
 * @c pre_shared_key binder over the partial ClientHello transcript with
 * @ref r_tls13_verify_data, the same construction as a Finished message.
 *
 * @param sched Schedule whose Early Secret was set from the PSK
 *              (@ref r_tls13_schedule_init_psk, or @ref r_tls13_schedule_init
 *              for the PSK-less binder in an external-PSK offer).
 * @param out   Destination for the @c HashLen-byte binder key.
 * @return @c TRUE on success.
 */
R_API rboolean r_tls13_binder_key (const RTLS13Schedule * sched, ruint8 * out);

/**
 * @brief Derive the client early-traffic secret for 0-RTT (RFC 8446, 7.1).
 *
 * @c client_early_traffic_secret = Derive-Secret(Early, "c e traffic",
 * Transcript-Hash(ClientHello)); stored in @c sched->cet. It protects the 0-RTT
 * data the client sends immediately after a resumption ClientHello (and the
 * @c EndOfEarlyData that closes the early-data flow), so it is bound to the
 * ClientHello alone -- before the ServerHello, unlike the handshake secrets.
 * The Early Secret must have been set from the ticket PSK
 * (@ref r_tls13_schedule_init_psk).
 *
 * @param sched           Schedule whose Early Secret was set from the PSK.
 * @param transcript_hash @c Transcript-Hash(ClientHello); @c HashLen bytes.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_tls13_schedule_early (RTLS13Schedule * sched,
    const ruint8 * transcript_hash);

/**
 * @brief Derive the Handshake Secret and the handshake-traffic secrets.
 *
 * @c Handshake = HKDF-Extract(Derive-Secret(Early, "derived", ""), ECDHE);
 * the @c "c hs traffic" / @c "s hs traffic" secrets are bound to
 * @p transcript_hash = @c Transcript-Hash(ClientHello..ServerHello).
 *
 * @param sched           Schedule, already @ref r_tls13_schedule_init.
 * @param ecdhe           The (EC)DHE shared secret.
 * @param ecdhelen        Length of @p ecdhe.
 * @param transcript_hash @c Transcript-Hash(ClientHello..ServerHello); @c HashLen bytes.
 * @return @c TRUE on success.
 */
R_API rboolean r_tls13_schedule_handshake (RTLS13Schedule * sched,
    const ruint8 * ecdhe, rsize ecdhelen, const ruint8 * transcript_hash);

/**
 * @brief Derive the Master Secret and the application-traffic secrets.
 *
 * @c Master = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0^HashLen);
 * the @c "c ap traffic" / @c "s ap traffic" secrets are bound to
 * @p transcript_hash = @c Transcript-Hash(ClientHello..server Finished).
 *
 * @param sched           Schedule, already @ref r_tls13_schedule_handshake.
 * @param transcript_hash @c Transcript-Hash(ClientHello..server Finished); @c HashLen bytes.
 * @return @c TRUE on success.
 */
R_API rboolean r_tls13_schedule_master (RTLS13Schedule * sched,
    const ruint8 * transcript_hash);

/**
 * @brief Derive the resumption master secret (RFC 8446, section 7.1).
 *
 * @c resumption_master_secret = Derive-Secret(Master, "res master",
 * Transcript-Hash(ClientHello..client Finished)); stored in @c sched->res_master
 * for @ref r_tls13_resumption_psk to expand into per-ticket PSKs. Bound to the
 * transcript through the client Finished, so it is derived once the handshake
 * has completed (unlike the application secrets, bound through the server
 * Finished).
 *
 * @param sched           Schedule, already @ref r_tls13_schedule_master.
 * @param transcript_hash @c Transcript-Hash(ClientHello..client Finished); @c HashLen bytes.
 * @return @c TRUE on success.
 */
R_API rboolean r_tls13_schedule_resumption (RTLS13Schedule * sched,
    const ruint8 * transcript_hash);

/**
 * @brief Expand a per-ticket resumption PSK (RFC 8446, section 4.6.1).
 *
 * @c PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
 * ticket_nonce, HashLen): the pre-shared key a NewSessionTicket represents,
 * bound to that ticket's @p nonce so distinct tickets from one connection yield
 * distinct PSKs.
 *
 * @param hash       Cipher-suite hash.
 * @param res_master The resumption master secret (@ref RTLS13Schedule.res_master);
 *                   @c HashLen bytes.
 * @param nonce      The ticket_nonce; may be @c NULL when @p noncelen is 0.
 * @param noncelen   Length of @p nonce, at most 255.
 * @param out        Destination for the @c HashLen-byte PSK.
 * @return @c TRUE on success; @c FALSE on invalid arguments.
 */
R_API rboolean r_tls13_resumption_psk (RMsgDigestType hash,
    const ruint8 * res_master, const ruint8 * nonce, rsize noncelen,
    ruint8 * out);

/**
 * @brief Derive the @c "key" / @c "iv" traffic keys from a traffic secret.
 *
 * Instantiates @p out->cipher for @p info keyed with
 * @c HKDF-Expand-Label(secret, "key", "", keylen) and fills the static IV from
 * @c HKDF-Expand-Label(secret, "iv", "", info->ivsize); @c out->seq is reset to 0.
 *
 * @param hash   Cipher-suite hash.
 * @param secret A traffic secret (@c HashLen bytes).
 * @param info   AEAD cipher descriptor (e.g. AES-128-GCM).
 * @param out    Receives the keyed cipher, IV and zeroed sequence number.
 * @return @c TRUE on success; @c FALSE on a derivation or cipher failure.
 */
R_API rboolean r_tls13_traffic_keys (RMsgDigestType hash, const ruint8 * secret,
    const RCryptoCipherInfo * info, RTLS13RecordKeys * out);

/**
 * @brief Advance an application-traffic secret one generation (RFC 8446, 7.2).
 *
 * @c application_traffic_secret_N+1 =
 * @c HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "",
 * Hash.length): the rekeying a @c KeyUpdate performs. Re-derive the record keys
 * from @p out with @ref r_tls13_traffic_keys. @p out may alias @p secret for an
 * in-place advance.
 *
 * @param hash   Cipher-suite hash.
 * @param secret The current application-traffic secret; @c HashLen bytes.
 * @param out    Destination for the next-generation secret; @c HashLen bytes.
 * @return @c TRUE on success; @c FALSE on invalid arguments or a derivation
 *  failure.
 */
R_API rboolean r_tls13_traffic_update (RMsgDigestType hash,
    const ruint8 * secret, ruint8 * out);

/**
 * @brief Derive a Finished key from a handshake-traffic secret.
 *
 * @c finished_key = HKDF-Expand-Label(secret, "finished", "", HashLen).
 *
 * @param hash   Cipher-suite hash.
 * @param secret The handshake-traffic secret (@c HashLen bytes).
 * @param out    Destination for the @c HashLen-byte Finished key.
 * @return @c TRUE on success.
 */
R_API rboolean r_tls13_finished_key (RMsgDigestType hash, const ruint8 * secret,
    ruint8 * out);

/**
 * @brief Compute Finished verify_data (RFC 8446, section 4.4.4).
 *
 * @c verify_data = HMAC(finished_key, Transcript-Hash(...)).
 *
 * @param hash            Cipher-suite hash.
 * @param finished_key    A Finished key from @ref r_tls13_finished_key.
 * @param transcript_hash The bound transcript hash; @c HashLen bytes.
 * @param out             Destination for the @c HashLen-byte verify_data.
 * @return @c TRUE on success.
 */
R_API rboolean r_tls13_verify_data (RMsgDigestType hash,
    const ruint8 * finished_key, const ruint8 * transcript_hash, ruint8 * out);

/** @brief Largest CertificateVerify signed content for the 1.3 hashes, in bytes. */
#define R_TLS13_CERT_VERIFY_TBS_MAX   (64 + 33 + 1 + R_TLS13_SECRET_MAX)

/**
 * @brief Build the CertificateVerify signed content (RFC 8446, section 4.4.3).
 *
 * @c 0x20*64 || context_string || 0x00 || @p transcript_hash, where the context
 * is @c "TLS 1.3, server CertificateVerify" (@p server @c TRUE) or
 * @c "...client...". The caller hashes this with the signature scheme's digest
 * and signs / verifies it.
 *
 * @param server          @c TRUE for the server context string, else the client's.
 * @param transcript_hash The bound transcript hash.
 * @param thlen           Length of @p transcript_hash.
 * @param out             Destination buffer.
 * @param outsize         Capacity of @p out (see @ref R_TLS13_CERT_VERIFY_TBS_MAX).
 * @param outlen          Out: bytes written.
 * @return @c TRUE on success; @c FALSE on a @c NULL argument or too-small @p out.
 */
R_API rboolean r_tls13_cert_verify_tbs (rboolean server,
    const ruint8 * transcript_hash, rsize thlen,
    ruint8 * out, rsize outsize, rsize * outlen);

/**
 * @brief Write the special HelloRetryRequest random (RFC 8446, section 4.1.3).
 *
 * A HelloRetryRequest is a ServerHello whose @c random is the fixed value
 * @c SHA-256("HelloRetryRequest"); this fills @p out with it.
 *
 * @param out Destination for the @ref R_TLS_HELLO_RANDOM_BYTES-byte value.
 */
R_API void r_tls13_hello_retry_random (ruint8 * out);

/**
 * @brief Whether a ServerHello @p random is the HelloRetryRequest sentinel.
 * @param random A ServerHello random field; @ref R_TLS_HELLO_RANDOM_BYTES bytes.
 * @return @c TRUE if @p random equals @c SHA-256("HelloRetryRequest").
 */
R_API rboolean r_tls13_random_is_hrr (const ruint8 * random);

/**
 * @brief Stamp the downgrade-protection sentinel into a ServerHello @p random
 * (RFC 8446, section 4.1.3).
 *
 * A server that supports TLS 1.3 but settles on a lower version overwrites the
 * last eight bytes of its ServerHello.random with a fixed sentinel so that a
 * 1.3-capable client can detect a forced downgrade: @c "DOWNGRD\x01"
 * (@c 44 4F 57 4E 47 52 44 01) when negotiating TLS 1.2, or @c "DOWNGRD\x00"
 * when negotiating TLS 1.1 or below. For any other @p negotiated version
 * (including 1.3 itself) @p random is left unchanged.
 *
 * @param random     ServerHello random to stamp; @ref R_TLS_HELLO_RANDOM_BYTES
 *                   bytes. The leading bytes are preserved.
 * @param negotiated The version the server selected.
 */
R_API void r_tls13_downgrade_random (ruint8 * random, RTLSVersion negotiated);

/**
 * @brief Whether a ServerHello @p random carries a downgrade sentinel.
 *
 * A 1.3-capable client that offered TLS 1.3 but was answered with a lower
 * version checks the ServerHello.random with this; a @c TRUE result is a
 * detected downgrade and the client must abort with @c illegal_parameter
 * (RFC 8446, section 4.1.3).
 *
 * @param random A ServerHello random field; @ref R_TLS_HELLO_RANDOM_BYTES bytes.
 * @return @c TRUE if the last eight bytes equal either downgrade sentinel.
 */
R_API rboolean r_tls13_random_is_downgrade (const ruint8 * random);

/**
 * @brief Build the synthetic @c message_hash handshake message (RFC 8446, 4.4.1).
 *
 * When a HelloRetryRequest is used the transcript replaces the first
 * ClientHello with @c Handshake(message_hash) carrying @c Hash(ClientHello1):
 * the handshake header (@c message_hash type @c 0xfe and a 3-byte length) over a
 * body of @c Hash(@p msg). The caller folds the result into the transcript.
 *
 * @param hash   Cipher-suite hash.
 * @param msg    The first ClientHello (handshake header + body).
 * @param msglen Length of @p msg.
 * @param out    Destination for the @c message_hash handshake message.
 * @param outsize Capacity of @p out (at least @c 4 + HashLen).
 * @param outlen  Out: bytes written (@c 4 + HashLen).
 * @return @c TRUE on success; @c FALSE on invalid arguments / too-small @p out.
 */
R_API rboolean r_tls13_message_hash (RMsgDigestType hash,
    const ruint8 * msg, rsize msglen, ruint8 * out, rsize outsize, rsize * outlen);

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_TLS13_H__ */
