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
#ifndef __R_NET_PROTO_TLS_PRIV_H__
#define __R_NET_PROTO_TLS_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rtls-private.h should only be used internally in rlib!"
#endif

#include <rlib/net/proto/rtls.h>
#include <rlib/net/proto/rtls12.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/rdh.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/rrand.h>
#include <rlib/rtime.h>
#include <rlib/rtypes.h>
#include <rlib/rclock.h>
#include <rlib/rbuffer.h>
#include <rlib/ev/revloop.h>
#include <rlib/data/rptrarray.h>
#include <rlib/data/rqueue.h>

R_BEGIN_DECLS

/* --- DTLS 1.3 flight retransmission (RFC 9147 5.8) + ACKs (7) ----------------
 * The handshake retransmits its last flight on a timer with exponential backoff
 * until the peer's response (or an ACK) confirms delivery. */
#define R_DTLS13_RTX_INITIAL      (R_SECOND)        /* initial retransmit timeout */
#define R_DTLS13_RTX_MAX          (60 * R_SECOND)   /* backoff ceiling */
#define R_DTLS13_RTX_TRIES        8                 /* give up after this many */
#define R_DTLS13_ACK_MAX          16                /* record numbers tracked per ACK */

/* One captured flight record, tagged with its (epoch, sequence_number) so an ACK
 * can acknowledge it individually (RFC 9147 7.1). */
typedef struct {
  RBuffer * rec;
  RDtls13RecordNumber num;
} RDtls13FlightRec;

/* Per-endpoint retransmission state. The outstanding flight is captured, tagged
 * with each record's number, as it is emitted; a timer re-sends the un-ACKed
 * records with exponential backoff until the peer confirms delivery. */
typedef struct {
  RPtrArray flight;                       /* RDtls13FlightRec* of the outstanding flight */
  RClockEntry * timer;
  RClockTimeDiff timeout;
  ruint tries;
  rboolean capturing;                     /* accumulate emitted records into the flight */
} RDtls13Rtx;

R_API_HIDDEN void r_dtls13_rtx_init (RDtls13Rtx * rtx);
/* Cancel any timer and release the flight (teardown). */
R_API_HIDDEN void r_dtls13_rtx_clear (RDtls13Rtx * rtx, REvLoop * loop);
/* Add @rec (record number @epoch/@seq) to the flight when capturing is enabled. */
R_API_HIDDEN void r_dtls13_rtx_capture (RDtls13Rtx * rtx, RBuffer * rec,
    ruint64 epoch, ruint64 seq);
/* Arm the retransmit timer for the captured flight, if not already armed. */
R_API_HIDDEN void r_dtls13_rtx_arm (RDtls13Rtx * rtx, REvLoop * loop,
    REvFunc fire, rpointer ep);
/* The peer confirmed the flight: cancel the timer, drop the flight, reset backoff. */
R_API_HIDDEN void r_dtls13_rtx_cancel (RDtls13Rtx * rtx, REvLoop * loop);
/* Drop from the flight the records acknowledged by the ACK message body @ack
 * (@acklen bytes: a uint16 length then 16-byte record numbers, RFC 9147 7).
 * Scans the body directly, so it handles an ACK of any length. Returns the
 * number of records still outstanding; when it reaches 0 the caller cancels. */
R_API_HIDDEN rsize r_dtls13_rtx_ack (RDtls13Rtx * rtx, const ruint8 * ack,
    rsize acklen);
/* Double the backoff (capped) and re-arm; call from the endpoint's fire callback
 * after re-emitting the flight. */
R_API_HIDDEN void r_dtls13_rtx_reschedule (RDtls13Rtx * rtx, REvLoop * loop,
    REvFunc fire, rpointer ep);

/* --- DTLS 1.3 handshake reassembly (RFC 9147 5.5) ----------------------------
 * Buffers fragmented / out-of-order handshake messages keyed by message_seq and
 * hands them to the state machine as complete messages in message_seq order. */
#define R_DTLS13_REASM_SLOTS      8       /* concurrent pending messages */
#define R_DTLS13_REASM_RANGES     16      /* fragment intervals per message */
#define R_DTLS13_MAX_HANDSHAKE    0x10000 /* cap a reassembled message (64 KiB) */

typedef struct {
  rboolean active;
  rboolean complete;
  ruint16 msgseq;
  ruint16 epoch;                          /* low epoch bits the fragments arrived under */
  ruint8 type;
  ruint32 len;                            /* total message body length */
  ruint8 * msg;                           /* R_DTLS_HS_HDR_SIZE + len; header + body */
  ruint32 nranges;                        /* covered body intervals (merged) */
  ruint32 rstart[R_DTLS13_REASM_RANGES];
  ruint32 rend[R_DTLS13_REASM_RANGES];
} RDtls13ReasmSlot;

typedef struct {
  ruint16 next;                           /* next message_seq to deliver */
  RDtls13ReasmSlot slots[R_DTLS13_REASM_SLOTS];
} RDtls13Reassembler;

R_API_HIDDEN RDtls13Reassembler * r_dtls13_reassembler_new (void);
R_API_HIDDEN void r_dtls13_reassembler_free (RDtls13Reassembler * r);
/* Insert one fragment of message @msgseq (total body @len) covering
 * [@foff, @foff+@flen) of the body, received under epoch bits @epoch. Duplicates,
 * already-delivered messages, and fragments whose epoch disagrees with the
 * message in progress (RFC 9147: a handshake message belongs to one epoch) are
 * ignored. */
R_API_HIDDEN RTLSError r_dtls13_reassembler_push (RDtls13Reassembler * r,
    ruint8 type, ruint16 msgseq, ruint16 epoch, ruint32 len, ruint32 foff,
    const ruint8 * frag, ruint32 flen);
/* Pop the next in-order fully-reassembled message (a complete DTLS handshake
 * message, header included), or NULL if it is not ready. The caller owns the
 * returned buffer and frees it (e.g. via r_tls_parser_clear after
 * r_dtls_parser_init_handshake13). */
R_API_HIDDEN ruint8 * r_dtls13_reassembler_next (RDtls13Reassembler * r,
    rsize * outlen);
/* Set up @parser over the reassembled handshake message @msg (@msglen bytes),
 * taking ownership of @msg. r_tls_parser_clear releases it. */
R_API_HIDDEN RTLSError r_dtls_parser_init_handshake13 (RTLSParser * parser,
    ruint8 * msg, rsize msglen);

/* --- DTLS 1.3 next-epoch record buffering (RFC 9147 4.2.1) -------------------
 * A record for the epoch about to be installed can arrive before its keys are
 * derived (reordering). Rather than drop it, buffer the raw record and replay it
 * once the read epoch advances. Bounded so a peer cannot force unbounded growth
 * with unauthenticated future-epoch records. */
#define R_DTLS13_DEFER_MAX        8       /* next-epoch records buffered at once */
/* Buffer a copy of @parser's current raw record, dropping the oldest past the
 * cap. */
R_API_HIDDEN void r_dtls13_defer_record (RQueue * q, const RTLSParser * parser);
/* Move the records in @deferred whose low epoch bits match @epoch into @ready
 * (the caller re-feeds them); records still for a future epoch stay in
 * @deferred. */
R_API_HIDDEN void r_dtls13_take_deferred (RQueue * deferred, ruint16 epoch,
    RQueue * ready);
/* Low 2 epoch bits of a buffered unified-header record, or 0xff if @rec is not
 * a unified-header record. */
R_API_HIDDEN ruint8 r_dtls13_record_epoch_bits (RBuffer * rec);

/* Write the 12-byte DTLS handshake header (type | length | message_seq |
 * fragment_offset | fragment_length) into @p. */
R_API_HIDDEN void r_dtls13_write_hs_hdr (ruint8 * p, ruint8 type, ruint32 len,
    ruint16 msgseq, ruint32 foff, ruint32 flen);

/* Default cipher-suite preference shared by the client and server, most
 * preferred first: AEAD (AES-GCM then ChaCha20-Poly1305) over CBC, ECDHE
 * (forward secrecy) over static RSA, ECDSA over RSA authentication within a
 * tier, AES-128 over AES-256, SHA-256 MAC over SHA-1. The server keeps only the
 * suites its certificate can authenticate; the client offers all and lets the
 * server choose. */
#define R_TLS_DEFAULT_CIPHER_SUITES                                            \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,                              \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,                             \
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                                \
    R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,                                \
    R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256,                                      \
    R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384,                                      \
    R_TLS_CS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,                        \
    R_TLS_CS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,                          \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,                             \
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,                               \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,                                \
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,                                \
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA,                                   \
    R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA,                                   \
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256,                                      \
    R_TLS_CS_RSA_WITH_AES_256_CBC_SHA256,                                      \
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA,                                         \
    R_TLS_CS_RSA_WITH_AES_256_CBC_SHA

/* The TLS 1.3 cipher suites (RFC 8446) this implementation offers and accepts:
 * the two AES-GCM suites plus ChaCha20-Poly1305. Each carries a table entry
 * whose AEAD cipher and hash drive the record layer and HKDF key schedule. */
static inline rboolean
r_tls13_cipher_suite_is_supported (RTLSCipherSuite cs)
{
  return cs == R_TLS_CS_AES_128_GCM_SHA256 ||
         cs == R_TLS_CS_AES_256_GCM_SHA384 ||
         cs == R_TLS_CS_CHACHA20_POLY1305_SHA256;
}

/* Map a TLS signature scheme to the message-digest its hash uses. This cut
 * only handles rsa_pkcs1_sha256 (SHA-256) - the scheme used for both the mTLS
 * CertificateVerify and the ECDHE ServerKeyExchange signature. Returns FALSE
 * for any other scheme. */
R_API_HIDDEN rboolean r_tls_sign_scheme_to_md (RTLSSignatureScheme scheme,
    RMsgDigestType * md);

/* Choose the TLS 1.2 signature scheme matching a signing key's algorithm:
 * ecdsa_secp256r1_sha256 for an ECDSA key, rsa_pkcs1_sha256 otherwise. Both
 * hash with SHA-256, so the caller's transcript/params hash is unchanged. */
R_API_HIDDEN RTLSSignatureScheme r_tls_sign_scheme_for_key (const RCryptoKey * key);

/* Select the TLS 1.2 PRF and a fresh handshake-transcript digest for a cipher
 * suite's hash (@ref RTLSCipherSuiteInfo.prf): SHA-256 or SHA-384. Writes the
 * PRF function to @prf and an owned digest (caller frees) to @hshash. Returns
 * FALSE on an unsupported hash or allocation failure. */
R_API_HIDDEN rboolean r_tls_prf_and_hash_for (RMsgDigestType hash,
    RTLSPrfFunc * prf, RMsgDigest ** hshash);

/* ECDHE curve abstraction shared by the TLS/DTLS client and server. The two
 * supported curves take different code paths: secp256r1 is short-Weierstrass
 * (SEC 1 uncompressed point 0x04||X||Y, the recc/ECDH primitives) and x25519
 * is Montgomery (raw little-endian u-coordinate, the rxdh primitives). These
 * helpers hide that split so both endpoints share one code path. */

/* Largest (EC)DHE shared secret and uncompressed ECPoint across the supported
 * groups: P-521 has 66-byte coordinates, so a 66-byte shared secret and a
 * 133-byte uncompressed point (0x04 || X || Y). Buffers on the key-exchange
 * paths are sized to these so any supported group fits (RFC 8446 7.4.2 / SEC 1). */
#define R_TLS_ECDHE_SECRET_MAX    66
#define R_TLS_ECDHE_POINT_MAX     133

/* Map a TLS supported_group to an REcurveID we can do ECDHE on, gating to the
 * curves this cut supports (secp256r1, secp384r1, secp521r1, x25519, x448).
 * Returns FALSE otherwise. */
R_API_HIDDEN rboolean r_tls_ecdhe_group_to_curve (RTLSSupportedGroup group,
    REcurveID * curve);

/* TRUE for Montgomery curves (x25519/x448) whose wire ECPoint is the raw
 * little-endian u-coordinate; FALSE for short-Weierstrass curves whose
 * ECPoint is the SEC 1 uncompressed encoding. */
R_API_HIDDEN rboolean r_tls_ecdhe_curve_is_montgomery (REcurveID curve);

/* Generate an ephemeral ECDH private key on @curve. NULL on failure. */
R_API_HIDDEN RCryptoKey * r_tls_ecdhe_keygen (REcurveID curve, RPrng * prng);

/* Serialize @key's public point into @out (capacity @cap) in TLS ECPoint wire
 * form for @curve, writing the byte length to @len. FALSE on bad key / small
 * buffer. */
R_API_HIDDEN rboolean r_tls_ecdhe_point_write (const RCryptoKey * key,
    REcurveID curve, ruint8 * out, rsize cap, ruint8 * len);

/* Parse a peer's TLS ECPoint (@point/@len) on @curve into a public key.
 * Weierstrass points are decoded and on-curve checked; Montgomery
 * u-coordinates are length checked (any 32 bytes form a valid input). NULL on
 * a malformed point. Identity / small-subgroup inputs are rejected later, by
 * r_tls_ecdhe_compute. */
R_API_HIDDEN RCryptoKey * r_tls_ecdhe_point_read (REcurveID curve,
    const ruint8 * point, rsize len);

/* Compute the ECDH shared secret between local private @priv and peer public
 * @peer into @out (capacity @cap), writing its length to @len. The TLS
 * pre-master secret is this raw, fixed-width coordinate. FALSE on failure or a
 * rejected (e.g. all-zero) secret. */
R_API_HIDDEN rboolean r_tls_ecdhe_compute (const RCryptoKey * priv,
    const RCryptoKey * peer, ruint8 * out, rsize cap, rsize * len);

/* TLS 1.3 key_share generalised over EC and finite-field (ffdhe) groups. The
 * ffdhe values dwarf the EC ones -- the ffdhe8192 public value / shared secret
 * are both 1024 bytes -- so key_share buffers on the 1.3 path use these. */
#define R_TLS_KE_VALUE_MAX    1024
#define R_TLS_KE_SECRET_MAX   1024

/* Map a TLS supported_group to an RFC 7919 FFDHE named group; FALSE if @group
 * is not one of the ffdhe* groups. */
R_API_HIDDEN rboolean r_tls_group_to_dh (RTLSSupportedGroup group,
    RDhNamedGroup * dh);

/* TRUE if @group is a key-exchange group we support (an EC curve via
 * r_tls_ecdhe_group_to_curve, or an ffdhe finite-field group). */
R_API_HIDDEN rboolean r_tls_ke_group_supported (RTLSSupportedGroup group);

/* Generate an ephemeral key-exchange private key for @group (EC or FFDHE).
 * NULL on an unsupported group or failure. */
R_API_HIDDEN RCryptoKey * r_tls_ke_keygen (RTLSSupportedGroup group, RPrng * prng);

/* Serialize @key's public value into @out (capacity @cap) as @group's TLS
 * KeyShareEntry.key_exchange, writing the length (up to R_TLS_KE_VALUE_MAX) to
 * @len. FALSE on a bad key / small buffer. */
R_API_HIDDEN rboolean r_tls_ke_pub_write (const RCryptoKey * key,
    RTLSSupportedGroup group, ruint8 * out, rsize cap, rsize * len);

/* Parse a peer's key_share value (@data/@len) for @group into a public key.
 * NULL on a malformed value. */
R_API_HIDDEN RCryptoKey * r_tls_ke_pub_read (RTLSSupportedGroup group,
    const ruint8 * data, rsize len);

/* Compute the key-exchange shared secret between @priv and @peer into @out
 * (capacity @cap), writing its length to @len. Dispatches on the key type. */
R_API_HIDDEN rboolean r_tls_ke_compute (const RCryptoKey * priv,
    const RCryptoKey * peer, ruint8 * out, rsize cap, rsize * len);

R_END_DECLS

#endif /* __R_NET_PROTO_TLS_PRIV_H__ */
