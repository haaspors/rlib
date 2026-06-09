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
#ifndef __R_NET_TLS_SESSION_TICKETS_PRIV_H__
#define __R_NET_TLS_SESSION_TICKETS_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rtlssessiontickets-private.h should only be used internally in rlib!"
#endif

#include <rlib/net/rtlssessiontickets.h>
#include <rlib/rtypes.h>

R_BEGIN_DECLS

/* Bytes a sealed ticket adds around the plaintext: key_name(16) + nonce(12)
 * + GCM tag(16). The wire ticket is key_name || nonce || ciphertext || tag. */
#define R_TLS_SESSION_TICKET_SEAL_OVERHEAD    (16 + 12 + 16)

/* Seal @plain under @keys into a freshly allocated ticket; the caller frees
 * @out. The key_name is authenticated (GCM AAD) so @ref
 * r_tls_session_ticket_keys_open can reject tickets sealed by other keys
 * before attempting to decrypt. Returns FALSE on entropy / cipher failure. */
R_API_HIDDEN rboolean r_tls_session_ticket_keys_seal (RTLSSessionTicketKeys * keys,
    const ruint8 * plain, rsize plainlen, ruint8 ** out, rsize * outlen);

/* Open @ticket under @keys: reject unless the leading key_name matches and the
 * AEAD tag verifies, then write the recovered plaintext into @plain_out (of
 * capacity @cap) and its length to @plainlen_out. Returns FALSE on any size,
 * key_name or tag mismatch. */
R_API_HIDDEN rboolean r_tls_session_ticket_keys_open (RTLSSessionTicketKeys * keys,
    const ruint8 * ticket, rsize len, ruint8 * plain_out, rsize cap,
    rsize * plainlen_out);

R_END_DECLS

#endif /* __R_NET_TLS_SESSION_TICKETS_PRIV_H__ */
