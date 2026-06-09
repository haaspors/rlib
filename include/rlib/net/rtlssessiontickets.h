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
#ifndef __R_NET_TLS_SESSION_TICKETS_H__
#define __R_NET_TLS_SESSION_TICKETS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/rtlssessiontickets.h
 * @brief Shared key store for sealing TLS / DTLS session tickets.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

/**
 * @defgroup r_tls_session_tickets TLS session-ticket keys
 * @ingroup r_net
 *
 * @brief Server-held key material for RFC 5077 session tickets.
 *
 * A session ticket lets a TLS / DTLS server hand its session state to the
 * client, sealed under a server-held key, so a later connection can resume
 * without a full handshake. Because the resuming connection is a different
 * @ref RTLSServer instance, the sealing key must be shared and outlive any
 * single session: create one @ref RTLSSessionTicketKeys and attach it to
 * every server that should issue and accept tickets with
 * @ref r_tls_server_set_session_ticket_keys. A server with no key store
 * configured neither offers nor issues tickets.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted session-ticket key store. */
typedef struct RTLSSessionTicketKeys RTLSSessionTicketKeys;

/**
 * @brief Create a key store holding a fresh random key drawn from OS entropy.
 *
 * @return A new store (the caller owns one reference), or @c NULL if the OS
 *   entropy source could not be read.
 */
R_API RTLSSessionTicketKeys * r_tls_session_ticket_keys_new (void) R_ATTR_MALLOC;
/** @brief Increment the key store's refcount. */
#define r_tls_session_ticket_keys_ref    r_ref_ref
/** @brief Decrement the refcount; scrubs and frees the key material at zero. */
#define r_tls_session_ticket_keys_unref  r_ref_unref

R_END_DECLS

/** @} */

#endif /* __R_NET_TLS_SESSION_TICKETS_H__ */
