/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_RTC_CRYPTO_TRANSPORT_H__
#define __R_RTC_CRYPTO_TRANSPORT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtc/rrtccryptotransport.h
 * @brief DTLS / crypto transport that secures media over an established
 * ICE transport.
 */

#include <rlib/rtypes.h>
#include <rlib/rtc/rrtctypes.h>
#include <rlib/rref.h>

#include <rlib/ev/revloop.h>

/**
 * @defgroup r_rtc_cryptotransport WebRTC DTLS/crypto transport
 * @ingroup r_rtc
 *
 * @brief The DTLS handshake and SRTP keying layer that runs on top of an
 * @ref r_rtc_icetransport, securing the media and data carried over it.
 *
 * The transport is reference-counted
 * (@ref r_rtc_crypto_transport_ref / @ref r_rtc_crypto_transport_unref) and
 * driven by an @c REvLoop via @ref r_rtc_crypto_transport_start /
 * @ref r_rtc_crypto_transport_close. Its DTLS role is selected by
 * @ref RRtcCryptoRole.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief DTLS role for the crypto transport. */
typedef enum {
  R_RTC_CRYPTO_ROLE_AUTO,     /**< Negotiate the role. */
  R_RTC_CRYPTO_ROLE_SERVER,   /**< DTLS server (passive). */
  R_RTC_CRYPTO_ROLE_CLIENT,   /**< DTLS client (active). */
} RRtcCryptoRole;

/** @brief Opaque, reference-counted DTLS / crypto transport. */
typedef struct RRtcCryptoTransport RRtcCryptoTransport;

/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_rtc_crypto_transport_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_rtc_crypto_transport_unref  r_ref_unref

/** @brief Start the crypto transport (begin the DTLS handshake) on @p loop. */
R_API RRtcError r_rtc_crypto_transport_start (RRtcCryptoTransport * crypto, REvLoop * loop);
/** @brief Close the crypto transport and tear down DTLS / SRTP state. */
R_API RRtcError r_rtc_crypto_transport_close (RRtcCryptoTransport * crypto);

R_END_DECLS

/** @} */

#endif /* __R_RTC_CRYPTO_TRANSPORT_H__ */


