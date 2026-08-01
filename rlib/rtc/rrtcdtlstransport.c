/* RLIB - Convenience library for useful things
 * Copyright (C) 2017  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include "config.h"
#include "rrtc-private.h"
#include <rlib/rtc/rrtccryptotransport.h>

#include <rlib/rassert.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>


static void
r_rtc_dtls_transport_free (RRtcDtlsTransport * dtls)
{
  r_rtc_crypto_transport_clear ((RRtcCryptoTransport *)dtls);

  if (dtls->role == R_RTC_CRYPTO_ROLE_CLIENT) {
    if (dtls->dtls.cli != NULL)
      r_tls_client_unref (dtls->dtls.cli);
  } else {
    if (dtls->dtls.srv != NULL)
      r_tls_server_unref (dtls->dtls.srv);
  }
  if (dtls->srtp != NULL)
    r_srtp_ctx_unref (dtls->srtp);

  if (dtls->prng != NULL)
    r_prng_unref (dtls->prng);

  r_free (dtls);
}

/* RFC 5764 5.2: the exported material is client-write-key ||
 * server-write-key || client-salt || server-salt. Split it and install
 * the half the remote peer encrypts with -- the client key for a server
 * transport, the server key for a client transport. */
static void
r_rtc_dtls_install_srtp (RRtcDtlsTransport * dtls, RSRTPCipherSuite cs,
    const RSRTPCipherSuiteInfo * csinfo, const ruint8 * material, rsize msize,
    rboolean use_server_key)
{
  rsize kb = csinfo->cipher->keybits / 8;
  rsize sb = csinfo->saltbits / 8;
  ruint8 * clikey = r_alloca (msize / 2);
  ruint8 * srvkey = r_alloca (msize / 2);
  const ruint8 * ptr = material;
  const ruint8 * key;
  RSRTPError srtperr;

  r_memcpy (clikey, ptr, kb); ptr += kb;
  r_memcpy (srvkey, ptr, kb); ptr += kb;
  r_memcpy (clikey + kb, ptr, sb); ptr += sb;
  r_memcpy (srvkey + kb, ptr, sb); ptr += sb;

  key = use_server_key ? srvkey : clikey;
  if ((srtperr = r_srtp_add_crypto_context_with_filter (dtls->srtp,
          R_SRTP_FILTER_ANY, cs, key)) == R_SRTP_ERROR_OK) {
    R_LOG_INFO ("Added crypto context %s for DTLS-SRTP", csinfo->str);
    R_LOG_MEM_DUMP (R_LOG_LEVEL_INFO, key, msize / 2);
    r_rtc_rtp_listener_notify_ready (dtls->crypto.listener, (RRtcCryptoTransport *)dtls);
  } else {
    R_LOG_WARNING ("Couldn't add crypto context for SRTP err %d",
        (ruint)srtperr);
  }
}

static void
r_rtc_dtls_srv_hs_done (rpointer data, rpointer session)
{
  RRtcDtlsTransport * dtls = data;
  RTLSServer * srv = session;
  RSRTPCipherSuite cs;
  const RSRTPCipherSuiteInfo * csinfo;
  ruint8 * material;
  rsize msize;
  RTLSError tlserr;

  cs = r_tls_server_get_dtls_srtp_profile (srv);
  if ((csinfo = r_srtp_cipher_suite_get_info (cs)) == NULL) {
    R_LOG_WARNING ("0x%.04x DTLS-SRTP profile not supported", (ruint)cs);
    return;
  }

  msize = 2 * ((csinfo->cipher->keybits + csinfo->saltbits) / 8);
  material = r_alloca (msize);
  if ((tlserr = r_tls_server_export_keying_material (srv, material, msize,
      R_STR_WITH_SIZE_ARGS ("EXTRACTOR-dtls_srtp"), NULL, 0)) == R_TLS_ERROR_OK)
    r_rtc_dtls_install_srtp (dtls, cs, csinfo, material, msize, FALSE);
  else
    R_LOG_WARNING ("Couldn't export keying material for SRTP from DTLS err %d",
        (ruint)tlserr);
}

static void
r_rtc_dtls_cli_hs_done (rpointer data, rpointer session)
{
  RRtcDtlsTransport * dtls = data;
  RTLSClient * cli = session;
  RSRTPCipherSuite cs;
  const RSRTPCipherSuiteInfo * csinfo;
  ruint8 * material;
  rsize msize;
  RTLSError tlserr;

  cs = r_tls_client_get_dtls_srtp_profile (cli);
  if ((csinfo = r_srtp_cipher_suite_get_info (cs)) == NULL) {
    R_LOG_WARNING ("0x%.04x DTLS-SRTP profile not supported", (ruint)cs);
    return;
  }

  msize = 2 * ((csinfo->cipher->keybits + csinfo->saltbits) / 8);
  material = r_alloca (msize);
  if ((tlserr = r_tls_client_export_keying_material (cli, material, msize,
      R_STR_WITH_SIZE_ARGS ("EXTRACTOR-dtls_srtp"), NULL, 0)) == R_TLS_ERROR_OK)
    r_rtc_dtls_install_srtp (dtls, cs, csinfo, material, msize, TRUE);
  else
    R_LOG_WARNING ("Couldn't export keying material for SRTP from DTLS err %d",
        (ruint)tlserr);
}

static rboolean
r_rtc_dtls_buffer_out (rpointer data, RBuffer * buf, rpointer session)
{
  RRtcCryptoTransport * crypto = data;
  (void) session;

  R_LOG_TRACE ("RtcCryptoTransport %p %p %"RSIZE_FMT,
      crypto, buf, r_buffer_get_size (buf));
  r_rtc_ice_transport_send (crypto->ice, buf);
  return TRUE;
}

static rboolean
r_rtc_dtls_buffer_appdata (rpointer data, RBuffer * buf, rpointer session)
{
  RRtcCryptoTransport * crypto = data;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  (void) crypto;
  (void) session;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    R_LOG_MEM_DUMP (R_LOG_LEVEL_TRACE, info.data, info.size);
    r_buffer_unmap (buf, &info);
  }

  return TRUE;
}

static void
r_rtc_dtls_transport_ice_packet (rpointer data, RBuffer * buf, rpointer ctx)
{
  RRtcDtlsTransport * dtls = data;
  RRtcIceTransport * ice = ctx;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RSRTPError err;
  RBuffer * decrypt;

  r_assert_cmpptr (ice, ==, dtls->crypto.ice);

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    if (r_rtp_is_valid_hdr (info.data, info.size)) {
      r_buffer_unmap (buf, &info);
      if ((decrypt = r_srtp_decrypt_rtp (dtls->srtp, buf, &err)) != NULL) {
        R_LOG_TRACE ("RtcCryptoTransport %p RTP packet", dtls);
        r_rtc_rtp_listener_handle_rtp (dtls->crypto.listener, decrypt,
            (RRtcCryptoTransport *)dtls);
        r_buffer_unref (decrypt);
      } else {
        R_LOG_WARNING ("Unable to decrypt SRTP buffer %p (err: %d)", buf, (int)err);
      }
    } else if (r_rtcp_is_valid_hdr (info.data, info.size)) {
      r_buffer_unmap (buf, &info);
      if ((decrypt = r_srtp_decrypt_rtcp (dtls->srtp, buf, &err)) != NULL) {
        R_LOG_TRACE ("RtcCryptoTransport %p RTCP packet", dtls);
        r_rtc_rtp_listener_handle_rtcp (dtls->crypto.listener, decrypt,
            (RRtcCryptoTransport *)dtls);
        r_buffer_unref (decrypt);
      } else {
        R_LOG_WARNING ("Unable to decrypt SRTCP buffer %p (err: %d)", buf, (int)err);
      }
    } else if (r_tls_version_is_dtls (r_tls_parse_data_shallow (info.data, info.size))) {
      R_LOG_TRACE ("RtcCryptoTransport %p DTLS packet %"RSIZE_FMT, dtls, info.size);
      r_buffer_unmap (buf, &info);
      if (dtls->role == R_RTC_CRYPTO_ROLE_CLIENT) {
        if (!r_tls_client_incoming_data (dtls->dtls.cli, buf))
          R_LOG_WARNING ("r_tls_client_incoming_data failed!");
      } else {
        if (!r_tls_server_incoming_data (dtls->dtls.srv, buf))
          R_LOG_WARNING ("r_tls_server_incoming_data failed!");
      }
    } else {
      R_LOG_WARNING ("Unknown packet received");
      r_buffer_unmap (buf, &info);
    }
  } else {
    R_LOG_WARNING ("Unable to map buffer %p", buf);
  }
}
static RRtcError
r_rtc_dtls_transport_start (rpointer rtc, REvLoop * loop)
{
  RRtcDtlsTransport * dtls = rtc;
  RRtcError ret = R_RTC_OK;

  if (dtls->role == R_RTC_CRYPTO_ROLE_CLIENT) {
    if (dtls->dtls.cli != NULL &&
        r_tls_client_start (dtls->dtls.cli, loop, dtls->prng,
            R_TLS_VERSION_DTLS_1_2) != R_TLS_ERROR_OK)
      ret = R_RTC_WRONG_STATE;
  } else {
    if (dtls->dtls.srv != NULL &&
        r_tls_server_start (dtls->dtls.srv, loop, dtls->prng) != R_TLS_ERROR_OK)
      ret = R_RTC_WRONG_STATE;
  }

  return ret;
}

static RRtcError
r_rtc_dtls_transport_send (rpointer rtc, RBuffer * buf)
{
  RRtcError ret;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RRtcDtlsTransport * dtls = rtc;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    RSRTPError srtperr;

    if (r_rtp_is_valid_hdr (info.data, info.size)) {
      r_buffer_unmap (buf, &info);
      if ((buf = r_srtp_encrypt_rtp (dtls->srtp, buf, &srtperr)) != NULL)
        ret = r_rtc_ice_transport_send (dtls->crypto.ice, buf);
      else
        ret = R_RTC_ENCRYPT_ERROR;
    } else if (r_rtcp_is_valid_hdr (info.data, info.size)) {
      r_buffer_unmap (buf, &info);
      if ((buf = r_srtp_encrypt_rtcp (dtls->srtp, buf, &srtperr)) != NULL)
        ret = r_rtc_ice_transport_send (dtls->crypto.ice, buf);
      else
        ret = R_RTC_ENCRYPT_ERROR;
    } else {
      ret = R_RTC_INVALID_MEDIA;
    }
  } else {
    ret = R_RTC_MAP_ERROR;
  }

  return ret;
}

RRtcCryptoTransport *
r_rtc_crypto_transport_new_dtls (RRtcIceTransport * ice, RPrng * prng,
    RRtcCryptoRole role, RCryptoCert * cert, RCryptoKey * privkey)
{
  RRtcDtlsTransport * ret;
  static RTLSCallbacks srv_cbs = {
    NULL,
    r_rtc_dtls_srv_hs_done,
    r_rtc_dtls_buffer_out,
    r_rtc_dtls_buffer_appdata,
    NULL,
    NULL,
    NULL,
    NULL,
  };
  static RTLSCallbacks cli_cbs = {
    NULL,
    r_rtc_dtls_cli_hs_done,
    r_rtc_dtls_buffer_out,
    r_rtc_dtls_buffer_appdata,
    NULL,
    NULL,
    NULL,
    NULL,
  };

  if (R_UNLIKELY (ice == NULL)) return NULL;
  if (R_UNLIKELY (prng == NULL)) return NULL;
  if (R_UNLIKELY (cert == NULL)) return NULL;
  if (R_UNLIKELY (privkey == NULL)) return NULL;

  /* The role must already be resolved to a concrete side; AUTO is
   * negotiated from the SDP a=setup attribute before we get here. */
  if (R_UNLIKELY (role != R_RTC_CRYPTO_ROLE_SERVER &&
        role != R_RTC_CRYPTO_ROLE_CLIENT))
    return NULL;

  if ((ret = r_mem_new0 (RRtcDtlsTransport)) != NULL) {
    r_ref_init (ret, r_rtc_dtls_transport_free);
    r_rtc_crypto_transport_init (ret, ice, r_rtc_dtls_transport_start,
        r_rtc_dtls_transport_ice_packet, r_rtc_dtls_transport_send);

    ret->srtp = r_srtp_ctx_new ();
    ret->role = role;
    if (role == R_RTC_CRYPTO_ROLE_CLIENT) {
      ret->dtls.cli = r_tls_client_new (&cli_cbs, ret, NULL);
      r_tls_client_set_cert (ret->dtls.cli, cert, privkey);
    } else {
      ret->dtls.srv = r_tls_server_new (&srv_cbs, ret, NULL);
      r_tls_server_set_cert (ret->dtls.srv, cert, privkey);
    }
    ret->prng = r_prng_ref (prng);
  }

  return (RRtcCryptoTransport *) ret;
}

