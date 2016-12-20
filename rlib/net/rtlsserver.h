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
#ifndef __R_NET_TLS_SERVER_H__
#define __R_NET_TLS_SERVER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rtlsciphersuite.h>
#include <rlib/crypto/rkey.h>
#include <rlib/ev/revloop.h>
#include <rlib/net/proto/rtls.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

typedef struct _RTLSServer RTLSServer;

typedef rboolean (*RTLSServerBufferCb) (rpointer ctx, RBuffer * buf, RTLSServer * server);
typedef void (*RTLSServerHandshakeDoneCb) (rpointer ctx, RTLSServer * server);
typedef rboolean (*RTLSPreferredCipherSuitesCb) (rpointer ctx, RTLSVersion ver, RTLSCipherSuite * cs, rsize * count);

typedef struct {
  RTLSPreferredCipherSuitesCb   preferred_cipher_suites;
  RTLSServerHandshakeDoneCb     handshake_done;
  RTLSServerBufferCb            out;
  RTLSServerBufferCb            appdata;
} RTLSCallbacks;

R_API RTLSServer * r_tls_server_new (const RTLSCallbacks * cb,
    rpointer userdata, RDestroyNotify notify) R_ATTR_MALLOC;
#define r_tls_server_ref    r_ref_ref
#define r_tls_server_unref  r_ref_unref

R_API RTLSError r_tls_server_set_cert (RTLSServer * server,
    RCryptoCert * cert, RCryptoKey * privkey);
R_API RTLSError r_tls_server_set_random (RTLSServer * server,
    const ruint8 servrandom[R_TLS_HELLO_RANDOM_BYTES]);
R_API RTLSError r_tls_server_start (RTLSServer * server, REvLoop * loop,
    RPrng * prng) R_ATTR_WARN_UNUSED_RESULT;

R_API rboolean r_tls_server_incoming_data (RTLSServer * server, RBuffer * buffer);
R_API rboolean r_tls_server_send_appdata (RTLSServer * server, RBuffer * buffer);

R_API RTLSError r_tls_server_export_keying_matierial (const RTLSServer * server,
    ruint8 * material, rsize size, const rchar * label, rsize len,
    const ruint8 * ctx, rsize ctxsize);


R_API RTLSVersion r_tls_server_get_version (const RTLSServer * server);
R_API const RTLSCipherSuiteInfo * r_tls_server_get_cipher_suite (const RTLSServer * server);
R_API RSRTPCipherSuite r_tls_server_get_dtls_srtp_profile (const RTLSServer * server);
R_API const ruint8 * r_tls_server_get_dtls_srtp_mki (const RTLSServer * server, ruint8 * size);

R_END_DECLS

#endif /* __R_NET_TLS_SERVER_H__ */

