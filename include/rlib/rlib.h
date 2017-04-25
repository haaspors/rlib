/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_LIB_H__
#define __R_LIB_H__

#ifndef __RLIB_H_INCLUDE_GUARD__
#define __RLIB_H_INCLUDE_GUARD__
#endif

#include <rlib/rascii.h>
#include <rlib/rassert.h>
#include <rlib/ratomic.h>
#include <rlib/rbase64.h>
#include <rlib/rbitset.h>
#include <rlib/rbuffer.h>
#include <rlib/rclock.h>
#include <rlib/rclr.h>
#include <rlib/rcrc.h>
#include <rlib/rdirtree.h>
#include <rlib/renv.h>
#include <rlib/rfd.h>
#include <rlib/rfile.h>
#include <rlib/rfs.h>
#include <rlib/rhashfuncs.h>
#include <rlib/rhashset.h>
#include <rlib/rhashtable.h>
#include <rlib/rhzrptr.h>
#include <rlib/rlist.h>
#include <rlib/rlog.h>
#include <rlib/rmacros.h>
#include <rlib/rmath.h>
#include <rlib/rmem.h>
#include <rlib/rmemallocator.h>
#include <rlib/rmemfile.h>
#include <rlib/rmodule.h>
#include <rlib/rmpint.h>
#include <rlib/rmsgdigest.h>
#include <rlib/roptparse.h>
#include <rlib/rproc.h>
#include <rlib/rptrarray.h>
#include <rlib/rqueue.h>
#include <rlib/rrand.h>
#include <rlib/rref.h>
#include <rlib/rsignal.h>
#include <rlib/rsocket.h>
#include <rlib/rsocketaddress.h>
#include <rlib/rstr.h>
#include <rlib/rstring.h>
#include <rlib/rsys.h>
#include <rlib/rtaskqueue.h>
#include <rlib/rtest.h>
#include <rlib/rthreads.h>
#include <rlib/rthreadpool.h>
#include <rlib/rtime.h>
#include <rlib/rtimeoutcblist.h>
#include <rlib/rtty.h>
#include <rlib/rtypes.h>
#include <rlib/runicode.h>
#include <rlib/ruri.h>

/* ASN.1 */
#include <rlib/asn1/rasn1.h>
#include <rlib/asn1/roid.h>

/* CRYPTO */
#include <rlib/crypto/raes.h>
#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rdsa.h>
#include <rlib/crypto/recc.h>
#include <rlib/crypto/rhmac.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rpem.h>
#include <rlib/crypto/rrsa.h>
#include <rlib/crypto/rsrtpciphersuite.h>
#include <rlib/crypto/rtlsciphersuite.h>
#include <rlib/crypto/rx509.h>

/* EV */
#include <rlib/ev/revloop.h>
#include <rlib/ev/revresolve.h>
#include <rlib/ev/revtcp.h>
#include <rlib/ev/revudp.h>

/* NET */
#include <rlib/net/proto/rhttp.h>
#include <rlib/net/proto/rrtp.h>
#include <rlib/net/proto/rsdp.h>
#include <rlib/net/proto/rstun.h>
#include <rlib/net/proto/rtls.h>
#include <rlib/net/rhttpserver.h>
#include <rlib/net/rsrtp.h>
#include <rlib/net/rtlsserver.h>

/* RTC */
#include <rlib/rtc/rrtc.h>
#include <rlib/rtc/rrtccryptotransport.h>
#include <rlib/rtc/rrtcicecandidate.h>
#include <rlib/rtc/rrtcicetransport.h>
#include <rlib/rtc/rrtcrtplistener.h>
#include <rlib/rtc/rrtcrtpparameters.h>
#include <rlib/rtc/rrtcrtpreceiver.h>
#include <rlib/rtc/rrtcrtpsender.h>
#include <rlib/rtc/rrtcrtptransceiver.h>
#include <rlib/rtc/rrtcsession.h>
#include <rlib/rtc/rrtcsessiondescription.h>

#endif /* __R_LIB_H__ */
