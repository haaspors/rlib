/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#define __RLIB_H_INCLUDE_GUARD__

#include <rlib/rascii.h>
#include <rlib/rassert.h>
#include <rlib/ratomic.h>
#include <rlib/rbase64.h>
#include <rlib/rbitset.h>
#include <rlib/rbuffer.h>
#include <rlib/rclock.h>
#include <rlib/rclr.h>
#include <rlib/rcrc.h>
#include <rlib/renv.h>
#include <rlib/rfd.h>
#include <rlib/rfile.h>
#include <rlib/rfs.h>
#include <rlib/rhash.h>
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
#include <rlib/roptparse.h>
#include <rlib/rproc.h>
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

#include <rlib/asn1/rasn1.h>
#include <rlib/asn1/roid.h>

#include <rlib/crypto/raes.h>
#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rciphersuite.h>
#include <rlib/crypto/rdsa.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rmac.h>
#include <rlib/crypto/rpem.h>
#include <rlib/crypto/rrsa.h>
#include <rlib/crypto/rx509.h>

#include <rlib/ev/revloop.h>
#include <rlib/ev/revudp.h>

#include <rlib/net/proto/rstun.h>
#include <rlib/net/proto/rtls.h>

#endif /* __R_LIB_H__ */
