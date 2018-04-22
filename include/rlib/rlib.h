/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include <rlib/rtypes.h>

#include <rlib/rargparse.h>
#include <rlib/rassert.h>
#include <rlib/ratomic.h>
#include <rlib/rbase64.h>
#include <rlib/rbuffer.h>
#include <rlib/rclock.h>
#include <rlib/rclr.h>
#include <rlib/rcrc.h>
#include <rlib/renv.h>
#include <rlib/rjson.h>
#include <rlib/rjsonparser.h>
#include <rlib/rlog.h>
#include <rlib/rmath.h>
#include <rlib/rmem.h>
#include <rlib/rmemallocator.h>
#include <rlib/rmemfile.h>
#include <rlib/rmodule.h>
#include <rlib/rmsgdigest.h>
#include <rlib/rrand.h>
#include <rlib/rref.h>
#include <rlib/rsocket.h>
#include <rlib/rsocketaddress.h>
#include <rlib/rstr.h>
#include <rlib/rtaskqueue.h>
#include <rlib/rtest.h>
#include <rlib/rthreads.h>
#include <rlib/rthreadpool.h>
#include <rlib/rtime.h>
#include <rlib/rtty.h>
#include <rlib/ruri.h>

/* CHARACTER SET */
#include <rlib/charset/rascii.h>
#include <rlib/charset/runicode.h>

/* DATA TYPES */
#include <rlib/data/rbitset.h>
#include <rlib/data/rdictionary.h>
#include <rlib/data/rdirtree.h>
#include <rlib/data/rhashfuncs.h>
#include <rlib/data/rhashset.h>
#include <rlib/data/rhashtable.h>
#include <rlib/data/rhzrptr.h>
#include <rlib/data/rkvptrarray.h>
#include <rlib/data/rlist.h>
#include <rlib/data/rmpint.h>
#include <rlib/data/rptrarray.h>
#include <rlib/data/rqueue.h>
#include <rlib/data/rstring.h>
#include <rlib/data/rtimeoutcblist.h>

/* FILE */
#include <rlib/file/rfd.h>
#include <rlib/file/rfile.h>
#include <rlib/file/rfs.h>

#endif /* __R_LIB_H__ */
