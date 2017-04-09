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
#ifndef __R_RTC_H__
#define __R_RTC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>

R_BEGIN_DECLS

typedef enum {
  R_RTC_OK      = 0,
  R_RTC_INVAL,
  R_RTC_OOM,
  R_RTC_WRONG_STATE,
  R_RTC_INVALID_MEDIA,
  R_RTC_INVALID_TYPE,
  R_RTC_ALREADY_FOUND,
  R_RTC_MAP_ERROR,
  R_RTC_DECRYPT_ERROR,
  R_RTC_ENCRYPT_ERROR,
  R_RTC_NO_HANDLER,
} RRtcError;

typedef RFunc RRtcEventCb;
typedef void (*RRtcBufferCb) (rpointer data, RBuffer * buf, rpointer ctx);

R_END_DECLS

#endif /* __R_RTC_H__ */

