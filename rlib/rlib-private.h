/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __RLIB_PRIVATE_H__
#define __RLIB_PRIVATE_H__

#if !defined(RLIB_COMPILATION)
#error "rlib-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>
#include <rlib/rlog.h>

R_API_HIDDEN void r_log_init (void);

R_API_HIDDEN void r_test_init (void);

R_API_HIDDEN void r_thread_init (void);
R_API_HIDDEN void r_thread_deinit (void);

R_API_HIDDEN void r_time_init (void);

R_API_HIDDEN R_LOG_CATEGORY_DEFINE_EXTERN (rlib_logcat);

#endif /* __RLIB_PRIVATE_H__ */
