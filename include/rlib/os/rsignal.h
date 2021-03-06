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
#ifndef __R_SIGNAL_H__
#define __R_SIGNAL_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rtime.h>

R_BEGIN_DECLS

typedef void (*RSignalFunc) (int sig);
typedef struct _RSigAlrmTimer RSigAlrmTimer;

R_API RSigAlrmTimer * r_sig_alrm_timer_new_oneshot (RClockTime timeout,
    RSignalFunc func);
R_API RSigAlrmTimer * r_sig_alrm_timer_new_interval (RClockTime interval,
    RSignalFunc func);
R_API RSigAlrmTimer * r_sig_alrm_timer_new_interval_delayed (RClockTime timeout,
    RClockTime interval, RSignalFunc func);

R_API void r_sig_alrm_timer_cancel (RSigAlrmTimer * timer);
R_API void r_sig_alrm_timer_delete (RSigAlrmTimer * timer);

R_END_DECLS

#endif /* __R_SIGNAL_H__ */

