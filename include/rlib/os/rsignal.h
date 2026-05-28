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

/**
 * @file rlib/os/rsignal.h
 * @brief @c SIGALRM-based one-shot and interval timers.
 */

#include <rlib/rtypes.h>
#include <rlib/rtime.h>

/**
 * @defgroup r_signal Signal timers
 * @ingroup r_os
 *
 * @brief @c SIGALRM-driven timers that invoke a callback once or on a
 * recurring interval.
 *
 * Each timer arms the process @c SIGALRM and calls the supplied
 * @ref RSignalFunc from signal context, so the callback must be
 * async-signal-safe.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Signal-handler callback; receives the delivered signal number. */
typedef void (*RSignalFunc) (int sig);
/** @brief Opaque @c SIGALRM timer handle. */
typedef struct RSigAlrmTimer RSigAlrmTimer;

/** @brief Arm a one-shot timer firing once after @p timeout. */
R_API RSigAlrmTimer * r_sig_alrm_timer_new_oneshot (RClockTime timeout,
    RSignalFunc func);
/** @brief Arm a recurring timer firing every @p interval. */
R_API RSigAlrmTimer * r_sig_alrm_timer_new_interval (RClockTime interval,
    RSignalFunc func);
/**
 * @brief Arm a recurring timer with an initial delay.
 * @param timeout  Delay before the first fire.
 * @param interval Period between subsequent fires.
 * @param func     Callback invoked on each fire.
 */
R_API RSigAlrmTimer * r_sig_alrm_timer_new_interval_delayed (RClockTime timeout,
    RClockTime interval, RSignalFunc func);

/** @brief Stop @p timer without freeing it. */
R_API void r_sig_alrm_timer_cancel (RSigAlrmTimer * timer);
/** @brief Cancel and free @p timer. */
R_API void r_sig_alrm_timer_delete (RSigAlrmTimer * timer);

R_END_DECLS

/** @} */

#endif /* __R_SIGNAL_H__ */

