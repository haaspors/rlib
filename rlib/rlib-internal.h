/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __RLIB_INTERNAL_H__
#define __RLIB_INTERNAL_H__

#if !defined(RLIB_COMPILATION)
#error "rlib-internal.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>

R_API_HIDDEN void r_log_init (void);

R_API_HIDDEN void r_test_init (void);

R_API_HIDDEN void r_thread_init (void);
R_API_HIDDEN void r_thread_deinit (void);

R_API_HIDDEN void r_time_init (void);

#endif /* __RLIB_INTERNAL_H__ */
