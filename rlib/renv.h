/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_ENV_H__
#define __R_ENV_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

R_API const rchar * r_getenv (const rchar * key);
R_API rboolean r_setenv (const rchar * key, const rchar * val, rboolean always);
R_API rboolean r_unsetenv (const rchar * key);

R_END_DECLS

#endif /* __R_ENV_H__ */
