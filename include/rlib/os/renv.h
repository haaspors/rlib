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
#ifndef __R_ENV_H__
#define __R_ENV_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/os/renv.h
 * @brief Environment-variable accessors (@c getenv / @c setenv /
 * @c unsetenv wrappers).
 */

#include <rlib/rtypes.h>

R_BEGIN_DECLS

/**
 * @defgroup r_env Environment variables
 * @ingroup r_os
 *
 * @brief Cross-platform wrappers around the C library's environment
 * accessors. Lookup, set (optionally overwriting) and unset.
 *
 * @{
 */

/**
 * @brief Look up @p key in the process environment.
 * @return Pointer to the value (owned by the environment, not the
 *         caller), or @c NULL if @p key is unset.
 */
R_API const rchar * r_getenv (const rchar * key);
/**
 * @brief Set @p key to @p val in the process environment.
 * @param key    Variable name.
 * @param val    New value.
 * @param always @c TRUE to overwrite an existing value, @c FALSE to
 *               keep an already-set value unchanged.
 * @return @c TRUE on success.
 */
R_API rboolean r_setenv (const rchar * key, const rchar * val, rboolean always);
/** @brief Remove @p key from the process environment. */
R_API rboolean r_unsetenv (const rchar * key);

R_END_DECLS

/** @} */

#endif /* __R_ENV_H__ */
