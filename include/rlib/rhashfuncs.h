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
#ifndef __R_HASH_FUNCS_H__
#define __R_HASH_FUNCS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#define R_HASH_EMPTY                            RSIZE_MAX

R_BEGIN_DECLS

R_API rsize r_direct_hash (rconstpointer data);
R_API rboolean r_direct_equal (rconstpointer a, rconstpointer b);
R_API rsize r_str_hash (rconstpointer data);
R_API rsize r_str_hash_sized (const rchar * data, rssize size);
R_API rboolean r_str_equal (rconstpointer a, rconstpointer b);

R_END_DECLS

#endif /* __R_HASH_FUNCS_H__ */

