/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_MODULE_H__
#define __R_MODULE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

typedef rpointer RMODULE;

typedef enum {
  R_MODULE_ERROR_OK = 0,
  R_MODULE_ERROR_NOT_FOUND,
} RModuleError;

R_API RMODULE r_module_open (const rchar * path, rboolean lazy, RModuleError * err);
R_API rpointer r_module_lookup (RMODULE mod, const rchar * sym);
R_API void r_module_close (RMODULE mod);

R_END_DECLS

#endif /* __R_MODULE_H__ */
