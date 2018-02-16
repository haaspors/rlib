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
#ifndef __R_PROC_H__
#define __R_PROC_H__

#include <rlib/rtypes.h>

R_BEGIN_DECLS

R_API rboolean r_proc_is_debugger_attached (void);
R_API rchar * r_proc_get_exe_path (void) R_ATTR_MALLOC;
R_API rchar * r_proc_get_exe_name (void) R_ATTR_MALLOC;

R_API int r_proc_get_id (void);

R_END_DECLS

#endif /* __R_PROC_H__ */

