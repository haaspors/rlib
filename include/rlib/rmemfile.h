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
#ifndef __R_MEM_FILE_H__
#define __R_MEM_FILE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

typedef struct _RMemFile RMemFile;

typedef enum {
  R_MEM_PROT_NONE   = 0x0,
  R_MEM_PROT_READ   = 0x1,
  R_MEM_PROT_WRITE  = 0x2,
  R_MEM_PROT_EXEC   = 0x4,
} RMemProt;

R_API RMemFile * r_mem_file_new (const rchar * file, RMemProt prot, rboolean writeback) R_ATTR_MALLOC;
R_API RMemFile * r_mem_file_new_from_fd (int fd, RMemProt prot, rboolean writeback) R_ATTR_MALLOC;
#define r_mem_file_ref r_ref_ref
#define r_mem_file_unref r_ref_unref

R_API rsize r_mem_file_get_size (RMemFile * file);
R_API rpointer r_mem_file_get_mem (RMemFile * file);

R_END_DECLS

#endif /* __R_MEM_FILE_H__ */

