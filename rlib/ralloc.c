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

#include "config.h"
#include <rlib/ralloc.h>
#include <string.h>

static const RMemVTable r_memsysvtable  = { malloc, calloc, realloc, free };
static RMemVTable r_memvtable           = { malloc, calloc, realloc, free };

void
r_free (rpointer ptr)
{
  r_memvtable.free (ptr);
}

rpointer
r_malloc (rsize size)
{
  rpointer ret;

  ret = r_memvtable.malloc (size);

  return ret;
}

rpointer
r_malloc0 (rsize size)
{
  rpointer ret;

  ret = r_memvtable.calloc (1, size);

  return ret;
}

rpointer
r_calloc (rsize count, rsize size)
{
  rpointer ret;

  ret = r_memvtable.calloc (count, size);

  return ret;
}

rpointer
r_realloc (rpointer ptr, rsize size)
{
  rpointer ret;

  ret = r_memvtable.realloc (ptr, size);

  return ret;
}

void
r_mem_set_vtable (RMemVTable * vtable)
{
  /* TODO: Sanity check incoming vtable? */
  r_memvtable = *vtable;
}

rboolean
r_mem_using_system_default (void)
{
  return memcmp (&r_memvtable, &r_memsysvtable, sizeof (RMemVTable)) == 0;
}

