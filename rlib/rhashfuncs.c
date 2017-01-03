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

#include "config.h"

#include <rlib/rhashfuncs.h>

#include <rlib/rstr.h>


rsize
r_direct_hash (rconstpointer data)
{
  return RPOINTER_TO_SIZE (data);
}

rboolean
r_direct_equal (rconstpointer a, rconstpointer b)
{
  return *((const rsize *) a) == *((const rsize *) b);
}


/*
 * Based upon the commonly used algorithm posted
 * by Daniel Bernstein to comp.lang.c mailinglist.
 */
rsize
r_str_hash (rconstpointer data)
{
  const signed char * p;
  rsize ret = 5381;

  for (p = data; *p != 0; p++)
    ret = (ret << 5) + ret + *p;

  return ret;
}

rboolean
r_str_equal (rconstpointer a, rconstpointer b)
{
  return r_str_equals (a, b);
}

