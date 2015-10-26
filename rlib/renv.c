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
#include <rlib/renv.h>
#include <stdlib.h>

/* TODO: Implement for win32 (need utf8<->utf16 conv) */

const rchar *
r_getenv (const rchar * key)
{
#ifdef R_OS_WIN32
  return getenv (key);
#else
  return getenv (key);
#endif
}

rboolean
r_setenv (const rchar * key, const rchar * val, rboolean always)
{
#ifdef R_OS_WIN32
  (void)key;
  (void)val;
  (void)always;
  return FALSE;
#else
  return setenv (key, val, always) == 0;
#endif
}

rboolean
r_unsetenv (const rchar * key)
{
#ifdef R_OS_WIN32
  (void)key;
  return FALSE;
#else
  return unsetenv (key) == 0;
#endif
}

