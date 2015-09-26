/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include "rlib-internal.h"

#ifdef R_OS_WIN32
#include <windows.h>
#endif

R_INITIALIZER (rlib_init)
{
  r_time_init ();
}

R_DEINITIALIZER (rlib_deinit)
{
}

#ifdef R_OS_WIN32
BOOL WINAPI
DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  (void)hinstDLL;
  (void)fdwReason;
  (void)lpvReserved;

  return TRUE;
}
#endif
