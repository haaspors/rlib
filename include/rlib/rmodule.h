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
#ifndef __R_MODULE_H__
#define __R_MODULE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#ifdef R_OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef HMODULE   RMODULE;
static inline rboolean r_module_open (RMODULE * mod, const rchar * path)
{
  return GetModuleHandleExA (0, path, mod);
}
static inline rpointer r_module_lookup (RMODULE mod, const rchar * sym)
{
  return GetProcAddress (mod, sym);
}
static inline void r_module_close (RMODULE mod)
{
  FreeLibrary (mod);
}
#elif HAVE_DLFCN_H
#include <dlfcn.h>

typedef rpointer RMODULE;
static inline rboolean r_module_open (RMODULE * mod, const rchar * path)
{
  *mod = dlopen (path, RTLD_NOW);
  return *mod != NULL;
}
static inline rpointer r_module_lookup (RMODULE mod, const rchar * sym)
{
  return dlsym (mod, sym);
}
static inline void r_module_close (RMODULE mod)
{
  dlclose (mod);
}
#else
typedef rpointer RMODULE;
static inline rboolean r_module_open (RMODULE * mod, const rchar * path)
{
  (void) mod;
  (void) path;
  return FALSE;
}
static inline rpointer r_module_lookup (RMODULE mod, const rchar * sym)
{
  (void) mod;
  (void) sym;
  return NULL;
}
static inline void r_module_close (RMODULE mod)
{
  (void) mod;
}
#endif

R_BEGIN_DECLS

R_END_DECLS

#endif /* __R_MODULE_H__ */
