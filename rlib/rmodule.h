/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_MODULE_H__
#define __R_MODULE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#ifdef R_OS_WIN32
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
#else
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
#endif

R_BEGIN_DECLS

R_END_DECLS

#endif /* __R_MODULE_H__ */
