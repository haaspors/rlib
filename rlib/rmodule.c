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
#include "rlib-private.h"
#include <rlib/rmodule.h>

#include <rlib/relfparser.h>
#include <rlib/rmachoparser.h>

#include <rlib/rlog.h>
#include <rlib/rproc.h>
#include <rlib/rstr.h>

#ifdef RLIB_HAVE_MODULE

R_LOG_CATEGORY_DEFINE_STATIC (rmodule_logcat, "module", "Module logger",
    R_CLR_FG_CYAN | R_CLR_BG_BLUE | R_CLR_FMT_BOLD);
#define R_LOG_CAT_DEFAULT &rmodule_logcat

void
r_module_init (void)
{
  r_log_category_register (&rmodule_logcat);
}

#if defined (R_OS_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

RMODULE
r_module_open (const rchar * path, rboolean lazy, RModuleError * err)
{
  HMODULE mod;

  (void) lazy;

  if (err != NULL)
    *err = R_MODULE_ERROR_OK;

  if (!GetModuleHandleExA (0, path, &mod)) {
    if ((mod = LoadLibraryEx (path, NULL, 0)) == NULL) {
      if (err != NULL)
        *err = R_MODULE_ERROR_NOT_FOUND;
    }
  }

  R_LOG_TRACE ("Open module %s (lazy: %s) -> %p", path, lazy ? "Y" : "N", mod);
  return (RMODULE)mod;
}
rpointer
r_module_lookup (RMODULE mod, const rchar * sym)
{
  return GetProcAddress (mod, sym);
}
void
r_module_close (RMODULE mod)
{
  R_LOG_TRACE ("Close module %p", mod);
  FreeLibrary (mod);
}
rpointer
r_module_find_section (RMODULE mod, const rchar * name, rssize nsize,
    rsize * secsize)
{
  (void) nsize;
#pragma message ("TODO: PE/COFF")
  R_LOG_FIXME ("Used but not implemented (mod %p, name: '%s'", mod, name);
  if (secsize != NULL)
    *secsize = 0;
  return NULL;
}
#elif defined (HAVE_DLFCN_H)
#include <dlfcn.h>
#ifdef HAVE_LINK_H
#include <link.h>
#endif

RMODULE
r_module_open (const rchar * path, rboolean lazy, RModuleError * err)
{
  RMODULE mod;

  if ((mod = dlopen (path, lazy ? RTLD_LAZY : RTLD_NOW)) == NULL) {
    if (err != NULL)
      *err = R_MODULE_ERROR_NOT_FOUND;
  }

  R_LOG_TRACE ("Open module %s (lazy: %s) -> %p", path, lazy ? "Y" : "N", mod);
  return mod;
}
rpointer
r_module_lookup (RMODULE mod, const rchar * sym)
{
  return dlsym (mod, sym);
}
void
r_module_close (RMODULE mod)
{
  R_LOG_TRACE ("Close module %p", mod);
  dlclose (mod);
}

#ifdef __ELF__
static rpointer
_find_elf_section (rpointer mem, const rchar * file,
    const rchar * name, rssize nsize, rsize * secsize)
{
  RElfParser * fp;
  rpointer ret = NULL;

  if (R_UNLIKELY (!r_elf_is_valid (mem)))
    return NULL;

  if ((fp = r_elf_parser_new (file)) != NULL) {
    switch (r_elf_parser_get_class (fp)) {
      case R_ELF_CLASS32:
        {
          RElf32SHdr * shdr;
          if ((shdr = r_elf_parser_find_shdr32 (fp, name, nsize)) != NULL) {
            ruint32 baddr = r_elf_parser_get_base_addr32 (fp);
            if (secsize != NULL)
              *secsize = shdr->size;
            ret = (ruint8 *)mem + shdr->addr - baddr;
          }
        }
        break;
      case R_ELF_CLASS64:
        {
          RElf64SHdr * shdr;
          if ((shdr = r_elf_parser_find_shdr64 (fp, name, nsize)) != NULL) {
            ruint64 baddr = r_elf_parser_get_base_addr64 (fp);
            if (secsize != NULL)
              *secsize = shdr->size;
            ret = (ruint8 *)mem + shdr->addr - baddr;
          }
        }
        break;
    }
    r_elf_parser_unref (fp);
  }

  return ret;
}
#endif

#ifdef __MACH__
static rpointer
_find_macho_section (rpointer mem, const rchar * file,
    const rchar * name, rssize nsize, rsize * secsize)
{
  RMachoParser * f;
  rpointer ret = NULL;

  if (R_UNLIKELY (!r_macho_is_valid (mem)))
    return NULL;

  if ((f = r_macho_parser_new (file)) != NULL) {
    switch (r_macho_parser_get_magic (f)) {
      case R_MACHO_MAGIC_32:
        {
          RMachoSection32 * sec;
          if ((sec = r_macho_parser_find_section32 (f, name, nsize)) != NULL) {
            if (secsize != NULL)
              *secsize = sec->size;
            ret = (ruint8 *)mem + sec->addr;
          }
        }
        break;
      case R_MACHO_MAGIC_64:
        {
          RMachoSection64 * sec;
          if ((sec = r_macho_parser_find_section64 (f, name, nsize)) != NULL) {
            if (secsize != NULL)
              *secsize = sec->size;
            ret = (ruint8 *)mem + sec->addr;
          }
        }
        break;
    }
    r_macho_parser_unref (f);
  }

  return ret;
}
#endif

rpointer
r_module_find_section (RMODULE mod, const rchar * name, rssize nsize,
    rsize * secsize)
{
  rpointer ret = NULL;
  rpointer sym = NULL;
#ifdef HAVE_LINK_H
  struct link_map * lmap;
#endif

  if (R_UNLIKELY (mod == NULL)) return NULL;
  if (R_UNLIKELY (name == NULL)) return NULL;
  if (nsize < 0) nsize = r_strlen (name);

#ifdef HAVE_LINK_H
#ifdef HAVE_DLINFO
  if (dlinfo (mod, RTLD_DI_LINKMAP, &lmap) == 0)
    sym = lmap->l_ld;
#else
  sym = ((struct link_map *)mod)->l_ld;
#endif
#endif
#ifdef __MACH__
  if (sym == NULL && (sym = dlsym (mod, "_mh_dylib_header")) == NULL)
    sym = dlsym (mod, "_mh_execute_header");
#endif
  if (sym == NULL && (sym = dlsym (mod, "_init")) == NULL)
    sym = dlsym (mod, "__bss_start");

  if (sym != NULL) {
    R_LOG_TRACE ("Found a symbol in module %p -> %p", mod, sym);
#ifdef HAVE_DLADDR
    Dl_info info;
    if (dladdr (sym, &info) != 0 && info.dli_fbase != NULL) {
      rchar * fn;
      if (info.dli_fname != NULL && *info.dli_fname != 0)
        fn = r_strdup (info.dli_fname);
#ifdef HAVE_LINK_H
      else if (lmap->l_name != NULL && *lmap->l_name != 0)
        fn = r_strdup (lmap->l_name);
#endif
      else
        fn = r_proc_get_exe_path ();

#if defined (__ELF__)
      ret = _find_elf_section (info.dli_fbase, fn, name, nsize, secsize);
#elif defined (__MACH__)
      ret = _find_macho_section (info.dli_fbase, fn, name, nsize, secsize);
#else
#pragma message ("Unsupported platform for module binary lookup")
#endif
      R_LOG_TRACE ("Found section '%s' in binary '%s' -> %p", name, fn, ret);
      r_free (fn);
    }
#else
#pragma message ("Unsupported platform for module binary lookup")
#endif
  } else {
    R_LOG_INFO ("Didn't find symbol in module, when finding section '%s'", name);
  }

  if (R_UNLIKELY (ret == NULL)) {
    if (secsize != NULL)
      *secsize = 0;
  }

  return ret;
}
#else
#error no MODULE imlementation - consider disabling support
#endif
#else
rboolean
r_module_open (const rchar * path, rboolean lazy, RModuleError * err)
{
  (void) path;
  (void) lazy;
  (void) err;
  return FALSE;
}
rpointer
r_module_lookup (RMODULE mod, const rchar * sym)
{
  (void) mod;
  (void) sym;
  return NULL;
}
void r_module_close (RMODULE mod)
{
  (void) mod;
}
rpointer
r_module_find_section (RMODULE mod, const rchar * name, rssize nsize,
    rsize * secsize)
{
  (void) mod;
  (void) name;
  (void) nsize;
  if (secsize != NULL)
    *secsize = 0;
  return NULL;
}
#endif

