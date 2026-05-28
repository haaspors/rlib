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

/**
 * @file rlib/os/rmodule.h
 * @brief Dynamic library loading (@c dlopen / @c LoadLibrary) with
 * symbol and section lookup.
 */

#include <rlib/rtypes.h>

R_BEGIN_DECLS

/**
 * @defgroup r_module Dynamic modules
 * @ingroup r_os
 *
 * @brief Open shared libraries at runtime, resolve exported symbols
 * and walk named sections.
 *
 * The implementation maps onto @c dlopen / @c dlsym / @c dlclose on
 * Unix and @c LoadLibrary / @c GetProcAddress / @c FreeLibrary on
 * Windows.
 *
 * @{
 */

/** @brief Opaque module handle returned by @ref r_module_open. */
typedef rpointer RMODULE;

/** @brief Result of @ref r_module_open. */
typedef enum {
  R_MODULE_ERROR_OK = 0,        /**< Module loaded successfully. */
  R_MODULE_ERROR_NOT_FOUND,     /**< File missing or could not be loaded. */
} RModuleError;

/**
 * @brief Open the shared library at @p path.
 * @param path Filesystem path to a @c .so / @c .dylib / @c .dll.
 * @param lazy @c TRUE for lazy symbol binding (@c RTLD_LAZY), @c FALSE
 *             for eager (@c RTLD_NOW).
 * @param err  Optional out-pointer that receives a @ref RModuleError code.
 * @return Module handle on success, @c NULL on failure (see @p err).
 */
R_API RMODULE r_module_open (const rchar * path, rboolean lazy, RModuleError * err);
/**
 * @brief Resolve symbol @p sym in @p mod.
 * @return Pointer to the symbol's address, or @c NULL if unresolved.
 */
R_API rpointer r_module_lookup (RMODULE mod, const rchar * sym);
/** @brief Close @p mod and release any backing OS resources. */
R_API void r_module_close (RMODULE mod);

/**
 * @brief Locate a named section within @p mod's loaded image.
 *
 * Useful for embedding read-only data tables and reaching them by
 * section name (e.g. ELF @c .rodata.foo, Mach-O @c __DATA,foo,
 * PE @c .rdata$foo) without exporting a symbol.
 *
 * @param mod     Module handle.
 * @param name    Section name.
 * @param nsize   Length of @p name in bytes, or @c -1 for @c strlen.
 * @param secsize Out-pointer that receives the section's byte size.
 * @return Pointer to the section's start, or @c NULL if absent.
 */
R_API rpointer r_module_find_section (RMODULE mod,
    const rchar * name, rssize nsize, rsize * secsize);

R_END_DECLS

/** @} */

#endif /* __R_MODULE_H__ */
