/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_BINFMT_H__
#define __R_BINFMT_H__

/**
 * @defgroup r_binfmt Binary executable formats
 *
 * @brief Parsers for the on-disk executable / object-file formats
 * used by the major operating systems: ELF (Linux, BSD, most Unix),
 * Mach-O (macOS, iOS) and PE / COFF (Windows).
 *
 * Each format ships as a pair of headers:
 *
 *   - A **spec header** (`r<fmt>.h`) carrying the on-disk constants
 *     and structs - magic numbers, header layouts, section / segment
 *     types, machine identifiers, flag bitmasks, etc. - in a form
 *     callers can read into directly after mmap.
 *   - A **parser header** (`r<fmt>parser.h`) wrapping the spec
 *     types in an opaque `R<Fmt>Parser` handle with accessors that
 *     walk the file, return slice pointers / parsed sub-structs,
 *     and resolve string tables.
 *
 * Use the parser when you want bounds-checked, opaque access; use
 * the spec header directly when you know the format and want to
 * cast through @c mmap'd bytes.
 *
 * Sub-areas:
 *
 *   - @ref r_binfmt_elf — ELF (Linux / BSD / SysV).
 *   - @ref r_binfmt_macho — Mach-O (macOS / iOS).
 *   - @ref r_binfmt_pe — PE / COFF (Windows).
 */

/**
 * @defgroup r_binfmt_elf ELF
 * @ingroup r_binfmt
 *
 * @brief Executable and Linkable Format - the SysV-style executable
 * / shared-object / relocatable file format used by Linux and most
 * Unix-like systems.
 *
 * Defined by the System V ABI; rlib covers both ELF32 and ELF64
 * variants and both endiannesses where the parser does not need to
 * load segment data into native memory.
 */

/**
 * @defgroup r_binfmt_macho Mach-O
 * @ingroup r_binfmt
 *
 * @brief Mach Object format - the executable / dylib / object-file
 * format used by macOS and iOS, descended from NeXTSTEP.
 *
 * Single- and fat-binary variants are supported; the latter packs
 * multiple per-architecture Mach-O slices into one file.
 */

/**
 * @defgroup r_binfmt_pe PE / COFF
 * @ingroup r_binfmt
 *
 * @brief Portable Executable - Microsoft's extension of COFF used
 * for Windows executables (`.exe`), DLLs, kernel modules and the
 * `.obj` object files that link them.
 *
 * The format layers a DOS stub plus a PE32 / PE32+ optional header
 * on top of a classic COFF section table; rlib's accessors hide
 * that layering behind the opaque @c RPeParser.
 */

#include <rlib/rlib.h>

#include <rlib/binfmt/relf.h>
#include <rlib/binfmt/relfparser.h>
#include <rlib/binfmt/rmacho.h>
#include <rlib/binfmt/rmachoparser.h>
#include <rlib/binfmt/rpe.h>
#include <rlib/binfmt/rpeparser.h>

#endif /* __R_BINFMT_H__ */

