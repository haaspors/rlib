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
/**
 * @defgroup r_mem_file Memory-mapped file regions
 * @brief Map a whole file (or an open file handle) into the process
 * address space as a single contiguous byte buffer.
 * @{
 */

/**
 * @file rlib/rmemfile.h
 * @brief Memory-mapped file API.
 *
 * Thin portability wrapper around @c mmap on POSIX and
 * @c CreateFileMapping / @c MapViewOfFile on Win32. Maps the entire
 * file at construction time; the resulting @c RMemFile is a
 * refcounted view (use @c r_mem_file_ref / @c r_mem_file_unref).
 *
 * Useful for read-only parsing of file-backed binary formats (ELF,
 * PE, PDF, etc.) where you want a single pointer + length to feed
 * into a streaming parser instead of doing buffered @c read calls.
 */
#ifndef __R_MEM_FILE_H__
#define __R_MEM_FILE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

/**
 * @brief Opaque handle to a memory-mapped file region.
 *
 * Refcounted; obtain a new reference with @c r_mem_file_ref, release
 * with @c r_mem_file_unref. The underlying mapping is torn down when
 * the last reference drops.
 */
typedef struct RMemFile RMemFile;

/**
 * @brief Page-level protection flags for the mapping.
 *
 * Combined with bitwise-OR. Mirrors POSIX @c PROT_* and Win32
 * @c PAGE_* semantics. @c R_MEM_PROT_WRITE on its own is rarely
 * useful - pair with @c R_MEM_PROT_READ.
 */
typedef enum {
  R_MEM_PROT_NONE   = 0x0,          /**< No access. */
  R_MEM_PROT_READ   = 0x1,          /**< Pages may be read. */
  R_MEM_PROT_WRITE  = 0x2,          /**< Pages may be written. */
  R_MEM_PROT_EXEC   = 0x4,          /**< Pages may be executed. */
} RMemProt;

/**
 * @brief Map @p file into memory by pathname.
 *
 * Opens @p file, maps it, and closes the file handle (the kernel
 * keeps the mapping alive). Equivalent to @c r_mem_file_new_from_handle
 * with the file-open step folded in.
 *
 * @param file      Filesystem path.
 * @param prot      Page-protection flags (see @c RMemProt).
 * @param writeback If @c TRUE and @p prot includes @c R_MEM_PROT_WRITE,
 *                  writes propagate back to the file
 *                  (@c MAP_SHARED on POSIX). If @c FALSE writes go to
 *                  a private copy (@c MAP_PRIVATE).
 * @return A new @c RMemFile reference, or @c NULL on open / map
 *         failure.
 */
R_API RMemFile * r_mem_file_new (const rchar * file, RMemProt prot, rboolean writeback) R_ATTR_MALLOC;

/**
 * @brief Map an already-opened file handle into memory.
 *
 * Lets the caller control the open flags (e.g. unicode paths,
 * @c O_DIRECT, OS-specific share modes). The mapping outlives the
 * handle's open state - on Win32 the @c CreateFileMapping object
 * keeps the file alive; on POSIX the kernel reference counts the
 * inode.
 *
 * @param handle    An open file handle (rlib's @c RIOHandle type).
 * @param prot      Page-protection flags.
 * @param writeback Write-back behaviour (see @c r_mem_file_new).
 * @return A new @c RMemFile reference, or @c NULL on map failure.
 */
R_API RMemFile * r_mem_file_new_from_handle (RIOHandle handle, RMemProt prot, rboolean writeback) R_ATTR_MALLOC;

/** @brief Acquire a new reference to @p file. */
#define r_mem_file_ref r_ref_ref

/** @brief Release a reference to @p file; unmaps when the last drops. */
#define r_mem_file_unref r_ref_unref

/**
 * @brief Size of the mapped region in bytes.
 *
 * @param file Mapped file (may be @c NULL, returns 0).
 * @return File size in bytes.
 */
R_API rsize r_mem_file_get_size (RMemFile * file);

/**
 * @brief Pointer to the first byte of the mapped region.
 *
 * The returned pointer is valid until the last @c RMemFile reference
 * is dropped. May be @c NULL for empty files or if the mapping
 * failed silently (e.g. platform without @c mmap and no Win32 path).
 *
 * @param file Mapped file (may be @c NULL, returns @c NULL).
 * @return Pointer to the first mapped byte.
 */
R_API rpointer r_mem_file_get_mem (RMemFile * file);

R_END_DECLS

/** @} */

#endif /* __R_MEM_FILE_H__ */

