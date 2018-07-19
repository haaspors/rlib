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
#include <rlib/rmemfile.h>

#include <rlib/file/rfd.h>
#include <rlib/rmem.h>


#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#if defined (R_OS_WIN32)
#include <windows.h>
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

struct _RMemFile {
  RRef ref;
  rpointer mem;
  rsize size;
#ifdef R_OS_WIN32
  HANDLE handle;
#endif
};

static void
r_mem_file_free (RMemFile * file)
{
  if (file != NULL) {
#if defined (R_OS_WIN32)
    UnmapViewOfFile (file->mem);
    CloseHandle (file->handle);
#elif defined (HAVE_MMAP)
    munmap (file->mem, file->size);
#endif

    r_free (file);
  }
}

RMemFile *
r_mem_file_new (const rchar * file, RMemProt prot, rboolean writeback)
{
  RMemFile * ret = NULL;
  int fd, flags;

  flags = writeback ? O_RDWR : O_RDONLY;
  if ((fd = r_fd_open (file, flags, 0)) >= 0) {
    ret = r_mem_file_new_from_fd (fd, prot, writeback);
    r_fd_close (fd);
  }

  return ret;
}

#if defined (R_OS_WIN32)
static DWORD
_get_page_flags (RMemProt prot)
{
  DWORD ret = (prot & R_MEM_PROT_WRITE) ? PAGE_READWRITE : PAGE_READONLY;

  if (prot & R_MEM_PROT_EXEC)
    ret <<= 4;
  return ret;
}

static DWORD
_get_file_flags (RMemProt prot, rboolean writeback)
{
  if ((prot & R_MEM_PROT_WRITE) == 0)
    return FILE_MAP_READ;
  if (!writeback)
    return FILE_MAP_COPY;

  return FILE_MAP_WRITE;
}
#endif

RMemFile *
r_mem_file_new_from_fd (int fd, RMemProt prot, rboolean writeback)
{
  RMemFile * ret = NULL;
  ruint64 size = r_fd_get_filesize (fd);

  if (R_LIKELY (size <= RSIZE_MAX && (ret = r_mem_new (RMemFile)) != NULL)) {
    r_ref_init (ret, r_mem_file_free);
    ret->size = size;

#if defined (R_OS_WIN32)
    if ((ret->handle = CreateFileMapping ((HANDLE) _get_osfhandle (fd), NULL,
            _get_page_flags (prot), 0, 0, NULL)) != NULL) {
      if ((ret->mem = MapViewOfFile (ret->handle,
              _get_file_flags (prot, writeback), 0, 0, 0)) == NULL) {
        CloseHandle (ret->handle);
        r_free (ret);
        ret = NULL;
      }
    } else {
      r_free (ret);
      ret = NULL;
    }
#elif defined (HAVE_MMAP)
    if (ret->size > 0) {
      ret->mem = mmap (NULL, ret->size, prot,
          writeback ? MAP_SHARED : MAP_PRIVATE, fd, 0);
    } else {
      ret->mem = NULL;
    }
#else
    (void) prot;
    (void) writeback;
    ret->mem = NULL;
#endif
  }

  return ret;
}

rsize
r_mem_file_get_size (RMemFile * file)
{
  return file->size;
}

rpointer
r_mem_file_get_mem (RMemFile * file)
{
  return file->mem;
}

