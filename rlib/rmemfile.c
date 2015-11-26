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
#include <rlib/ratomic.h>
#include <rlib/rfd.h>
#include <rlib/rmem.h>

#include <sys/stat.h>
#if defined (R_OS_WIN32)
#include <windows.h>
#include <io.h>
#ifdef fstat
#undef fstat
#endif
#ifdef stat
#undef stat
#endif
#define fstat(a,b) _fstati64(a,b)
#define stat _stati64
#elif defined (R_OS_UNIX)
#include <sys/mman.h>
#include <unistd.h>
#endif

struct _RMemFile {
  rauint refcount;
  rpointer mem;
  rsize size;
#ifdef R_OS_WIN32
  HANDLE handle;
#endif
};

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

RMemFile *
r_mem_file_new_from_fd (int fd, RMemProt prot, rboolean writeback)
{
  RMemFile * ret = NULL;
  struct stat st;

  if (fstat (fd, &st) == 0) {
    if (R_LIKELY ((ret = r_malloc (sizeof (RMemFile))) != NULL)) {
      r_atomic_uint_store (&ret->refcount, 1);
      ret->size = (rsize)st.st_size;
#if defined (R_OS_WIN32)
      if ((ret->handle = CreateFileMapping ((HANDLE) _get_osfhandle (fd), NULL,
              _get_page_flags (prot, writeback), 0, 0, NULL)) != NULL) {
        if ((file->mem = MapViewOfFile (file->handle, _get_file_flags (prot),
                0, 0, 0)) == NULL) {
          CloseHandle (file->handle);
          r_free (ret);
          ret = NULL;
        }
      } else {
        r_free (ret);
        ret = NULL;
      }
#elif defined (R_OS_UNIX)
      ret->mem = mmap (NULL, ret->size, prot,
          writeback ? MAP_SHARED : MAP_PRIVATE, fd, 0);
#endif
    }
  }

  return ret;
}

static void
r_mem_file_free (RMemFile * file)
{
  if (file != NULL) {
#if defined (R_OS_WIN32)
    UnmapViewOfFile (file->mem);
    CloseHandle (file->handle);
#elif defined (R_OS_UNIX)
    munmap (file->mem, file->size);
#endif

    r_free (file);
  }
}

RMemFile *
r_mem_file_ref (RMemFile * file)
{
  r_atomic_uint_fetch_add (&file->refcount, 1);
  return file;
}

void
r_mem_file_unref (RMemFile * file)
{
  if (r_atomic_uint_fetch_sub (&file->refcount, 1) == 1)
    r_mem_file_free (file);
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

