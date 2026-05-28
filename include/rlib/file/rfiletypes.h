/* RLIB - Convenience library for useful things
 * Copyright (C) 2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_FILE_TYPES_H__
#define __R_FILE_TYPES_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/file/rfiletypes.h
 * @brief Enums and flags shared across the file / filesystem / file-IO
 * APIs (access, open mode, share mode, flags, seek, error).
 */

#include <rlib/rtypes.h>
#include <stdio.h>

/** @addtogroup r_file
 *  @{ */

/** @brief File access rights (bitmask). */
typedef enum {
  R_FILE_ACCESS_NONE  = 0x00,                       /**< No access. */
  R_FILE_EXECUTE      = 0x01,                        /**< Execute permission. */
  R_FILE_WRITE        = 0x02,                        /**< Write permission. */
  R_FILE_READ         = 0x04,                        /**< Read permission. */
  R_FILE_RDWR         = (R_FILE_READ | R_FILE_WRITE),/**< Read + write. */
  R_FILE_ACCESS_ALL   = (R_FILE_EXECUTE | R_FILE_RDWR), /**< Read + write + execute. */
} RFileAccess;

/** @brief Unix-style permission triple (others / group / user). */
typedef struct {
  RFileAccess others;   /**< Access for other users. */
  RFileAccess group;    /**< Access for the owning group. */
  RFileAccess user;     /**< Access for the owning user. */
} RFilePermission;

/** @brief Disposition for opening a file (create / open / truncate). */
typedef enum {
  R_FILE_CREATE_NEW         = 1,  /**< Create; fail if it already exists. */
  R_FILE_CREATE_ALWAYS      = 2,  /**< Create, truncating any existing file. */
  R_FILE_OPEN_EXISTING      = 3,  /**< Open; fail if it does not exist. */
  R_FILE_OPEN_ALWAYS        = 4,  /**< Open, creating it if absent. */
  R_FILE_TRUNCATE_EXISTING  = 5,  /**< Open and truncate; fail if absent. */
} RFileOpenMode;

/** @brief Auxiliary flags for file open (bitmask). */
typedef enum {
  R_FILE_FLAG_NONE          = 0x00, /**< No flags. */
  R_FILE_FLAG_NONBLOCK      = 0x01, /**< Non-blocking I/O. */
  R_FILE_FLAG_CLOEXEC       = 0x02, /**< Close on @c exec. */
  R_FILE_FLAG_TEMPORARY     = 0x04, /**< Delete when the last handle closes. */
  R_FILE_FLAG_DIRECTORY     = 0x08, /**< Open a directory rather than a file. */
  R_FILE_FLAG_NO_CACHE      = 0x10, /**< Bypass the OS page cache. */
} RFileFlags;

/** @brief Sharing mode controlling concurrent access by others (bitmask). */
typedef enum {
  R_FILE_SHARE_EXCLUSIVE  = 0,  /**< No sharing. */
  R_FILE_SHARE_READ       = 1,  /**< Allow concurrent readers. */
  R_FILE_SHARE_WRITE      = 2,  /**< Allow concurrent writers. */
  R_FILE_SHARE_DELETE     = 4,  /**< Allow concurrent delete / rename. */
  R_FILE_SHARE_ALL        = (R_FILE_SHARE_READ | R_FILE_SHARE_WRITE | R_FILE_SHARE_DELETE), /**< Allow all of the above. */
} RFileShareMode;

/** @brief Reference point for a seek operation. */
typedef enum {
  R_SEEK_MODE_SET,  /**< From the start of the file. */
  R_SEEK_MODE_CUR,  /**< From the current position. */
  R_SEEK_MODE_END   /**< From the end of the file. */
} RSeekMode;

/** @brief Result code for file / IO operations. */
typedef enum {
  R_FILE_ERROR_OK,        /**< Success. */
  R_FILE_ERROR_AGAIN,     /**< Would block; retry later. */
  R_FILE_ERROR_INVAL,     /**< Invalid argument. */
  R_FILE_ERROR_BAD_FILE,  /**< Invalid or closed file handle. */
  R_FILE_ERROR_ERROR      /**< Generic / unmapped error. */
} RIOError;

/** @} */

#endif /* __R_FILE_TYPES_H__ */

