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
#include <rlib/os/rproc.h>

#include <rlib/file/rfd.h>
#include <rlib/file/rfs.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#ifdef R_OS_WIN32
#include <windows.h>
#include <process.h>
#endif
#ifdef R_OS_DARWIN
#include <mach-o/dyld.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

/* FIXME: Swapout readlink with something more rlibish */

rboolean
r_proc_is_debugger_attached (void)
{
  rboolean ret = FALSE;

#if defined(R_OS_WIN32)
  ret = IsDebuggerPresent ();
#elif defined (P_TRACED)
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
  struct kinfo_proc info;
  rsize size = size = sizeof (info);

  mib[3] = getpid ();
  if (sysctl (mib, 4, &info, &size, NULL, 0) == 0)
    ret = (info.kp_proc.p_flag & P_TRACED) != 0;
#else
    rchar buf[1024];
    int fd;

    if ((fd = r_fd_open ("/proc/self/status", O_RDONLY, 0)) >= 0) {
      rssize num_read = r_fd_read (fd, buf, sizeof (buf) - 1);

      if (num_read > 0 && num_read < (rssize)sizeof (buf)) {
          rchar * tracer_pid;

          buf[num_read] = 0;
          if ((tracer_pid = r_strstr (buf, "TracerPid:")) != NULL)
            ret = r_str_to_int (tracer_pid + R_STR_SIZEOF ("TracerPid:"), NULL, 10, NULL) != 0;
      }
      r_fd_close (fd);
    }

#endif

  return ret;
}

rchar *
r_proc_get_exe_path (void)
{
  rchar * ret = NULL;
#if defined(R_OS_WIN32)
  rchar tmp[MAX_PATH + 1];
  if (GetModuleFileNameA (NULL, tmp, MAX_PATH) != 0)
    ret = r_strdup (tmp);
#elif defined(R_OS_DARWIN)
  uint32_t size = 0;
  _NSGetExecutablePath (NULL, &size);
  if (size > 0) {
    rchar * tmp = r_alloca (size + 1);
    if (_NSGetExecutablePath (tmp, &size) == 0)
      ret = realpath (tmp, NULL);
  }
#elif defined(R_OS_SOLARIS)
  ret = r_strdup (getexename ());
#else
  rsize size;
  for (size = 64; (ret = r_realloc (ret, size + 1)) != NULL; size *= 2) {
    rssize linksize;
    if ((linksize = readlink ("/proc/self/exe", ret, size)) >= 0) {
      ret[linksize] = 0;
      break;
    } else if (errno != ENAMETOOLONG) {
      r_free (ret);
      ret = NULL;
      break;
    }
  }
#endif
  return ret;
}

rchar *
r_proc_get_exe_name (void)
{
  rchar * path = r_proc_get_exe_path ();
  rchar * ret = r_fs_path_basename (path);

  r_free (path);
  return ret;
}

int
r_proc_get_id (void)
{
  return getpid ();
}

