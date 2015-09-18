/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include <rlib/rproc.h>
#include <stdlib.h>
#include <string.h>
#ifdef R_OS_WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

/* FIXME: Swapout /proc/self/status file stuff with rfile */

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

    if ((fd = open ("/proc/self/status", O_RDONLY)) > 0) {
      ssize_t num_read = read (fd, buf, sizeof (buf));

      if (num_read > 0) {
          rchar * tracer_pid;

          buf[num_read] = 0;
          if ((tracer_pid = strstr (buf, "TracerPid:")) != NULL)
            ret = atoi (tracer_pid + sizeof ("TracerPid:") - 1) != 0;
      }
      close (fd);
    }

#endif

  return ret;
}

