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
#include "rlib-private.h"
#include <rlib/rthreads.h>

#ifdef R_OS_WIN32
#include <windows.h>
#endif

R_LOG_CATEGORY_DEFINE (rlib_logcat, "rlib", "Internal RLib logger",
    R_CLR_BG_CYAN | R_CLR_FMT_BOLD);

R_INITIALIZER (rlib_init)
{
  r_log_init ();
  r_log_category_register (&rlib_logcat);
  if (rlib_logcat.threshold < R_LOG_LEVEL_WARNING)
    r_log_category_set_threshold (&rlib_logcat, R_LOG_LEVEL_WARNING);

  r_ev_loop_init ();
  r_http_server_init ();
  r_mem_allocator_init ();
  r_module_init ();
  r_networking_init ();
  r_rtc_init ();
  r_srtp_init ();
  r_task_queue_init ();
  r_time_init ();
  r_thread_init ();
  r_test_init ();
  r_tls_server_init ();
}

R_DEINITIALIZER (rlib_deinit)
{
  r_thread_deinit ();
  r_networking_deinit ();
  r_mem_allocator_deinit ();
  r_ev_loop_deinit ();

  r_log_deinit ();
}

#ifdef R_OS_WIN32
BOOL WINAPI
DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  (void)hinstDLL;
  (void)fdwReason;
  (void)lpvReserved;

  if (fdwReason == DLL_THREAD_DETACH)
    r_thread_win32_dll_thread_detach ();

  return TRUE;
}
#endif
