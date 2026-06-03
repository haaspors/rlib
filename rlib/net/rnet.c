/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rsocket-private.h"
#include "rnet-private.h"

void
r_networking_init (void)
{
#ifdef HAVE_WINSOCK2
  WORD req = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup (req, &wsaData);
#endif
}

void
r_networking_deinit (void)
{
#ifdef HAVE_WINSOCK2
  WSACleanup ();
#endif
}

