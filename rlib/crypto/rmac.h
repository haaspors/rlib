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
#ifndef __R_CRYPTO_MAC_H__
#define __R_CRYPTO_MAC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rhash.h>

R_BEGIN_DECLS

typedef struct _RHmac       RHmac;

R_API RHmac * r_hmac_new (RHashType type, rconstpointer key, rsize keysize) R_ATTR_MALLOC;
R_API void r_hmac_free (RHmac * hmac);

R_API void r_hmac_reset (RHmac * hmac);

R_API rboolean r_hmac_update (RHmac * hmac, rconstpointer data, rsize size);
R_API rboolean r_hmac_get_data (RHmac * hmac, ruint8 * data, rsize * size);
R_API rchar * r_hmac_get_hex (RHmac * hmac);

R_END_DECLS

#endif /* __R_CRYPTO_MAC_H__ */

