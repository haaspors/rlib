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
#ifndef __R_HZR_PTR_H__
#define __R_HZR_PTR_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/ratomic.h>


R_BEGIN_DECLS

#define R_HZR_PTR_INIT(notify) { 0, (RDestroyNotify)notify }
typedef struct {
  raptr ptr;
  RDestroyNotify notify;
} rhzrptr;
typedef struct _RHzrPtrRec RHzrPtrRec;

/* Access to the hzr pointer should be guarded with aqcuire/release pattern */
R_API rpointer r_hzr_ptr_aqcuire (rhzrptr * hzrptr, RHzrPtrRec * rec);
R_API void     r_hzr_ptr_release (rhzrptr * hzrptr, RHzrPtrRec * rec);
/* Overwriting the pointer should be done with replace, which will
 * automatically enforce garbage collecition for the previous */
R_API void r_hzr_ptr_replace (rhzrptr * hzrptr, rpointer ptr);


R_API RHzrPtrRec * r_hzr_ptr_rec_new (void);
R_API void r_hzr_ptr_rec_free (RHzrPtrRec * rec);

#endif /* __R_HZR_PTR_H__ */
