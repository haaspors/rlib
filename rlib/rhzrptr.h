/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
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
