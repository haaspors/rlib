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

/**
 * @defgroup r_hzrptr Hazard pointers
 * @ingroup r_data
 *
 * @brief Safe reclamation for lock-free data structures: readers
 * publish "I'm using @c p" hazard records so writers know not to
 * free @c p until every reader has moved on.
 *
 * The shape mirrors the canonical Michael 2004 design:
 *
 *   - Each reader thread owns an @ref RHzrPtrRec (created via
 *     @ref r_hzr_ptr_rec_new, freed at thread exit with
 *     @ref r_hzr_ptr_rec_free).
 *   - Accesses to a hazard pointer happen between
 *     @ref r_hzr_ptr_aqcuire and @ref r_hzr_ptr_release.
 *   - Writers swap pointers via @ref r_hzr_ptr_replace, which
 *     defers freeing the displaced value until no
 *     @ref RHzrPtrRec still references it. The per-pointer destroy
 *     notifier (stored on the @ref rhzrptr) runs at that point.
 *
 * @{
 */

/**
 * @file rlib/data/rhzrptr.h
 * @brief Hazard pointers — safe reclamation for lock-free reads.
 */

#include <rlib/rtypes.h>
#include <rlib/ratomic.h>


R_BEGIN_DECLS

/** @brief Static initialiser for an @ref rhzrptr with destroy notifier @p notify. */
#define R_HZR_PTR_INIT(notify) { 0, (RDestroyNotify)notify }
/**
 * @brief Pointer slot that participates in hazard-pointer
 * reclamation.
 *
 * @c ptr is the atomically-published value; @c notify is the
 * destructor called on the displaced value once every reader has
 * dropped their record.
 */
typedef struct {
  raptr ptr;                    /**< Published value (read/written atomically). */
  RDestroyNotify notify;        /**< Destructor for displaced values. */
} rhzrptr;
/** @brief Opaque per-thread hazard record. */
typedef struct RHzrPtrRec RHzrPtrRec;

/**
 * @brief Publish a hazard for the current value of @p hzrptr and
 * return it.
 *
 * Pair with @ref r_hzr_ptr_release once the caller is done with
 * the returned pointer; while a hazard is active on the value,
 * writers will defer freeing it.
 */
R_API rpointer r_hzr_ptr_aqcuire (rhzrptr * hzrptr, RHzrPtrRec * rec);
/** @brief Drop the hazard published by a previous @ref r_hzr_ptr_aqcuire. */
R_API void     r_hzr_ptr_release (rhzrptr * hzrptr, RHzrPtrRec * rec);
/**
 * @brief Atomically replace @p hzrptr's value with @p ptr and
 * schedule the displaced value for delayed reclamation.
 *
 * The previous value is freed via @c hzrptr->notify once no
 * @ref RHzrPtrRec still holds a hazard on it.
 */
R_API void r_hzr_ptr_replace (rhzrptr * hzrptr, rpointer ptr);


/** @brief Allocate a per-thread hazard record. */
R_API RHzrPtrRec * r_hzr_ptr_rec_new (void);
/** @brief Free a per-thread hazard record at thread exit. */
R_API void r_hzr_ptr_rec_free (RHzrPtrRec * rec);

/** @} */

#endif /* __R_HZR_PTR_H__ */
