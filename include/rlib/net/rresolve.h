/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_RESOLVE_H__
#define __R_RESOLVE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/net/rresolve.h
 * @brief Hostname / service resolution into a linked list of socket
 * addresses (synchronous @c getaddrinfo wrapper).
 */

#include <rlib/rtypes.h>

#include <rlib/net/rsocket.h>
#include <rlib/net/rsocketaddress.h>

/**
 * @defgroup r_resolve DNS resolution
 * @ingroup r_net
 *
 * @brief Resolve a host/service name into a linked list of
 * @ref RResolvedAddr socket addresses.
 *
 * @ref r_resolve_sync wraps the platform @c getaddrinfo: pass a host
 * and/or service string, optional @ref RResolveHints to constrain the
 * family / type / protocol, and @ref RResolveAddrFlags (mapped to the
 * @c R_AI_* flags). The result is a caller-owned list freed with
 * @ref r_resolved_addr_free.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Result code from a resolve operation. */
typedef enum {
  R_RESOLVE_IN_PROGRESS = -1, /**< Async resolution still pending. */
  R_RESOLVE_OK = 0,           /**< Success. */
  R_RESOLVE_INVAL,            /**< Invalid argument. */
  R_RESOLVE_OOM,              /**< Allocation failed. */
  R_RESOLVE_BAD_HINTS,        /**< Invalid @ref RResolveHints. */
  R_RESOLVE_BAD_FLAGS,        /**< Invalid @ref RResolveAddrFlags. */
  R_RESOLVE_NO_DATA,          /**< Name resolved but has no addresses. */
  R_RESOLVE_NOT_SUPPORTED,    /**< Requested family / operation unsupported. */
  R_RESOLVE_ERROR,            /**< Generic / unmapped resolver error. */
} RResolveResult;

/** @brief Resolution flags; mirror the platform @c AI_* hint flags. */
typedef enum {
  R_RESOLVE_ADDR_FLAG_PASSIVE     = R_AI_PASSIVE,     /**< Address intended for @c bind. */
  R_RESOLVE_ADDR_FLAG_CANONNAME   = R_AI_CANONNAME,   /**< Request the canonical name. */
  R_RESOLVE_ADDR_FLAG_NUMERICHOST = R_AI_NUMERICHOST, /**< Host is a numeric address. */
  R_RESOLVE_ADDR_FLAG_V4MAPPED    = R_AI_V4MAPPED,    /**< Allow IPv4-mapped IPv6. */
  R_RESOLVE_ADDR_FLAG_ALL         = R_AI_ALL,         /**< Return IPv6 + IPv4-mapped. */
  R_RESOLVE_ADDR_FLAG_ADDRCONFIG  = R_AI_ADDRCONFIG,  /**< Only host-configured families. */
} RResolveAddrFlag;
/** @brief Bitwise-OR of @ref RResolveAddrFlag values. */
typedef ruint32 RResolveAddrFlags;

/** @brief Constraints narrowing which addresses a resolve returns. */
typedef struct {
  RSocketFamily family;     /**< Desired address family, or @c NONE for any. */
  RSocketType type;         /**< Desired socket type, or @c NONE for any. */
  RSocketProtocol protocol; /**< Desired protocol, or @c DEFAULT for any. */
} RResolveHints;

/** @brief One resolved address; a node in a singly-linked result list. */
typedef struct RResolvedAddr RResolvedAddr;
struct RResolvedAddr {
  RResolveHints hints;      /**< Family / type / protocol of this address. */
  RSocketAddress * addr;    /**< The resolved socket address. */
  RResolvedAddr * next;     /**< Next address, or @c NULL at the end. */
};

/** @brief Free a resolved-address list returned by @ref r_resolve_sync. */
R_API void r_resolved_addr_free (RResolvedAddr * addr);
/**
 * @brief Synchronously resolve @p host / @p service into addresses.
 *
 * @param host    Host name or numeric address; may be @c NULL.
 * @param service Service name or port string; may be @c NULL.
 * @param flags   @ref RResolveAddrFlags controlling resolution.
 * @param hints   Optional constraints; may be @c NULL.
 * @param res     Optional out-pointer for the @ref RResolveResult.
 * @return Head of a caller-owned @ref RResolvedAddr list (free with
 *         @ref r_resolved_addr_free), or @c NULL on failure.
 */
R_API RResolvedAddr * r_resolve_sync (const rchar * host, const rchar * service,
    RResolveAddrFlags flags, const RResolveHints * hints, RResolveResult * res);


R_END_DECLS

/** @} */

#endif /* __R_RESOLVE_H__ */



