/* RLIB - Convenience library for useful things
 * Copyright (C) 2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rasn1-private.h"

#include <rlib/asn1/roid.h>
#include <rlib/rstr.h>

static const struct x500attrtype {
  const rchar * name;
  rsize namesize;
  const rchar * oid;
  rsize oidsize;
} x500_attr_table[] = {
  { R_STR_WITH_SIZE_ARGS ("CN"),     R_STR_WITH_SIZE_ARGS (R_ID_AT_OID_COMMON_NAME) },
  { R_STR_WITH_SIZE_ARGS ("SN"),     R_STR_WITH_SIZE_ARGS (R_ID_AT_OID_SURNAME) },
  { R_STR_WITH_SIZE_ARGS ("C"),      R_STR_WITH_SIZE_ARGS (R_ID_AT_OID_CUNTRY_NAME) },
  { R_STR_WITH_SIZE_ARGS ("L"),      R_STR_WITH_SIZE_ARGS (R_ID_AT_OID_LOCALITY_NAME) },
  { R_STR_WITH_SIZE_ARGS ("ST"),     R_STR_WITH_SIZE_ARGS (R_ID_AT_OID_STATE_OR_PROVINCE_NAME) },
  { R_STR_WITH_SIZE_ARGS ("STREET"), R_STR_WITH_SIZE_ARGS (R_ID_AT_OID_STREET_ADDRESS) },
  { R_STR_WITH_SIZE_ARGS ("O"),      R_STR_WITH_SIZE_ARGS (R_ID_AT_OID_ORGANIZATION_NAME) },
  { R_STR_WITH_SIZE_ARGS ("OU"),     R_STR_WITH_SIZE_ARGS (R_ID_AT_OID_ORGANIZATIONAL_UNIT_NAME) },
  { R_STR_WITH_SIZE_ARGS ("UID"),    R_STR_WITH_SIZE_ARGS (R_PSS_OID_USER_ID) },
  { R_STR_WITH_SIZE_ARGS ("DC"),     R_STR_WITH_SIZE_ARGS (R_PSS_OID_DOMAIN_COMPONENT) },
};

const rchar *
r_asn1_x500_name_from_oid (rconstpointer p, rsize size)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (x500_attr_table); i++) {
    if (r_asn1_oid_bin_equals_full (p, size,
          x500_attr_table[i].oid, x500_attr_table[i].oidsize)) {
      return x500_attr_table[i].name;
    }
  }

  return NULL;
}

const rchar *
r_asn1_x500_name_to_oid (const rchar * name, rsize size)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (x500_attr_table); i++) {
    if (size == x500_attr_table[i].namesize &&
        r_strncmp (x500_attr_table[i].name, name, size) == 0)
      return x500_attr_table[i].oid;
  }

  return NULL;
}

