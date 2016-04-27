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
#ifndef __R_ASN1_PRIVATE_H__
#define __R_ASN1_PRIVATE_H__

#if !defined(RLIB_COMPILATION)
#error "rasn1-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>
#include <rlib/asn1/rasn1.h>
#include <rlib/rlist.h>
#include <rlib/rmemfile.h>

R_BEGIN_DECLS

#define R_ASN1_BIN_TLV_NEXT(tlv) ((tlv)->value + (tlv)->len)


typedef struct _RAsn1BinDecoder
{
  RRef ref;

  const ruint8 * data;
  rsize size;

  RSList * stack;
} RAsn1BinDecoder;


static void
r_asn1_bin_decoder_free (RAsn1BinDecoder * dec)
{
  r_slist_destroy_full (dec->stack, r_free);
  r_free (dec);
}

static inline RAsn1BinDecoder *
r_asn1_bin_decoder_new (const ruint8 * data, rsize size)
{
  RAsn1BinDecoder * ret;

  if (data != NULL && size > 0) {
    if ((ret = r_mem_new (RAsn1BinDecoder)) != NULL) {
      r_ref_init (ret, r_asn1_bin_decoder_free);
      ret->data = data;
      ret->size = size;
      ret->stack = NULL;
    }
  } else {
    ret = NULL;
  }

  return ret;
}

static inline RAsn1BinDecoder *
r_asn1_bin_decoder_new_file (const rchar * file)
{
  RMemFile * memfile;
  RAsn1BinDecoder * ret;

  if ((memfile = r_mem_file_new (file, R_MEM_PROT_READ, FALSE)) != NULL) {
    ret = r_asn1_bin_decoder_new (r_mem_file_get_mem (memfile),
        r_mem_file_get_size (memfile));
    r_mem_file_unref (memfile);
  } else {
    ret = NULL;
  }

  return ret;
}

R_END_DECLS

#endif /* __R_ASN1_PRIVATE_H__ */

