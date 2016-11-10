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
#include <rlib/asn1/rasn1-private.h>

#include <rlib/rstr.h>
#include <rlib/rtime.h>

static void
r_asn1_bin_encoder_free (RAsn1BinEncoder * enc)
{
  r_slist_destroy_full (enc->stack, r_buffer_unref);
  r_buffer_unref (enc->buf);
  r_free (enc);
}

RAsn1BinEncoder *
r_asn1_bin_encoder_new (RAsn1EncodingRules enc)
{
  RAsn1BinEncoder * ret;

  if (R_UNLIKELY (enc >= R_ASN1_ENCODING_RULES_COUNT)) return NULL;

  if ((ret = r_mem_new (RAsn1BinEncoder)) != NULL) {
    r_ref_init (ret, r_asn1_bin_encoder_free);
    ret->enc = enc;
    ret->buf = r_buffer_new ();
    ret->stack = NULL;
    ret->offset = 0;
  }

  return ret;
}

ruint8 *
r_asn1_bin_encoder_get_data (RAsn1BinEncoder * enc, rsize * size)
{
  RBuffer * buf = NULL;
  ruint8 * ret = NULL;

  if (r_asn1_bin_encoder_get_buffer (enc, &buf) == R_ASN1_ENCODER_OK) {
    ret = r_buffer_extract_dup (buf, 0, r_buffer_get_size (buf), size);
    r_buffer_unref (buf);
  }

  return ret;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_get_buffer (RAsn1BinEncoder * enc, RBuffer ** buf)
{
  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY (buf == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if (R_UNLIKELY (enc->stack != NULL)) return R_ASN1_ENCODER_INDEFINITE;
  if (R_UNLIKELY ((*buf = r_buffer_new ()) == NULL)) return R_ASN1_ENCODER_OOM;

  if (r_buffer_append_region_from (*buf, enc->buf, (rsize)0, enc->offset))
    return R_ASN1_ENCODER_OK;

  r_buffer_unref (*buf);
  *buf = NULL;
  return R_ASN1_ENCODER_INDEFINITE;
}

static rsize
r_asn1_bin_write_definite_len (ruint8 * ptr, rsize len)
{
  /* short form */
  if (len < 0x80) {
    ptr[0] = (ruint8)(len & 0x7f);
    return 1;
  }

  /* long form */
  if (len <= RUINT8_MAX) {
    ptr[0] = 0x81;
    ptr[1] = (len      ) & 0xff;
    return 2;
  }
#if RLIB_SIZEOF_SIZE_T >= 2
  else if (len <= RUINT16_MAX) {
    ptr[0] = 0x82;
    ptr[1] = (len >>  8) & 0xff;
    ptr[2] = (len      ) & 0xff;
    return 3;
  }
#endif
#if RLIB_SIZEOF_SIZE_T >= 4
  else if (len <= RUINT32_MAX) {
    ptr[0] = 0x84;
    ptr[1] = (len >> 24) & 0xff;
    ptr[2] = (len >> 16) & 0xff;
    ptr[3] = (len >>  8) & 0xff;
    ptr[4] = (len      ) & 0xff;
    return 5;
  }
#endif
#if RLIB_SIZEOF_SIZE_T >= 8
  else if (len <= RUINT64_MAX) {
    ptr[0] = 0x88;
    ptr[1] = (len >> 56) & 0xff;
    ptr[2] = (len >> 48) & 0xff;
    ptr[3] = (len >> 40) & 0xff;
    ptr[4] = (len >> 32) & 0xff;
    ptr[5] = (len >> 24) & 0xff;
    ptr[6] = (len >> 16) & 0xff;
    ptr[7] = (len >>  8) & 0xff;
    ptr[8] = (len      ) & 0xff;
    return 9;
  }
#endif

  return 0;
}

static ruint8 *
r_asn1_bin_encoder_map (RAsn1BinEncoder * enc, rsize size)
{
  ruint8 * ret = NULL;

  if (enc->offset + size > r_buffer_get_size (enc->buf)) {
    RMem * mem = r_mem_allocator_alloc_full (NULL, MAX (size, 4096), NULL);
    if (mem != NULL) {
      if (r_buffer_mem_append (enc->buf, mem)) {
        if (r_buffer_map_byte_range (enc->buf, enc->offset, (rssize)size, &enc->info, R_MEM_MAP_WRITE))
          ret = enc->info.data;
      }
      r_mem_unref (mem);
    }
  } else {
    if (r_buffer_map_byte_range (enc->buf, enc->offset, (rssize)size, &enc->info, R_MEM_MAP_WRITE))
      ret = enc->info.data;
  }

  return ret;
}

static inline rboolean
r_asn1_bin_encoder_unmap (RAsn1BinEncoder * enc, rsize used)
{
  enc->offset += used;
  return r_buffer_unmap (enc->buf, &enc->info);
}

RAsn1EncoderStatus
r_asn1_bin_encoder_begin_constructed (RAsn1BinEncoder * enc, ruint8 id, rsize sizehint)
{
  ruint8 * ptr;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if (enc->enc == R_ASN1_BER) {
    if ((ptr = r_asn1_bin_encoder_map (enc, 2)) == NULL)
      return R_ASN1_ENCODER_OOM;

    ptr[0] = id;
    ptr[1] = R_ASN1_BIN_LENGTH_INDEFINITE;
    r_asn1_bin_encoder_unmap (enc, 2);
    enc->stack = r_slist_prepend (enc->stack, r_buffer_ref (enc->buf));
  } else /*if (enc->enc == R_ASN1_DER)*/ {
    RBuffer * buf;

    if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (rsize))) == NULL)
      return R_ASN1_ENCODER_OOM;

    ptr[0] = id;
    r_memclear (&ptr[1], 1 + sizeof (rsize));
    r_asn1_bin_encoder_unmap (enc, 2 + sizeof (rsize));

    if ((buf = r_buffer_new ()) == NULL)
      return R_ASN1_ENCODER_OOM;
    if (sizehint > 0) {
      RMem * mem = r_mem_allocator_alloc_full (NULL, sizehint, NULL);
      if (mem != NULL) {
        r_buffer_mem_append (buf, mem);
        r_mem_unref (mem);
      }
    }

    r_buffer_set_size (enc->buf, enc->offset);
    enc->stack = r_slist_prepend (enc->stack, enc->buf);
    enc->buf = buf;
    enc->offset = 0;
  }

  return R_ASN1_ENCODER_OK;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_begin_bit_string (RAsn1BinEncoder * enc, rsize sizehint)
{
  RAsn1EncoderStatus ret;
  ruint8 id;

  id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_BIT_STRING);
  if ((ret = r_asn1_bin_encoder_begin_constructed (enc, id, sizehint)) == R_ASN1_ENCODER_OK) {
    ruint8 * ptr;

    if ((ptr = r_asn1_bin_encoder_map (enc, 1)) != NULL) {
      ptr[0] = 0;
      r_asn1_bin_encoder_unmap (enc, 1);
    } else {
      ret = R_ASN1_ENCODER_OOM;
      r_asn1_bin_encoder_end_constructed (enc);
    }
  }

  return ret;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_end_constructed (RAsn1BinEncoder * enc)
{
  ruint8 * ptr;
  RSList * lst;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY ((lst = enc->stack) == NULL))
    return R_ASN1_ENCODER_INVALID_ARG;

  enc->stack = r_slist_next (enc->stack);
  if (enc->enc == R_ASN1_BER) {
    r_slist_free1_full (lst, r_buffer_unref);

    if ((ptr = r_asn1_bin_encoder_map (enc, 2)) == NULL)
      return R_ASN1_ENCODER_OOM;

    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_EOC);
    ptr[1] = 0;
    r_asn1_bin_encoder_unmap (enc, 2);
  } else /*if (enc->enc == R_ASN1_DER)*/ {
    RBuffer * buf;
    RMemMapInfo info;
    rsize size;

    r_buffer_set_size (enc->buf, enc->offset);
    buf = enc->buf;
    enc->buf = r_slist_data (lst);
    r_slist_free1 (lst);

    size = r_buffer_get_size (enc->buf) - (1 + sizeof (rsize));
    if (r_buffer_map_byte_range (enc->buf, size, 1 + sizeof (rsize),
        &info, R_MEM_MAP_WRITE)) {
      size += r_asn1_bin_write_definite_len (info.data, enc->offset);
      r_buffer_unmap (enc->buf, &info);

      r_buffer_set_size (enc->buf, size);

      r_buffer_append_from (enc->buf, buf);
      enc->offset += size;
      r_buffer_unref (buf);
    } else {
      r_buffer_unref (buf);
      return R_ASN1_ENCODER_INDEFINITE;
    }
  }

  return R_ASN1_ENCODER_OK;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_raw (RAsn1BinEncoder * enc, ruint8 id,
    rconstpointer data, rsize size)
{
  ruint8 * ptr;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY (data == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (rsize) + size)) != NULL) {
    rsize off = 1;

    ptr[0] = id;
    off += r_asn1_bin_write_definite_len (&ptr[off], size);
    r_memcpy (&ptr[off], data, size);
    r_asn1_bin_encoder_unmap (enc, off + size);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_null (RAsn1BinEncoder * enc)
{
  ruint8 * ptr;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2)) != NULL) {
    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_NULL);
    ptr[1] = 0;
    r_asn1_bin_encoder_unmap (enc, 2);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_boolean (RAsn1BinEncoder * enc, rboolean value)
{
  ruint8 * ptr;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 3)) != NULL) {
    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_BOOLEAN);
    ptr[1] = 1;
    ptr[2] = value ? 0xff : 0x00;
    r_asn1_bin_encoder_unmap (enc, 3);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_integer_i32 (RAsn1BinEncoder * enc, rint32 value)
{
  ruint8 * ptr;

  if (value >= 0)
    return r_asn1_bin_encoder_add_integer_u32 (enc, (ruint32) value);

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (ruint32))) != NULL) {
    ruint32 u = -value - 1;

    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_INTEGER);

    if (u < 0x000000ff) {
      u ^= RUINT32_MAX;
      ptr[1] = 1;
      ptr[2] = (ruint8)((u      ) & 0xff);
    } else if (u < 0x0000ffff) {
      u ^= RUINT32_MAX;
      ptr[1] = 2;
      ptr[2] = (ruint8)((u >>  8) & 0xff);
      ptr[3] = (ruint8)((u      ) & 0xff);
    } else if (u < 0x00ffffff) {
      u ^= RUINT32_MAX;
      ptr[1] = 3;
      ptr[2] = (ruint8)((u >> 16) & 0xff);
      ptr[3] = (ruint8)((u >>  8) & 0xff);
      ptr[4] = (ruint8)((u      ) & 0xff);
    } else {
      u ^= RUINT32_MAX;
      ptr[1] = 4;
      ptr[2] = (ruint8)((u >> 24) & 0xff);
      ptr[3] = (ruint8)((u >> 16) & 0xff);
      ptr[4] = (ruint8)((u >>  8) & 0xff);
      ptr[5] = (ruint8)((u      ) & 0xff);
    }

    r_asn1_bin_encoder_unmap (enc, 2 + ptr[1]);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_integer_u32 (RAsn1BinEncoder * enc, ruint32 value)
{
  ruint8 * ptr;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (ruint32))) != NULL) {
    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_INTEGER);

    if (value < 0x000000ff) {
      ptr[1] = 1;
      ptr[2] = (ruint8)((value      ) & 0x7f);
    } else if (value < 0x0000ffff) {
      ptr[1] = 2;
      ptr[2] = (ruint8)((value >>  8) & 0x7f);
      ptr[3] = (ruint8)((value      ) & 0x7f);
    } else if (value < 0x00ffffff) {
      ptr[1] = 3;
      ptr[2] = (ruint8)((value >> 16) & 0x7f);
      ptr[3] = (ruint8)((value >>  8) & 0x7f);
      ptr[4] = (ruint8)((value      ) & 0x7f);
    } else if (value < 0xffffffff) {
      ptr[1] = 4;
      ptr[2] = (ruint8)((value >> 24) & 0x7f);
      ptr[3] = (ruint8)((value >> 16) & 0x7f);
      ptr[4] = (ruint8)((value >>  8) & 0x7f);
      ptr[5] = (ruint8)((value      ) & 0x7f);
    } else {
      ptr[1] = 5;
      ptr[2] = 0x00;
      ptr[3] = (ruint8)((value >> 24) & 0x7f);
      ptr[4] = (ruint8)((value >> 16) & 0x7f);
      ptr[5] = (ruint8)((value >>  8) & 0x7f);
      ptr[6] = (ruint8)((value      ) & 0x7f);
    }

    r_asn1_bin_encoder_unmap (enc, 2 + ptr[1]);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_integer_i64 (RAsn1BinEncoder * enc, rint64 value)
{
  ruint8 * ptr;

  if (value >= 0)
    return r_asn1_bin_encoder_add_integer_u64 (enc, (ruint64) value);

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (ruint64))) != NULL) {
    ruint64 u = -value - 1;

    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_INTEGER);

    if (u < RUINT64_CONSTANT (0x00000000000000ff)) {
      u ^= RUINT64_MAX;
      ptr[1] = 1;
      ptr[2] = (ruint8)((u      ) & 0xff);
    } else if (u < RUINT64_CONSTANT (0x000000000000ffff)) {
      u ^= RUINT64_MAX;
      ptr[1] = 2;
      ptr[2] = (ruint8)((u >>  8) & 0xff);
      ptr[3] = (ruint8)((u      ) & 0xff);
    } else if (u < RUINT64_CONSTANT (0x0000000000ffffff)) {
      u ^= RUINT64_MAX;
      ptr[1] = 3;
      ptr[2] = (ruint8)((u >> 16) & 0xff);
      ptr[3] = (ruint8)((u >>  8) & 0xff);
      ptr[4] = (ruint8)((u      ) & 0xff);
    } else if (u < RUINT64_CONSTANT (0x00000000ffffffff)) {
      u ^= RUINT64_MAX;
      ptr[1] = 4;
      ptr[2] = (ruint8)((u >> 24) & 0xff);
      ptr[3] = (ruint8)((u >> 16) & 0xff);
      ptr[4] = (ruint8)((u >>  8) & 0xff);
      ptr[5] = (ruint8)((u      ) & 0xff);
    } else if (u < RUINT64_CONSTANT (0x000000ffffffffff)) {
      u ^= RUINT64_MAX;
      ptr[1] = 5;
      ptr[2] = (ruint8)((u >> 32) & 0xff);
      ptr[3] = (ruint8)((u >> 24) & 0xff);
      ptr[4] = (ruint8)((u >> 16) & 0xff);
      ptr[5] = (ruint8)((u >>  8) & 0xff);
      ptr[6] = (ruint8)((u      ) & 0xff);
    } else if (u < RUINT64_CONSTANT (0x0000ffffffffffff)) {
      u ^= RUINT64_MAX;
      ptr[1] = 6;
      ptr[2] = (ruint8)((u >> 40) & 0xff);
      ptr[3] = (ruint8)((u >> 32) & 0xff);
      ptr[4] = (ruint8)((u >> 24) & 0xff);
      ptr[5] = (ruint8)((u >> 16) & 0xff);
      ptr[6] = (ruint8)((u >>  8) & 0xff);
      ptr[7] = (ruint8)((u      ) & 0xff);
    } else if (u < RUINT64_CONSTANT (0x00ffffffffffffff)) {
      u ^= RUINT64_MAX;
      ptr[1] = 7;
      ptr[2] = (ruint8)((u >> 48) & 0xff);
      ptr[3] = (ruint8)((u >> 40) & 0xff);
      ptr[4] = (ruint8)((u >> 32) & 0xff);
      ptr[5] = (ruint8)((u >> 24) & 0xff);
      ptr[6] = (ruint8)((u >> 16) & 0xff);
      ptr[7] = (ruint8)((u >>  8) & 0xff);
      ptr[8] = (ruint8)((u      ) & 0xff);
    } else {
      u ^= RUINT64_MAX;
      ptr[1] = 8;
      ptr[2] = (ruint8)((u >> 56) & 0xff);
      ptr[3] = (ruint8)((u >> 48) & 0xff);
      ptr[4] = (ruint8)((u >> 40) & 0xff);
      ptr[5] = (ruint8)((u >> 32) & 0xff);
      ptr[6] = (ruint8)((u >> 24) & 0xff);
      ptr[7] = (ruint8)((u >> 16) & 0xff);
      ptr[8] = (ruint8)((u >>  8) & 0xff);
      ptr[9] = (ruint8)((u      ) & 0xff);
    }

    r_asn1_bin_encoder_unmap (enc, 2 + ptr[1]);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_integer_u64 (RAsn1BinEncoder * enc, ruint64 value)
{
  ruint8 * ptr;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (ruint64))) != NULL) {
    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_INTEGER);

    if (value < RUINT64_CONSTANT (0x00000000000000ff)) {
      ptr[1] = 1;
      ptr[2] = (ruint8)((value      ) & 0x7f);
      r_asn1_bin_encoder_unmap (enc, 3);
    } else if (value < RUINT64_CONSTANT (0x000000000000ffff)) {
      ptr[1] = 2;
      ptr[2] = (ruint8)((value >>  8) & 0x7f);
      ptr[3] = (ruint8)((value      ) & 0x7f);
      r_asn1_bin_encoder_unmap (enc, 4);
    } else if (value < RUINT64_CONSTANT (0x0000000000ffffff)) {
      ptr[1] = 3;
      ptr[2] = (ruint8)((value >> 16) & 0x7f);
      ptr[3] = (ruint8)((value >>  8) & 0x7f);
      ptr[4] = (ruint8)((value      ) & 0x7f);
      r_asn1_bin_encoder_unmap (enc, 5);
    } else if (value < RUINT64_CONSTANT (0x00000000ffffffff)) {
      ptr[1] = 4;
      ptr[2] = (ruint8)((value >> 24) & 0x7f);
      ptr[3] = (ruint8)((value >> 16) & 0x7f);
      ptr[4] = (ruint8)((value >>  8) & 0x7f);
      ptr[5] = (ruint8)((value      ) & 0x7f);
      r_asn1_bin_encoder_unmap (enc, 6);
    } else if (value < RUINT64_CONSTANT (0x000000ffffffffff)) {
      ptr[1] = 5;
      ptr[2] = (ruint8)((value >> 32) & 0xff);
      ptr[3] = (ruint8)((value >> 24) & 0xff);
      ptr[4] = (ruint8)((value >> 16) & 0xff);
      ptr[5] = (ruint8)((value >>  8) & 0xff);
      ptr[6] = (ruint8)((value      ) & 0xff);
    } else if (value < RUINT64_CONSTANT (0x0000ffffffffffff)) {
      ptr[1] = 6;
      ptr[2] = (ruint8)((value >> 40) & 0xff);
      ptr[3] = (ruint8)((value >> 32) & 0xff);
      ptr[4] = (ruint8)((value >> 24) & 0xff);
      ptr[5] = (ruint8)((value >> 16) & 0xff);
      ptr[6] = (ruint8)((value >>  8) & 0xff);
      ptr[7] = (ruint8)((value      ) & 0xff);
    } else if (value < RUINT64_CONSTANT (0x00ffffffffffffff)) {
      ptr[1] = 7;
      ptr[2] = (ruint8)((value >> 48) & 0xff);
      ptr[3] = (ruint8)((value >> 40) & 0xff);
      ptr[4] = (ruint8)((value >> 32) & 0xff);
      ptr[5] = (ruint8)((value >> 24) & 0xff);
      ptr[6] = (ruint8)((value >> 16) & 0xff);
      ptr[7] = (ruint8)((value >>  8) & 0xff);
      ptr[8] = (ruint8)((value      ) & 0xff);
    } else if (value < RUINT64_CONSTANT (0x7fffffffffffffff)) {
      ptr[1] = 8;
      ptr[2] = (ruint8)((value >> 56) & 0xff);
      ptr[3] = (ruint8)((value >> 48) & 0xff);
      ptr[4] = (ruint8)((value >> 40) & 0xff);
      ptr[5] = (ruint8)((value >> 32) & 0xff);
      ptr[6] = (ruint8)((value >> 24) & 0xff);
      ptr[7] = (ruint8)((value >> 16) & 0xff);
      ptr[8] = (ruint8)((value >>  8) & 0xff);
      ptr[9] = (ruint8)((value      ) & 0xff);
    } else {
      ptr[1] = 9;
      ptr[2] = 0x00;
      ptr[3] = (ruint8)((value >> 56) & 0xff);
      ptr[4] = (ruint8)((value >> 48) & 0xff);
      ptr[5] = (ruint8)((value >> 40) & 0xff);
      ptr[6] = (ruint8)((value >> 32) & 0xff);
      ptr[7] = (ruint8)((value >> 24) & 0xff);
      ptr[8] = (ruint8)((value >> 16) & 0xff);
      ptr[9] = (ruint8)((value >>  8) & 0xff);
      ptr[10] = (ruint8)((value     ) & 0xff);
    }

    r_asn1_bin_encoder_unmap (enc, 2 + ptr[1]);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_integer_mpint (RAsn1BinEncoder * enc, const rmpint * value)
{
  ruint8 * ptr;
  rsize len;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY (value == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  /* FIXME: Support negative mpints */
  if (R_UNLIKELY (r_mpint_isneg (value))) return R_ASN1_ENCODER_INVALID_ARG;

  len = r_mpint_bytes_used (value);

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (rsize) + 1 + len)) != NULL) {
    rsize act = 1;
    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_INTEGER);
    if (r_mpint_bits_used (value) % 8 == 0) {
      act += r_asn1_bin_write_definite_len (&ptr[act], 1 + len);
      ptr[act++] = 0;
    } else {
      act += r_asn1_bin_write_definite_len (&ptr[act], len);
    }
    r_mpint_to_binary (value, &ptr[act], &len);
    r_asn1_bin_encoder_unmap (enc, act + len);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_oid_rawsz (RAsn1BinEncoder * enc, const rchar * rawsz)
{
  ruint8 * ptr;
  rsize len;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY ((len = r_strlen (rawsz)) == 0)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + len)) != NULL) {
    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OBJECT_IDENTIFIER);
    ptr[1] = len;
    r_memcpy (&ptr[2], rawsz, len);
    r_asn1_bin_encoder_unmap (enc, 2 + len);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_bit_string_raw (RAsn1BinEncoder * enc, const ruint8 * bits, rsize size)
{
  ruint8 * ptr;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY (bits == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (rsize) + 1 + size)) != NULL) {
    rsize off = 1;

    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_BIT_STRING);
    off += r_asn1_bin_write_definite_len (&ptr[off], size + 1);
    ptr[off++] = 0;
    r_memcpy (&ptr[off], bits, size);
    r_asn1_bin_encoder_unmap (enc, off + size);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_utc_time (RAsn1BinEncoder * enc, ruint64 time)
{
  ruint8 * ptr;
  ruint16 yy;
  ruint8 y, m, d, hh, mm, ss;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY (!r_time_parse_unix_time (time, &yy, &m, &d, &hh, &mm, &ss)))
    return R_ASN1_ENCODER_INVALID_ARG;

  y = yy % 100;

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + 12 + 1)) != NULL) {
    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_UTC_TIME);
    if (ss == 0) {
      ptr[1] = r_sprintf ((rchar *)&ptr[2], "%2hhu%2hhu%2hhu%2hhu%2hhuZ",
          y, m, d, hh, mm);
    } else {
      ptr[1] = r_sprintf ((rchar *)&ptr[2], "%2hhu%2hhu%2hhu%2hhu%2hhu%2hhuZ",
          y, m, d, hh, mm, ss);
    }

    r_asn1_bin_encoder_unmap (enc, 2 + ptr[1]);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

static inline RAsn1EncoderStatus
r_asn1_bin_encoder_add_string (RAsn1BinEncoder * enc, ruint8 type, const rchar * str, rssize size)
{
  ruint8 * ptr;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY (str == NULL)) return R_ASN1_ENCODER_INVALID_ARG;

  if (size < 0)
    size = r_strlen (str);

  if ((ptr = r_asn1_bin_encoder_map (enc, 2 + sizeof (rsize) + size)) != NULL) {
    rsize off = 1;

    ptr[0] = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, type);
    off += r_asn1_bin_write_definite_len (&ptr[off], size);
    r_memcpy (&ptr[off], str, size);
    r_asn1_bin_encoder_unmap (enc, off + size);
    return R_ASN1_ENCODER_OK;
  }

  return R_ASN1_ENCODER_OOM;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_ia5_string (RAsn1BinEncoder * enc, const rchar * str, rssize size)
{
  return r_asn1_bin_encoder_add_string (enc, R_ASN1_ID_IA5_STRING, str, size);
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_utf8_string (RAsn1BinEncoder * enc, const rchar * str, rssize size)
{
  return r_asn1_bin_encoder_add_string (enc, R_ASN1_ID_UTF8_STRING, str, size);
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_printable_string (RAsn1BinEncoder * enc, const rchar * str, rssize size)
{
  return r_asn1_bin_encoder_add_string (enc, R_ASN1_ID_PRINTABLE_STRING, str, size);
}

static RAsn1EncoderStatus
r_asn1_bin_encoder_add_type_and_value (RAsn1BinEncoder * enc,
    const rchar * t, rsize tsize, const rchar * v, rsize vsize)
{
  RAsn1EncoderStatus ret;
  const rchar * oid;

  if ((oid = r_asn1_x500_name_to_oid (t, tsize)) == NULL)
    return R_ASN1_ENCODER_INDEFINITE;

  if ((ret = r_asn1_bin_encoder_begin_constructed (enc,
          R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE),
          0)) == R_ASN1_ENCODER_OK) {
    /* FIXME: unescape value string! */
    if ((ret = r_asn1_bin_encoder_add_oid_rawsz (enc, oid)) == R_ASN1_ENCODER_OK)
      ret = r_asn1_bin_encoder_add_utf8_string (enc, v, vsize);
    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

RAsn1EncoderStatus
r_asn1_bin_encoder_add_distinguished_name (RAsn1BinEncoder * enc, const rchar * dn)
{
  RAsn1EncoderStatus ret;

  if (R_UNLIKELY (enc == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY (dn == NULL)) return R_ASN1_ENCODER_INVALID_ARG;
  if (R_UNLIKELY (*dn == 0)) return R_ASN1_ENCODER_INVALID_ARG;

  if ((ret = r_asn1_bin_encoder_begin_constructed (enc,
          R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE),
          0)) == R_ASN1_ENCODER_OK) {
    const rchar * t, * v;
    rsize size = r_strlen (dn);
    do {
      while ((t = r_strnrchr (dn, (int)',', size)) != NULL && t[-1] == '\\')
        ;
      if (t != NULL)
        t++;
      else
        t = dn;

      if ((v = r_strchr (t, (int)'=')) != NULL) {
        if ((ret = r_asn1_bin_encoder_begin_constructed (enc,
                R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SET),
                0)) == R_ASN1_ENCODER_OK) {
          v++;
          ret = r_asn1_bin_encoder_add_type_and_value (enc,
              t, RPOINTER_TO_SIZE (v - t) - 1,
              v, size - RPOINTER_TO_SIZE (v - dn));
          r_asn1_bin_encoder_end_constructed (enc);
        }

      } else {
        ret = R_ASN1_ENCODER_INDEFINITE;
        break;
      }

      size = RPOINTER_TO_SIZE (t - 1 - dn);
    } while (t > dn);
    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

