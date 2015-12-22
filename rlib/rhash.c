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
#include <rlib/rhash.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#define R_HASH_MAX_SIZE         (1024 / 8)

/* MD5 */
#define R_HASH_MD5_SIZE         (128 / 8)
#define R_HASH_MD5_WORD_SIZE    (R_HASH_MD5_SIZE / sizeof (ruint32))
#define R_HASH_MD5_BLOCK_SIZE   (512 / 8)
typedef struct {
  ruint32 data[R_HASH_MD5_WORD_SIZE];
  ruint64 len;

  ruint8 buffer[R_HASH_MD5_BLOCK_SIZE];
  rsize bufsize;
} RMd5Hash;
static void r_md5_hash_init (RMd5Hash * md5);
static void r_md5_hash_final (RMd5Hash * md5);
static rboolean r_md5_hash_update (RMd5Hash * md5, rconstpointer data, rsize size);
static rboolean r_md5_hash_get (RMd5Hash * md5, ruint8 * data, rsize * size);

/* SHA-1 */
typedef struct {

} RSha1Hash;

struct _RHash {
  RHashType type;
  rboolean is_final;

  union {
    RMd5Hash md5;
    /*RSha1Hash sha1;*/
    /*RSha256Hash sha256;*/
    /*RSha512Hash sha512;*/
  } hash;
};

RHash *
r_hash_new (RHashType type)
{
  RHash * ret;
  if ((ret = r_mem_new0 (RHash)) != NULL) {
    ret->type = type;
    r_hash_reset (ret);
  }
  return ret;
}

void
r_hash_free (RHash * hash)
{
  r_free (hash);
}

rsize
r_hash_size (RHash * hash)
{
  switch (hash->type) {
    case R_HASH_TYPE_MD5:
      return sizeof (hash->hash.md5.data);
    case R_HASH_TYPE_SHA1:
    case R_HASH_TYPE_SHA256:
    case R_HASH_TYPE_SHA512:
      break;
  }

  return 0;
}

rsize
r_hash_blocksize (RHash * hash)
{
  switch (hash->type) {
    case R_HASH_TYPE_MD5:
      return sizeof (hash->hash.md5.buffer);
    case R_HASH_TYPE_SHA1:
    case R_HASH_TYPE_SHA256:
    case R_HASH_TYPE_SHA512:
      break;
  }

  return 0;
}

void
r_hash_reset (RHash * hash)
{
  hash->is_final = FALSE;

  switch (hash->type) {
    case R_HASH_TYPE_MD5:
      r_md5_hash_init (&hash->hash.md5);
      break;
    case R_HASH_TYPE_SHA1:
    case R_HASH_TYPE_SHA256:
    case R_HASH_TYPE_SHA512:
      break;
  }
}

rboolean
r_hash_update (RHash * hash, rconstpointer data, rsize size)
{
  if (!hash->is_final) {
    switch (hash->type) {
      case R_HASH_TYPE_MD5:
        return r_md5_hash_update (&hash->hash.md5, data, size);
      case R_HASH_TYPE_SHA1:
      case R_HASH_TYPE_SHA256:
      case R_HASH_TYPE_SHA512:
        break;
    }
  }

  return FALSE;
}

rboolean
r_hash_get_data (RHash * hash, ruint8 * data, rsize * size)
{
  switch (hash->type) {
    case R_HASH_TYPE_MD5:
      if (!hash->is_final) {
        r_md5_hash_final (&hash->hash.md5);
        hash->is_final = TRUE;
      }
      return r_md5_hash_get (&hash->hash.md5, data, size);
    case R_HASH_TYPE_SHA1:
    case R_HASH_TYPE_SHA256:
    case R_HASH_TYPE_SHA512:
      break;
  }

  return FALSE;
}

rchar *
r_hash_get_hex (RHash * hash)
{
  ruint8 * data;
  rsize size = R_HASH_MAX_SIZE;

  if (hash != NULL && (data = r_alloca (size)) != NULL &&
      r_hash_get_data (hash, data, &size))
    return r_str_mem_hex (data, size);

  return NULL;
}

/**************************************/
/*                MD5                 */
/**************************************/
static void
r_md5_hash_init (RMd5Hash * md5)
{
  md5->bufsize = 0;
  md5->len = 0;
  md5->data[0] = 0x67452301;
  md5->data[1] = 0xefcdab89;
  md5->data[2] = 0x98badcfe;
  md5->data[3] = 0x10325476;
}

static void
r_md5_hash_update_block (RMd5Hash * md5, const ruint8 * data)
{
  ruint32 a, b, c, d, x[R_HASH_MD5_BLOCK_SIZE / sizeof (ruint32)];
  rsize i;

  for (i = 0; i < R_HASH_MD5_BLOCK_SIZE / sizeof (ruint32); i++)
    x[i] = RUINT32_FROM_LE (((ruint32 *)data)[i]);

  a = md5->data[0];
  b = md5->data[1];
  c = md5->data[2];
  d = md5->data[3];

  /* Round 1 */
#define MD5_CORE(a, b, c, d, x, s, ac) \
  (a) += (((b) & (c)) | ((~b) & (d))) + (x) + (ruint32)(ac); \
  (a) = ((a) << (s)) | ((a) >> (32-(s))); \
  (a) += (b);
  MD5_CORE (a, b, c, d, x[ 0],  7, 0xd76aa478);
  MD5_CORE (d, a, b, c, x[ 1], 12, 0xe8c7b756);
  MD5_CORE (c, d, a, b, x[ 2], 17, 0x242070db);
  MD5_CORE (b, c, d, a, x[ 3], 22, 0xc1bdceee);
  MD5_CORE (a, b, c, d, x[ 4],  7, 0xf57c0faf);
  MD5_CORE (d, a, b, c, x[ 5], 12, 0x4787c62a);
  MD5_CORE (c, d, a, b, x[ 6], 17, 0xa8304613);
  MD5_CORE (b, c, d, a, x[ 7], 22, 0xfd469501);
  MD5_CORE (a, b, c, d, x[ 8],  7, 0x698098d8);
  MD5_CORE (d, a, b, c, x[ 9], 12, 0x8b44f7af);
  MD5_CORE (c, d, a, b, x[10], 17, 0xffff5bb1);
  MD5_CORE (b, c, d, a, x[11], 22, 0x895cd7be);
  MD5_CORE (a, b, c, d, x[12],  7, 0x6b901122);
  MD5_CORE (d, a, b, c, x[13], 12, 0xfd987193);
  MD5_CORE (c, d, a, b, x[14], 17, 0xa679438e);
  MD5_CORE (b, c, d, a, x[15], 22, 0x49b40821);
#undef MD5_CORE

  /* Round 2 */
#define MD5_CORE(a, b, c, d, x, s, ac) \
  (a) += (((b) & (d)) | ((c) & (~d))) + (x) + (ruint32)(ac); \
  (a) = ((a) << (s)) | ((a) >> (32-(s))); \
  (a) += (b);
  MD5_CORE (a, b, c, d, x[ 1],  5, 0xf61e2562);
  MD5_CORE (d, a, b, c, x[ 6],  9, 0xc040b340);
  MD5_CORE (c, d, a, b, x[11], 14, 0x265e5a51);
  MD5_CORE (b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
  MD5_CORE (a, b, c, d, x[ 5],  5, 0xd62f105d);
  MD5_CORE (d, a, b, c, x[10],  9,  0x2441453);
  MD5_CORE (c, d, a, b, x[15], 14, 0xd8a1e681);
  MD5_CORE (b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
  MD5_CORE (a, b, c, d, x[ 9],  5, 0x21e1cde6);
  MD5_CORE (d, a, b, c, x[14],  9, 0xc33707d6);
  MD5_CORE (c, d, a, b, x[ 3], 14, 0xf4d50d87);
  MD5_CORE (b, c, d, a, x[ 8], 20, 0x455a14ed);
  MD5_CORE (a, b, c, d, x[13],  5, 0xa9e3e905);
  MD5_CORE (d, a, b, c, x[ 2],  9, 0xfcefa3f8);
  MD5_CORE (c, d, a, b, x[ 7], 14, 0x676f02d9);
  MD5_CORE (b, c, d, a, x[12], 20, 0x8d2a4c8a);
#undef MD5_CORE

  /* Round 3 */
#define MD5_CORE(a, b, c, d, x, s, ac) \
  (a) += ((b) ^ (c) ^ (d)) + (x) + (ruint32)(ac); \
  (a) = ((a) << (s)) | ((a) >> (32-(s))); \
  (a) += (b);
  MD5_CORE (a, b, c, d, x[ 5],  4, 0xfffa3942);
  MD5_CORE (d, a, b, c, x[ 8], 11, 0x8771f681);
  MD5_CORE (c, d, a, b, x[11], 16, 0x6d9d6122);
  MD5_CORE (b, c, d, a, x[14], 23, 0xfde5380c);
  MD5_CORE (a, b, c, d, x[ 1],  4, 0xa4beea44);
  MD5_CORE (d, a, b, c, x[ 4], 11, 0x4bdecfa9);
  MD5_CORE (c, d, a, b, x[ 7], 16, 0xf6bb4b60);
  MD5_CORE (b, c, d, a, x[10], 23, 0xbebfbc70);
  MD5_CORE (a, b, c, d, x[13],  4, 0x289b7ec6);
  MD5_CORE (d, a, b, c, x[ 0], 11, 0xeaa127fa);
  MD5_CORE (c, d, a, b, x[ 3], 16, 0xd4ef3085);
  MD5_CORE (b, c, d, a, x[ 6], 23,  0x4881d05);
  MD5_CORE (a, b, c, d, x[ 9],  4, 0xd9d4d039);
  MD5_CORE (d, a, b, c, x[12], 11, 0xe6db99e5);
  MD5_CORE (c, d, a, b, x[15], 16, 0x1fa27cf8);
  MD5_CORE (b, c, d, a, x[ 2], 23, 0xc4ac5665);
#undef MD5_CORE

  /* Round 4 */
#define MD5_CORE(a, b, c, d, x, s, ac) \
  (a) += ((c) ^ ((b) | (~d))) + (x) + (ruint32)(ac); \
  (a) = ((a) << (s)) | ((a) >> (32-(s))); \
  (a) += (b);
  MD5_CORE (a, b, c, d, x[ 0],  6, 0xf4292244);
  MD5_CORE (d, a, b, c, x[ 7], 10, 0x432aff97);
  MD5_CORE (c, d, a, b, x[14], 15, 0xab9423a7);
  MD5_CORE (b, c, d, a, x[ 5], 21, 0xfc93a039);
  MD5_CORE (a, b, c, d, x[12],  6, 0x655b59c3);
  MD5_CORE (d, a, b, c, x[ 3], 10, 0x8f0ccc92);
  MD5_CORE (c, d, a, b, x[10], 15, 0xffeff47d);
  MD5_CORE (b, c, d, a, x[ 1], 21, 0x85845dd1);
  MD5_CORE (a, b, c, d, x[ 8],  6, 0x6fa87e4f);
  MD5_CORE (d, a, b, c, x[15], 10, 0xfe2ce6e0);
  MD5_CORE (c, d, a, b, x[ 6], 15, 0xa3014314);
  MD5_CORE (b, c, d, a, x[13], 21, 0x4e0811a1);
  MD5_CORE (a, b, c, d, x[ 4],  6, 0xf7537e82);
  MD5_CORE (d, a, b, c, x[11], 10, 0xbd3af235);
  MD5_CORE (c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
  MD5_CORE (b, c, d, a, x[ 9], 21, 0xeb86d391);
#undef MD5_CORE

  md5->data[0] += a;
  md5->data[1] += b;
  md5->data[2] += c;
  md5->data[3] += d;
}

static rboolean
r_md5_hash_update (RMd5Hash * md5, rconstpointer data, rsize size)
{
  const ruint8 * ptr;

  if (R_UNLIKELY (md5 == NULL || data == NULL))
    return FALSE;

  ptr = data;
  md5->len += size;
  if (md5->bufsize > 0) {
    rsize s = sizeof (md5->buffer) - md5->bufsize;
    if (s < size) {
      r_memcpy (&md5->buffer[md5->bufsize], ptr, s);
      ptr += s;
      size -= s;
      md5->bufsize = 0;
      r_md5_hash_update_block (md5, md5->buffer);
      r_memset (md5->buffer, 0, sizeof (md5->buffer));
    } else {
      r_memcpy (&md5->buffer[md5->bufsize], ptr, size);
      md5->bufsize += size;
      return TRUE;
    }
  }

  for (; size >= R_HASH_MD5_BLOCK_SIZE; size -= R_HASH_MD5_BLOCK_SIZE) {
    r_md5_hash_update_block (md5, ptr);
    ptr += R_HASH_MD5_BLOCK_SIZE;
  }

  if ((md5->bufsize = size) > 0)
    r_memcpy (md5->buffer, ptr, md5->bufsize);

  return TRUE;
}

static void
r_md5_hash_final (RMd5Hash * md5)
{
  rsize bufsize = md5->bufsize;
  ruint8 * ptr;

  md5->buffer[bufsize++] = 0x80;
  ptr = md5->buffer;
  if (bufsize <= sizeof (md5->buffer) - sizeof (ruint64)) {
    rsize s = sizeof (md5->buffer) - sizeof (ruint64) - bufsize;
    r_memset (&ptr[bufsize], 0, s);
  } else {
    rsize s = sizeof (md5->buffer) - bufsize;
    r_memset (&ptr[bufsize], 0, s);

    r_md5_hash_update_block (md5, md5->buffer);
    r_memset (md5->buffer, 0, sizeof (md5->buffer));
    ptr = r_alloca0 (R_HASH_MD5_BLOCK_SIZE);
  }

  *(ruint64 *)(&ptr[R_HASH_MD5_BLOCK_SIZE - sizeof (ruint64)]) =
    RUINT64_TO_LE (md5->len << 3);
  r_md5_hash_update_block (md5, ptr);
}

static rboolean
r_md5_hash_get (RMd5Hash * md5, ruint8 * data, rsize * size)
{
  rsize i;

  if (R_UNLIKELY (data == NULL || size == NULL || *size < R_HASH_MD5_SIZE))
    return FALSE;

  for (i = 0; i < R_HASH_MD5_SIZE / sizeof (ruint32); i++)
    ((ruint32 *)data)[i] = RUINT32_TO_LE (md5->data[i]);
  *size = R_HASH_MD5_SIZE;

  return TRUE;
}

