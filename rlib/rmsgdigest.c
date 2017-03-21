/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/rmsgdigest.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

/* FIXME: Move or use stuff from rmacros.h?? */
#define RUINT32_SHL(x, n)       (((x) & RUINT32_MAX) << (n))
#define RUINT32_SHR(x, n)       (((x) & RUINT32_MAX) >> (n))
#define RUINT32_ROTL(x, n)      (RUINT32_SHL (x, n) | RUINT32_SHR (x, 32-(n)))
#define RUINT32_ROTR(x, n)      (RUINT32_SHR (x, n) | RUINT32_SHL (x, 32-(n)))
#define RUINT64_SHL(x, n)       (((x) & RUINT64_MAX) << (n))
#define RUINT64_SHR(x, n)       (((x) & RUINT64_MAX) >> (n))
#define RUINT64_ROTL(x, n)      (RUINT64_SHL (x, n) | RUINT64_SHR (x, 64-(n)))
#define RUINT64_ROTR(x, n)      (RUINT64_SHR (x, n) | RUINT64_SHL (x, 64-(n)))

typedef     void (*RMDInit) (RMsgDigest * md);
typedef rboolean (*RMDFinal) (RMsgDigest * md);
typedef rboolean (*RMDUpdate) (RMsgDigest * md, rconstpointer data, rsize size);
typedef rboolean (*RMDGet) (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);

/* MD5 */
#define R_MD5_SIZE         (128 / 8)
#define R_MD5_WORD_SIZE    (R_MD5_SIZE / sizeof (ruint32))
#define R_MD5_BLOCK_SIZE   (512 / 8)
typedef struct {
  ruint32 data[R_MD5_WORD_SIZE];
  ruint64 len;

  ruint8 buffer[R_MD5_BLOCK_SIZE];
  rsize bufsize;
} RMd5;
static void r_md5_init (RMsgDigest * md);
static rboolean r_md5_final (RMsgDigest * md);
static rboolean r_md5_update (RMsgDigest * md, rconstpointer data, rsize size);
static rboolean r_md5_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);

/* SHA-1 */
#define R_SHA1_SIZE          (160 / 8)
#define R_SHA1_WORD_SIZE     (R_SHA1_SIZE / sizeof (ruint32))
#define R_SHA1_BLOCK_SIZE    (512 / 8)
typedef struct {
  ruint32 data[R_SHA1_WORD_SIZE];
  ruint64 len;

  ruint8 buffer[R_SHA1_BLOCK_SIZE];
  rsize bufsize;
} RSha1;
static void r_sha1_init (RMsgDigest * md);
static rboolean r_sha1_final (RMsgDigest * md);
static rboolean r_sha1_update (RMsgDigest * md, rconstpointer data, rsize size);
static rboolean r_sha1_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);

/* SHA-224 */
#define R_SHA224_SIZE          (224 / 8)
static void r_sha224_init (RMsgDigest * md);
static rboolean r_sha224_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);

/* SHA-256 */
#define R_SHA256_SIZE          (256 / 8)
#define R_SHA256_WORD_SIZE     (R_SHA256_SIZE / sizeof (ruint32))
#define R_SHA256_BLOCK_SIZE    (512 / 8)
typedef struct {
  ruint32 data[R_SHA256_WORD_SIZE];
  ruint64 len;

  ruint8 buffer[R_SHA256_BLOCK_SIZE];
  rsize bufsize;
} RSha256;
static void r_sha256_init (RMsgDigest * md);
static rboolean r_sha256_final (RMsgDigest * md);
static rboolean r_sha256_update (RMsgDigest * md, rconstpointer data, rsize size);
static rboolean r_sha256_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);

/* SHA-384 */
#define R_SHA384_SIZE          (384 / 8)
static void r_sha384_init (RMsgDigest * md);
static rboolean r_sha384_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);

/* SHA-512 */
#define R_SHA512_SIZE          (512 / 8)
#define R_SHA512_WORD_SIZE     (R_SHA512_SIZE / sizeof (ruint64))
#define R_SHA512_BLOCK_SIZE    (1024 / 8)
typedef struct {
  ruint64 data[R_SHA512_WORD_SIZE];
  ruint64 len[2];

  ruint8 buffer[R_SHA512_BLOCK_SIZE];
  rsize bufsize;
} RSha512;
static void r_sha512_init (RMsgDigest * md);
static rboolean r_sha512_final (RMsgDigest * md);
static rboolean r_sha512_update (RMsgDigest * md, rconstpointer data, rsize size);
static rboolean r_sha512_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);

struct _RMsgDigest {
  RMsgDigestType type;
  rboolean is_final;

  rsize mdsize;
  rsize blocksize;
  RMDInit init;
  RMDFinal final;
  RMDUpdate update;
  RMDGet get;
};

RMsgDigest *
r_msg_digest_new (RMsgDigestType type)
{
  switch (type) {
    case R_MSG_DIGEST_TYPE_MD5:
      return r_msg_digest_new_md5 ();
    case R_MSG_DIGEST_TYPE_SHA1:
      return r_msg_digest_new_sha1 ();
    case R_MSG_DIGEST_TYPE_SHA256:
      return r_msg_digest_new_sha256 ();
    case R_MSG_DIGEST_TYPE_SHA512:
      return r_msg_digest_new_sha512 ();
    default:
      break;
  }
  return NULL;
}

void
r_msg_digest_free (RMsgDigest * md)
{
  r_free (md);
}

rsize
r_msg_digest_type_size (RMsgDigestType type)
{
  switch (type) {
    case R_MSG_DIGEST_TYPE_MD5:
      return R_MD5_SIZE;
    case R_MSG_DIGEST_TYPE_SHA1:
      return R_SHA1_SIZE;
    case R_MSG_DIGEST_TYPE_SHA224:
      return R_SHA224_SIZE;
    case R_MSG_DIGEST_TYPE_SHA256:
      return R_SHA256_SIZE;
    case R_MSG_DIGEST_TYPE_SHA384:
      return R_SHA384_SIZE;
    case R_MSG_DIGEST_TYPE_SHA512:
      return R_SHA512_SIZE;
    default:
      return 0;
  }
}

rsize
r_msg_digest_type_blocksize (RMsgDigestType type)
{
  switch (type) {
    case R_MSG_DIGEST_TYPE_MD5:
      return R_MD5_BLOCK_SIZE;
    case R_MSG_DIGEST_TYPE_SHA1:
      return R_SHA1_BLOCK_SIZE;
    case R_MSG_DIGEST_TYPE_SHA224:
    case R_MSG_DIGEST_TYPE_SHA256:
      return R_SHA256_BLOCK_SIZE;
    case R_MSG_DIGEST_TYPE_SHA384:
    case R_MSG_DIGEST_TYPE_SHA512:
      return R_SHA512_BLOCK_SIZE;
    default:
      return 0;
  }
}

const rchar *
r_msg_digest_type_string (RMsgDigestType type)
{
  switch (type) {
    case R_MSG_DIGEST_TYPE_MD5:
      return "md5";
    case R_MSG_DIGEST_TYPE_SHA1:
      return "sha-1";
    case R_MSG_DIGEST_TYPE_SHA224:
      return "sha-224";
    case R_MSG_DIGEST_TYPE_SHA256:
      return "sha-256";
    case R_MSG_DIGEST_TYPE_SHA384:
      return "sha-384";
    case R_MSG_DIGEST_TYPE_SHA512:
      return "sha-512";
    default:
      return 0;
  }
}

rsize
r_msg_digest_size (const RMsgDigest * md)
{
  return r_msg_digest_type_size (md->type);
}

rsize
r_msg_digest_blocksize (const RMsgDigest * md)
{
  return md->blocksize;
}

void
r_msg_digest_reset (RMsgDigest * md)
{
  md->is_final = FALSE;
  md->init (md);
}

rboolean
r_msg_digest_update (RMsgDigest * md, rconstpointer data, rsize size)
{
  return (!md->is_final) ?  md->update (md, data, size) : FALSE;
}

rboolean
r_msg_digest_finish (RMsgDigest * md)
{
  if (!md->is_final)
    md->is_final = md->final (md);

  return md->is_final;
}

rboolean
r_msg_digest_get_data (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out)
{
  if (!md->is_final) {
    RMsgDigest * h = (RMsgDigest *) r_alloca (md->mdsize);

    r_memcpy (h, md, md->mdsize);
    r_msg_digest_finish (h);

    return md->get (h, data, size, out);
  }

  return md->get (md, data, size, out);
}

rchar *
r_msg_digest_get_hex (const RMsgDigest * md)
{
  ruint8 data[128];
  rsize size;

  if (md != NULL && r_msg_digest_get_data (md, data, sizeof (data), &size))
    return r_str_mem_hex (data, size);

  return NULL;
}

rchar *
r_msg_digest_get_hex_full (const RMsgDigest * md,
    const rchar * divider, rsize interval)
{
  ruint8 data[128];
  rsize size;

  if (md != NULL && r_msg_digest_get_data (md, data, sizeof (data), &size))
    return r_str_mem_hex_full (data, size, divider, interval);

  return NULL;
}

/**************************************/
/*                MD5                 */
/**************************************/
RMsgDigest *
r_msg_digest_new_md5 (void)
{
  RMsgDigest * ret;
  rsize mdsize = sizeof (RMsgDigest) + sizeof (RMd5);

  if ((ret = r_malloc (mdsize)) != NULL) {
    ret->type = R_MSG_DIGEST_TYPE_MD5;
    ret->is_final = FALSE;
    ret->mdsize = mdsize;
    ret->blocksize = R_MD5_BLOCK_SIZE;
    ret->init = r_md5_init;
    ret->final = r_md5_final;
    ret->update = r_md5_update;
    ret->get = r_md5_get;

    ret->init (ret);
  }

  return ret;
}

static void
r_md5_init (RMsgDigest * md)
{
  RMd5 * md5 = (RMd5 *)(md + 1);
  md5->bufsize = 0;
  md5->len = 0;
  md5->data[0] = 0x67452301;
  md5->data[1] = 0xefcdab89;
  md5->data[2] = 0x98badcfe;
  md5->data[3] = 0x10325476;
}

static void
r_md5_update_block (RMd5 * md5, const ruint8 * data)
{
  ruint32 a, b, c, d, x[R_MD5_BLOCK_SIZE / sizeof (ruint32)];
  rsize i;

  for (i = 0; i < R_MD5_BLOCK_SIZE / sizeof (ruint32); i++)
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
r_md5_update (RMsgDigest * md, rconstpointer data, rsize size)
{
  RMd5 * md5;
  const ruint8 * ptr;

  if (R_UNLIKELY (md == NULL || data == NULL))
    return FALSE;

  ptr = data;
  md5 = (RMd5 *)(md + 1);
  md5->len += size;
  if (md5->bufsize > 0) {
    rsize s = sizeof (md5->buffer) - md5->bufsize;
    if (s <= size) {
      r_memcpy (&md5->buffer[md5->bufsize], ptr, s);
      ptr += s;
      size -= s;
      md5->bufsize = 0;
      r_md5_update_block (md5, md5->buffer);
      r_memset (md5->buffer, 0, sizeof (md5->buffer));
    } else {
      r_memcpy (&md5->buffer[md5->bufsize], ptr, size);
      md5->bufsize += size;
      return TRUE;
    }
  }

  for (; size >= R_MD5_BLOCK_SIZE; size -= R_MD5_BLOCK_SIZE) {
    r_md5_update_block (md5, ptr);
    ptr += R_MD5_BLOCK_SIZE;
  }

  if ((md5->bufsize = size) > 0)
    r_memcpy (md5->buffer, ptr, md5->bufsize);

  return TRUE;
}

static rboolean
r_md5_final (RMsgDigest * md)
{
  RMd5 * md5 = (RMd5 *)(md + 1);
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

    r_md5_update_block (md5, md5->buffer);
    r_memset (md5->buffer, 0, sizeof (md5->buffer));
    ptr = r_alloca0 (R_MD5_BLOCK_SIZE);
  }

  *(ruint64 *)(&ptr[R_MD5_BLOCK_SIZE - sizeof (ruint64)]) =
    RUINT64_TO_LE (md5->len << 3);
  r_md5_update_block (md5, ptr);
  return TRUE;
}

static rboolean
r_md5_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out)
{
  const RMd5 * md5 = (const RMd5 *)(md + 1);
  rsize i;

  if (R_UNLIKELY (data == NULL || size < R_MD5_SIZE))
    return FALSE;

  for (i = 0; i < R_MD5_SIZE / sizeof (ruint32); i++)
    ((ruint32 *)data)[i] = RUINT32_TO_LE (md5->data[i]);
  if (out != NULL)
    *out = R_MD5_SIZE;

  return TRUE;
}

/**************************************/
/*               SHA1                 */
/**************************************/
RMsgDigest *
r_msg_digest_new_sha1 (void)
{
  RMsgDigest * ret;
  rsize mdsize = sizeof (RMsgDigest) + sizeof (RSha1);

  if ((ret = r_malloc (mdsize)) != NULL) {
    ret->type = R_MSG_DIGEST_TYPE_SHA1;
    ret->is_final = FALSE;
    ret->mdsize = mdsize;
    ret->blocksize = R_SHA1_BLOCK_SIZE;
    ret->init = r_sha1_init;
    ret->final = r_sha1_final;
    ret->update = r_sha1_update;
    ret->get = r_sha1_get;

    ret->init (ret);
  }

  return ret;
}

static void
r_sha1_init (RMsgDigest * md)
{
  RSha1 * sha1 = (RSha1 *)(md + 1);
  sha1->bufsize = 0;
  sha1->len = 0;
  sha1->data[0] = 0x67452301;
  sha1->data[1] = 0xefcdab89;
  sha1->data[2] = 0x98badcfe;
  sha1->data[3] = 0x10325476;
  sha1->data[4] = 0xc3d2e1f0;
}

static void
r_sha1_update_block (RSha1 * sha1, const ruint8 * data)
{
  ruint32 a, b, c, d, e, x[R_SHA1_BLOCK_SIZE / sizeof (ruint32)];
  rsize i;

  for (i = 0; i < R_SHA1_BLOCK_SIZE / sizeof (ruint32); i++)
    x[i] = RUINT32_FROM_BE (((ruint32 *)data)[i]);

  a = sha1->data[0];
  b = sha1->data[1];
  c = sha1->data[2];
  d = sha1->data[3];
  e = sha1->data[4];

#define SHA1_W(w, t) \
  ((w)[(t) & 15] = RUINT32_ROTL ( \
    w[((t) - 3) & 15] ^ w[((t) - 8) & 15] ^ w[((t) - 14) & 15] ^ w[(t) & 15], 1))

#define SHA1_CORE(a, b, c, d, e, x) \
  (e) += RUINT32_ROTL ((a), 5) + ((d) ^ ((b) & ((c) ^ (d)))) + 0x5a827999 + (x); \
  (b) = RUINT32_ROTL ((b), 30)
  SHA1_CORE (a, b, c, d, e, x[ 0]);
  SHA1_CORE (e, a, b, c, d, x[ 1]);
  SHA1_CORE (d, e, a, b, c, x[ 2]);
  SHA1_CORE (c, d, e, a, b, x[ 3]);
  SHA1_CORE (b, c, d, e, a, x[ 4]);
  SHA1_CORE (a, b, c, d, e, x[ 5]);
  SHA1_CORE (e, a, b, c, d, x[ 6]);
  SHA1_CORE (d, e, a, b, c, x[ 7]);
  SHA1_CORE (c, d, e, a, b, x[ 8]);
  SHA1_CORE (b, c, d, e, a, x[ 9]);
  SHA1_CORE (a, b, c, d, e, x[10]);
  SHA1_CORE (e, a, b, c, d, x[11]);
  SHA1_CORE (d, e, a, b, c, x[12]);
  SHA1_CORE (c, d, e, a, b, x[13]);
  SHA1_CORE (b, c, d, e, a, x[14]);
  SHA1_CORE (a, b, c, d, e, x[15]);
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 16));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 17));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 18));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 19));
#undef SHA1_CORE

#define SHA1_CORE(a, b, c, d, e, x) \
  (e) += RUINT32_ROTL ((a), 5) + ((b) ^ (c) ^ (d)) + 0x6ed9eba1 + (x); \
  (b) = RUINT32_ROTL ((b), 30)
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 20));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 21));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 22));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 23));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 24));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 25));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 26));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 27));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 28));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 29));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 30));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 31));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 32));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 33));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 34));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 35));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 36));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 37));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 38));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 39));
#undef SHA1_CORE

#define SHA1_CORE(a, b, c, d, e, x) \
  (e) += RUINT32_ROTL ((a), 5) + (((b) & (c)) | ((d) & ((b) | (c)))) + 0x8f1bbcdc + (x); \
  (b) = RUINT32_ROTL ((b), 30)
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 40));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 41));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 42));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 43));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 44));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 45));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 46));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 47));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 48));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 49));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 50));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 51));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 52));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 53));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 54));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 55));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 56));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 57));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 58));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 59));
#undef SHA1_CORE

#define SHA1_CORE(a, b, c, d, e, x) \
  (e) += RUINT32_ROTL ((a), 5) + ((b) ^ (c) ^ (d)) + 0xca62c1d6 + (x); \
  (b) = RUINT32_ROTL ((b), 30)
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 60));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 61));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 62));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 63));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 64));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 65));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 66));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 67));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 68));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 69));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 70));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 71));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 72));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 73));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 74));
  SHA1_CORE (a, b, c, d, e, SHA1_W (x, 75));
  SHA1_CORE (e, a, b, c, d, SHA1_W (x, 76));
  SHA1_CORE (d, e, a, b, c, SHA1_W (x, 77));
  SHA1_CORE (c, d, e, a, b, SHA1_W (x, 78));
  SHA1_CORE (b, c, d, e, a, SHA1_W (x, 79));
#undef SHA1_CORE

#undef SHA1_W

  sha1->data[0] += a;
  sha1->data[1] += b;
  sha1->data[2] += c;
  sha1->data[3] += d;
  sha1->data[4] += e;
}

static rboolean
r_sha1_update (RMsgDigest * md, rconstpointer data, rsize size)
{
  RSha1 * sha1;
  const ruint8 * ptr;

  if (R_UNLIKELY (md == NULL || data == NULL))
    return FALSE;

  ptr = data;
  sha1 = (RSha1 *)(md + 1);
  sha1->len += size;
  if (sha1->bufsize > 0) {
    rsize s = sizeof (sha1->buffer) - sha1->bufsize;
    if (s <= size) {
      r_memcpy (&sha1->buffer[sha1->bufsize], ptr, s);
      ptr += s;
      size -= s;
      sha1->bufsize = 0;
      r_sha1_update_block (sha1, sha1->buffer);
      r_memset (sha1->buffer, 0, sizeof (sha1->buffer));
    } else {
      r_memcpy (&sha1->buffer[sha1->bufsize], ptr, size);
      sha1->bufsize += size;
      return TRUE;
    }
  }

  for (; size >= R_SHA1_BLOCK_SIZE; size -= R_SHA1_BLOCK_SIZE) {
    r_sha1_update_block (sha1, ptr);
    ptr += R_SHA1_BLOCK_SIZE;
  }

  if ((sha1->bufsize = size) > 0)
    r_memcpy (sha1->buffer, ptr, sha1->bufsize);

  return TRUE;
}

static rboolean
r_sha1_final (RMsgDigest * md)
{
  RSha1 * sha1 = (RSha1 *)(md + 1);
  rsize bufsize = sha1->bufsize;
  ruint8 * ptr;

  sha1->buffer[bufsize++] = 0x80;
  ptr = sha1->buffer;
  if (bufsize <= sizeof (sha1->buffer) - sizeof (ruint64)) {
    rsize s = sizeof (sha1->buffer) - sizeof (ruint64) - bufsize;
    r_memset (&ptr[bufsize], 0, s);
  } else {
    rsize s = sizeof (sha1->buffer) - bufsize;
    r_memset (&ptr[bufsize], 0, s);

    r_sha1_update_block (sha1, sha1->buffer);
    r_memset (sha1->buffer, 0, sizeof (sha1->buffer));
    ptr = r_alloca0 (R_SHA1_BLOCK_SIZE);
  }

  *(ruint64 *)(&ptr[R_SHA1_BLOCK_SIZE - sizeof (ruint64)]) =
    RUINT64_TO_BE (sha1->len << 3);
  r_sha1_update_block (sha1, ptr);
  return TRUE;
}

static rboolean
r_sha1_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out)
{
  const RSha1 * sha1;
  rsize i;

  if (R_UNLIKELY (data == NULL || size < R_SHA1_SIZE))
    return FALSE;

  sha1 = (const RSha1 *)(md + 1);
  for (i = 0; i < R_SHA1_SIZE / sizeof (ruint32); i++)
    ((ruint32 *)data)[i] = RUINT32_TO_BE (sha1->data[i]);
  if (out != NULL)
    *out = R_SHA1_SIZE;

  return TRUE;
}

/**************************************/
/*              SHA-224               */
/**************************************/
RMsgDigest *
r_msg_digest_new_sha224 (void)
{
  RMsgDigest * ret;
  rsize mdsize = sizeof (RMsgDigest) + sizeof (RSha256);

  if ((ret = r_malloc (mdsize)) != NULL) {
    ret->type = R_MSG_DIGEST_TYPE_SHA224;
    ret->is_final = FALSE;
    ret->mdsize = mdsize;
    ret->blocksize = R_SHA256_BLOCK_SIZE;
    ret->init = r_sha224_init;
    ret->final = r_sha256_final;
    ret->update = r_sha256_update;
    ret->get = r_sha224_get;

    ret->init (ret);
  }

  return ret;
}

void
r_sha224_init (RMsgDigest * md)
{
  RSha256 * sha224 = (RSha256 *)(md + 1);
  sha224->bufsize = 0;
  sha224->len = 0;
  sha224->data[0] = 0xc1059ed8;
  sha224->data[1] = 0x367cd507;
  sha224->data[2] = 0x3070dd17;
  sha224->data[3] = 0xf70e5939;
  sha224->data[4] = 0xffc00b31;
  sha224->data[5] = 0x68581511;
  sha224->data[6] = 0x64f98fa7;
  sha224->data[7] = 0xbefa4fa4;
}

rboolean
r_sha224_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out)
{
  const RSha256 * sha224;
  rsize i;

  if (R_UNLIKELY (data == NULL || size < R_SHA224_SIZE))
    return FALSE;

  sha224 = (const RSha256 *)(md + 1);
  for (i = 0; i < R_SHA224_SIZE / sizeof (ruint32); i++)
    ((ruint32 *)data)[i] = RUINT32_TO_BE (sha224->data[i]);
  if (out != NULL)
    *out = R_SHA224_SIZE;

  return TRUE;
}

/**************************************/
/*              SHA-256               */
/**************************************/
RMsgDigest *
r_msg_digest_new_sha256 (void)
{
  RMsgDigest * ret;
  rsize mdsize = sizeof (RMsgDigest) + sizeof (RSha256);

  if ((ret = r_malloc (mdsize)) != NULL) {
    ret->type = R_MSG_DIGEST_TYPE_SHA256;
    ret->is_final = FALSE;
    ret->mdsize = mdsize;
    ret->blocksize = R_SHA256_BLOCK_SIZE;
    ret->init = r_sha256_init;
    ret->final = r_sha256_final;
    ret->update = r_sha256_update;
    ret->get = r_sha256_get;

    ret->init (ret);
  }

  return ret;
}

static void
r_sha256_init (RMsgDigest * md)
{
  RSha256 * sha256 = (RSha256 *)(md + 1);
  sha256->bufsize = 0;
  sha256->len = 0;
  sha256->data[0] = 0x6a09e667;
  sha256->data[1] = 0xbb67ae85;
  sha256->data[2] = 0x3c6ef372;
  sha256->data[3] = 0xa54ff53a;
  sha256->data[4] = 0x510e527f;
  sha256->data[5] = 0x9b05688c;
  sha256->data[6] = 0x1f83d9ab;
  sha256->data[7] = 0x5be0cd19;
}

static void
r_sha256_update_block (RSha256 * sha256, const ruint8 * data)
{
  ruint32 a, b, c, d, e, f, g, h;
  ruint32 x[R_SHA256_BLOCK_SIZE / sizeof (ruint32)];
  rsize i;

  for (i = 0; i < R_SHA256_BLOCK_SIZE / sizeof (ruint32); i++)
    x[i] = RUINT32_FROM_BE (((ruint32 *)data)[i]);

  a = sha256->data[0];
  b = sha256->data[1];
  c = sha256->data[2];
  d = sha256->data[3];
  e = sha256->data[4];
  f = sha256->data[5];
  g = sha256->data[6];
  h = sha256->data[7];

#define SHA256_SIG0(x) (RUINT32_ROTR (x, 7) ^ RUINT32_ROTR (x,18) ^ RUINT32_SHR  (x, 3))
#define SHA256_SIG1(x) (RUINT32_ROTR (x,17) ^ RUINT32_ROTR (x,19) ^ RUINT32_SHR  (x,10))
#define SHA256_W(x, t) (x[(t) & 15] = \
  SHA256_SIG1(x[((t) -  2) & 15]) + x[((t) - 7) & 15] + \
  SHA256_SIG0(x[((t) - 15) & 15]) + x[(t) & 15])
#define SHA256_CORE(a, b, c, d, e, f, g, h, x, K)                           \
  (h) += RUINT32_ROTR (e, 6) ^ RUINT32_ROTR (e, 11) ^ RUINT32_ROTR (e, 25); \
  (h) += ((g) ^ ((e) & ((f) ^ (g)))) + (K) + (x);                           \
  (d) += (h);                                                               \
  (h) += RUINT32_ROTR (a, 2) ^ RUINT32_ROTR (a, 13) ^ RUINT32_ROTR (a, 22); \
  (h) += (((a) & (b)) | ((c) & ((a) | (b))))

  SHA256_CORE (a, b, c, d, e, f, g, h, x[ 0], 0x428a2f98);
  SHA256_CORE (h, a, b, c, d, e, f, g, x[ 1], 0x71374491);
  SHA256_CORE (g, h, a, b, c, d, e, f, x[ 2], 0xb5c0fbcf);
  SHA256_CORE (f, g, h, a, b, c, d, e, x[ 3], 0xe9b5dba5);
  SHA256_CORE (e, f, g, h, a, b, c, d, x[ 4], 0x3956c25b);
  SHA256_CORE (d, e, f, g, h, a, b, c, x[ 5], 0x59f111f1);
  SHA256_CORE (c, d, e, f, g, h, a, b, x[ 6], 0x923f82a4);
  SHA256_CORE (b, c, d, e, f, g, h, a, x[ 7], 0xab1c5ed5);
  SHA256_CORE (a, b, c, d, e, f, g, h, x[ 8], 0xd807aa98);
  SHA256_CORE (h, a, b, c, d, e, f, g, x[ 9], 0x12835b01);
  SHA256_CORE (g, h, a, b, c, d, e, f, x[10], 0x243185be);
  SHA256_CORE (f, g, h, a, b, c, d, e, x[11], 0x550c7dc3);
  SHA256_CORE (e, f, g, h, a, b, c, d, x[12], 0x72be5d74);
  SHA256_CORE (d, e, f, g, h, a, b, c, x[13], 0x80deb1fe);
  SHA256_CORE (c, d, e, f, g, h, a, b, x[14], 0x9bdc06a7);
  SHA256_CORE (b, c, d, e, f, g, h, a, x[15], 0xc19bf174);
  SHA256_CORE (a, b, c, d, e, f, g, h, SHA256_W (x, 16), 0xe49b69c1);
  SHA256_CORE (h, a, b, c, d, e, f, g, SHA256_W (x, 17), 0xefbe4786);
  SHA256_CORE (g, h, a, b, c, d, e, f, SHA256_W (x, 18), 0x0fc19dc6);
  SHA256_CORE (f, g, h, a, b, c, d, e, SHA256_W (x, 19), 0x240ca1cc);
  SHA256_CORE (e, f, g, h, a, b, c, d, SHA256_W (x, 20), 0x2de92c6f);
  SHA256_CORE (d, e, f, g, h, a, b, c, SHA256_W (x, 21), 0x4a7484aa);
  SHA256_CORE (c, d, e, f, g, h, a, b, SHA256_W (x, 22), 0x5cb0a9dc);
  SHA256_CORE (b, c, d, e, f, g, h, a, SHA256_W (x, 23), 0x76f988da);
  SHA256_CORE (a, b, c, d, e, f, g, h, SHA256_W (x, 24), 0x983e5152);
  SHA256_CORE (h, a, b, c, d, e, f, g, SHA256_W (x, 25), 0xa831c66d);
  SHA256_CORE (g, h, a, b, c, d, e, f, SHA256_W (x, 26), 0xb00327c8);
  SHA256_CORE (f, g, h, a, b, c, d, e, SHA256_W (x, 27), 0xbf597fc7);
  SHA256_CORE (e, f, g, h, a, b, c, d, SHA256_W (x, 28), 0xc6e00bf3);
  SHA256_CORE (d, e, f, g, h, a, b, c, SHA256_W (x, 29), 0xd5a79147);
  SHA256_CORE (c, d, e, f, g, h, a, b, SHA256_W (x, 30), 0x06ca6351);
  SHA256_CORE (b, c, d, e, f, g, h, a, SHA256_W (x, 31), 0x14292967);
  SHA256_CORE (a, b, c, d, e, f, g, h, SHA256_W (x, 32), 0x27b70a85);
  SHA256_CORE (h, a, b, c, d, e, f, g, SHA256_W (x, 33), 0x2e1b2138);
  SHA256_CORE (g, h, a, b, c, d, e, f, SHA256_W (x, 34), 0x4d2c6dfc);
  SHA256_CORE (f, g, h, a, b, c, d, e, SHA256_W (x, 35), 0x53380d13);
  SHA256_CORE (e, f, g, h, a, b, c, d, SHA256_W (x, 36), 0x650a7354);
  SHA256_CORE (d, e, f, g, h, a, b, c, SHA256_W (x, 37), 0x766a0abb);
  SHA256_CORE (c, d, e, f, g, h, a, b, SHA256_W (x, 38), 0x81c2c92e);
  SHA256_CORE (b, c, d, e, f, g, h, a, SHA256_W (x, 39), 0x92722c85);
  SHA256_CORE (a, b, c, d, e, f, g, h, SHA256_W (x, 40), 0xa2bfe8a1);
  SHA256_CORE (h, a, b, c, d, e, f, g, SHA256_W (x, 41), 0xa81a664b);
  SHA256_CORE (g, h, a, b, c, d, e, f, SHA256_W (x, 42), 0xc24b8b70);
  SHA256_CORE (f, g, h, a, b, c, d, e, SHA256_W (x, 43), 0xc76c51a3);
  SHA256_CORE (e, f, g, h, a, b, c, d, SHA256_W (x, 44), 0xd192e819);
  SHA256_CORE (d, e, f, g, h, a, b, c, SHA256_W (x, 45), 0xd6990624);
  SHA256_CORE (c, d, e, f, g, h, a, b, SHA256_W (x, 46), 0xf40e3585);
  SHA256_CORE (b, c, d, e, f, g, h, a, SHA256_W (x, 47), 0x106aa070);
  SHA256_CORE (a, b, c, d, e, f, g, h, SHA256_W (x, 48), 0x19a4c116);
  SHA256_CORE (h, a, b, c, d, e, f, g, SHA256_W (x, 49), 0x1e376c08);
  SHA256_CORE (g, h, a, b, c, d, e, f, SHA256_W (x, 50), 0x2748774c);
  SHA256_CORE (f, g, h, a, b, c, d, e, SHA256_W (x, 51), 0x34b0bcb5);
  SHA256_CORE (e, f, g, h, a, b, c, d, SHA256_W (x, 52), 0x391c0cb3);
  SHA256_CORE (d, e, f, g, h, a, b, c, SHA256_W (x, 53), 0x4ed8aa4a);
  SHA256_CORE (c, d, e, f, g, h, a, b, SHA256_W (x, 54), 0x5b9cca4f);
  SHA256_CORE (b, c, d, e, f, g, h, a, SHA256_W (x, 55), 0x682e6ff3);
  SHA256_CORE (a, b, c, d, e, f, g, h, SHA256_W (x, 56), 0x748f82ee);
  SHA256_CORE (h, a, b, c, d, e, f, g, SHA256_W (x, 57), 0x78a5636f);
  SHA256_CORE (g, h, a, b, c, d, e, f, SHA256_W (x, 58), 0x84c87814);
  SHA256_CORE (f, g, h, a, b, c, d, e, SHA256_W (x, 59), 0x8cc70208);
  SHA256_CORE (e, f, g, h, a, b, c, d, SHA256_W (x, 60), 0x90befffa);
  SHA256_CORE (d, e, f, g, h, a, b, c, SHA256_W (x, 61), 0xa4506ceb);
  SHA256_CORE (c, d, e, f, g, h, a, b, SHA256_W (x, 62), 0xbef9a3f7);
  SHA256_CORE (b, c, d, e, f, g, h, a, SHA256_W (x, 63), 0xc67178f2);

#undef SHA256_CORE
#undef SHA256_W
#undef SHA256_SIG1
#undef SHA256_SIG0

  sha256->data[0] += a;
  sha256->data[1] += b;
  sha256->data[2] += c;
  sha256->data[3] += d;
  sha256->data[4] += e;
  sha256->data[5] += f;
  sha256->data[6] += g;
  sha256->data[7] += h;
}

static rboolean
r_sha256_final (RMsgDigest * md)
{
  RSha256 * sha256 = (RSha256 *)(md + 1);
  rsize bufsize = sha256->bufsize;
  ruint8 * ptr;

  sha256->buffer[bufsize++] = 0x80;
  ptr = sha256->buffer;
  if (bufsize <= sizeof (sha256->buffer) - sizeof (ruint64)) {
    rsize s = sizeof (sha256->buffer) - sizeof (ruint64) - bufsize;
    r_memset (&ptr[bufsize], 0, s);
  } else {
    rsize s = sizeof (sha256->buffer) - bufsize;
    r_memset (&ptr[bufsize], 0, s);

    r_sha256_update_block (sha256, sha256->buffer);
    r_memset (sha256->buffer, 0, sizeof (sha256->buffer));
    ptr = r_alloca0 (R_SHA256_BLOCK_SIZE);
  }

  *(ruint64 *)(&ptr[R_SHA256_BLOCK_SIZE - sizeof (ruint64)]) =
    RUINT64_TO_BE (sha256->len << 3);
  r_sha256_update_block (sha256, ptr);
  return TRUE;
}

static rboolean
r_sha256_update (RMsgDigest * md, rconstpointer data, rsize size)
{
  RSha256 * sha256;
  const ruint8 * ptr;

  if (R_UNLIKELY (md == NULL || data == NULL))
    return FALSE;

  ptr = data;
  sha256 = (RSha256 *)(md + 1);
  sha256->len += size;
  if (sha256->bufsize > 0) {
    rsize s = sizeof (sha256->buffer) - sha256->bufsize;
    if (s <= size) {
      r_memcpy (&sha256->buffer[sha256->bufsize], ptr, s);
      ptr += s;
      size -= s;
      sha256->bufsize = 0;
      r_sha256_update_block (sha256, sha256->buffer);
      r_memset (sha256->buffer, 0, sizeof (sha256->buffer));
    } else {
      r_memcpy (&sha256->buffer[sha256->bufsize], ptr, size);
      sha256->bufsize += size;
      return TRUE;
    }
  }

  for (; size >= R_SHA256_BLOCK_SIZE; size -= R_SHA256_BLOCK_SIZE) {
    r_sha256_update_block (sha256, ptr);
    ptr += R_SHA256_BLOCK_SIZE;
  }

  if ((sha256->bufsize = size) > 0)
    r_memcpy (sha256->buffer, ptr, sha256->bufsize);

  return TRUE;
}

static rboolean
r_sha256_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out)
{
  const RSha256 * sha256;
  rsize i;

  if (R_UNLIKELY (data == NULL || size < R_SHA256_SIZE))
    return FALSE;

  sha256 = (const RSha256 *)(md + 1);
  for (i = 0; i < R_SHA256_SIZE / sizeof (ruint32); i++)
    ((ruint32 *)data)[i] = RUINT32_TO_BE (sha256->data[i]);
  if (out != NULL)
    *out = R_SHA256_SIZE;

  return TRUE;
}

/**************************************/
/*              SHA-384               */
/**************************************/
RMsgDigest *
r_msg_digest_new_sha384 (void)
{
  RMsgDigest * ret;
  rsize mdsize = sizeof (RMsgDigest) + sizeof (RSha512);

  if ((ret = r_malloc (mdsize)) != NULL) {
    ret->type = R_MSG_DIGEST_TYPE_SHA384;
    ret->is_final = FALSE;
    ret->mdsize = mdsize;
    ret->blocksize = R_SHA512_BLOCK_SIZE;
    ret->init = r_sha384_init;
    ret->final = r_sha512_final;
    ret->update = r_sha512_update;
    ret->get = r_sha384_get;

    ret->init (ret);
  }

  return ret;
}

void
r_sha384_init (RMsgDigest * md)
{
  RSha512 * sha384 = (RSha512 *)(md + 1);
  sha384->bufsize = 0;
  sha384->len[0] = sha384->len[1] = 0;
  sha384->data[0] = RUINT64_CONSTANT (0xcbbb9d5dc1059ed8);
  sha384->data[1] = RUINT64_CONSTANT (0x629a292a367cd507);
  sha384->data[2] = RUINT64_CONSTANT (0x9159015a3070dd17);
  sha384->data[3] = RUINT64_CONSTANT (0x152fecd8f70e5939);
  sha384->data[4] = RUINT64_CONSTANT (0x67332667ffc00b31);
  sha384->data[5] = RUINT64_CONSTANT (0x8eb44a8768581511);
  sha384->data[6] = RUINT64_CONSTANT (0xdb0c2e0d64f98fa7);
  sha384->data[7] = RUINT64_CONSTANT (0x47b5481dbefa4fa4);
}

rboolean
r_sha384_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out)
{
  const RSha512 * sha384;
  rsize i;

  if (R_UNLIKELY (data == NULL || size < R_SHA384_SIZE))
    return FALSE;

  sha384 = (const RSha512 *)(md + 1);
  for (i = 0; i < R_SHA384_SIZE / sizeof (ruint64); i++)
    ((ruint64 *)data)[i] = RUINT64_TO_BE (sha384->data[i]);
  if (out != NULL)
    *out = R_SHA384_SIZE;

  return TRUE;
}

/**************************************/
/*              SHA-512               */
/**************************************/
RMsgDigest *
r_msg_digest_new_sha512 (void)
{
  RMsgDigest * ret;
  rsize mdsize = sizeof (RMsgDigest) + sizeof (RSha512);

  if ((ret = r_malloc (mdsize)) != NULL) {
    ret->type = R_MSG_DIGEST_TYPE_SHA512;
    ret->is_final = FALSE;
    ret->mdsize = mdsize;
    ret->blocksize = R_SHA512_BLOCK_SIZE;
    ret->init = r_sha512_init;
    ret->final = r_sha512_final;
    ret->update = r_sha512_update;
    ret->get = r_sha512_get;

    ret->init (ret);
  }

  return ret;
}
static void
r_sha512_init (RMsgDigest * md)
{
  RSha512 * sha512 = (RSha512 *)(md + 1);
  sha512->bufsize = 0;
  sha512->len[0] = sha512->len[1] = 0;
  sha512->data[0] = RUINT64_CONSTANT (0x6a09e667f3bcc908);
  sha512->data[1] = RUINT64_CONSTANT (0xbb67ae8584caa73b);
  sha512->data[2] = RUINT64_CONSTANT (0x3c6ef372fe94f82b);
  sha512->data[3] = RUINT64_CONSTANT (0xa54ff53a5f1d36f1);
  sha512->data[4] = RUINT64_CONSTANT (0x510e527fade682d1);
  sha512->data[5] = RUINT64_CONSTANT (0x9b05688c2b3e6c1f);
  sha512->data[6] = RUINT64_CONSTANT (0x1f83d9abfb41bd6b);
  sha512->data[7] = RUINT64_CONSTANT (0x5be0cd19137e2179);
}

static void
r_sha512_update_block (RSha512 * sha512, const ruint8 * data)
{
  ruint64 a, b, c, d, e, f, g, h;
  ruint64 x[R_SHA512_BLOCK_SIZE / sizeof (ruint64)];
  rsize i;

  for (i = 0; i < R_SHA512_BLOCK_SIZE / sizeof (ruint64); i++)
    x[i] = RUINT64_FROM_BE (((ruint64 *)data)[i]);

  a = sha512->data[0];
  b = sha512->data[1];
  c = sha512->data[2];
  d = sha512->data[3];
  e = sha512->data[4];
  f = sha512->data[5];
  g = sha512->data[6];
  h = sha512->data[7];

#define SHA512_SIG0(x) (RUINT64_ROTR (x, 1) ^ RUINT64_ROTR (x, 8) ^ RUINT64_SHR  (x, 7))
#define SHA512_SIG1(x) (RUINT64_ROTR (x,19) ^ RUINT64_ROTR (x,61) ^ RUINT64_SHR  (x, 6))
#define SHA512_W(x, t) (x[(t) & 15] = \
  SHA512_SIG1(x[((t) -  2) & 15]) + x[((t) - 7) & 15] + \
  SHA512_SIG0(x[((t) - 15) & 15]) + x[(t) & 15])
#define SHA512_CORE(a, b, c, d, e, f, g, h, x, K)                             \
  (h) += RUINT64_ROTR (e, 14) ^ RUINT64_ROTR (e, 18) ^ RUINT64_ROTR (e, 41);  \
  (h) += ((g) ^ ((e) & ((f) ^ (g)))) + (K) + (x);                             \
  (d) += (h);                                                                 \
  (h) += RUINT64_ROTR (a, 28) ^ RUINT64_ROTR (a, 34) ^ RUINT64_ROTR (a, 39);  \
  (h) += (((a) & (b)) | ((c) & ((a) | (b))))

  SHA512_CORE (a, b, c, d, e, f, g, h, x[ 0], RUINT64_CONSTANT (0x428a2f98d728ae22));
  SHA512_CORE (h, a, b, c, d, e, f, g, x[ 1], RUINT64_CONSTANT (0x7137449123ef65cd));
  SHA512_CORE (g, h, a, b, c, d, e, f, x[ 2], RUINT64_CONSTANT (0xb5c0fbcfec4d3b2f));
  SHA512_CORE (f, g, h, a, b, c, d, e, x[ 3], RUINT64_CONSTANT (0xe9b5dba58189dbbc));
  SHA512_CORE (e, f, g, h, a, b, c, d, x[ 4], RUINT64_CONSTANT (0x3956c25bf348b538));
  SHA512_CORE (d, e, f, g, h, a, b, c, x[ 5], RUINT64_CONSTANT (0x59f111f1b605d019));
  SHA512_CORE (c, d, e, f, g, h, a, b, x[ 6], RUINT64_CONSTANT (0x923f82a4af194f9b));
  SHA512_CORE (b, c, d, e, f, g, h, a, x[ 7], RUINT64_CONSTANT (0xab1c5ed5da6d8118));
  SHA512_CORE (a, b, c, d, e, f, g, h, x[ 8], RUINT64_CONSTANT (0xd807aa98a3030242));
  SHA512_CORE (h, a, b, c, d, e, f, g, x[ 9], RUINT64_CONSTANT (0x12835b0145706fbe));
  SHA512_CORE (g, h, a, b, c, d, e, f, x[10], RUINT64_CONSTANT (0x243185be4ee4b28c));
  SHA512_CORE (f, g, h, a, b, c, d, e, x[11], RUINT64_CONSTANT (0x550c7dc3d5ffb4e2));
  SHA512_CORE (e, f, g, h, a, b, c, d, x[12], RUINT64_CONSTANT (0x72be5d74f27b896f));
  SHA512_CORE (d, e, f, g, h, a, b, c, x[13], RUINT64_CONSTANT (0x80deb1fe3b1696b1));
  SHA512_CORE (c, d, e, f, g, h, a, b, x[14], RUINT64_CONSTANT (0x9bdc06a725c71235));
  SHA512_CORE (b, c, d, e, f, g, h, a, x[15], RUINT64_CONSTANT (0xc19bf174cf692694));
  SHA512_CORE (a, b, c, d, e, f, g, h, SHA512_W (x, 16), RUINT64_CONSTANT (0xe49b69c19ef14ad2));
  SHA512_CORE (h, a, b, c, d, e, f, g, SHA512_W (x, 17), RUINT64_CONSTANT (0xefbe4786384f25e3));
  SHA512_CORE (g, h, a, b, c, d, e, f, SHA512_W (x, 18), RUINT64_CONSTANT (0x0fc19dc68b8cd5b5));
  SHA512_CORE (f, g, h, a, b, c, d, e, SHA512_W (x, 19), RUINT64_CONSTANT (0x240ca1cc77ac9c65));
  SHA512_CORE (e, f, g, h, a, b, c, d, SHA512_W (x, 20), RUINT64_CONSTANT (0x2de92c6f592b0275));
  SHA512_CORE (d, e, f, g, h, a, b, c, SHA512_W (x, 21), RUINT64_CONSTANT (0x4a7484aa6ea6e483));
  SHA512_CORE (c, d, e, f, g, h, a, b, SHA512_W (x, 22), RUINT64_CONSTANT (0x5cb0a9dcbd41fbd4));
  SHA512_CORE (b, c, d, e, f, g, h, a, SHA512_W (x, 23), RUINT64_CONSTANT (0x76f988da831153b5));
  SHA512_CORE (a, b, c, d, e, f, g, h, SHA512_W (x, 24), RUINT64_CONSTANT (0x983e5152ee66dfab));
  SHA512_CORE (h, a, b, c, d, e, f, g, SHA512_W (x, 25), RUINT64_CONSTANT (0xa831c66d2db43210));
  SHA512_CORE (g, h, a, b, c, d, e, f, SHA512_W (x, 26), RUINT64_CONSTANT (0xb00327c898fb213f));
  SHA512_CORE (f, g, h, a, b, c, d, e, SHA512_W (x, 27), RUINT64_CONSTANT (0xbf597fc7beef0ee4));
  SHA512_CORE (e, f, g, h, a, b, c, d, SHA512_W (x, 28), RUINT64_CONSTANT (0xc6e00bf33da88fc2));
  SHA512_CORE (d, e, f, g, h, a, b, c, SHA512_W (x, 29), RUINT64_CONSTANT (0xd5a79147930aa725));
  SHA512_CORE (c, d, e, f, g, h, a, b, SHA512_W (x, 30), RUINT64_CONSTANT (0x06ca6351e003826f));
  SHA512_CORE (b, c, d, e, f, g, h, a, SHA512_W (x, 31), RUINT64_CONSTANT (0x142929670a0e6e70));
  SHA512_CORE (a, b, c, d, e, f, g, h, SHA512_W (x, 32), RUINT64_CONSTANT (0x27b70a8546d22ffc));
  SHA512_CORE (h, a, b, c, d, e, f, g, SHA512_W (x, 33), RUINT64_CONSTANT (0x2e1b21385c26c926));
  SHA512_CORE (g, h, a, b, c, d, e, f, SHA512_W (x, 34), RUINT64_CONSTANT (0x4d2c6dfc5ac42aed));
  SHA512_CORE (f, g, h, a, b, c, d, e, SHA512_W (x, 35), RUINT64_CONSTANT (0x53380d139d95b3df));
  SHA512_CORE (e, f, g, h, a, b, c, d, SHA512_W (x, 36), RUINT64_CONSTANT (0x650a73548baf63de));
  SHA512_CORE (d, e, f, g, h, a, b, c, SHA512_W (x, 37), RUINT64_CONSTANT (0x766a0abb3c77b2a8));
  SHA512_CORE (c, d, e, f, g, h, a, b, SHA512_W (x, 38), RUINT64_CONSTANT (0x81c2c92e47edaee6));
  SHA512_CORE (b, c, d, e, f, g, h, a, SHA512_W (x, 39), RUINT64_CONSTANT (0x92722c851482353b));
  SHA512_CORE (a, b, c, d, e, f, g, h, SHA512_W (x, 40), RUINT64_CONSTANT (0xa2bfe8a14cf10364));
  SHA512_CORE (h, a, b, c, d, e, f, g, SHA512_W (x, 41), RUINT64_CONSTANT (0xa81a664bbc423001));
  SHA512_CORE (g, h, a, b, c, d, e, f, SHA512_W (x, 42), RUINT64_CONSTANT (0xc24b8b70d0f89791));
  SHA512_CORE (f, g, h, a, b, c, d, e, SHA512_W (x, 43), RUINT64_CONSTANT (0xc76c51a30654be30));
  SHA512_CORE (e, f, g, h, a, b, c, d, SHA512_W (x, 44), RUINT64_CONSTANT (0xd192e819d6ef5218));
  SHA512_CORE (d, e, f, g, h, a, b, c, SHA512_W (x, 45), RUINT64_CONSTANT (0xd69906245565a910));
  SHA512_CORE (c, d, e, f, g, h, a, b, SHA512_W (x, 46), RUINT64_CONSTANT (0xf40e35855771202a));
  SHA512_CORE (b, c, d, e, f, g, h, a, SHA512_W (x, 47), RUINT64_CONSTANT (0x106aa07032bbd1b8));
  SHA512_CORE (a, b, c, d, e, f, g, h, SHA512_W (x, 48), RUINT64_CONSTANT (0x19a4c116b8d2d0c8));
  SHA512_CORE (h, a, b, c, d, e, f, g, SHA512_W (x, 49), RUINT64_CONSTANT (0x1e376c085141ab53));
  SHA512_CORE (g, h, a, b, c, d, e, f, SHA512_W (x, 50), RUINT64_CONSTANT (0x2748774cdf8eeb99));
  SHA512_CORE (f, g, h, a, b, c, d, e, SHA512_W (x, 51), RUINT64_CONSTANT (0x34b0bcb5e19b48a8));
  SHA512_CORE (e, f, g, h, a, b, c, d, SHA512_W (x, 52), RUINT64_CONSTANT (0x391c0cb3c5c95a63));
  SHA512_CORE (d, e, f, g, h, a, b, c, SHA512_W (x, 53), RUINT64_CONSTANT (0x4ed8aa4ae3418acb));
  SHA512_CORE (c, d, e, f, g, h, a, b, SHA512_W (x, 54), RUINT64_CONSTANT (0x5b9cca4f7763e373));
  SHA512_CORE (b, c, d, e, f, g, h, a, SHA512_W (x, 55), RUINT64_CONSTANT (0x682e6ff3d6b2b8a3));
  SHA512_CORE (a, b, c, d, e, f, g, h, SHA512_W (x, 56), RUINT64_CONSTANT (0x748f82ee5defb2fc));
  SHA512_CORE (h, a, b, c, d, e, f, g, SHA512_W (x, 57), RUINT64_CONSTANT (0x78a5636f43172f60));
  SHA512_CORE (g, h, a, b, c, d, e, f, SHA512_W (x, 58), RUINT64_CONSTANT (0x84c87814a1f0ab72));
  SHA512_CORE (f, g, h, a, b, c, d, e, SHA512_W (x, 59), RUINT64_CONSTANT (0x8cc702081a6439ec));
  SHA512_CORE (e, f, g, h, a, b, c, d, SHA512_W (x, 60), RUINT64_CONSTANT (0x90befffa23631e28));
  SHA512_CORE (d, e, f, g, h, a, b, c, SHA512_W (x, 61), RUINT64_CONSTANT (0xa4506cebde82bde9));
  SHA512_CORE (c, d, e, f, g, h, a, b, SHA512_W (x, 62), RUINT64_CONSTANT (0xbef9a3f7b2c67915));
  SHA512_CORE (b, c, d, e, f, g, h, a, SHA512_W (x, 63), RUINT64_CONSTANT (0xc67178f2e372532b));
  SHA512_CORE (a, b, c, d, e, f, g, h, SHA512_W (x, 64), RUINT64_CONSTANT (0xca273eceea26619c));
  SHA512_CORE (h, a, b, c, d, e, f, g, SHA512_W (x, 65), RUINT64_CONSTANT (0xd186b8c721c0c207));
  SHA512_CORE (g, h, a, b, c, d, e, f, SHA512_W (x, 66), RUINT64_CONSTANT (0xeada7dd6cde0eb1e));
  SHA512_CORE (f, g, h, a, b, c, d, e, SHA512_W (x, 67), RUINT64_CONSTANT (0xf57d4f7fee6ed178));
  SHA512_CORE (e, f, g, h, a, b, c, d, SHA512_W (x, 68), RUINT64_CONSTANT (0x06f067aa72176fba));
  SHA512_CORE (d, e, f, g, h, a, b, c, SHA512_W (x, 69), RUINT64_CONSTANT (0x0a637dc5a2c898a6));
  SHA512_CORE (c, d, e, f, g, h, a, b, SHA512_W (x, 70), RUINT64_CONSTANT (0x113f9804bef90dae));
  SHA512_CORE (b, c, d, e, f, g, h, a, SHA512_W (x, 71), RUINT64_CONSTANT (0x1b710b35131c471b));
  SHA512_CORE (a, b, c, d, e, f, g, h, SHA512_W (x, 72), RUINT64_CONSTANT (0x28db77f523047d84));
  SHA512_CORE (h, a, b, c, d, e, f, g, SHA512_W (x, 73), RUINT64_CONSTANT (0x32caab7b40c72493));
  SHA512_CORE (g, h, a, b, c, d, e, f, SHA512_W (x, 74), RUINT64_CONSTANT (0x3c9ebe0a15c9bebc));
  SHA512_CORE (f, g, h, a, b, c, d, e, SHA512_W (x, 75), RUINT64_CONSTANT (0x431d67c49c100d4c));
  SHA512_CORE (e, f, g, h, a, b, c, d, SHA512_W (x, 76), RUINT64_CONSTANT (0x4cc5d4becb3e42b6));
  SHA512_CORE (d, e, f, g, h, a, b, c, SHA512_W (x, 77), RUINT64_CONSTANT (0x597f299cfc657e2a));
  SHA512_CORE (c, d, e, f, g, h, a, b, SHA512_W (x, 78), RUINT64_CONSTANT (0x5fcb6fab3ad6faec));
  SHA512_CORE (b, c, d, e, f, g, h, a, SHA512_W (x, 79), RUINT64_CONSTANT (0x6c44198c4a475817));

#undef SHA512_CORE
#undef SHA512_W
#undef SHA512_SIG1
#undef SHA512_SIG0

  sha512->data[0] += a;
  sha512->data[1] += b;
  sha512->data[2] += c;
  sha512->data[3] += d;
  sha512->data[4] += e;
  sha512->data[5] += f;
  sha512->data[6] += g;
  sha512->data[7] += h;
}

static rboolean
r_sha512_final (RMsgDigest * md)
{
  RSha512 * sha512 = (RSha512 *)(md + 1);
  rsize bufsize = sha512->bufsize;
  ruint8 * ptr;

  sha512->buffer[bufsize++] = 0x80;
  ptr = sha512->buffer;
  if (bufsize <= sizeof (sha512->buffer) - sizeof (ruint64)) {
    rsize s = sizeof (sha512->buffer) - sizeof (ruint64) - bufsize;
    r_memset (&ptr[bufsize], 0, s);
  } else {
    rsize s = sizeof (sha512->buffer) - bufsize;
    r_memset (&ptr[bufsize], 0, s);

    r_sha512_update_block (sha512, sha512->buffer);
    r_memset (sha512->buffer, 0, sizeof (sha512->buffer));
    ptr = r_alloca0 (R_SHA512_BLOCK_SIZE);
  }

  *(ruint64 *)(&ptr[R_SHA512_BLOCK_SIZE - 1*sizeof (ruint64)]) =
    RUINT64_TO_BE (sha512->len[0] << 3);
  *(ruint64 *)(&ptr[R_SHA512_BLOCK_SIZE - 2*sizeof (ruint64)]) =
    RUINT64_TO_BE ((sha512->len[1] << 3) | (sha512->len[0] >> 61));
  r_sha512_update_block (sha512, ptr);
  return TRUE;
}

static rboolean
r_sha512_update (RMsgDigest * md, rconstpointer data, rsize size)
{
  RSha512 * sha512;
  const ruint8 * ptr;

  if (R_UNLIKELY (md == NULL || data == NULL))
    return FALSE;

  ptr = data;
  sha512 = (RSha512 *)(md + 1);
  sha512->len[0] += size;
  if (R_UNLIKELY (sha512->len[0] < size))
    sha512->len[1]++;

  if (sha512->bufsize > 0) {
    rsize s = sizeof (sha512->buffer) - sha512->bufsize;
    if (s <= size) {
      r_memcpy (&sha512->buffer[sha512->bufsize], ptr, s);
      ptr += s;
      size -= s;
      sha512->bufsize = 0;
      r_sha512_update_block (sha512, sha512->buffer);
      r_memset (sha512->buffer, 0, sizeof (sha512->buffer));
    } else {
      r_memcpy (&sha512->buffer[sha512->bufsize], ptr, size);
      sha512->bufsize += size;
      return TRUE;
    }
  }

  for (; size >= R_SHA512_BLOCK_SIZE; size -= R_SHA512_BLOCK_SIZE) {
    r_sha512_update_block (sha512, ptr);
    ptr += R_SHA512_BLOCK_SIZE;
  }

  if ((sha512->bufsize = size) > 0)
    r_memcpy (sha512->buffer, ptr, sha512->bufsize);

  return TRUE;
}

static rboolean
r_sha512_get (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out)
{
  const RSha512 * sha512;
  rsize i;

  if (R_UNLIKELY (data == NULL || size < R_SHA512_SIZE))
    return FALSE;

  sha512 = (const RSha512 *)(md + 1);
  for (i = 0; i < R_SHA512_SIZE / sizeof (ruint64); i++)
    ((ruint64 *)data)[i] = RUINT64_TO_BE (sha512->data[i]);
  if (out != NULL)
    *out = R_SHA512_SIZE;

  return TRUE;
}

