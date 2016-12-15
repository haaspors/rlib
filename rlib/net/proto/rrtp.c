/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/net/proto/rrtp.h>

#define R_RTP_MINSIZE                 (3 * sizeof (ruint32))
#define R_RTP_VERSION_MASK            0xc0
#define R_RTP_PADDING_MASK            0x20
#define R_RTP_EXTENSION_MASK          0x10
#define R_RTP_CSRC_COUNT_MASK         0x0f
#define R_RTP_PT_MASK                 0x7f

#define R_RTCP_MINSIZE                (2 * sizeof (ruint32))

typedef struct {
#if R_BYTE_ORDER == R_LITTLE_ENDIAN
  ruint cc:4; /* CSRC count */
  ruint x:1;  /* header extension */
  ruint p:1;  /* padding */
  ruint v:2;  /* version */
  ruint pt:7; /* payload type */
  ruint m:1;  /* marker */
#elif R_BYTE_ORDER == R_BIG_ENDIAN
  ruint v:2;  /* version */
  ruint p:1;  /* padding */
  ruint x:1;  /* header extension */
  ruint cc:4; /* CSRC count */
  ruint m:1;  /* marker */
  ruint pt:7; /* payload type */
#else
#error "R_BYTE_ORDER not supported"
#endif
  ruint seq:16;          /* sequence number */
  ruint timestamp:32;    /* timestamp */
  ruint ssrc:32;         /* synchronization source */
  ruint32 csrclist[];    /* optional CSRC list, 32 bits each */
} RRTPHdr;

rboolean
r_rtp_is_valid_hdr (rconstpointer buf, rsize size)
{
  const RRTPHdr * hdr;
  rsize minsize = R_RTP_MINSIZE;

  if (R_UNLIKELY (buf == NULL)) return FALSE;
  if (R_UNLIKELY (size < minsize)) return FALSE;
  hdr = buf;

  /* version check */
  if (R_UNLIKELY (hdr->v != R_RTP_VERSION))
    return FALSE;

  /* check for reserved PT to avoid RTCP conflict */
  if (R_UNLIKELY (hdr->pt >= 72 && hdr->pt <= 76))
    return FALSE;

  minsize += hdr->cc * sizeof (ruint32);

  /* extension header */
  if (hdr->x) {
    const ruint8 * p = buf;
    minsize += sizeof (ruint32);
    if (R_UNLIKELY (size < minsize)) return FALSE;
    minsize += RUINT16_FROM_BE (*(ruint16 *)&p[minsize - sizeof (ruint16)]) * sizeof (ruint32);
  }

  /* Padding */
  /* skip checking for last octet as this might be encrypted */

  return size >= minsize;
}

rboolean
r_rtcp_is_valid_hdr (rconstpointer buf, rsize size)
{
  const ruint8 * p = buf;
  rsize minsize = R_RTCP_MINSIZE;

  if (R_UNLIKELY (buf == NULL)) return FALSE;
  if (R_UNLIKELY (size < minsize)) return FALSE;
  if (R_UNLIKELY (((p[0] & R_RTP_VERSION_MASK) >> 6) != R_RTP_VERSION)) return FALSE;
  if (R_UNLIKELY ((p[1] & 0x80) == 0)) return FALSE;

  /* SKIP SR/RR check to support reduced size RTCP */
  /* SKIP padding bit check if first packet of compound packet */
  minsize = (RUINT16_FROM_BE (*(const ruint16 *)&p[2]) + 1) * sizeof (ruint32);

  return size >= minsize;
}

