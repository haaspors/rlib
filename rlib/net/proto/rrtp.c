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

#define R_RTCP_MINSIZE                (2 * sizeof (ruint32))
#define R_RTCP_VERSION_MASK            0xc0

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
  rsize minsize = R_RTP_HDR_SIZE;

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
  if (R_UNLIKELY (((p[0] & R_RTCP_VERSION_MASK) >> 6) != R_RTP_VERSION)) return FALSE;
  if (R_UNLIKELY ((p[1] & 0x80) == 0)) return FALSE;

  /* SKIP SR/RR check to support reduced size RTCP */
  /* SKIP padding bit check if first packet of compound packet */
  minsize = (RUINT16_FROM_BE (*(const ruint16 *)&p[2]) + 1) * sizeof (ruint32);

  return size >= minsize;
}

RBuffer *
r_buffer_new_rtp_buffer (RBuffer * payload, ruint8 pad, ruint8 cc)
{
  RBuffer * ret;

  if (R_UNLIKELY (payload == NULL)) return NULL;
  if (R_UNLIKELY (cc > 0x0f)) return NULL;

  if ((ret = r_buffer_new ()) != NULL) {
    RRTPHdr * hdr;
    rsize size;
    RMem * mem;
    rboolean res;

    size = R_RTP_HDR_SIZE + cc * sizeof (ruint32);
    if (R_UNLIKELY ((hdr = r_malloc0 (size)) == NULL))
      goto error;

    hdr->v = R_RTP_VERSION;
    hdr->p = pad > 0 ? 1 : 0;
    hdr->x = 0;
    hdr->cc = cc;
    if (R_UNLIKELY ((mem = r_mem_new_take (R_MEM_FLAG_NONE, hdr, size, size, 0)) == NULL)) {
      r_free (hdr);
      goto error;
    }

    res = r_buffer_mem_append (ret, mem);
    r_mem_unref (mem);
    if (R_UNLIKELY (!res))
      goto error;

    if (R_UNLIKELY (!r_buffer_append_mem_from_buffer (ret, payload)))
      goto error;

    if (pad > 0) {
      ruint8 * data;

      size = pad;
      if (R_UNLIKELY ((data = r_malloc0 (size)) == NULL))
        goto error;

      data[size - 1] = pad;
      if (R_UNLIKELY ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data, size, size, 0)) == NULL)) {
        r_free (data);
        goto error;
      }

      res = r_buffer_mem_append (ret, mem);
      r_mem_unref (mem);
      if (R_UNLIKELY (!res))
        goto error;
    }
  }

  return ret;
error:
  r_buffer_unref (ret);
  return NULL;
}

RBuffer *
r_buffer_new_rtp_buffer_take (rpointer payload, rsize size,
    ruint8 pad, ruint8 cc)
{
  RBuffer * paybuf, * ret;

  if ((paybuf = r_buffer_new_take (payload, size)) != NULL) {
    ret = r_buffer_new_rtp_buffer (paybuf, pad, cc);
    r_buffer_unref (paybuf);
  } else {
    ret = NULL;
  }

  return ret;
}

RBuffer *
r_buffer_new_rtp_buffer_alloc (rsize payload, ruint8 pad, ruint8 cc)
{
  RBuffer * paybuf, * ret;

  if ((paybuf = r_buffer_new_alloc (NULL, payload, NULL)) != NULL) {
    ret = r_buffer_new_rtp_buffer (paybuf, pad, cc);
    r_buffer_unref (paybuf);
  } else {
    ret = NULL;
  }

  return ret;
}

rboolean
r_rtp_buffer_map (RRTPBuffer * rtp, RBuffer * buf, RMemMapFlags flags)
{
  rboolean ret;

  if (R_UNLIKELY (buf == NULL)) return FALSE;
  if (R_UNLIKELY (rtp == NULL)) return FALSE;
  if (R_UNLIKELY (rtp->buffer != NULL)) return FALSE;

  if ((ret = r_buffer_map_byte_range (buf, 0, R_RTP_HDR_SIZE, &rtp->hdr, flags))) {
    if ((ret = r_rtp_is_valid_hdr (rtp->hdr.data, rtp->hdr.size))) {
      const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
      rsize size;

      if (hdr->cc > 0) {
        size = R_RTP_HDR_SIZE + hdr->cc * sizeof (ruint32);

        r_buffer_unmap (buf, &rtp->hdr);
        if (!(ret = r_buffer_map_byte_range (buf, 0, size, &rtp->hdr, flags)))
          goto beach;

        hdr = (const RRTPHdr *)rtp->hdr.data;
      }

      if (hdr->x) {
        size = sizeof (ruint32);
        if (!(ret = r_buffer_map_byte_range (buf, rtp->hdr.size, size, &rtp->ext, flags)))
          goto beach;

        size += RUINT16_FROM_BE (*(ruint16 *)&rtp->ext.data[sizeof (ruint16)]) * sizeof (ruint32);
        r_buffer_unmap (buf, &rtp->ext);
        if (!(ret = r_buffer_map_byte_range (buf, rtp->hdr.size, size, &rtp->ext, flags)))
          goto beach;
      }

      if (!(ret = r_buffer_map_byte_range (buf,
              rtp->hdr.size + rtp->ext.size, -1, &rtp->pay, flags)))
        goto beach;

      if ((flags & R_RTP_BUFFER_MAP_FLAG_SKIP_PADDING) == 0) {
        if (hdr->p)
          rtp->pay.size -= rtp->pay.data[rtp->pay.size - 1];
      }
      rtp->buffer = r_buffer_ref (buf);
    }
  }

beach:
  if (R_UNLIKELY (rtp->buffer == NULL)) {
    r_buffer_unmap (buf, &rtp->pay);
    r_buffer_unmap (buf, &rtp->ext);
    r_buffer_unmap (buf, &rtp->hdr);
  }
  return ret;
}

rboolean
r_rtp_buffer_unmap (RRTPBuffer * rtp, RBuffer * buf)
{
  rboolean ret;

  if (R_UNLIKELY (rtp == NULL)) return FALSE;
  if (R_UNLIKELY (buf != rtp->buffer)) return FALSE;

  if ((ret = (r_buffer_unmap (buf, &rtp->hdr) &&
        r_buffer_unmap (buf, &rtp->ext) && r_buffer_unmap (buf, &rtp->pay)))) {
    r_buffer_unref (rtp->buffer);
    r_memclear (rtp, sizeof (RRTPBuffer));
  }

  return ret;
}


rboolean
r_rtp_buffer_has_padding (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return hdr->p;
}

rboolean
r_rtp_buffer_has_extension (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return hdr->x;
}

rboolean
r_rtp_buffer_has_marker (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return hdr->m;
}

ruint32
r_rtp_buffer_get_ssrc (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return RUINT32_FROM_BE (hdr->ssrc);
}

RRTPPayloadType
r_rtp_buffer_get_pt (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return (RRTPPayloadType)hdr->pt;
}

ruint16
r_rtp_buffer_get_seq (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return RUINT16_FROM_BE (hdr->seq);
}

ruint32
r_rtp_buffer_get_timestamp (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return RUINT32_FROM_BE (hdr->timestamp);
}

ruint8
r_rtp_buffer_get_csrc_count (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return hdr->cc;
}

ruint32
r_rtp_buffer_get_csrc (const RRTPBuffer * rtp, ruint8 n)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return RUINT32_FROM_BE (hdr->csrclist[n]);
}

void
r_rtp_buffer_set_marker (RRTPBuffer * rtp, rboolean marker)
{
  RRTPHdr * hdr = (RRTPHdr *)rtp->hdr.data;
  hdr->m = marker ? 1 : 0;
}

void
r_rtp_buffer_set_ssrc (RRTPBuffer * rtp, ruint32 ssrc)
{
  RRTPHdr * hdr = (RRTPHdr *)rtp->hdr.data;
  hdr->ssrc = RUINT32_TO_BE (ssrc);
}

void
r_rtp_buffer_set_pt (RRTPBuffer * rtp, RRTPPayloadType pt)
{
  RRTPHdr * hdr = (RRTPHdr *)rtp->hdr.data;
  ruint8 u8 = (ruint8)pt;
  hdr->pt = u8;
}

void
r_rtp_buffer_set_seq (RRTPBuffer * rtp, ruint16 seq)
{
  RRTPHdr * hdr = (RRTPHdr *)rtp->hdr.data;
  hdr->seq = RUINT16_TO_BE (seq);
}

void
r_rtp_buffer_set_timestamp (RRTPBuffer * rtp, ruint32 ts)
{
  RRTPHdr * hdr = (RRTPHdr *)rtp->hdr.data;
  hdr->timestamp = RUINT32_TO_BE (ts);
}

