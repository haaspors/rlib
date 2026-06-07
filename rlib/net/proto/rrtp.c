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

#define r_rtp_hdr_is_valid(hdr) \
  (hdr->v == R_RTP_VERSION && (hdr->pt < 72 || hdr->pt > 76))

rboolean
r_rtp_is_valid_hdr (rconstpointer buf, rsize size)
{
  const RRTPHdr * hdr;
  rsize minsize = R_RTP_HDR_SIZE;

  if (R_UNLIKELY (size < minsize)) return FALSE;
  if (R_UNLIKELY ((hdr = buf) == NULL)) return FALSE;

  /* version hdr */
  if (R_UNLIKELY (!r_rtp_hdr_is_valid (hdr)))
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

static RBuffer *
r_rtp_new (RBuffer * payload, ruint8 pad, ruint8 cc, rboolean ext,
    ruint16 profile, rconstpointer extdata, rsize extsize)
{
  RBuffer * ret;

  if (R_UNLIKELY (payload == NULL)) return NULL;
  if (R_UNLIKELY (cc > 0x0f)) return NULL;
  /* The extension is a whole number of 32-bit words, counted by a 16-bit
   * length field (RFC 3550 5.3.1). */
  if (R_UNLIKELY (ext && ((extsize & 0x3) != 0 ||
          extsize > (rsize)0xffff * sizeof (ruint32)))) return NULL;

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
    hdr->x = ext ? 1 : 0;
    hdr->cc = cc;
    if (R_UNLIKELY ((mem = r_mem_new_take (R_MEM_FLAG_NONE, hdr, size, size, 0)) == NULL)) {
      r_free (hdr);
      goto error;
    }

    res = r_buffer_mem_append (ret, mem);
    r_mem_unref (mem);
    if (R_UNLIKELY (!res))
      goto error;

    if (ext) {
      ruint8 * e;

      size = sizeof (ruint32) + extsize;     /* profile+length word, then data */
      if (R_UNLIKELY ((e = r_malloc0 (size)) == NULL))
        goto error;

      *(ruint16 *)&e[0] = RUINT16_TO_BE (profile);
      *(ruint16 *)&e[sizeof (ruint16)] =
          RUINT16_TO_BE ((ruint16)(extsize / sizeof (ruint32)));
      if (extsize > 0 && extdata != NULL)
        r_memcpy (e + sizeof (ruint32), extdata, extsize);

      if (R_UNLIKELY ((mem = r_mem_new_take (R_MEM_FLAG_NONE, e, size, size, 0)) == NULL)) {
        r_free (e);
        goto error;
      }

      res = r_buffer_mem_append (ret, mem);
      r_mem_unref (mem);
      if (R_UNLIKELY (!res))
        goto error;
    }

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
r_buffer_new_rtp_buffer (RBuffer * payload, ruint8 pad, ruint8 cc)
{
  return r_rtp_new (payload, pad, cc, FALSE, 0, NULL, 0);
}

RBuffer *
r_buffer_new_rtp_buffer_ext (RBuffer * payload, ruint8 pad, ruint8 cc,
    ruint16 profile, rconstpointer extdata, rsize extsize)
{
  return r_rtp_new (payload, pad, cc, TRUE, profile, extdata, extsize);
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
    const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
    if ((ret = r_rtp_hdr_is_valid (hdr))) {
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
        /* The padding-count byte is attacker-controlled; ignore it unless
         * there is a payload and the count fits, so pay.size (unsigned)
         * can't wrap into a huge value. */
        if (hdr->p && rtp->pay.size > 0 &&
            rtp->pay.data[rtp->pay.size - 1] <= rtp->pay.size)
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

ruint8
r_rtp_buffer_get_padding (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr;
  rsize total;
  ruint8 pad = 0;

  if (R_UNLIKELY (rtp == NULL || rtp->hdr.data == NULL || rtp->buffer == NULL))
    return 0;
  hdr = (const RRTPHdr *)rtp->hdr.data;
  if (!hdr->p)
    return 0;

  /* The pad count is the packet's last octet regardless of how the payload was
   * mapped (it may be excluded from rtp->pay), so read it from the buffer. */
  total = r_buffer_get_size (rtp->buffer);
  if (R_UNLIKELY (total == 0))
    return 0;
  if (R_UNLIKELY (r_buffer_extract (rtp->buffer, total - 1, &pad, 1) != 1))
    return 0;

  return pad;
}

rboolean
r_rtp_buffer_has_extension (const RRTPBuffer * rtp)
{
  const RRTPHdr * hdr = (const RRTPHdr *)rtp->hdr.data;
  return hdr->x;
}

rboolean
r_rtp_buffer_get_extension (const RRTPBuffer * rtp, ruint16 * profile,
    const ruint8 ** data, ruint16 * size)
{
  const RRTPHdr * hdr;

  if (R_UNLIKELY (rtp == NULL || rtp->hdr.data == NULL))
    return FALSE;
  hdr = (const RRTPHdr *)rtp->hdr.data;
  if (!hdr->x || rtp->ext.data == NULL || rtp->ext.size < sizeof (ruint32))
    return FALSE;

  /* ext region: [profile(16) | length-in-words(16) | data...]; the mapped
   * size already accounts for length, so data is everything past the word. */
  if (profile != NULL)
    *profile = RUINT16_FROM_BE (*(const ruint16 *)rtp->ext.data);
  if (data != NULL)
    *data = rtp->ext.data + sizeof (ruint32);
  if (size != NULL)
    *size = (ruint16)(rtp->ext.size - sizeof (ruint32));

  return TRUE;
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
  if (R_UNLIKELY (n >= hdr->cc))
    return 0;
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

rboolean
r_rtp_buffer_set_csrc (RRTPBuffer * rtp, ruint8 n, ruint32 csrc)
{
  RRTPHdr * hdr;
  if (R_UNLIKELY (rtp == NULL || rtp->hdr.data == NULL)) return FALSE;
  hdr = (RRTPHdr *)rtp->hdr.data;
  if (n >= hdr->cc) return FALSE;
  hdr->csrclist[n] = RUINT32_TO_BE (csrc);
  return TRUE;
}

ruint64
r_rtp_estimate_seq_idx (ruint16 seq, ruint64 curidx)
{
  if (curidx > R_RTP_SEQ_MEDIAN) {
    const ruint32 curroc = (ruint32)(curidx >> 16);
    const ruint16 curseq = (ruint16)(curidx);

    if (curseq < R_RTP_SEQ_MEDIAN) {
      if (curseq + R_RTP_SEQ_MEDIAN < seq)
        return (((ruint64)curroc - 1) << 16) | seq;
    } else {
      if (curseq - R_RTP_SEQ_MEDIAN > seq)
        return (((ruint64)curroc + 1) << 16) | seq;
    }

    return (((ruint64)curroc) << 16) | seq;
  } else {
    return (ruint64)seq;
  }
}

ruint64
r_rtp_buffer_estimate_seq_idx (RRTPBuffer * rtp, ruint64 curidx)
{
  return r_rtp_estimate_seq_idx (r_rtp_buffer_get_seq (rtp), curidx);
}

