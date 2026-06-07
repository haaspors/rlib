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

#include "config.h"
#include <rlib/net/proto/rrtp.h>

#include <rlib/rstr.h>

#define R_RTCP_MINSIZE                (2 * sizeof (ruint32))
#define r_rtcp_packet_end(packet) (((const ruint8 *)packet) + r_rtcp_packet_get_length (packet))

struct RRTCPPacket {
#if R_BYTE_ORDER == R_LITTLE_ENDIAN
  ruint c:5;    /* count */
  ruint p:1;    /* padding */
  ruint v:2;    /* version */
#elif R_BYTE_ORDER == R_BIG_ENDIAN
  ruint v:2;    /* version */
  ruint p:1;    /* padding */
  ruint c:5;    /* count */
#else
#error "R_BYTE_ORDER not supported"
#endif
  ruint pt:8;   /* payload type */
  ruint len:16; /* length */
  ruint8 data[];
};


rboolean
r_rtcp_is_valid_hdr (rconstpointer buf, rsize size)
{
  const RRTCPPacket * p;

  if (R_UNLIKELY ((p = buf) == NULL)) return FALSE;
  if (R_UNLIKELY (size < sizeof (RRTCPPacket))) return FALSE;
  if (R_UNLIKELY (p->v != R_RTP_VERSION)) return FALSE;
  if (R_UNLIKELY (p->pt < 0x80)) return FALSE;

  /* SKIP SR/RR check to support reduced size RTCP */
  /* SKIP padding bit check if first packet of compound packet */
  return size >= r_rtcp_packet_get_length (p);
}

rboolean
r_rtcp_buffer_map (RRTCPBuffer * rtcp, RBuffer * buf, RMemMapFlags flags)
{
  rboolean ret;

  if (R_UNLIKELY (rtcp == NULL)) return FALSE;
  if (R_UNLIKELY (buf == NULL)) return FALSE;
  if (R_UNLIKELY (rtcp->buffer != NULL)) return FALSE;

  if ((ret = r_buffer_map (buf, &rtcp->info, flags))) {
    if ((ret = r_rtcp_is_valid_hdr (rtcp->info.data, rtcp->info.size)))
      rtcp->buffer = r_buffer_ref (buf);
    else
      r_buffer_unmap (buf, &rtcp->info);
  }

  return ret;
}

rboolean
r_rtcp_buffer_unmap (RRTCPBuffer * rtcp, RBuffer * buf)
{
  rboolean ret;

  if (R_UNLIKELY (rtcp == NULL)) return FALSE;
  if (R_UNLIKELY (buf != rtcp->buffer)) return FALSE;

  if ((ret = r_buffer_unmap (buf, &rtcp->info))) {
    r_buffer_unref (rtcp->buffer);
    rtcp->buffer = NULL;
  }

  return ret;
}

ruint
r_rtcp_buffer_get_packet_count (const RRTCPBuffer * rtcp)
{
  ruint ret = 0;
  const ruint8 * ptr, * end;

  for (ptr = rtcp->info.data, end = rtcp->info.data + rtcp->info.size;
      ptr < end && r_rtcp_is_valid_hdr (ptr, end - ptr);
      ptr += r_rtcp_packet_get_length ((const RRTCPPacket *)ptr)) {
    ret++;
  }

  return ret;
}

RRTCPPacket *
r_rtcp_buffer_get_next_packet (RRTCPBuffer * rtcp, const RRTCPPacket * p)
{
  RRTCPPacket * ret;

  if (p != NULL) {
    rsize offset = r_rtcp_packet_get_length (p);

    if (RPOINTER_TO_SIZE (p) >= RPOINTER_TO_SIZE (rtcp->info.data) &&
        RPOINTER_TO_SIZE (p) + offset < RPOINTER_TO_SIZE (rtcp->info.data) + rtcp->info.size) {
      offset += RPOINTER_TO_SIZE (p) - RPOINTER_TO_SIZE (rtcp->info.data);
      ret = (RRTCPPacket *)(rtcp->info.data + offset);
    } else {
      ret = NULL;
    }
  } else {
    ret = (RRTCPPacket *)rtcp->info.data;
  }

  return ret;
}

rboolean
r_rtcp_packet_has_padding (const RRTCPPacket * p)
{
  return p->p ? TRUE : FALSE;
}

ruint8
r_rtcp_packet_get_count (const RRTCPPacket * p)
{
  return p->c;
}

RRTCPPacketType
r_rtcp_packet_get_type (const RRTCPPacket * p)
{
  return (RRTCPPacketType)p->pt;
}

ruint
r_rtcp_packet_get_length (const RRTCPPacket * p)
{
  return ((ruint)RUINT16_FROM_BE (p->len) + 1) * sizeof (ruint32);
}

ruint32
r_rtcp_packet_get_ssrc (const RRTCPPacket * packet)
{
  const ruint8 * ptr = packet->data;
  if (r_rtcp_packet_get_length (packet) < 2 * sizeof (ruint32))
    return 0;
  return RUINT32_TO_BE (*(const ruint32 *)&ptr[0]);
}

rboolean
r_rtcp_packet_sr_get_sender_info (const RRTCPPacket * packet,
    RRTCPSenderInfo * srinfo)
{
  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_SR &&
      r_rtcp_packet_get_length (packet) >= R_RTCP_MINSIZE + 5 * sizeof (ruint32)) {
    const ruint8 * ptr = packet->data;

    srinfo->ssrc    = RUINT32_TO_BE (*(const ruint32 *)&ptr[0 * sizeof (ruint32)]);
    srinfo->ntptime = RUINT64_TO_BE (*(const ruint64 *)&ptr[1 * sizeof (ruint32)]);
    srinfo->rtptime = RUINT32_TO_BE (*(const ruint32 *)&ptr[3 * sizeof (ruint32)]);
    srinfo->packets = RUINT32_TO_BE (*(const ruint32 *)&ptr[4 * sizeof (ruint32)]);
    srinfo->bytes   = RUINT32_TO_BE (*(const ruint32 *)&ptr[5 * sizeof (ruint32)]);
    return TRUE;
  }

  return FALSE;
}

rboolean
r_rtcp_packet_sr_get_report_block (const RRTCPPacket * packet, ruint8 idx,
    RRTCPReportBlock * rb)
{
  const ruint8 * ptr;
  rsize header;

  if (idx >= r_rtcp_packet_get_count (packet))
    return FALSE;

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_RR) {
    header = 2 * sizeof (ruint32);
  } else if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_SR) {
    header = 7 * sizeof (ruint32);
  } else {
    return FALSE;
  }

  if (r_rtcp_packet_get_length (packet) <
      header + ((rsize)idx + 1) * 6 * sizeof (ruint32))
    return FALSE;

  ptr = (const ruint8 *)packet + header + (rsize)idx * 6 * sizeof (ruint32);

  rb->ssrc          = RUINT32_TO_BE (*(const ruint32 *)&ptr[0 * sizeof (ruint32)]);
  rb->packetslost   = RUINT32_TO_BE (*(const ruint32 *)&ptr[1 * sizeof (ruint32)]);
  rb->exthighestseq = RUINT32_TO_BE (*(const ruint32 *)&ptr[2 * sizeof (ruint32)]);
  rb->jitter        = RUINT32_TO_BE (*(const ruint32 *)&ptr[3 * sizeof (ruint32)]);
  rb->lsr           = RUINT32_TO_BE (*(const ruint32 *)&ptr[4 * sizeof (ruint32)]);
  rb->dlsr          = RUINT32_TO_BE (*(const ruint32 *)&ptr[5 * sizeof (ruint32)]);

  rb->fractionlost = rb->packetslost >> 24;
  if (rb->packetslost & 0x00800000)
    rb->packetslost |= 0xff000000;
  else
    rb->packetslost &= 0x00ffffff;

  return TRUE;
}

ruint32
r_rtcp_packet_rr_get_ssrc (const RRTCPPacket * packet)
{
  const ruint8 * ptr = packet->data;

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_RR &&
      r_rtcp_packet_get_length (packet) >= 2 * sizeof (ruint32))
    return RUINT32_TO_BE (*(const ruint32 *)&ptr[0]);

  return 0;
}

RRTCPSDESChunk *
r_rtcp_packet_sdes_get_next_chunk (RRTCPPacket * packet,
    RRTCPSDESChunk * chunk)
{
  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_SDES) {
    RRTCPSDESItem item = R_RTCP_SDES_ITEM_INIT;
    RRTCPParseResult res;

    if (chunk == NULL)
      return (RRTCPSDESChunk *)packet->data;

    do {
      res = r_rtcp_packet_sdes_chunk_get_next_item (packet, chunk, &item);
    } while (res == R_RTCP_PARSE_OK);

    if (res == R_RTCP_PARSE_ZERO &&
        item.data + item.len < r_rtcp_packet_end (packet))
      return (RRTCPSDESChunk *)(item.data + item.len);
  }

  return NULL;
}

ruint32
r_rtcp_packet_sdes_chunk_get_ssrc (const RRTCPPacket * packet,
    const RRTCPSDESChunk * chunk)
{
  const ruint8 * ptr = (const ruint8 *)chunk;

  if (RPOINTER_TO_SIZE (chunk) + sizeof (ruint32) <=
      RPOINTER_TO_SIZE (r_rtcp_packet_end (packet)))
    return RUINT32_TO_BE (*(const ruint32 *)&ptr[0]);

  return 0;
}

RRTCPParseResult
r_rtcp_packet_sdes_chunk_get_next_item (const RRTCPPacket * packet,
    RRTCPSDESChunk * chunk, RRTCPSDESItem * item)
{
  const ruint8 * end = r_rtcp_packet_end (packet);
  ruint8 * ptr;

  if (item->type == R_RTCP_SDES_UNKNOWN)
    ptr = (ruint8 *)chunk + sizeof (ruint32);
  else
    ptr = item->data + item->len;

  if (ptr >= end)
    return R_RTCP_PARSE_OVERFLOW;

  item->type = *ptr++;
  if (item->type == R_RTCP_SDES_ZERO) {
    const ruint8 * zend;
    item->len = 0;
    item->data = ptr;

    zend = ((item->data - packet->data + 0x03) & ~0x03) + packet->data;
    if (zend > end)
      return R_RTCP_PARSE_OVERFLOW;
    for (; ptr < zend; ptr++) {
      if (*ptr != 0)
        return R_RTCP_PARSE_UNEXPECTED;
      item->len++;
    }
    return R_RTCP_PARSE_ZERO;
  } else if (item->type < R_RTCP_SDES_MAX) {
    item->len = *ptr++;
    item->data = ptr;
    if (R_UNLIKELY (item->data + item->len > end))
      return R_RTCP_PARSE_OVERFLOW;
    return R_RTCP_PARSE_OK;
  }

  return R_RTCP_PARSE_UNEXPECTED;
}

ruint32
r_rtcp_packet_bye_get_ssrc (const RRTCPPacket * packet, ruint8 idx)
{
  const ruint8 * ptr = packet->data;

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_BYE &&
      idx < r_rtcp_packet_bye_get_ssrc_count (packet)) {
    return RUINT32_TO_BE (((const ruint32 *)&ptr[0])[idx]);
  }

  return 0;
}

RRTCPParseResult
r_rtcp_packet_bye_get_reason (const RRTCPPacket * packet,
    rchar * reason, rsize len, ruint8 * out)
{
  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_BYE) {
    if (RUINT16_FROM_BE (packet->len) > packet->c) { /* quick check */
      const ruint8 * ptr = packet->data + packet->c * sizeof (ruint32);

      /* The reason-length byte must itself lie within the packet before
       * we dereference it. */
      if (ptr >= r_rtcp_packet_end (packet))
        return R_RTCP_PARSE_OVERFLOW;

      if (out != NULL)
        *out = *ptr;

      if (ptr + 1 + *ptr > r_rtcp_packet_end (packet))
        return R_RTCP_PARSE_OVERFLOW;
      if (len <= *ptr)
        return R_RTCP_PARSE_BUF_TOO_SMALL;

      r_memcpy (reason, ptr + 1, *ptr);
      reason[*ptr] = 0;

      return R_RTCP_PARSE_OK;
    }

    if (out != NULL)
      *out = 0;
    return R_RTCP_PARSE_ZERO;
  }

  return R_RTCP_PARSE_WRONG_PT;
}

ruint32
r_rtcp_packet_app_get_ssrc (const RRTCPPacket * packet)
{
  const ruint8 * ptr = packet->data;

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_APP &&
      r_rtcp_packet_get_length (packet) >= 2 * sizeof (ruint32))
    return RUINT32_TO_BE (*(const ruint32 *)&ptr[0]);

  return 0;
}

const rchar *
r_rtcp_packet_app_get_name (const RRTCPPacket * packet)
{
  const ruint8 * ptr = packet->data;

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_APP &&
      r_rtcp_packet_get_length (packet) >= 3 * sizeof (ruint32))
    return (const rchar *)&ptr[4];

  return NULL;
}

const ruint8 *
r_rtcp_packet_app_get_data (const RRTCPPacket * packet, ruint16 * size)
{
  const ruint8 * ptr = packet->data;

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_APP) {
    /* APP = 2 header words + SSRC + name = 3 words before the data;
     * a shorter (malformed) packet would underflow the size. */
    if (r_rtcp_packet_get_length (packet) < 3 * sizeof (ruint32))
      return NULL;
    if (size != NULL)
      *size = (ruint16)(r_rtcp_packet_get_length (packet) - 3 * sizeof (ruint32));
    return &ptr[8];
  }

  return NULL;
}


/* ------------------------------------------------------------------------- *
 * RTCP serialization
 *
 * Packets are appended to a plain RBuffer (one RMem segment each), producing
 * a compound buffer with the same on-wire layout the parser above reads back.
 * ------------------------------------------------------------------------- */

#define R_RTCP_REPORT_BLOCK_SIZE  (6 * sizeof (ruint32))

/* Append [v=2 p=0 c=count | pt | len | body]; bodylen is a whole word count. */
static rboolean
r_rtcp_append (RBuffer * buf, ruint8 pt, ruint8 count,
    const ruint8 * body, rsize bodylen)
{
  RRTCPPacket * h;
  RMem * mem;
  ruint8 * pkt;
  rsize total, words;
  rboolean res;

  if (R_UNLIKELY (buf == NULL || (bodylen & 0x3) != 0))
    return FALSE;
  total = sizeof (ruint32) + bodylen;
  words = total / sizeof (ruint32);
  if (R_UNLIKELY (words == 0 || words - 1 > 0xffff))
    return FALSE;
  if (R_UNLIKELY ((pkt = r_malloc0 (total)) == NULL))
    return FALSE;

  h = (RRTCPPacket *)pkt;
  h->v = R_RTP_VERSION;
  h->p = 0;
  h->c = count;
  h->pt = pt;
  h->len = RUINT16_TO_BE ((ruint16)(words - 1));
  if (bodylen > 0 && body != NULL)
    r_memcpy (pkt + sizeof (ruint32), body, bodylen);

  if (R_UNLIKELY ((mem = r_mem_new_take (R_MEM_FLAG_NONE, pkt, total, total, 0)) == NULL)) {
    r_free (pkt);
    return FALSE;
  }
  res = r_buffer_mem_append (buf, mem);
  r_mem_unref (mem);
  return res;
}

static void
r_rtcp_write_report_block (ruint8 * p, const RRTCPReportBlock * rb)
{
  r_store_be32 (&p[0],  rb->ssrc);
  r_store_be32 (&p[4],  ((ruint32)rb->fractionlost << 24) |
      ((ruint32)rb->packetslost & 0x00ffffff));
  r_store_be32 (&p[8],  rb->exthighestseq);
  r_store_be32 (&p[12], rb->jitter);
  r_store_be32 (&p[16], rb->lsr);
  r_store_be32 (&p[20], rb->dlsr);
}

rboolean
r_rtcp_buffer_add_sr (RBuffer * buf, const RRTCPSenderInfo * srinfo,
    const RRTCPReportBlock * rb, ruint8 nrb)
{
  ruint8 * body;
  rsize bodylen;
  rboolean res;
  ruint8 i;

  if (R_UNLIKELY (buf == NULL || srinfo == NULL || nrb > 0x1f))
    return FALSE;
  if (R_UNLIKELY (nrb > 0 && rb == NULL))
    return FALSE;

  /* sender info: ssrc + ntp(2 words) + rtptime + packets + bytes = 6 words */
  bodylen = 6 * sizeof (ruint32) + (rsize)nrb * R_RTCP_REPORT_BLOCK_SIZE;
  if (R_UNLIKELY ((body = r_malloc0 (bodylen)) == NULL))
    return FALSE;

  r_store_be32 (&body[0],  srinfo->ssrc);
  r_store_be64 (&body[4],  srinfo->ntptime);
  r_store_be32 (&body[12], srinfo->rtptime);
  r_store_be32 (&body[16], srinfo->packets);
  r_store_be32 (&body[20], srinfo->bytes);
  for (i = 0; i < nrb; i++)
    r_rtcp_write_report_block (&body[24 + (rsize)i * R_RTCP_REPORT_BLOCK_SIZE], &rb[i]);

  res = r_rtcp_append (buf, R_RTCP_PT_SR, nrb, body, bodylen);
  r_free (body);
  return res;
}

rboolean
r_rtcp_buffer_add_rr (RBuffer * buf, ruint32 ssrc,
    const RRTCPReportBlock * rb, ruint8 nrb)
{
  ruint8 * body;
  rsize bodylen;
  rboolean res;
  ruint8 i;

  if (R_UNLIKELY (buf == NULL || nrb > 0x1f))
    return FALSE;
  if (R_UNLIKELY (nrb > 0 && rb == NULL))
    return FALSE;

  bodylen = sizeof (ruint32) + (rsize)nrb * R_RTCP_REPORT_BLOCK_SIZE;
  if (R_UNLIKELY ((body = r_malloc0 (bodylen)) == NULL))
    return FALSE;

  r_store_be32 (&body[0], ssrc);
  for (i = 0; i < nrb; i++)
    r_rtcp_write_report_block (&body[4 + (rsize)i * R_RTCP_REPORT_BLOCK_SIZE], &rb[i]);

  res = r_rtcp_append (buf, R_RTCP_PT_RR, nrb, body, bodylen);
  r_free (body);
  return res;
}

rboolean
r_rtcp_buffer_add_sdes (RBuffer * buf, ruint32 ssrc,
    const RRTCPSDESItem * items, ruint8 nitems)
{
  ruint8 * body;
  rsize bodylen, itemsbytes = 0, off;
  rboolean res;
  ruint8 i;

  if (R_UNLIKELY (buf == NULL))
    return FALSE;
  if (R_UNLIKELY (nitems > 0 && items == NULL))
    return FALSE;
  for (i = 0; i < nitems; i++) {
    if (R_UNLIKELY (items[i].type < R_RTCP_SDES_CNAME ||
            items[i].type >= R_RTCP_SDES_MAX))
      return FALSE;
    if (R_UNLIKELY (items[i].len > 0 && items[i].data == NULL))
      return FALSE;
    itemsbytes += 2u + items[i].len;
  }

  /* chunk = ssrc + items + >=1 null terminator, padded to a 32-bit boundary. */
  bodylen = sizeof (ruint32) + (((itemsbytes + 1) + 3) & ~(rsize)3);
  if (R_UNLIKELY ((body = r_malloc0 (bodylen)) == NULL))
    return FALSE;

  r_store_be32 (&body[0], ssrc);
  off = sizeof (ruint32);
  for (i = 0; i < nitems; i++) {
    body[off++] = (ruint8) items[i].type;
    body[off++] = items[i].len;
    if (items[i].len > 0) {
      r_memcpy (&body[off], items[i].data, items[i].len);
      off += items[i].len;
    }
  }
  /* The trailing bytes (terminator + padding) are already zero. */

  res = r_rtcp_append (buf, R_RTCP_PT_SDES, 1, body, bodylen);
  r_free (body);
  return res;
}

rboolean
r_rtcp_buffer_add_bye (RBuffer * buf, const ruint32 * ssrcs, ruint8 nssrc,
    const rchar * reason)
{
  ruint8 * body;
  rsize bodylen, rlen = 0, off;
  rboolean res;
  ruint8 i;

  if (R_UNLIKELY (buf == NULL || nssrc > 0x1f))
    return FALSE;
  if (R_UNLIKELY (nssrc > 0 && ssrcs == NULL))
    return FALSE;
  if (reason != NULL) {
    rlen = r_strlen (reason);
    if (R_UNLIKELY (rlen > 0xff))
      return FALSE;
  }

  bodylen = (rsize)nssrc * sizeof (ruint32);
  if (reason != NULL)               /* length octet + text, padded to 32 bits */
    bodylen += ((1 + rlen) + 3) & ~(rsize)3;
  if (R_UNLIKELY ((body = r_malloc0 (bodylen)) == NULL))
    return FALSE;

  for (i = 0; i < nssrc; i++)
    r_store_be32 (&body[(rsize)i * sizeof (ruint32)], ssrcs[i]);
  if (reason != NULL) {
    off = (rsize)nssrc * sizeof (ruint32);
    body[off++] = (ruint8) rlen;
    if (rlen > 0)
      r_memcpy (&body[off], reason, rlen);
  }

  res = r_rtcp_append (buf, R_RTCP_PT_BYE, nssrc, body, bodylen);
  r_free (body);
  return res;
}

rboolean
r_rtcp_buffer_add_app (RBuffer * buf, ruint8 subtype, ruint32 ssrc,
    const rchar name[4], const ruint8 * data, ruint16 size)
{
  ruint8 * body;
  rsize bodylen;
  rboolean res;

  if (R_UNLIKELY (buf == NULL || subtype > 0x1f || name == NULL))
    return FALSE;
  if (R_UNLIKELY ((size & 0x3) != 0))   /* application data is 32-bit aligned */
    return FALSE;
  if (R_UNLIKELY (size > 0 && data == NULL))
    return FALSE;

  bodylen = 2 * sizeof (ruint32) + size;   /* ssrc + 4-octet name + data */
  if (R_UNLIKELY ((body = r_malloc0 (bodylen)) == NULL))
    return FALSE;

  r_store_be32 (&body[0], ssrc);
  r_memcpy (&body[sizeof (ruint32)], name, 4);
  if (size > 0)
    r_memcpy (&body[2 * sizeof (ruint32)], data, size);

  res = r_rtcp_append (buf, R_RTCP_PT_APP, subtype, body, bodylen);
  r_free (body);
  return res;
}
