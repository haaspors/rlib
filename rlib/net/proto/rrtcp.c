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

#define R_RTCP_MINSIZE                (2 * sizeof (ruint32))
#define r_rtcp_packet_end(packet) (((const ruint8 *)packet) + r_rtcp_packet_get_length (packet))

struct _RRTCPPacket {
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

rboolean
r_rtcp_packet_sr_get_sender_info (const RRTCPPacket * packet,
    RRTCPSenderInfo * srinfo)
{
  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_SR) {
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

  if (idx >= r_rtcp_packet_get_count (packet))
    return FALSE;

  ptr = packet->data + idx * 6 * sizeof (ruint32);
  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_RR) {
    ptr += sizeof (ruint32);
  } else if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_SR) {
    ptr += 6 * sizeof (ruint32);
  } else {
    return FALSE;
  }

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

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_RR)
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

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_APP)
    return RUINT32_TO_BE (*(const ruint32 *)&ptr[0]);

  return 0;
}

const rchar *
r_rtcp_packet_app_get_name (const RRTCPPacket * packet)
{
  const ruint8 * ptr = packet->data;

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_APP)
    return (const rchar *)&ptr[4];

  return NULL;
}

const ruint8 *
r_rtcp_packet_app_get_data (const RRTCPPacket * packet, ruint16 * size)
{
  const ruint8 * ptr = packet->data;

  if (r_rtcp_packet_get_type (packet) == R_RTCP_PT_APP) {
    if (size != NULL)
      *size = r_rtcp_packet_get_length (packet) - 3 * sizeof (ruint32);
    return &ptr[8];
  }

  return NULL;
}

