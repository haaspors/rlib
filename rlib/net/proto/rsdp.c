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
#include <rlib/net/proto/rsdp.h>

#include <rlib/rmem.h>

static void
r_sdp_timing_clear (RSdpTimingBuf * time)
{
  r_free (time->repeat); time->repeat = NULL;
}

static void
r_sdp_media_clear (RSdpMediaBuf * media)
{
  r_free (media->fmt); media->fmt = NULL;
  r_free (media->connection); media->connection = NULL;
  r_free (media->bandwidth); media->bandwidth = NULL;
  r_free (media->attrib); media->attrib = NULL;
}

static void
r_sdp_buf_clear (RSdpBuf * sdp)
{
  rsize i;

  r_free (sdp->email); sdp->email = NULL;
  r_free (sdp->phone); sdp->phone = NULL;
  r_free (sdp->bandwidth); sdp->bandwidth = NULL;
  for (i = 0; i < sdp->tcount; i++)
    r_sdp_timing_clear (&sdp->timing[i]);
  r_free (sdp->timing); sdp->timing = NULL;
  r_free (sdp->zone); sdp->zone = NULL;
  r_free (sdp->attrib); sdp->attrib = NULL;
  for (i = 0; i < sdp->mcount; i++)
    r_sdp_media_clear (&sdp->media[i]);
  r_free (sdp->media); sdp->media = NULL;
}

static RSdpResult
r_sdp_parse_next_valid_line (const RStrChunk * chunk, RStrChunk * line)
{
  static const rchar r_sdp_valid_types[] = "abceikmoprstuvz";
  RStrParse res;

  while ((res = r_str_chunk_next_line (chunk, line)) == R_STR_PARSE_OK) {
    if (line->size > 1 && line->str[1] == '=' &&
        r_str_idx_of_c (R_STR_WITH_SIZE_ARGS (r_sdp_valid_types), line->str[0]) >= 0)
      return R_SDP_OK;
  }

  return res == R_STR_PARSE_RANGE ? R_SDP_EOB : R_SDP_BAD_DATA;
}

static RSdpResult
r_sdp_message_line_parse_value (RStrChunk * value, const RStrChunk * line, rchar k)
{
  if (line->str != NULL && line->str[0] == k) {
    value->str = line->str + 2;
    value->size = line->size - 2;
    return R_SDP_OK;
  }

  value->str = NULL;
  value->size = 0;
  return R_SDP_MISSING_REQUIRED_LINE;
}

static RSdpResult
r_sdp_originator_parse (RSdpOriginatorBuf * orig, rchar * str, rsize size)
{
  rchar * p = str;
  rssize s;

  orig->username.str = p;
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  orig->username.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  orig->sess_id.str = p;
  orig->sess_id.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  orig->sess_version.str = p;
  orig->sess_version.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  orig->nettype.str = p;
  orig->nettype.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  orig->addrtype.str = p;
  orig->addrtype.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  orig->addr.str = p;
  orig->addr.size = size - RPOINTER_TO_SIZE (p - str);

  return R_SDP_OK;
}

static RSdpResult
r_sdp_connection_parse (RSdpConnectionBuf * conn, rchar * str, rsize size)
{
  rchar * p = str;
  rssize s;

  conn->nettype.str = p;
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  conn->nettype.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  conn->addrtype.str = p;
  conn->addrtype.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  conn->addr.str = p;
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), '/')) < 0) {
    conn->addr.size = size - RPOINTER_TO_SIZE (p - str);
    conn->ttl = 0;
    conn->addrcount = 1;
  } else {
    conn->addr.size = (rsize)s;

    p = (rchar *)r_str_lwstrip (p + s + 1);
    conn->ttl = r_str_to_int (p, NULL, 10, NULL);
    if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), '/')) < 0) {
      conn->addrcount = 1;
    } else {
      p = (rchar *)r_str_lwstrip (p + s + 1);
      conn->addrcount = r_str_to_int (p, NULL, 10, NULL);
    }
  }

  return R_SDP_OK;
}

static RSdpResult
r_sdp_bandwidth_parse (RStrKV * bandwidth, rchar * str, rsize size)
{
  return r_str_kv_parse (bandwidth, str, size, ":", NULL) == R_STR_PARSE_OK ?
    R_SDP_OK : R_SDP_BAD_DATA;
}

static RSdpResult
r_sdp_timing_parse (RSdpTimingBuf * timing, rchar * str, rsize size)
{
  rchar * p = str;
  rssize s;

  timing->rcount = 0;
  timing->repeat = NULL;

  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  timing->start.str = p;
  timing->start.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  timing->stop.str = p;
  timing->stop.size = size - RPOINTER_TO_SIZE (p - str);

  return R_SDP_OK;
}

static RSdpResult
r_sdp_attrib_parse (RStrKV * attrib, rchar * str, rsize size)
{
  r_memclear (attrib, sizeof (RStrKV));

  if (r_str_kv_parse (attrib, str, size, ":", NULL) != R_STR_PARSE_OK) {
    attrib->key.str = str;
    attrib->key.size = size;
  }

  return R_SDP_OK;
}

#define r_sdp_key_parse r_sdp_attrib_parse

static RSdpResult
r_sdp_media_desc_parse (RSdpMediaBuf * media, rchar * str, rsize size)
{
  rchar * p = str, * port;
  const rchar * next;
  rssize s;
  RStrParse res;

  r_memclear (media, sizeof (RSdpMediaBuf));

  /* type */
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  media->type.str = p;
  media->type.size = (rsize)s;

  port = (rchar *)r_str_lwstrip (p + s);
  if ((p = r_str_ptr_of_c (port, size - RPOINTER_TO_SIZE (port - str), ' ')) == NULL)
    return R_SDP_BAD_DATA;

  media->port = r_str_to_int (port, &next, 10, &res);
  if (res != R_STR_PARSE_OK)
    return R_SDP_BAD_DATA;
  if (next >= p || next[0] != '/') {
    media->portcount = 1;
  } else {
    media->portcount = r_str_to_int (next, NULL, 10, &res);
    if (res != R_STR_PARSE_OK)
      return R_SDP_BAD_DATA;
  }

  /* proto */
  p = (rchar *)r_str_lwstrip (p);
  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  media->proto.str = p;
  media->proto.size = (rsize)s;

  /* fmt */
  for (p = (rchar *)r_str_lwstrip (p + s);
      RPOINTER_TO_SIZE (p - str) < size;
      p = (rchar *)r_str_lwstrip (p + s)) {
    if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
      s = (rssize)size - RPOINTER_TO_SIZE (p - str);

    media->fmtcount++;
    media->fmt = r_realloc (media->fmt, media->fmtcount * sizeof (RStrChunk));
    media->fmt[media->fmtcount - 1].str = p;
    media->fmt[media->fmtcount - 1].size = (rsize)s;
  }

  return (media->fmtcount > 0) ? R_SDP_OK : R_SDP_BAD_DATA;
}

static RSdpResult
r_sdp_media_parse (RSdpMediaBuf * media, RStrChunk * chunk, RStrChunk * line)
{
  RSdpResult ret;
  RStrChunk tmp;

  if ((ret = r_sdp_parse_next_valid_line (chunk, line)) != R_SDP_OK)
    goto done;

  /* i= OPTIONAL */
  if (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&media->info, line, 'i') == R_SDP_OK) {
    if ((ret = r_sdp_parse_next_valid_line (chunk, line)) != R_SDP_OK)
      goto done;
  }

  /* c= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, line, 'c') == R_SDP_OK) {
    media->ccount++;
    media->connection = r_realloc (media->connection, media->ccount * sizeof (RSdpConnectionBuf));
    if ((ret = r_sdp_connection_parse (&media->connection[media->ccount - 1], tmp.str, tmp.size)) != R_SDP_OK)
      goto done;
    if ((ret = r_sdp_parse_next_valid_line (chunk, line)) != R_SDP_OK)
      goto done;
  }

  /* b= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, line, 'b') == R_SDP_OK) {
    media->bcount++;
    media->bandwidth = r_realloc (media->bandwidth, media->bcount * sizeof (RStrKV));
    if ((ret = r_sdp_bandwidth_parse (&media->bandwidth[media->bcount - 1], tmp.str, tmp.size)) != R_SDP_OK)
      goto done;
    if ((ret = r_sdp_parse_next_valid_line (chunk, line)) != R_SDP_OK)
      goto done;
  }

  /* k= OPTIONAL */
  if (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, line, 'k') == R_SDP_OK) {
    if ((ret = r_sdp_key_parse (&media->key, tmp.str, tmp.size)) != R_SDP_OK)
      goto done;
    if ((ret = r_sdp_parse_next_valid_line (chunk, line)) != R_SDP_OK)
      goto done;
  }

  /* a= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, line, 'a') == R_SDP_OK) {
    media->acount++;
    media->attrib = r_realloc (media->attrib, media->acount * sizeof (RStrKV));
    if ((ret = r_sdp_attrib_parse (&media->attrib[media->acount - 1], tmp.str, tmp.size)) != R_SDP_OK)
      goto done;
    if ((ret = r_sdp_parse_next_valid_line (chunk, line)) != R_SDP_OK)
      goto done;
  }

done:
  return ret;
}


RSdpResult
r_sdp_buffer_map (RSdpBuf * sdp, RBuffer * buf)
{
  RStrChunk chunk, line = R_STR_CHUNK_INIT, tmp;
  RSdpResult ret;

  if (R_UNLIKELY (sdp == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_SDP_INVAL;

  r_memclear (sdp, sizeof (RSdpBuf));
  if (R_UNLIKELY (!r_buffer_map (buf, &sdp->info, R_MEM_MAP_READ)))
    return R_SDP_MAP_FAILED;

  chunk.str = (rchar *)sdp->info.data;
  chunk.size = sdp->info.size;

  if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
    goto error;

  /* v= */
  if ((ret = r_sdp_message_line_parse_value (&sdp->ver, &line, 'v')) != R_SDP_OK)
    goto error;
  if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
    goto error;

  /* o= */
  if ((ret = r_sdp_message_line_parse_value (&tmp, &line, 'o')) != R_SDP_OK)
    goto error;
  if ((ret = r_sdp_originator_parse (&sdp->orig, tmp.str, tmp.size)) != R_SDP_OK)
    goto error;
  if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
    goto error;

  /* s= */
  if ((ret = r_sdp_message_line_parse_value (&sdp->session_name, &line, 's')) != R_SDP_OK)
    goto error;
  if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
    goto error;

  /* i= OPTIONAL */
  if (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&sdp->session_info, &line, 'i') == R_SDP_OK) {
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* u= OPTIONAL */
  if (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&sdp->uri, &line, 'u') == R_SDP_OK) {
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* e= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'e') == R_SDP_OK) {
    sdp->ecount++;
    sdp->email = r_realloc (sdp->email, sdp->ecount * sizeof (RStrChunk));
    sdp->email[sdp->ecount - 1] = tmp;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* p= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'p') == R_SDP_OK) {
    sdp->pcount++;
    sdp->phone = r_realloc (sdp->phone, sdp->pcount * sizeof (RStrChunk));
    sdp->phone[sdp->pcount - 1] = tmp;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* c= OPTIONAL */
  if (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'c') == R_SDP_OK) {
    if ((ret = r_sdp_connection_parse (&sdp->connection, tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* b= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'b') == R_SDP_OK) {
    sdp->bcount++;
    sdp->bandwidth = r_realloc (sdp->bandwidth, sdp->bcount * sizeof (RStrKV));
    if ((ret = r_sdp_bandwidth_parse (&sdp->bandwidth[sdp->bcount - 1], tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* t= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 't') == R_SDP_OK) {
    RSdpTimingBuf * timing;
    sdp->tcount++;
    sdp->timing = r_realloc (sdp->timing, sdp->tcount * sizeof (RSdpTimingBuf));
    timing = &sdp->timing[sdp->tcount - 1];
    if ((ret = r_sdp_timing_parse (timing, tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
    while (ret == R_SDP_OK &&
        r_sdp_message_line_parse_value (&tmp, &line, 't') == R_SDP_OK) {
      timing->rcount++;
      timing->repeat = r_realloc (timing->repeat, timing->rcount * sizeof (RStrChunk));
      timing->repeat[timing->rcount - 1] = tmp;
      if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
        goto error;
    }
  }

  /* z= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'z') == R_SDP_OK) {
    do {
      RStrKV * z;
      sdp->zone = r_realloc (sdp->zone, ++sdp->zcount * sizeof (RStrKV));
      z = &sdp->zone[sdp->zcount - 1];
      if (r_str_chunk_split (&tmp, " ", &z->key, z->val, NULL) != 2) {
        ret = R_SDP_BAD_DATA;
        goto error;
      }
    } while (tmp.size > 0);
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* k= OPTIONAL */
  if (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'k') == R_SDP_OK) {
    if ((ret = r_sdp_key_parse (&sdp->key, tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* a= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'a') == R_SDP_OK) {
    sdp->acount++;
    sdp->attrib = r_realloc (sdp->attrib, sdp->acount * sizeof (RStrKV));
    if ((ret = r_sdp_attrib_parse (&sdp->attrib[sdp->acount - 1], tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* m= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'm') == R_SDP_OK) {
    RSdpMediaBuf * media;
    sdp->mcount++;
    sdp->media = r_realloc (sdp->media, sdp->mcount * sizeof (RSdpMediaBuf));
    media = &sdp->media[sdp->mcount - 1];
    if ((ret = r_sdp_media_desc_parse (media, tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_media_parse (media, &chunk, &line)) > R_SDP_OK)
      goto error;
  }

  if (ret == R_SDP_EOB)
    return R_SDP_OK;
  else if (ret == R_SDP_OK)
    ret = R_SDP_MORE_DATA;
error:
  r_sdp_buffer_unmap (sdp, buf);
  return ret;
}

RSdpResult
r_sdp_buffer_unmap (RSdpBuf * sdp, RBuffer * buf)
{
  RSdpResult ret;

  if (R_UNLIKELY (sdp == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_SDP_INVAL;

  r_sdp_buf_clear (sdp);
  ret = r_buffer_unmap (buf, &sdp->info) ? R_SDP_OK : R_SDP_MAP_FAILED;
  r_memclear (sdp, sizeof (RSdpBuf));
  return ret;
}

RSdpResult
r_sdp_attrib_check (const RStrKV * attrib, rsize acount, const rchar * field, rssize fsize)
{
  rsize i, len;

  if (R_UNLIKELY (field == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (fsize == 0)) return R_SDP_INVAL;
  if (attrib == NULL) return (acount == 0) ? R_SDP_NOT_FOUND : R_SDP_INVAL;

  len = fsize > 0 ? (rsize)fsize : r_strlen (field);
  for (i = 0; i < acount; i++) {
    if (len == attrib[i].key.size &&
        r_strncmp (attrib[i].key.str, field, len) == 0)
      return R_SDP_OK;
  }

  return R_SDP_NOT_FOUND;
}

rchar *
r_sdp_attrib (const RStrKV * attrib, rsize acount, rsize start,
    const rchar * field, rssize fsize)
{
  rsize i, len;

  if (R_UNLIKELY (attrib == NULL)) return NULL;
  if (R_UNLIKELY (field == NULL)) return NULL;
  if (R_UNLIKELY (fsize == 0)) return NULL;

  len = fsize > 0 ? (rsize)fsize : r_strlen (field);
  for (i = start; i < acount; i++) {
    if (len == attrib[i].key.size &&
        r_strncmp (attrib[i].key.str, field, len) == 0)
      return r_str_kv_dup_value (&attrib[i]);
  }

  return NULL;
}

rssize
r_sdp_media_buf_find_fmt (const RSdpMediaBuf * media, const rchar * fmt, rssize size)
{
  rsize i;

  if (R_UNLIKELY (media == NULL)) return -1;
  if (R_UNLIKELY (fmt == NULL)) return -1;
  if (size < 0) size = (rssize)r_strlen (fmt);

  for (i = 0; i < media->fmtcount; i++) {
    if (r_str_chunk_cmp (&media->fmt[i], fmt, size) == 0)
      return (rssize)i;
  }
  return -1;
}

RSdpResult
r_sdp_media_buf_fmt_specific_attrib (const RSdpMediaBuf * media,
    const rchar * fmt, rssize fmtsize, const rchar * field, rssize fsize,
    RStrChunk * attrib)
{
  rssize i;

  if ((i = r_sdp_media_buf_find_fmt (media, fmt, fmtsize)) >= 0) {
    return r_sdp_media_buf_fmtidx_specific_attrib (media, (rsize)i, field, fsize,
        attrib);
  }

  return R_SDP_NOT_FOUND;
}

RSdpResult
r_sdp_media_buf_fmtidx_specific_attrib (const RSdpMediaBuf * media,
    rsize fmtidx, const rchar * field, rssize fsize, RStrChunk * attrib)
{
  rsize i;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (attrib == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (fmtidx >= media->fmtcount)) return R_SDP_INVAL;
  if (fsize < 0) fsize = (rssize)r_strlen (field);

  for (i = 0; i < media->acount; i++) {
    if (r_str_kv_is_key (&media->attrib[i], field, fsize)) {
      if (media->attrib[i].val.size > media->fmt[fmtidx].size &&
          r_strncmp (media->attrib[i].val.str, media->fmt[fmtidx].str, media->fmt[fmtidx].size) == 0) {
        attrib->str = (rchar *)r_str_lwstrip (media->attrib[i].val.str + media->fmt[fmtidx].size);
        attrib->size = media->attrib[i].val.size -
          RPOINTER_TO_SIZE (attrib->str - media->attrib[i].val.str);
        return R_SDP_OK;
      }
    }
  }

  r_memclear (attrib, sizeof (RStrChunk));
  return R_SDP_NOT_FOUND;
}

