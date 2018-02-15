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

#include <rlib/rassert.h>
#include <rlib/rmem.h>
#include <rlib/rptrarray.h>
#include <rlib/rstring.h>

typedef struct {
  rchar * nettype;
  rchar * addrtype;
  rchar * addr;
  ruint ttl;
  ruint addrcount;
} RSdpConn;

typedef struct {
  ruint64 start, stop;
  RPtrArray * repeat;
} RSdpTime;

typedef struct {
  RStrKV kv;
  rchar data[0];
} RSdpAttrib;

struct _RSdpMedia {
  RRef ref;

  rchar * type;
  ruint port;
  ruint portcount;
  rchar * proto;

  RPtrArray * fmt;

  rchar * info;
  RPtrArray * conn;
  RPtrArray * bw;
  RSdpAttrib * key;
  RPtrArray * attrib;
};

struct _RSdpMsg {
  RRef ref;

  rboolean jsep;
  RSdpAttrib * bundle;

  rchar * ver;
  rchar * username;
  rchar * sid;
  rchar * sver;
  rchar * origin_nt;
  rchar * origin_at;
  rchar * origin_addr;
  rchar * name;
  rchar * info;
  RUri * uri;
  RPtrArray * email;
  RPtrArray * phone;
  RSdpConn conn;
  RPtrArray * bw;
  RPtrArray * time;
  RPtrArray * zone;
  RSdpAttrib * key;
  RPtrArray * attrib;
  RPtrArray * media;
};

static void
r_sdp_msg_free (RSdpMsg * msg)
{
  r_free (msg->ver);
  r_free (msg->username);
  r_free (msg->sid);
  r_free (msg->sver);
  r_free (msg->origin_nt);
  r_free (msg->origin_at);
  r_free (msg->origin_addr);
  r_free (msg->name);
  r_free (msg->info);
  if (msg->uri != NULL)
    r_uri_unref (msg->uri);
  r_ptr_array_unref (msg->email);
  r_ptr_array_unref (msg->phone);
  r_free (msg->conn.nettype);
  r_free (msg->conn.addrtype);
  r_free (msg->conn.addr);
  r_ptr_array_unref (msg->bw);
  r_ptr_array_unref (msg->time);
  r_ptr_array_unref (msg->zone);
  r_free (msg->key);
  r_ptr_array_unref (msg->attrib);
  r_ptr_array_unref (msg->media);
  r_free (msg);
}

RSdpMsg *
r_sdp_msg_new (void)
{
  RSdpMsg * ret;

  if ((ret = r_mem_new0 (RSdpMsg)) != NULL) {
    r_ref_init (ret, r_sdp_msg_free);

    ret->email = r_ptr_array_new ();
    ret->phone = r_ptr_array_new ();
    ret->bw = r_ptr_array_new ();
    ret->time = r_ptr_array_new ();
    ret->zone = r_ptr_array_new ();
    ret->attrib = r_ptr_array_new ();
    ret->media = r_ptr_array_new ();
  }

  return ret;
}

RSdpMsg *
r_sdp_msg_new_jsep (ruint64 sessid, ruint sessver)
{
  RSdpMsg * ret;

  if ((ret = r_sdp_msg_new ()) != NULL) {
    ret->jsep = TRUE;
    ret->sid = r_strprintf ("%"RUINT64_FMT, sessid);
    ret->sver = r_strprintf ("%u", sessver);
    r_sdp_msg_add_time (ret, 0, 0);
  }

  return ret;
}

RSdpMsg *
r_sdp_msg_new_from_sdp_buffer (const RSdpBuf * buf)
{
  RSdpMsg * ret;

  if ((ret = r_sdp_msg_new ()) != NULL) {
    RUri * uri;
    rsize i, j;

    r_sdp_msg_set_version (ret, buf->ver.str, buf->ver.size);
    r_sdp_msg_set_originator (ret,
        buf->orig.username.str, buf->orig.username.size,
        buf->orig.sess_id.str, buf->orig.sess_id.size,
        buf->orig.sess_version.str, buf->orig.sess_version.size,
        buf->orig.nettype.str, buf->orig.nettype.size,
        buf->orig.addrtype.str, buf->orig.addrtype.size,
        buf->orig.addr.str, buf->orig.addr.size);
    r_sdp_msg_set_session_name (ret,
        buf->session_name.str, buf->session_name.size);
    r_sdp_msg_set_session_info (ret,
        buf->session_info.str, buf->session_info.size);
    if (buf->uri.str != NULL &&
        (uri = r_uri_new_escaped (buf->uri.str, buf->uri.size)) != NULL) {
      r_sdp_msg_set_uri (ret, uri);
      r_uri_unref (uri);
    }
    for (i = 0; i < buf->ecount; i++)
      r_sdp_msg_add_email (ret, buf->email[i].str, buf->email[i].size);
    for (i = 0; i < buf->pcount; i++)
      r_sdp_msg_add_phone (ret, buf->phone[i].str, buf->phone[i].size);
    if (buf->conn.addrcount > 0) {
      r_sdp_msg_set_connection_full (ret,
          buf->conn.nettype.str, buf->conn.nettype.size,
          buf->conn.addrtype.str, buf->conn.addrtype.size,
          buf->conn.addr.str, buf->conn.addr.size,
          buf->conn.ttl, buf->conn.addrcount);
    }
    for (i = 0; i < buf->bcount; i++) {
      r_sdp_msg_add_bandwidth (ret, buf->bw[i].key.str, buf->bw[i].key.size,
          r_sdp_buf_bandwidth_kbps (buf, i));
    }
    for (i = 0; i < buf->tcount; i++) {
      r_sdp_msg_add_time (ret,
          r_str_to_uint (buf->time[i].start.str, NULL, 10, NULL),
          r_str_to_uint (buf->time[i].stop.str, NULL, 10, NULL));
      /* FIXME: Repeat lines */
    }
    for (i = 0; i < buf->zcount; i++) {
      /* FIXME: r_sdp_msg_add_time_zone (ret, ); */
    }
    r_sdp_msg_set_key (ret,
        buf->key.key.str, buf->key.key.size,
        buf->key.val.str, buf->key.val.size);
    for (i = 0; i < buf->acount; i++) {
      r_sdp_msg_add_attribute (ret,
          buf->attrib[i].key.str, buf->attrib[i].key.size,
          buf->attrib[i].val.str, buf->attrib[i].val.size);
    }
    for (j = 0; j < buf->mcount; j++) {
      RSdpMedia * media;

      if (R_UNLIKELY ((media = r_sdp_media_new_full (
                buf->media[j].type.str, buf->media[j].type.size,
                buf->media[j].port, buf->media[j].portcount,
                buf->media[j].proto.str, buf->media[j].proto.size)) == NULL))
        continue;
      r_sdp_msg_add_media (ret, media);

      for (i = 0; i < buf->media[j].fmtcount; i++)
        r_ptr_array_add (media->fmt, r_sdp_buf_media_fmt (buf, j, i), r_free);
      r_sdp_media_set_media_info (media,
          buf->media[j].info.str, buf->media[j].info.size);
      for (i = 0; i < buf->media[j].ccount; i++) {
        r_sdp_media_add_connection_full (media,
            buf->media[j].conn[i].nettype.str,  buf->media[j].conn[i].nettype.size,
            buf->media[j].conn[i].addrtype.str, buf->media[j].conn[i].addrtype.size,
            buf->media[j].conn[i].addr.str,     buf->media[j].conn[i].addr.size,
            r_sdp_buf_media_conn_ttl (buf, j, i),
            r_sdp_buf_media_conn_addrcount (buf, j, i));
      }
      for (i = 0; i < buf->media[j].bcount; i++) {
        r_sdp_media_add_bandwidth (media,
            buf->media[j].bw[i].key.str, buf->media[j].bw[i].key.size,
            r_sdp_buf_media_bandwidth_kbps (buf, j, i));
      }
      r_sdp_media_set_key (media,
          buf->media[j].key.key.str, buf->media[j].key.key.size,
          buf->media[j].key.val.str, buf->media[j].key.val.size);
      for (i = 0; i < buf->media[j].acount; i++) {
        r_sdp_media_add_attribute (media,
            buf->media[j].attrib[i].key.str, buf->media[j].attrib[i].key.size,
            buf->media[j].attrib[i].val.str, buf->media[j].attrib[i].val.size);
      }
      r_sdp_media_unref (media);
    }
  }

  return ret;
}

static void
_r_sdp_msg_add_e_line (rpointer data, rpointer user)
{
  r_string_append_printf (user, "e=%s\r\n", (rchar *)data);
}

static void
_r_sdp_msg_add_p_line (rpointer data, rpointer user)
{
  r_string_append_printf (user, "p=%s\r\n", (rchar *)data);
}

static void
_r_sdp_msg_add_netaddr (RString * str, const rchar * nettype,
    const rchar * addrtype, const rchar * addr, const rchar * def)
{
  if (addr != NULL)
    r_string_append_printf (str, "%s %s %s", nettype, addrtype, addr);
  else
    r_string_append (str, def);
}

static void
_r_sdp_msg_add_c_line (rpointer data, rpointer user)
{
  const RSdpConn * c = data;

  r_string_append (user, "c=");
  _r_sdp_msg_add_netaddr (user, c->nettype, c->addrtype, c->addr,
      "IN IP4 0.0.0.0");
  if (c->addr != NULL && c->addrtype != NULL) {
    if (c->ttl > 0 && r_str_equals (c->addrtype, "IP4"))
      r_string_append_printf (user, "/%u", c->ttl);
    if (c->addrcount > 1)
      r_string_append_printf (user, "/%u", c->addrcount);
  }
  r_string_append (user, "\r\n");
}

static void
_r_sdp_msg_add_b_line (rpointer data, rpointer user)
{
  r_string_append_printf (user, "b=%s\r\n", ((const RSdpAttrib *)data)->data);
}

static void
_r_sdp_msg_add_k_line (rpointer data, rpointer user)
{
  r_string_append_printf (user, "k=%s\r\n", ((const RSdpAttrib *)data)->data);
}

static void
_r_sdp_msg_add_r_line (rpointer data, rpointer user)
{
  /* TODO */
  (void) data;
  r_string_append (user, "r=??\r\n");
}

static void
_r_sdp_msg_add_t_line (rpointer data, rpointer user)
{
  const RSdpTime * t = data;
  r_string_append_printf (user, "t=%"RUINT64_FMT" %"RUINT64_FMT"\r\n",
      t->start, t->stop);
  r_ptr_array_foreach (t->repeat, _r_sdp_msg_add_r_line, user);
}

static void
_r_sdp_msg_add_z_line (rpointer data, rpointer user)
{
  /* TODO */
  (void) data;
  r_string_append (user, "z=??\r\n");
}

static void
_r_sdp_msg_add_a_line (rpointer data, rpointer user)
{
  r_string_append_printf (user, "a=%s\r\n", ((const RSdpAttrib *)data)->data);
}

static void
_r_sdp_media_add_fmt (rpointer data, rpointer user)
{
  r_string_append_printf (user, " %s", (rchar *)data);
}

static void
_r_sdp_msg_add_m_line (rpointer data, rpointer user)
{
  const RSdpMedia * m = data;
  if (m->portcount <= 1)
    r_string_append_printf (user, "m=%s %u %s", m->type, m->port, m->proto);
  else
    r_string_append_printf (user, "m=%s %u/%u %s", m->type, m->port, m->portcount, m->proto);
  r_ptr_array_foreach (m->fmt, _r_sdp_media_add_fmt, user);
  r_string_append (user, "\r\n");

  /* i= */
  if (m->info != NULL)
    r_string_append_printf (user, "i=%s\r\n", m->info);

  /* c= */
  r_ptr_array_foreach (m->conn, _r_sdp_msg_add_c_line, user);
  /* b= */
  r_ptr_array_foreach (m->bw, _r_sdp_msg_add_b_line, user);
  /* k= */
  if (m->key != NULL)
    _r_sdp_msg_add_k_line (m->key, user);
  /* a= */
  r_ptr_array_foreach (m->attrib, _r_sdp_msg_add_a_line, user);
}

RBuffer *
r_sdp_msg_to_buffer (const RSdpMsg * msg)
{
  RBuffer * ret;

  if ((ret = r_buffer_new ()) != NULL) {
    RString * str;

    if ((str = r_string_new_sized (4096)) != NULL) {
      rsize alloc, size;
      rpointer data;
      RMem * mem;

      /* v= */
      if (msg->ver != NULL)
        r_string_append_printf (str, "v=%s\r\n", msg->ver);
      else
        r_string_append (str, "v=0\r\n");

      /* o= */
      r_string_append_printf (str, "o=%s %s %s ",
          (msg->username != NULL) ? msg->username : "-",
          (msg->sid != NULL)      ? msg->sid      : "0", /* FIXME: default? */
          (msg->sver != NULL)     ? msg->sver     : "0");
      _r_sdp_msg_add_netaddr (str, msg->origin_nt, msg->origin_at, msg->origin_addr,
          "IN IP4 127.0.0.1");
      r_string_append (str, "\r\n");

      /* s= */
      if (msg->name != NULL)
        r_string_append_printf (str, "s=%s\r\n", msg->name);
      else
        r_string_append (str, "s=-\r\n");

      /* i= */
      if (msg->info != NULL)
        r_string_append_printf (str, "i=%s\r\n", msg->info);

      /* u= */
      if (msg->uri != NULL) {
        rchar * u;
        if ((u = r_uri_get_escaped (msg->uri)) != NULL) {
          r_string_append_printf (str, "u=%s\r\n", u);
          r_free (u);
        }
      }

      /* e= */
      r_ptr_array_foreach (msg->email, _r_sdp_msg_add_e_line, str);
      /* p= */
      r_ptr_array_foreach (msg->phone, _r_sdp_msg_add_p_line, str);
      /* c= */
      if (msg->conn.addrcount > 0)
        _r_sdp_msg_add_c_line ((rpointer)&msg->conn, str);
      /* b= */
      r_ptr_array_foreach (msg->bw, _r_sdp_msg_add_b_line, str);
      /* t= */
      r_ptr_array_foreach (msg->time, _r_sdp_msg_add_t_line, str);
      /* z= */
      r_ptr_array_foreach (msg->zone, _r_sdp_msg_add_z_line, str);
      /* k= */
      if (msg->key != NULL)
        _r_sdp_msg_add_k_line (msg->key, str);
      /* a= */
      r_ptr_array_foreach (msg->attrib, _r_sdp_msg_add_a_line, str);
      /* m= */
      r_ptr_array_foreach (msg->media, _r_sdp_msg_add_m_line, str);

      size = r_string_length (str);
      alloc = r_string_alloc_size (str);
      data = r_string_free_keep (str);
      if ((mem = r_mem_new_take (R_MEM_FLAG_NONE, data, alloc, size, 0)) == NULL ||
          !r_buffer_mem_append (ret, mem)) {
        r_buffer_unref (ret);
        ret = NULL;
      }
      if (mem != NULL)
        r_mem_unref (mem);
    } else {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

RSdpResult
r_sdp_msg_set_version (RSdpMsg * msg, const rchar * ver, rssize size)
{
  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;

  r_free (msg->ver);
  msg->ver = r_strdup_size (ver, size);
  return R_SDP_OK;
}

RSdpResult
r_sdp_msg_set_originator (RSdpMsg * msg,
    const rchar * username, rssize usize,
    const rchar * sid, rssize sidsize, const rchar * sver, rssize sversize,
    const rchar * nettype, rssize ntsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize)
{
  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;

  r_free (msg->username);
  msg->username = r_strdup_size (username, usize);
  r_free (msg->sid);
  msg->sid = r_strdup_size (sid, sidsize);
  r_free (msg->sver);
  msg->sver = r_strdup_size (sver, sversize);

  r_free (msg->origin_nt);
  msg->origin_nt = r_strdup_size (nettype, ntsize);
  r_free (msg->origin_at);
  msg->origin_at = r_strdup_size (addrtype, atsize);
  r_free (msg->origin_addr);
  msg->origin_addr = r_strdup_size (addr, asize);
  return R_SDP_OK;
}

RSdpResult
r_sdp_msg_set_session_name (RSdpMsg * msg,
    const rchar * name, rssize size)
{
  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;

  r_free (msg->name);
  msg->name = r_strdup_size (name, size);
  return R_SDP_OK;
}

RSdpResult
r_sdp_msg_set_session_info (RSdpMsg * msg,
    const rchar * info, rssize size)
{
  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;

  r_free (msg->info);
  msg->info = r_strdup_size (info, size);
  return R_SDP_OK;
}

RSdpResult
r_sdp_msg_set_uri (RSdpMsg * msg, RUri * uri)
{
  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;

  if (msg->uri != NULL)
    r_uri_unref (msg->uri);
  if (uri != NULL)
    r_uri_ref (uri);
  msg->uri = uri;
  return R_SDP_OK;
}

RSdpResult
r_sdp_msg_add_email (RSdpMsg * msg, const rchar * email, rssize size)
{
  rchar * e;

  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (email == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (size == 0)) return R_SDP_INVAL;
  if (R_UNLIKELY (email[0] == 0)) return R_SDP_INVAL;

  if ((e = r_strdup_size (email, size)) != NULL) {
    r_ptr_array_add (msg->email, e, r_free);
    return R_SDP_OK;
  }

  return R_SDP_OOM;
}

RSdpResult
r_sdp_msg_add_phone (RSdpMsg * msg, const rchar * phone, rssize size)
{
  rchar * p;

  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (phone == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (size == 0)) return R_SDP_INVAL;
  if (R_UNLIKELY (phone[0] == 0)) return R_SDP_INVAL;

  if ((p = r_strdup_size (phone, size)) != NULL) {
    r_ptr_array_add (msg->phone, p, r_free);
    return R_SDP_OK;
  }

  return R_SDP_OOM;
}

RSdpResult
r_sdp_msg_clear_connection (RSdpMsg * msg, rboolean def)
{
  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;

  r_free (msg->conn.nettype);
  r_free (msg->conn.addrtype);
  r_free (msg->conn.addr);
  r_memclear (&msg->conn, sizeof (RSdpConn));
  msg->conn.addrcount = def ? 1 : 0;
  return R_SDP_OK;
}

RSdpResult
r_sdp_msg_set_connection_full (RSdpMsg * msg,
    const rchar * nettype, rssize ntsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize,
    ruint ttl, ruint addrcount)
{
  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (addr == NULL)) return R_SDP_INVAL;

  r_free (msg->conn.nettype);
  msg->conn.nettype = r_strdup_size (nettype, ntsize);
  r_free (msg->conn.addrtype);
  msg->conn.addrtype = r_strdup_size (addrtype, atsize);
  r_free (msg->conn.addr);
  msg->conn.addr = r_strdup_size (addr, asize);
  msg->conn.addrcount = addrcount;
  msg->conn.ttl = ttl;
  return R_SDP_OK;
}

static RSdpAttrib *
r_sdp_attrib_new (const rchar * key, rssize ksize,
    const rchar * value, rssize vsize)
{
  RSdpAttrib * ret;

  if (ksize < 0) ksize = (rssize)r_strlen (key);
  if (value == NULL)
    vsize = 0;
  else if (vsize < 0)
    vsize = (rssize)r_strlen (value);

  if  ((ret = r_malloc (sizeof (RSdpAttrib) + ksize + 1 + vsize + 1)) != NULL) {
    if (vsize > 0) {
      r_sprintf (ret->data, "%.*s:%.*s", (int)ksize, key, (int)vsize, value);
      ret->kv.val.str = ret->data + ksize + 1;
      ret->kv.val.size = vsize;
    } else {
      r_sprintf (ret->data, "%.*s", (int)ksize, key);
      r_memclear (&ret->kv.val, sizeof (RStrChunk));
    }
    ret->kv.key.str = ret->data;
    ret->kv.key.size = ksize;
  }

  return ret;
}

RSdpResult
r_sdp_msg_add_bandwidth (RSdpMsg * msg,
    const rchar * type, rssize tsize, ruint kbps)
{
  rchar * v;
  RSdpAttrib * bw;

  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (type == NULL)) return R_SDP_INVAL;

  if (R_UNLIKELY ((v = r_strprintf ("%u", kbps)) == NULL))
    return R_SDP_OOM;

  bw = r_sdp_attrib_new (type, tsize, v, -1);
  r_free (v);
  if (R_UNLIKELY (bw == NULL))
    return R_SDP_OOM;

  r_ptr_array_add (msg->bw, bw, r_free);
  return R_SDP_OK;
}

static void
r_sdp_time_free (rpointer data)
{
  r_ptr_array_unref (((RSdpTime *)data)->repeat);
  r_free (data);
}

RSdpResult
r_sdp_msg_add_time (RSdpMsg * msg, ruint64 start, ruint64 stop)
{
  RSdpTime * t;

  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY ((t = r_mem_new (RSdpTime)) == NULL))
    return R_SDP_OOM;

  t->start = start;
  t->stop = stop;
  if (R_UNLIKELY ((t->repeat = r_ptr_array_new ()) == NULL)) {
    r_free (t);
    return R_SDP_OOM;
  }
  r_ptr_array_add (msg->time, t, r_sdp_time_free);

  return R_SDP_OK;
}

RSdpResult
r_sdp_msg_set_key (RSdpMsg * msg,
    const rchar * method, rssize msize, const rchar * data, rssize size)
{
  RSdpAttrib * key;

  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;

  if (method != NULL) {
    if (R_UNLIKELY ((key = r_sdp_attrib_new (method, msize, data, size)) == NULL))
      return R_SDP_OOM;
  } else {
    key = NULL;
  }

  if (msg->key != NULL)
    r_free (msg->key);
  msg->key = key;
  return R_SDP_OK;
}

RSdpResult
r_sdp_msg_add_attribute (RSdpMsg * msg,
    const rchar * key, rssize ksize, const rchar * value, rssize vsize)
{
  RSdpAttrib * a;

  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (key == NULL)) return R_SDP_INVAL;
  if (ksize < 0) ksize = (rssize)r_strlen (key);
  if (R_UNLIKELY (ksize == 0)) return R_SDP_INVAL;

  if (R_UNLIKELY ((a = r_sdp_attrib_new (key, ksize, value, vsize)) == NULL))
    return R_SDP_OOM;

  r_ptr_array_add (msg->attrib, a, r_free);
  return R_SDP_OK;
}

static void
_r_sdp_aggreagate_bundle (rpointer data, rpointer user)
{
  rchar * mid;

  if ((mid = r_sdp_media_get_mid (data)) != NULL) {
    r_string_append_printf (user, " %s", mid);
    r_free (mid);
  }
}

static void
r_sdp_msg_update_bundle (RSdpMsg * msg)
{
  RSdpAttrib * a;
  RString * str = r_string_new_sized (64);
  rchar * val;

  r_string_append (str, "BUNDLE");
  r_ptr_array_foreach (msg->media, _r_sdp_aggreagate_bundle, str);
  val = r_string_free_keep (str);

  if ((a = r_sdp_attrib_new (R_STR_WITH_SIZE_ARGS ("group"), val, -1)) != NULL) {
    if (msg->bundle != NULL) {
      r_ptr_array_update_idx (msg->attrib,
          r_ptr_array_find (msg->attrib, msg->bundle), a, r_free);
    } else {
      r_ptr_array_add (msg->attrib, a, r_free);
    }
    msg->bundle = a;
  }

  r_free (val);
}

RSdpResult
r_sdp_msg_add_media (RSdpMsg * msg, RSdpMedia * media)
{
  if (R_UNLIKELY (msg == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;

  r_ptr_array_add (msg->media, r_sdp_media_ref (media), r_sdp_media_unref);
  if (msg->jsep)
    r_sdp_msg_update_bundle (msg);

  return R_SDP_OK;
}



static void
r_sdp_media_free (RSdpMedia * media)
{
  r_free (media->type);
  r_free (media->proto);
  r_ptr_array_unref (media->fmt);
  r_free (media->info);
  r_ptr_array_unref (media->conn);
  r_ptr_array_unref (media->bw);
  r_free (media->key);
  r_ptr_array_unref (media->attrib);
  r_free (media);
}

RSdpMedia *
r_sdp_media_new (void)
{
  RSdpMedia * ret;

  if ((ret = r_mem_new0 (RSdpMedia)) != NULL) {
    r_ref_init (ret, r_sdp_media_free);
    ret->fmt = r_ptr_array_new ();
    ret->conn = r_ptr_array_new ();
    ret->bw = r_ptr_array_new ();
    ret->attrib = r_ptr_array_new ();
  }

  return ret;
}

RSdpMedia *
r_sdp_media_new_jsep_dtls (const rchar * type, rssize tsize,
    const rchar * mid, rssize msize, RSdpMediaDirection md)
{
  RSdpMedia * ret;

  if ((ret = r_sdp_media_new_full (type, tsize, 9, 1, "UDP/TLS/RTP/SAVPF", -1)) != NULL) {
    r_ptr_array_add (ret->conn, r_mem_new0 (RSdpConn), r_free);
    r_sdp_media_add_attribute (ret, R_STR_WITH_SIZE_ARGS ("rtcp"),
        R_STR_WITH_SIZE_ARGS ("9 IN IP4 0.0.0.0"));
    r_sdp_media_add_attribute (ret, R_STR_WITH_SIZE_ARGS ("mid"), mid, msize);
    r_sdp_media_add_attribute (ret, R_STR_WITH_SIZE_ARGS ("rtcp-mux"), NULL, 0);
    switch (md) {
      case R_SDP_MD_INACTIVE:
          r_sdp_media_add_attribute (ret, R_STR_WITH_SIZE_ARGS ("inactive"), NULL, 0);
        break;
      case R_SDP_MD_SENDONLY:
          r_sdp_media_add_attribute (ret, R_STR_WITH_SIZE_ARGS ("sendonly"), NULL, 0);
        break;
      case R_SDP_MD_RECVONLY:
          r_sdp_media_add_attribute (ret, R_STR_WITH_SIZE_ARGS ("recvonly"), NULL, 0);
        break;
      case R_SDP_MD_SENDRECV:
          r_sdp_media_add_attribute (ret, R_STR_WITH_SIZE_ARGS ("sendrecv"), NULL, 0);
        break;
      default:
        r_assert_not_reached ();
    }
  }

  return ret;
}

RSdpMedia *
r_sdp_media_new_full (const rchar * type, rssize tsize,
    ruint port, ruint portcount, const rchar * proto, rssize psize)
{
  RSdpMedia * ret;

  if ((ret = r_sdp_media_new ()) != NULL) {
    ret->type = r_strdup_size (type, tsize);
    ret->port = port;
    ret->portcount = portcount;
    ret->proto = r_strdup_size (proto, psize);
  }

  return ret;
}

rchar *
r_sdp_media_get_attribute (const RSdpMedia * media,
    const rchar * key, rssize ksize)
{
  const RSdpAttrib * a;
  rsize i;

  if (ksize < 0) ksize = r_strlen (key);

  for (i = 0; i < r_ptr_array_size (media->attrib); i++) {
    a = r_ptr_array_get (media->attrib, i);

    if (r_str_kv_is_key (&a->kv, key, ksize))
      return r_str_kv_dup_value (&a->kv);
  }

  return NULL;
}

RSdpResult
r_sdp_media_add_rtp_fmt (RSdpMedia * media,
    RRTPPayloadType pt, const rchar * enc, rssize esize,
    ruint rate, ruint params)
{
  rchar * fmt;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (pt > R_RTP_PT_DYNAMIC_LAST)) return R_SDP_INVAL;

  if (R_UNLIKELY ((fmt = r_strprintf ("%"RUINT8_FMT, (ruint8)pt)) == NULL))
    return R_SDP_OOM;

  if (enc != NULL) {
    rchar * v;

    if (esize < 0)
      esize = (rssize)r_strlen (enc);
    if (params > 1)
      v = r_strprintf ("%s %.*s/%u/%u", fmt, (int)esize, enc, rate, params);
    else
      v = r_strprintf ("%s %.*s/%u", fmt, (int)esize, enc, rate);

    if (R_UNLIKELY (v == NULL)) {
      r_free (fmt);
      return R_SDP_OOM;
    }

    r_sdp_media_add_attribute (media, R_STR_WITH_SIZE_ARGS ("rtpmap"), v, -1);
    r_free (v);
  }

  r_ptr_array_add (media->fmt, fmt, r_free);
  return R_SDP_OK;
}

static void
r_sdp_conn_free (rpointer data)
{
  RSdpConn * conn = data;

  r_free (conn->nettype);
  r_free (conn->addrtype);
  r_free (conn->addr);
  r_free (data);
}

RSdpResult
r_sdp_media_add_connection_addr (RSdpMedia * media,
    RSocketAddress * addr, ruint ttl, ruint addrcount)
{
  RSdpResult ret;
  const rchar * addrtype;
  rchar * addrstr;

  if (R_UNLIKELY (addr == NULL)) return R_SDP_INVAL;

  switch (r_socket_address_get_family (addr)) {
    case R_SOCKET_FAMILY_IPV4:
      addrtype = "IP4";
      addrstr = r_socket_address_ipv4_to_str (addr, FALSE);
      break;
    /*case R_SOCKET_FAMILY_IPV6: FIXME */
    default:
      return R_SDP_INVAL;
  }

  ret = r_sdp_media_add_connection_full (media, R_STR_WITH_SIZE_ARGS ("IN"),
      addrtype, -1, addrstr, -1, ttl, addrcount);
  r_free (addrstr);

  return ret;
}

RSdpResult
r_sdp_media_add_connection_full (RSdpMedia * media,
    const rchar * nettype, rssize ntsize,
    const rchar * addrtype, rssize atsize, const rchar * addr, rssize asize,
    ruint ttl, ruint addrcount)
{
  RSdpConn * conn;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (addr == NULL)) return R_SDP_INVAL;

  if (R_UNLIKELY ((conn = r_mem_new (RSdpConn)) == NULL))
    return R_SDP_OOM;

  conn->nettype = r_strdup_size (nettype, ntsize);
  conn->addrtype = r_strdup_size (addrtype, atsize);
  conn->addr = r_strdup_size (addr, asize);
  conn->addrcount = addrcount;
  conn->ttl = ttl;

  r_ptr_array_add (media->conn, conn, r_sdp_conn_free);
  return R_SDP_OK;
}

RSdpResult
r_sdp_media_set_media_info (RSdpMedia * media,
    const rchar * info, rssize size)
{
  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;

  r_free (media->info);
  media->info = r_strdup_size (info, size);
  return R_SDP_OK;
}

RSdpResult
r_sdp_media_add_bandwidth (RSdpMedia * media,
    const rchar * type, rssize tsize, ruint kbps)
{
  rchar * v;
  RSdpAttrib * bw;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (type == NULL)) return R_SDP_INVAL;

  if (R_UNLIKELY ((v = r_strprintf ("%u", kbps)) == NULL))
    return R_SDP_OOM;

  bw = r_sdp_attrib_new (type, tsize, v, -1);
  r_free (v);
  if (R_UNLIKELY (bw == NULL))
    return R_SDP_OOM;

  r_ptr_array_add (media->bw, bw, r_free);
  return R_SDP_OK;
}

RSdpResult
r_sdp_media_set_key (RSdpMedia * media,
    const rchar * method, rssize msize, const rchar * data, rssize size)
{
  RSdpAttrib * key;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;

  if (method != NULL) {
    if (R_UNLIKELY ((key = r_sdp_attrib_new (method, msize, data, size)) == NULL))
      return R_SDP_OOM;
  } else {
    key = NULL;
  }

  if (media->key != NULL)
    r_free (media->key);
  media->key = key;
  return R_SDP_OK;
}

RSdpResult
r_sdp_media_add_attribute (RSdpMedia * media,
    const rchar * key, rssize ksize, const rchar * value, rssize vsize)
{
  RSdpAttrib * a;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (key == NULL)) return R_SDP_INVAL;
  if (ksize < 0) ksize = r_strlen (key);
  if (R_UNLIKELY (ksize == 0)) return R_SDP_INVAL;

  if (R_UNLIKELY ((a = r_sdp_attrib_new (key, ksize, value, vsize)) == NULL))
    return R_SDP_OOM;

  r_ptr_array_add (media->attrib, a, r_free);
  return R_SDP_OK;
}

RSdpResult
r_sdp_media_add_pt_specific_attribute (RSdpMedia * media, RRTPPayloadType pt,
    const rchar * key, rssize ksize, const rchar * value, rssize vsize)
{
  RSdpResult ret;
  rchar * val;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (pt == 0 || pt > R_RTP_PT_DYNAMIC_LAST)) return R_SDP_INVAL;

  if (R_UNLIKELY (key == NULL)) return R_SDP_INVAL;
  if (ksize < 0) ksize = r_strlen (key);
  if (R_UNLIKELY (ksize == 0)) return R_SDP_INVAL;

  if (R_UNLIKELY (value == NULL)) return R_SDP_INVAL;
  if (vsize < 0) vsize = r_strlen (value);
  if (R_UNLIKELY (vsize == 0)) return R_SDP_INVAL;

  val = r_strprintf ("%"RUINT8_FMT" %.*s", (ruint8)pt, (int)vsize, value);
  ret = r_sdp_media_add_attribute (media, key, ksize, val, -1);
  r_free (val);

  return ret;
}

RSdpResult
r_sdp_media_add_source_specific_attribute (RSdpMedia * media,
    ruint32 ssrc, const rchar * key, rssize ksize, const rchar * value, rssize vsize)
{
  RSdpResult ret;
  rchar * val;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (ssrc == 0)) return R_SDP_INVAL;
  if (R_UNLIKELY (key == NULL)) return R_SDP_INVAL;
  if (ksize < 0) ksize = r_strlen (key);
  if (R_UNLIKELY (ksize == 0)) return R_SDP_INVAL;

  if (vsize < 0) vsize = r_strlen (value);

  if (value != NULL && vsize > 0) {
    val = r_strprintf ("%"RUINT32_FMT" %.*s:%.*s", ssrc, (int)ksize, key, (int)vsize, value);
  } else {
    val = r_strprintf ("%"RUINT32_FMT" %.*s", ssrc, (int)ksize, key);
  }

  ret = r_sdp_media_add_attribute (media, R_STR_WITH_SIZE_ARGS ("ssrc"), val, -1);
  r_free (val);

  return ret;
}

RSdpResult
r_sdp_media_add_jsep_msid (RSdpMedia * media, ruint32 ssrc,
    const rchar * msidval, rssize vsize, const rchar * msidappdata, rssize asize)
{
  RSdpResult ret;
  rchar * val;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (ssrc == 0)) return R_SDP_INVAL;
  if (R_UNLIKELY (msidval == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (msidappdata == NULL)) return R_SDP_INVAL;

  if (vsize < 0) vsize = r_strlen (msidval);
  if (asize < 0) asize = r_strlen (msidappdata);

  if ((val = r_strprintf ("%.*s %.*s", (int)vsize, msidval, (int)asize, msidappdata)) != NULL) {
    ret = r_sdp_media_add_source_specific_attribute (media, ssrc,
        R_STR_WITH_SIZE_ARGS ("msid"), val, -1);
    r_free (val);

    if (ret == R_SDP_OK)
      ret = r_sdp_media_add_source_specific_attribute (media, ssrc,
          R_STR_WITH_SIZE_ARGS ("mslabel"), msidval, vsize);
    if (ret == R_SDP_OK)
      ret = r_sdp_media_add_source_specific_attribute (media, ssrc,
          R_STR_WITH_SIZE_ARGS ("label"), msidappdata, asize);
  } else {
    ret = R_SDP_OOM;
  }

  return ret;
}

RSdpResult
r_sdp_media_add_ice_credentials (RSdpMedia * media,
    const rchar * ufrag, rssize usize, const rchar * pwd, rssize psize)
{
  RSdpResult ret;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;

  if ((ret = r_sdp_media_add_attribute (media,
          R_STR_WITH_SIZE_ARGS ("ice-ufrag"), ufrag, usize)) == R_SDP_OK) {
    ret = r_sdp_media_add_attribute (media, R_STR_WITH_SIZE_ARGS ("ice-pwd"), pwd, psize);
  }

  return ret;
}

RSdpResult
r_sdp_media_add_ice_candidate_raw (RSdpMedia * media,
    const rchar * foundation, rssize fsize, ruint componentid,
    const rchar * transport, rssize transize, ruint64 pri,
    const rchar * addr, rssize asize, ruint16 port,
    const rchar * type, rssize typesize,
    const rchar * raddr, rssize rasize, ruint16 rport,
    const rchar * extension, rssize esize)
{
  RSdpResult ret;
  RString * str;
  rchar * val;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (fsize < 0) fsize = r_strlen (foundation);
  if (transize < 0) transize = r_strlen (transport);
  if (asize < 0) asize = r_strlen (addr);
  if (rasize < 0) rasize = r_strlen (addr);
  if (esize < 0) esize = r_strlen (extension);
  if (R_UNLIKELY (foundation == NULL || fsize == 0)) return R_SDP_INVAL;
  if (R_UNLIKELY (transport == NULL || transize == 0)) return R_SDP_INVAL;
  if (R_UNLIKELY (addr == NULL || asize == 0)) return R_SDP_INVAL;
  if (R_UNLIKELY (type == NULL || typesize == 0)) return R_SDP_INVAL;

  if (R_UNLIKELY ((str = r_string_new_sized (128)) == NULL))
    return R_SDP_OOM;

  r_string_append_printf (str,
      "%.*s %u %.*s %"RUINT64_FMT" %.*s %"RUINT16_FMT" typ %.*s",
      (int)fsize, foundation, componentid, (int)transize, transport, pri,
      (int)asize, addr, port, (int)typesize, type);
  if (raddr != NULL && rasize > 0)
    r_string_append_printf (str, " raddr %.*s", (int)rasize, raddr);
  if (rport > 0)
    r_string_append_printf (str, " %"RUINT16_FMT, rport);
  if (extension != NULL || esize > 0)
    r_string_append_printf (str, " %.*s", (int)esize, extension);

  if ((val = r_string_free_keep (str)) != NULL) {
    ret = r_sdp_media_add_attribute (media,
        R_STR_WITH_SIZE_ARGS ("candidate"), val, -1);
    r_free (val);
  } else {
    ret = R_SDP_OOM;
  }

  return ret;
}

RSdpResult
r_sdp_media_add_ice_candidate (RSdpMedia * media,
    const rchar * foundation, rssize fsize, ruint componentid,
    const rchar * transport, rssize tsize, ruint64 pri,
    const RSocketAddress * addr, RSdpICEType type,
    const RSocketAddress * raddr, const rchar * extension, rssize esize)
{
  RSdpResult ret;
  const rchar * _type;
  rchar * _addr, * _raddr;
  ruint16 port, rport;

  if (R_UNLIKELY (addr == NULL)) return R_SDP_INVAL;
  switch (r_socket_address_get_family (addr)) {
    case R_SOCKET_FAMILY_IPV4:
      _addr = r_socket_address_ipv4_to_str (addr, FALSE);
      port = r_socket_address_ipv4_get_port (addr);
      break;
    /*case R_SOCKET_FAMILY_IPV6: FIXME */
    default:
      return R_SDP_INVAL;
  }

  switch (type) {
    case R_SDP_ICE_TYPE_HOST:
      _type = "host";
      break;
    case R_SDP_ICE_TYPE_SRFLX:
      _type = "srflx";
      break;
    case R_SDP_ICE_TYPE_PRFLX:
      _type = "prflx";
      break;
    case R_SDP_ICE_TYPE_RELAY:
      _type = "relay";
      break;
    default:
      return R_SDP_INVAL;
  }

  if (raddr != NULL) {
    switch (r_socket_address_get_family (raddr)) {
      case R_SOCKET_FAMILY_IPV4:
        _raddr = r_socket_address_ipv4_to_str (raddr, FALSE);
        rport = r_socket_address_ipv4_get_port (raddr);
        break;
      /*case R_SOCKET_FAMILY_IPV6: FIXME */
      default:
        r_free (_addr);
        return R_SDP_INVAL;
    }
  } else {
    _raddr = NULL;
    rport = 0;
  }

  ret = r_sdp_media_add_ice_candidate_raw (media, foundation, fsize, componentid,
      transport, tsize, pri, _addr, -1, port, _type, -1, _raddr, -1, rport,
      extension, esize);

  r_free (_addr);
  r_free (_raddr);

  return ret;
}

RSdpResult
r_sdp_media_add_dtls_setup (RSdpMedia * media, RSdpConnRole role,
    RMsgDigestType type, const rchar * fingerprint, rssize fsize)
{
  RSdpResult ret;
  const rchar * strrole, * strtype;
  rchar * val;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (fingerprint == NULL)) return R_SDP_INVAL;
  if (fsize < 0) fsize = r_strlen (fingerprint);
  if (R_UNLIKELY (fsize == 0)) return R_SDP_INVAL;
  if ((strtype = r_msg_digest_type_string (type)) == NULL) return R_SDP_INVAL;

  switch (role) {
    case R_SDP_CONN_ROLE_HOLDCONN:
      strrole = "holdconn";
      break;
    case R_SDP_CONN_ROLE_ACTIVE:
      strrole = "active";
      break;
    case R_SDP_CONN_ROLE_PASSIVE:
      strrole = "passive";
      break;
    case R_SDP_CONN_ROLE_ACTPASS:
      strrole = "actpass";
      break;
    default:
      return R_SDP_INVAL;
  }

  if (R_UNLIKELY ((val = r_strprintf ("%s %.*s", strtype, (int)fsize, fingerprint)) == NULL))
    return R_SDP_OOM;

  if ((ret = r_sdp_media_add_attribute (media,
          R_STR_WITH_SIZE_ARGS ("fingerprint"), val, -1)) == R_SDP_OK) {
    ret = r_sdp_media_add_attribute (media, R_STR_WITH_SIZE_ARGS ("setup"), strrole, -1);
  }
  r_free (val);

  return ret;
}






static void
r_sdp_time_clear (RSdpTimeBuf * time)
{
  r_free (time->repeat); time->repeat = NULL;
}

static void
r_sdp_media_buf_clear (RSdpMediaBuf * media)
{
  r_free (media->fmt); media->fmt = NULL;
  r_free (media->conn); media->conn = NULL;
  r_free (media->bw); media->bw = NULL;
  r_free (media->attrib); media->attrib = NULL;
}

static void
r_sdp_buf_clear (RSdpBuf * sdp)
{
  rsize i;

  r_free (sdp->email); sdp->email = NULL;
  r_free (sdp->phone); sdp->phone = NULL;
  r_free (sdp->bw); sdp->bw = NULL;
  for (i = 0; i < sdp->tcount; i++)
    r_sdp_time_clear (&sdp->time[i]);
  r_free (sdp->time); sdp->time = NULL;
  r_free (sdp->zone); sdp->zone = NULL;
  r_free (sdp->attrib); sdp->attrib = NULL;
  for (i = 0; i < sdp->mcount; i++)
    r_sdp_media_buf_clear (&sdp->media[i]);
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
r_sdp_bandwidth_parse (RStrKV * bw, rchar * str, rsize size)
{
  return r_str_kv_parse (bw, str, size, ":", NULL) == R_STR_PARSE_OK ?
    R_SDP_OK : R_SDP_BAD_DATA;
}

static RSdpResult
r_sdp_time_parse (RSdpTimeBuf * time, rchar * str, rsize size)
{
  rchar * p = str;
  rssize s;

  time->rcount = 0;
  time->repeat = NULL;

  if ((s = r_str_idx_of_c (p, size - RPOINTER_TO_SIZE (p - str), ' ')) < 0)
    return R_SDP_BAD_DATA;
  time->start.str = p;
  time->start.size = (rsize)s;

  p = (rchar *)r_str_lwstrip (p + s);
  time->stop.str = p;
  time->stop.size = size - RPOINTER_TO_SIZE (p - str);

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
    media->conn = r_realloc (media->conn, media->ccount * sizeof (RSdpConnectionBuf));
    if ((ret = r_sdp_connection_parse (&media->conn[media->ccount - 1], tmp.str, tmp.size)) != R_SDP_OK)
      goto done;
    if ((ret = r_sdp_parse_next_valid_line (chunk, line)) != R_SDP_OK)
      goto done;
  }

  /* b= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, line, 'b') == R_SDP_OK) {
    media->bcount++;
    media->bw = r_realloc (media->bw, media->bcount * sizeof (RStrKV));
    if ((ret = r_sdp_bandwidth_parse (&media->bw[media->bcount - 1], tmp.str, tmp.size)) != R_SDP_OK)
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
    if ((ret = r_sdp_connection_parse (&sdp->conn, tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* b= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 'b') == R_SDP_OK) {
    sdp->bcount++;
    sdp->bw = r_realloc (sdp->bw, sdp->bcount * sizeof (RStrKV));
    if ((ret = r_sdp_bandwidth_parse (&sdp->bw[sdp->bcount - 1], tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
  }

  /* t= OPTIONAL */
  while (ret == R_SDP_OK &&
      r_sdp_message_line_parse_value (&tmp, &line, 't') == R_SDP_OK) {
    RSdpTimeBuf * time;
    sdp->tcount++;
    sdp->time = r_realloc (sdp->time, sdp->tcount * sizeof (RSdpTimeBuf));
    time = &sdp->time[sdp->tcount - 1];
    if ((ret = r_sdp_time_parse (time, tmp.str, tmp.size)) != R_SDP_OK)
      goto error;
    if ((ret = r_sdp_parse_next_valid_line (&chunk, &line)) > R_SDP_OK)
      goto error;
    while (ret == R_SDP_OK &&
        r_sdp_message_line_parse_value (&tmp, &line, 't') == R_SDP_OK) {
      time->rcount++;
      time->repeat = r_realloc (time->repeat, time->rcount * sizeof (RStrChunk));
      time->repeat[time->rcount - 1] = tmp;
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

RSocketAddress *
r_sdp_connection_buf_to_socket_address (const RSdpConnectionBuf * conn, ruint port)
{
  RSocketAddress * ret = NULL;

  if (R_UNLIKELY (conn == NULL)) return NULL;

  if (r_str_chunk_casecmp (&conn->nettype, "IN", 2) == 0) {
    if (r_str_chunk_casecmp (&conn->addrtype, "IP4", 3) == 0) {
      rchar * ip = r_str_chunk_dup (&conn->addr);
      ret = r_socket_address_ipv4_new_from_string (ip, port);
      r_free (ip);
    } else if (r_str_chunk_casecmp (&conn->addrtype, "IP6", 3) == 0) {
      /* FIXME: IPv6 support */
    }
  }

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

const RStrChunk *
r_sdp_attrib_find (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize, rsize * start)
{
  rsize i, len;

  if (R_UNLIKELY (attrib == NULL)) return NULL;
  if (R_UNLIKELY (field == NULL)) return NULL;
  if (R_UNLIKELY (fsize == 0)) return NULL;

  len = fsize > 0 ? (rsize)fsize : r_strlen (field);
  for (i = start != NULL ? *start : 0; i < acount; i++) {
    if (len == attrib[i].key.size &&
        r_strncmp (attrib[i].key.str, field, len) == 0) {
      if (start != NULL) *start = i;
      return &attrib[i].val;
    }
  }

  if (start != NULL) *start = acount;
  return NULL;
}

rchar *
r_sdp_attrib_dup_value (const RStrKV * attrib, rsize acount,
    const rchar * field, rssize fsize, rsize * start)
{
  const RStrChunk * val;

  if ((val = r_sdp_attrib_find (attrib, acount, field, fsize, start)) != NULL)
    return r_str_chunk_dup (val);

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
    RStrChunk * attrib, rsize * start)
{
  rssize i;

  if ((i = r_sdp_media_buf_find_fmt (media, fmt, fmtsize)) >= 0) {
    return r_sdp_media_buf_fmtidx_specific_attrib (media, (rsize)i, field, fsize,
        attrib, start);
  }

  return R_SDP_NOT_FOUND;
}

RSdpResult
r_sdp_media_buf_fmtidx_specific_attrib (const RSdpMediaBuf * media,
    rsize fmtidx, const rchar * field, rssize fsize, RStrChunk * attrib, rsize * start)
{
  rsize i;

  if (R_UNLIKELY (media == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (attrib == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (fmtidx >= media->fmtcount)) return R_SDP_INVAL;
  if (fsize < 0) fsize = (rssize)r_strlen (field);

  for (i = (start != NULL ? *start : 0); i < media->acount; i++) {
    if (r_str_kv_is_key (&media->attrib[i], field, fsize)) {
      if (media->attrib[i].val.size > media->fmt[fmtidx].size &&
          r_strncmp (media->attrib[i].val.str, media->fmt[fmtidx].str, media->fmt[fmtidx].size) == 0) {
        attrib->str = (rchar *)r_str_lwstrip (media->attrib[i].val.str + media->fmt[fmtidx].size);
        attrib->size = media->attrib[i].val.size -
          RPOINTER_TO_SIZE (attrib->str - media->attrib[i].val.str);
        if (start != NULL) *start = i;
        return R_SDP_OK;
      }
    }
  }

  if (start != NULL) *start = i;
  r_memclear (attrib, sizeof (RStrChunk));
  return R_SDP_NOT_FOUND;
}

ruint32 *
r_sdp_media_buf_source_specific_sources (const RSdpMediaBuf * media, rsize * size)
{
  const RStrChunk * res;
  ruint32 * ret = NULL;
  rsize i, alloc = 0, count = 0, next = 0;
  ruint32 ssrc;
  const rchar * end;

  while ((res = r_sdp_attrib_find (media->attrib, media->acount,
          R_STR_WITH_SIZE_ARGS ("ssrc"), &next)) != NULL) {
    if ((ssrc = r_str_to_uint32 (res->str, &end, 10, NULL)) > 0 &&
        RPOINTER_TO_SIZE (end - res->str) <= res->size) {
      for (i = 0; i < count; i++) {
        if (ssrc == ret[i]) goto next;
      }

      if (count >= alloc) {
        alloc += 8;
        ret = r_realloc (ret, sizeof (ruint32) * alloc);
      }

      ret[count++] = ssrc;
    }

next:
    next++;
  }

  if (size != NULL)
    *size = count;
  return ret;
}

RStrKV *
r_sdp_media_buf_source_specific_all_media_attribs (const RSdpMediaBuf * media,
    ruint32 ssrc, rsize * size)
{
  const RStrChunk * res;
  RStrKV * ret = NULL;
  rsize alloc = 0, count = 0, next = 0;
  const rchar * end;

  while ((res = r_sdp_attrib_find (media->attrib, media->acount,
          R_STR_WITH_SIZE_ARGS ("ssrc"), &next)) != NULL) {
    if (r_str_to_uint32 (res->str, &end, 10, NULL) == ssrc &&
        RPOINTER_TO_SIZE (end - res->str) < res->size && *end == ' ') {
      RStrChunk mattrib = { (rchar *)end + 1, res->size - RPOINTER_TO_SIZE (end - res->str) };
      r_str_chunk_wstrip (&mattrib);

      if (mattrib.size > 0) {
        if (count >= alloc) {
          alloc += 8;
          ret = r_realloc (ret, sizeof (RStrKV) * alloc);
        }

        if (r_str_kv_parse (&ret[count], mattrib.str, mattrib.size, ":", NULL) != R_STR_PARSE_OK) {
          r_memcpy (&ret[count].key, &mattrib, sizeof (RStrChunk));
          r_memclear (&ret[count].val, sizeof (RStrChunk));
        }
        count++;
      }
    }

    next++;
  }

  if (size != NULL)
    *size = count;
  return ret;
}

RSdpResult
r_sdp_media_buf_source_specific_media_attrib (const RSdpMediaBuf * media,
    ruint32 ssrc, const rchar * field, rssize fsize, RStrChunk * attrib)
{
  const RStrChunk * res;
  rsize next = 0;
  const rchar * end;

  if (R_UNLIKELY (attrib == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (field == NULL)) return R_SDP_INVAL;
  if (fsize < 0) fsize = r_strlen (field);
  if (R_UNLIKELY (fsize == 0)) return R_SDP_INVAL;

  while ((res = r_sdp_attrib_find (media->attrib, media->acount,
          R_STR_WITH_SIZE_ARGS ("ssrc"), &next)) != NULL) {
    if (r_str_to_uint32 (res->str, &end, 10, NULL) == ssrc &&
        RPOINTER_TO_SIZE (end - res->str) < res->size && *end == ' ') {
      RStrChunk mattrib = { (rchar *)end + 1, res->size - RPOINTER_TO_SIZE (end - res->str) };
      RStrKV kv = R_STR_KV_INIT;

      r_str_chunk_wstrip (&mattrib);

      if (r_str_kv_parse (&kv, mattrib.str, mattrib.size, ":", NULL) == R_STR_PARSE_OK) {
        if (r_str_chunk_casecmp (&kv.key, field, fsize) == 0) {
          r_memcpy (attrib, &kv.val, sizeof (RStrChunk));
          return R_SDP_OK;
        }
      } else {
        if (r_str_chunk_casecmp (&mattrib, field, fsize) == 0) {
          r_memclear (attrib, sizeof (RStrChunk));
          return R_SDP_OK;
        }
      }
    }

    next++;
  }

  return R_SDP_NOT_FOUND;
}

RSdpResult
r_sdp_media_buf_ssrc_group_attrib (const RSdpMediaBuf * media,
    const rchar * semantics, rssize size, RStrChunk * attrib, rsize * start)
{
  const RStrChunk * res;
  rsize next;

  if (R_UNLIKELY (attrib == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (semantics == NULL)) return R_SDP_INVAL;
  if (size < 0) size = r_strlen (semantics);
  if (R_UNLIKELY (size == 0)) return R_SDP_INVAL;

  next = start != NULL ? *start : 0;
  while ((res = r_sdp_attrib_find (media->attrib, media->acount,
          R_STR_WITH_SIZE_ARGS ("ssrc-group"), &next)) != NULL) {
    if (res->size > (rsize)size && res->str[size] == ' ' &&
        r_strncasecmp (res->str, semantics, (rsize)size) == 0) {
      attrib->str = res->str + size + 1;
      attrib->size = res->size - RPOINTER_TO_SIZE (attrib->str - res->str);

      r_str_chunk_wstrip (attrib);
      if (start != NULL) *start = next;
      return R_SDP_OK;
    }

    next++;
  }

  if (start != NULL) *start = next;
  return R_SDP_NOT_FOUND;
}

RSdpResult
r_sdp_media_buf_extmap_attrib (const RSdpMediaBuf * media,
    ruint16 * id, RStrChunk * attrib, rsize * start)
{
  const RStrChunk * res;

  if (R_UNLIKELY (id == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (attrib == NULL)) return R_SDP_INVAL;

  if ((res = r_sdp_media_buf_attrib_find (media, "extmap", 6, start)) != NULL) {
    const rchar * end;

    if ((*id = r_str_to_uint16 (res->str, &end, 10, NULL)) == 0)
      return R_SDP_BAD_DATA;

    attrib->str = (rchar *)end;
    attrib->size = res->size + RPOINTER_TO_SIZE (end - res->str);
    r_str_chunk_wstrip (attrib);
    return R_SDP_OK;
  }

  return R_SDP_NOT_FOUND;
}

RSdpResult
r_sdp_buf_find_grouping (const RSdpBuf * sdp, RStrChunk * group,
    const rchar * semantics, rssize ssize, const rchar * mid, rssize midsize)
{
  const RStrChunk * cur;
  rsize i = 0;

  if (R_UNLIKELY (group == NULL)) return R_SDP_INVAL;
  if (R_UNLIKELY (mid == NULL)) return R_SDP_INVAL;
  if (midsize < 0) midsize = r_strlen (mid);
  if (R_UNLIKELY (midsize == 0)) return R_SDP_INVAL;

  if (ssize < 0) ssize = r_strlen (semantics);

  while ((cur = r_sdp_buf_attrib_find (sdp, "group", -1, &i)) != NULL) {
    if (r_str_chunk_has_prefix (cur, semantics, ssize)) {
      rssize idx;

      r_memcpy (group, cur, sizeof (RStrChunk));
      group->size -= ssize;
      group->str += ssize;
      r_str_chunk_wstrip (group);

      if ((idx = r_str_chunk_idx_of_str (group, mid, midsize)) >= 0 &&
          ((rsize)(idx + midsize) == group->size ||
           group->str[idx + midsize] == ' ')) {
        return R_SDP_OK;
      }
    }
    i++;
  }

  group->str = NULL;
  group->size = 0;
  return R_SDP_NOT_FOUND;
}

