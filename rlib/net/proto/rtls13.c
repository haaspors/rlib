/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/net/proto/rtls13.h>

#include <rlib/crypto/rkdf.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#define R_TLS13_LABEL_PREFIX      "tls13 "
#define R_TLS13_LABEL_PREFIX_LEN  6

rboolean
r_tls13_expand_label (RMsgDigestType hash, const ruint8 * secret,
    const rchar * label, rsize labellen, const ruint8 * context, rsize ctxlen,
    ruint8 * out, rsize outlen)
{
  /* HkdfLabel: uint16 length | opaque label<7..255> | opaque context<0..255>.
   * Max = 2 + 1 + (6 + 249) + 1 + 255. */
  ruint8 info[2 + 1 + (R_TLS13_LABEL_PREFIX_LEN + 249) + 1 + 255];
  rsize n = 0, hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (secret == NULL || label == NULL || out == NULL ||
        hlen == 0 || outlen == 0 || outlen > 0xffff ||
        labellen == 0 || labellen > 255 - R_TLS13_LABEL_PREFIX_LEN ||
        ctxlen > 255 || (context == NULL && ctxlen != 0)))
    return FALSE;

  info[n++] = (ruint8) (outlen >> 8);
  info[n++] = (ruint8) outlen;
  info[n++] = (ruint8) (R_TLS13_LABEL_PREFIX_LEN + labellen);
  r_memcpy (info + n, R_TLS13_LABEL_PREFIX, R_TLS13_LABEL_PREFIX_LEN);
  n += R_TLS13_LABEL_PREFIX_LEN;
  r_memcpy (info + n, label, labellen);
  n += labellen;
  info[n++] = (ruint8) ctxlen;
  if (ctxlen != 0) {
    r_memcpy (info + n, context, ctxlen);
    n += ctxlen;
  }

  return r_hkdf_expand (hash, secret, hlen, info, n, out, outlen);
}

rboolean
r_tls13_derive_secret (RMsgDigestType hash, const ruint8 * secret,
    const rchar * label, rsize labellen, const ruint8 * transcript_hash,
    ruint8 * out)
{
  rsize hlen = r_msg_digest_type_size (hash);

  if (R_UNLIKELY (transcript_hash == NULL || hlen == 0))
    return FALSE;

  /* Derive-Secret(Secret, Label, Messages) =
   *   HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), HashLen). */
  return r_tls13_expand_label (hash, secret, label, labellen,
      transcript_hash, hlen, out, hlen);
}
