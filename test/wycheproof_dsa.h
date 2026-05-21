/* Wrapper around the auto-generated Wycheproof DSA vector .inc files.
 *
 * Each .inc declares static \`WycheproofDsaKey\` and \`WycheproofDsaTest\`
 * arrays scoped by a C name prefix tied to its (L, N, hash) combination.
 * Drive each with its own RTEST_LOOP plus the matching r_msg_digest.
 */
#ifndef __WYCHEPROOF_DSA_H__
#define __WYCHEPROOF_DSA_H__

#include <rlib/rtypes.h>

typedef enum {
  WYCHEPROOF_INVALID = 0,
  WYCHEPROOF_VALID = 1,
  WYCHEPROOF_ACCEPTABLE = 2,
} WycheproofResult;

typedef struct {
  const ruint8 * p;     rsize p_len;
  const ruint8 * q;     rsize q_len;
  const ruint8 * g;     rsize g_len;
  const ruint8 * y;     rsize y_len;
} WycheproofDsaKey;

typedef struct {
  ruint16 key_idx;
  ruint16 tc_id;
  const rchar * comment;
  const ruint8 * msg;   rsize msg_len;
  const ruint8 * sig;   rsize sig_len;
  WycheproofResult expected;
} WycheproofDsaTest;

#include "wycheproof_dsa_2048_256_sha256.inc"

#endif /* __WYCHEPROOF_DSA_H__ */
