/* Wrapper around the auto-generated Wycheproof ECDH vector .inc files.
 *
 * Each .inc declares a static WycheproofEcdhTest array scoped by a C
 * name prefix tied to its curve. Drive each with its own RTEST_LOOP.
 */
#ifndef __WYCHEPROOF_ECDH_H__
#define __WYCHEPROOF_ECDH_H__

#include <rlib/rcrypto.h>

typedef enum {
  WYCHEPROOF_INVALID = 0,
  WYCHEPROOF_VALID = 1,
  WYCHEPROOF_ACCEPTABLE = 2,
} WycheproofResult;

typedef struct {
  REcurveID curve;
  ruint16 tc_id;
  const rchar * comment;
  const ruint8 * pub;     rsize pub_len;
  const ruint8 * priv;    rsize priv_len;
  const ruint8 * shared;  rsize shared_len;
  WycheproofResult expected;
} WycheproofEcdhTest;

#include "wycheproof_ecdh_secp224r1.inc"
#include "wycheproof_ecdh_secp256r1.inc"
#include "wycheproof_ecdh_secp384r1.inc"
#include "wycheproof_ecdh_secp521r1.inc"

#endif /* __WYCHEPROOF_ECDH_H__ */
