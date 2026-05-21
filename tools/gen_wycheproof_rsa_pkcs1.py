#!/usr/bin/env python3
"""Generate a C header of Wycheproof RSA PKCS#1 v1.5 decrypt vectors.

Reads a Wycheproof JSON file (rsa_pkcs1_<bits>_test.json) and emits a
self-contained C header that test/rrsa.c can include directly. The C
side stays free of any JSON dependency at build time.

Usage:
  ./tools/gen_wycheproof_rsa_pkcs1.py <input.json> <output.h>

Re-fetch upstream first:
  curl -L https://raw.githubusercontent.com/C2SP/wycheproof/main/\\
       testvectors_v1/rsa_pkcs1_2048_test.json -o /tmp/rsa_pkcs1_2048.json
"""
import json
import sys
import textwrap
from pathlib import Path


def hex_to_c_array(name: str, hex_str: str) -> str:
    data = bytes.fromhex(hex_str) if hex_str else b""
    if not data:
        return f"static const ruint8 {name}[1] = {{ 0 }};\n"
    lines = []
    line = "static const ruint8 " + name + "[] = {"
    for i, b in enumerate(data):
        if i % 12 == 0:
            lines.append(line)
            line = "  "
        line += f"0x{b:02x}, "
    lines.append(line.rstrip(", "))
    lines.append("};")
    return "\n".join(lines) + "\n"


def emit(input_path: Path, output_path: Path) -> None:
    data = json.loads(input_path.read_text())
    parts = []

    parts.append(textwrap.dedent(f"""\
        /* AUTO-GENERATED from {input_path.name} — do not edit by hand.
         *
         * Source: https://github.com/C2SP/wycheproof
         *         testvectors_v1/{input_path.name}
         * Algorithm: {data.get("algorithm", "?")}
         *
         * Regenerate with tools/gen_wycheproof_rsa_pkcs1.py.
         */
        #ifndef __WYCHEPROOF_RSA_PKCS1_H__
        #define __WYCHEPROOF_RSA_PKCS1_H__

        #include <rlib/rtypes.h>

        typedef struct {{
          const ruint8 * n;     rsize n_len;
          const ruint8 * e;     rsize e_len;
          const ruint8 * d;     rsize d_len;
        }} WycheproofRsaKey;

        typedef struct {{
          ruint16 key_idx;
          ruint16 tc_id;
          const rchar * comment;
          const ruint8 * ct;    rsize ct_len;
          const ruint8 * msg;   rsize msg_len;
          rboolean valid;
        }} WycheproofRsaPkcs1Test;

        """))

    # One block of byte arrays per key, one per ct/msg.
    keys = []
    tests = []
    for g_idx, g in enumerate(data["testGroups"]):
        pk = g["privateKey"]
        key_prefix = f"wp_key{g_idx}"
        parts.append(hex_to_c_array(f"{key_prefix}_n", pk["modulus"].lstrip("0") or "0"))
        parts.append(hex_to_c_array(f"{key_prefix}_e", pk["publicExponent"]))
        parts.append(hex_to_c_array(f"{key_prefix}_d", pk["privateExponent"]))
        keys.append(g_idx)
        for t in g["tests"]:
            t_prefix = f"wp_test{t['tcId']}"
            parts.append(hex_to_c_array(f"{t_prefix}_ct", t["ct"]))
            parts.append(hex_to_c_array(f"{t_prefix}_msg", t["msg"]))
            tests.append((g_idx, t))

    parts.append("\nstatic const WycheproofRsaKey wp_rsa_keys[] = {\n")
    for g_idx in keys:
        p = f"wp_key{g_idx}"
        parts.append(
            f"  {{ {p}_n, sizeof ({p}_n), {p}_e, sizeof ({p}_e), {p}_d, sizeof ({p}_d) }},\n"
        )
    parts.append("};\n")

    parts.append("\nstatic const WycheproofRsaPkcs1Test wp_rsa_pkcs1_tests[] = {\n")
    for g_idx, t in tests:
        p = f"wp_test{t['tcId']}"
        # Comments may contain "*/" or quotes; sanitize.
        comment = t["comment"].replace("\\", "\\\\").replace('"', '\\"').replace("*/", "* /")
        valid = "TRUE" if t["result"] == "valid" else "FALSE"
        msg_expr = (
            f"{p}_msg, sizeof ({p}_msg)"
            if t["msg"]
            else f"{p}_msg, 0"
        )
        parts.append(
            f'  {{ {g_idx}, {t["tcId"]}, "{comment}", '
            f'{p}_ct, sizeof ({p}_ct), {msg_expr}, {valid} }},\n'
        )
    parts.append("};\n")

    parts.append("\n#endif /* __WYCHEPROOF_RSA_PKCS1_H__ */\n")

    output_path.write_text("".join(parts))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    emit(Path(sys.argv[1]), Path(sys.argv[2]))
