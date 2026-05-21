#!/usr/bin/env python3
"""Generate a C header of Wycheproof DSA verify vectors.

Each invocation reads ONE Wycheproof JSON (dsa_<L>_<N>_<hash>_test.json)
plus a C name prefix and emits a self-contained .inc file that the DSA
test in test/rdsa.c can include directly. Combine multiple invocations
in a wrapper .h to cover several (L, N, hash) combinations.

Usage:
  ./tools/gen_wycheproof_dsa.py <input.json> <c_prefix> <output.inc>

Re-fetch upstream first:
  curl -L https://raw.githubusercontent.com/C2SP/wycheproof/main/\\
       testvectors_v1/dsa_2048_224_sha224_test.json \\
       -o /tmp/dsa_2048_224_sha224.json
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


def emit(input_path: Path, prefix: str, output_path: Path) -> None:
    data = json.loads(input_path.read_text())
    parts = []

    parts.append(textwrap.dedent(f"""\
        /* AUTO-GENERATED from {input_path.name} — do not edit by hand.
         *
         * Source: https://github.com/C2SP/wycheproof
         *         testvectors_v1/{input_path.name}
         * Algorithm: {data.get("algorithm", "?")}, hash: {data["testGroups"][0].get("sha", "?")}
         *
         * Regenerate with tools/gen_wycheproof_dsa.py.
         */

        """))

    keys = []
    tests = []
    for g_idx, g in enumerate(data["testGroups"]):
        pk = g["publicKey"]
        kpfx = f"{prefix}_key{g_idx}"
        parts.append(hex_to_c_array(f"{kpfx}_p", pk["p"]))
        parts.append(hex_to_c_array(f"{kpfx}_q", pk["q"]))
        parts.append(hex_to_c_array(f"{kpfx}_g", pk["g"]))
        parts.append(hex_to_c_array(f"{kpfx}_y", pk["y"]))
        keys.append(g_idx)
        for t in g["tests"]:
            tpfx = f"{prefix}_test{t['tcId']}"
            parts.append(hex_to_c_array(f"{tpfx}_msg", t["msg"]))
            parts.append(hex_to_c_array(f"{tpfx}_sig", t["sig"]))
            tests.append((g_idx, t))

    parts.append(f"\nstatic const WycheproofDsaKey {prefix}_keys[] = {{\n")
    for g_idx in keys:
        kpfx = f"{prefix}_key{g_idx}"
        parts.append(
            f"  {{ {kpfx}_p, sizeof ({kpfx}_p), {kpfx}_q, sizeof ({kpfx}_q),"
            f" {kpfx}_g, sizeof ({kpfx}_g), {kpfx}_y, sizeof ({kpfx}_y) }},\n"
        )
    parts.append("};\n")

    parts.append(f"\nstatic const WycheproofDsaTest {prefix}_tests[] = {{\n")
    for g_idx, t in tests:
        tpfx = f"{prefix}_test{t['tcId']}"
        comment = t["comment"].replace("\\", "\\\\").replace('"', '\\"').replace("*/", "* /")
        if t["result"] == "valid":
            result = "WYCHEPROOF_VALID"
        elif t["result"] == "acceptable":
            result = "WYCHEPROOF_ACCEPTABLE"
        else:
            result = "WYCHEPROOF_INVALID"
        msg_expr = f"{tpfx}_msg, sizeof ({tpfx}_msg)" if t["msg"] else f"{tpfx}_msg, 0"
        parts.append(
            f'  {{ {g_idx}, {t["tcId"]}, "{comment}",'
            f' {msg_expr}, {tpfx}_sig, sizeof ({tpfx}_sig), {result} }},\n'
        )
    parts.append("};\n")

    output_path.write_text("".join(parts))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    emit(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
