#!/usr/bin/env python3
"""Generate a C header of Wycheproof ECDH test vectors.

Reads one Wycheproof JSON (ecdh_<curve>_ecpoint_test.json - the
"EcdhEcpointTest" variant where the peer public key is a raw SEC 1
uncompressed point, not an ASN.1 SubjectPublicKeyInfo). Emits a
self-contained .inc file the ECDH test in test/recdh.c can include.

Usage:
  ./tools/gen_wycheproof_ecdh.py <input.json> <c_prefix> <output.inc>

Re-fetch upstream first:
  curl -L https://raw.githubusercontent.com/C2SP/wycheproof/main/\\
       testvectors_v1/ecdh_secp256r1_ecpoint_test.json \\
       -o /tmp/ecdh_secp256r1_ecpoint.json
"""
import json
import sys
import textwrap
from pathlib import Path


CURVE_NAME_TO_ENUM = {
    "secp192r1": "R_ECURVE_ID_SECP192R1",
    "secp224r1": "R_ECURVE_ID_SECP224R1",
    "secp256r1": "R_ECURVE_ID_SECP256R1",
    "secp384r1": "R_ECURVE_ID_SECP384R1",
    "secp521r1": "R_ECURVE_ID_SECP521R1",
    "secp256k1": "R_ECURVE_ID_SECP256K1",
}


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

    assert len(data["testGroups"]) == 1, "expected one group per ecpoint file"
    group = data["testGroups"][0]
    assert group["encoding"] == "ecpoint", "this generator handles the ecpoint variant only"

    curve_name = group["curve"]
    curve_enum = CURVE_NAME_TO_ENUM.get(curve_name)
    if curve_enum is None:
        raise SystemExit(f"unsupported curve {curve_name!r}")

    parts = []
    parts.append(textwrap.dedent(f"""\
        /* AUTO-GENERATED from {input_path.name} - do not edit by hand.
         *
         * Source: https://github.com/C2SP/wycheproof
         *         testvectors_v1/{input_path.name}
         * Curve: {curve_name}, encoding: {group["encoding"]}
         *
         * Regenerate with tools/gen_wycheproof_ecdh.py.
         */

        """))

    tests = []
    for t in group["tests"]:
        tpfx = f"{prefix}_t{t['tcId']}"
        parts.append(hex_to_c_array(f"{tpfx}_pub", t["public"]))
        parts.append(hex_to_c_array(f"{tpfx}_priv", t["private"]))
        parts.append(hex_to_c_array(f"{tpfx}_shared", t["shared"]))
        tests.append(t)

    parts.append(f"\nstatic const WycheproofEcdhTest {prefix}_tests[] = {{\n")
    for t in tests:
        tpfx = f"{prefix}_t{t['tcId']}"
        comment = t["comment"].replace("\\", "\\\\").replace('"', '\\"').replace("*/", "* /")
        if t["result"] == "valid":
            result = "WYCHEPROOF_VALID"
        elif t["result"] == "acceptable":
            result = "WYCHEPROOF_ACCEPTABLE"
        else:
            result = "WYCHEPROOF_INVALID"
        pub_expr = f"{tpfx}_pub, sizeof ({tpfx}_pub)" if t["public"] else f"{tpfx}_pub, 0"
        shared_expr = (
            f"{tpfx}_shared, sizeof ({tpfx}_shared)" if t["shared"]
            else f"{tpfx}_shared, 0"
        )
        parts.append(
            f'  {{ {curve_enum}, {t["tcId"]}, "{comment}",'
            f' {pub_expr}, {tpfx}_priv, sizeof ({tpfx}_priv),'
            f' {shared_expr}, {result} }},\n'
        )
    parts.append("};\n")

    output_path.write_text("".join(parts))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    emit(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
