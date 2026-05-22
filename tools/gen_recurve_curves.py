#!/usr/bin/env python3
"""Generate the static curve parameter tables for the prime curves rlib
supports.

For each named curve emits four byte arrays — p (field prime), a, b
(short-Weierstrass coefficients), n (group order of G) — plus the
generator's X and Y coordinates. A `REcurveParamData` lookup table
indexed by REcurveID lets the runtime initialiser pull them in.

Source values: SEC 2 v2 (secp*r1, secp256k1) and NIST FIPS 186-4
(P-192, P-224, P-256, P-384, P-521 are the same curves as secp192r1
through secp521r1).

Usage:
  ./tools/gen_recurve_curves.py <output.inc>
"""
import sys
from pathlib import Path


# Each entry: (rlib_enum_name, p, a, b, n, Gx, Gy).
# Coefficients given as hex strings; `a` is often p-3 for NIST curves
# but we list it expanded so the lookup is uniform.
CURVES = [
    (
        "R_ECURVE_ID_SECP192R1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
        "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
    ),
    (
        "R_ECURVE_ID_SECP224R1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
        "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
        "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
        "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
    ),
    (
        "R_ECURVE_ID_SECP256R1",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    ),
    (
        "R_ECURVE_ID_SECP384R1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "FFFFFFFF0000000000000000FFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "FFFFFFFF0000000000000000FFFFFFFC",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
        "C656398D8A2ED19D2A85C8EDD3EC2AEF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
        "5502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
        "0A60B1CE1D7E819D7A431D7C90EA0E5F",
    ),
    (
        "R_ECURVE_ID_SECP521R1",
        # p = 2^521 - 1, encoded as 66 bytes: 0x01 then 65 * 0xFF.
        "01" + "FF" * 65,
        # a = p - 3
        "01" + "FF" * 64 + "FC",
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
        "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
        "3F00",
        # n: 521-bit group order, padded to 66 bytes (top byte 0x01).
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E9138"
        "6409",
        "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
        "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5"
        "BD66",
        "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
        "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD1"
        "6650",
    ),
    (
        "R_ECURVE_ID_SECP256K1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    ),
]


def hex_to_c_array(name: str, hex_str: str) -> str:
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    data = bytes.fromhex(hex_str)
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


def _sanity_check_curves() -> None:
    """Fail fast on hex typos: every G must satisfy y^2 = x^3 + a*x + b mod p.

    This is cheap to compute and catches the kind of off-by-N-character
    mistakes that are otherwise invisible until point arithmetic produces
    nonsense at runtime.
    """
    for name, p_hex, a_hex, b_hex, n_hex, gx_hex, gy_hex in CURVES:
        p = int(p_hex.replace(" ", ""), 16)
        a = int(a_hex.replace(" ", ""), 16)
        b = int(b_hex.replace(" ", ""), 16)
        gx = int(gx_hex.replace(" ", ""), 16)
        gy = int(gy_hex.replace(" ", ""), 16)
        n = int(n_hex.replace(" ", ""), 16)
        lhs = (gy * gy) % p
        rhs = (gx * gx * gx + a * gx + b) % p
        if lhs != rhs:
            raise SystemExit(f"{name}: G is not on the curve - check hex constants")
        if n <= 1 or n >= p * 2:
            raise SystemExit(f"{name}: implausible group order n")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    _sanity_check_curves()
    out = Path(sys.argv[1])
    parts = [
        "/* AUTO-GENERATED from tools/gen_recurve_curves.py — do not edit by hand.\n"
        " *\n"
        " * Short-Weierstrass curve parameters (p, a, b, n, Gx, Gy) for the\n"
        " * prime curves rlib's REcurveID enum names. Values sourced from\n"
        " * SEC 2 v2 and NIST FIPS 186-4.\n"
        " */\n\n"
    ]
    for name, p, a, b, n, gx, gy in CURVES:
        slug = name.replace("R_ECURVE_ID_", "").lower()
        parts.append(hex_to_c_array(f"rec_{slug}_p", p))
        parts.append(hex_to_c_array(f"rec_{slug}_a", a))
        parts.append(hex_to_c_array(f"rec_{slug}_b", b))
        parts.append(hex_to_c_array(f"rec_{slug}_n", n))
        parts.append(hex_to_c_array(f"rec_{slug}_gx", gx))
        parts.append(hex_to_c_array(f"rec_{slug}_gy", gy))

    parts.append("\nstatic const REcurveParamData g__recurves[] = {\n")
    for name, p, _a, _b, _n, _gx, _gy in CURVES:
        slug = name.replace("R_ECURVE_ID_", "").lower()
        pbytes = len(bytes.fromhex(p.replace(" ", "").replace("\n", "")))
        parts.append(
            f"  {{ {name}, {pbytes},\n"
            f"    rec_{slug}_p,  sizeof (rec_{slug}_p),\n"
            f"    rec_{slug}_a,  sizeof (rec_{slug}_a),\n"
            f"    rec_{slug}_b,  sizeof (rec_{slug}_b),\n"
            f"    rec_{slug}_n,  sizeof (rec_{slug}_n),\n"
            f"    rec_{slug}_gx, sizeof (rec_{slug}_gx),\n"
            f"    rec_{slug}_gy, sizeof (rec_{slug}_gy) }},\n"
        )
    parts.append("};\n")

    out.write_text("".join(parts))


if __name__ == "__main__":
    main()
