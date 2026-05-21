#!/usr/bin/env python3
"""Generate the static prime tables for RFC 3526 (MODP) and RFC 7919
(FFDHE) Diffie-Hellman groups from the RFC text.

Usage:
  ./tools/gen_dh_named_groups.py <rfc3526.txt> <rfc7919.txt> <output.inc>

Fetch the source RFCs first (no checksum is enforced; the only signal
that the parse worked is the bit-count assertion at the end of this
script):

  curl -L https://www.rfc-editor.org/rfc/rfc3526.txt -o /tmp/rfc3526.txt
  curl -L https://www.rfc-editor.org/rfc/rfc7919.txt -o /tmp/rfc7919.txt
"""
import re
import sys
from pathlib import Path


def extract_hex_block(lines, start_idx, stop_pattern):
    """Collect contiguous hex tokens starting after start_idx until a
    line that matches stop_pattern (typically the "generator is:" line)."""
    out = []
    for line in lines[start_idx:]:
        if stop_pattern.search(line):
            break
        # Pull hex tokens out of the line. Both RFCs indent the prime
        # body and break it into 8-char groups separated by spaces.
        tokens = re.findall(r"[0-9A-Fa-f]{2,}", line)
        # A page-break/header line will also contain hex-ish words
        # ("RFC", "Page"), so require each token to be pure hex of even
        # length to count it.
        for tok in tokens:
            if len(tok) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", tok):
                out.append(tok)
    return "".join(out)


def parse_rfc3526(text):
    lines = text.splitlines()
    groups = {}
    # Sections 3..7 in RFC 3526 cover groups 14..18. Each starts with
    # "N.  <bits>-bit MODP Group" at column 0.
    section_re = re.compile(r"^(\d+)\.\s+(\d+)-bit MODP Group\s*$")
    hex_marker = re.compile(r"^\s*Its hexadecimal value is:\s*$")
    stop = re.compile(r"^\s*The generator is:")

    sec_to_id = {3: 14, 4: 15, 5: 16, 6: 17, 7: 18}
    i = 0
    while i < len(lines):
        m = section_re.match(lines[i])
        if m:
            sec = int(m.group(1))
            bits = int(m.group(2))
            if sec in sec_to_id:
                # Look forward for the hex marker, then collect.
                for j in range(i + 1, min(i + 60, len(lines))):
                    if hex_marker.match(lines[j]):
                        body = extract_hex_block(lines, j + 1, stop)
                        groups[sec_to_id[sec]] = (bits, body.upper())
                        break
        i += 1
    return groups


def parse_rfc7919(text):
    lines = text.splitlines()
    groups = {}
    # Appendix sections "A.1." through "A.5." cover ffdhe2048..ffdhe8192.
    section_re = re.compile(r"^A\.(\d+)\.\s+ffdhe(\d+)\s*$")
    hex_marker = re.compile(r"^\s*The hexadecimal representation of p is:\s*$")
    stop = re.compile(r"^\s*The generator is:")
    i = 0
    while i < len(lines):
        m = section_re.match(lines[i])
        if m:
            bits = int(m.group(2))
            for j in range(i + 1, min(i + 200, len(lines))):
                if hex_marker.match(lines[j]):
                    body = extract_hex_block(lines, j + 1, stop)
                    groups[f"ffdhe{bits}"] = (bits, body.upper())
                    break
        i += 1
    return groups


def emit_array(name, hex_str):
    data = bytes.fromhex(hex_str)
    lines = [f"static const ruint8 {name}[] = {{"]
    line = "  "
    for i, b in enumerate(data):
        if i % 12 == 0 and i != 0:
            lines.append(line.rstrip())
            line = "  "
        line += f"0x{b:02x}, "
    lines.append(line.rstrip())
    lines.append("};")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    rfc3526 = Path(sys.argv[1]).read_text()
    rfc7919 = Path(sys.argv[2]).read_text()
    out = Path(sys.argv[3])

    modp = parse_rfc3526(rfc3526)
    ffdhe = parse_rfc7919(rfc7919)

    assert set(modp.keys()) == {14, 15, 16, 17, 18}, f"missing MODP groups: {modp.keys()}"
    assert set(ffdhe.keys()) == {"ffdhe2048", "ffdhe3072", "ffdhe4096",
                                  "ffdhe6144", "ffdhe8192"}, f"missing FFDHE: {ffdhe.keys()}"
    for gid, (bits, h) in modp.items():
        got = len(h) * 4
        assert got == bits, f"MODP group {gid}: expected {bits} bits, got {got}"
    for name, (bits, h) in ffdhe.items():
        got = len(h) * 4
        assert got == bits, f"{name}: expected {bits} bits, got {got}"

    parts = [
        "/* AUTO-GENERATED from RFC 3526 and RFC 7919 — do not edit by hand.\n"
        " *\n"
        " * Regenerate with tools/gen_dh_named_groups.py after fetching the\n"
        " * source RFCs (see that script's docstring).\n"
        " */\n",
    ]
    for gid in (14, 15, 16, 17, 18):
        bits, h = modp[gid]
        parts.append(emit_array(f"rfc3526_group{gid}_p", h))
    for name in ("ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"):
        bits, h = ffdhe[name]
        parts.append(emit_array(f"rfc7919_{name}_p", h))

    out.write_text("".join(parts))


if __name__ == "__main__":
    main()
