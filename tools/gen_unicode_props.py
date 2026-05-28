#!/usr/bin/env python3
"""Generate Unicode character-property + simple-case-mapping tables.

Reads the vendored UCD files under data/ucd/<version>/ and emits a
C include file at rlib/charset/runicode-props.inc with:

  - A two-level lookup keyed by codepoint into per-codepoint property
    records. Each record carries the General_Category (5 bits) and
    the White_Space derived-property flag (1 bit), packed into one
    byte. The lookup is stage-1 page index (uint16) + stage-2 page
    of 256 bytes; only unique stage-2 pages are stored.

  - A sparse, sorted simple_case_mappings table: one row per
    codepoint that has any non-identity Simple_Uppercase /
    Simple_Lowercase / Simple_Titlecase mapping. Runtime does a
    binary search.

Usage:
  ./tools/gen_unicode_props.py <ucd_dir> <output.inc>

Input files expected under ucd_dir:
  UnicodeData.txt
  PropList.txt
"""
import sys
from pathlib import Path


# General_Category values per UAX #44 §5.7.1.
GC_CODES = [
    "Lu", "Ll", "Lt", "Lm", "Lo",
    "Mn", "Mc", "Me",
    "Nd", "Nl", "No",
    "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
    "Sm", "Sc", "Sk", "So",
    "Zs", "Zl", "Zp",
    "Cc", "Cf", "Cs", "Co", "Cn",
]
assert len(GC_CODES) == 30  # 5 bits.
GC_TO_INDEX = {gc: i for i, gc in enumerate(GC_CODES)}

# Flag bit packed into the GC byte alongside the 5-bit GC index.
WHITE_SPACE_BIT = 1 << 5

PAGE_SIZE = 256
TOTAL_CODEPOINTS = 0x110000
NUM_PAGES = TOTAL_CODEPOINTS // PAGE_SIZE  # 4352


def parse_unicode_data(path):
    """Yield (cp, gc, simple_upper, simple_lower, simple_title) for every
    assigned codepoint. Range entries (`...First...` / `...Last...`)
    expand to the full closed interval. Unassigned codepoints aren't
    yielded - the caller defaults them to "Cn"."""
    gc_by_cp = {}
    upper_by_cp = {}
    lower_by_cp = {}
    title_by_cp = {}

    pending_range_start = None
    pending_range_gc = None

    def parse_hex(s):
        return int(s, 16) if s else None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split(";")
            cp = int(parts[0], 16)
            name = parts[1]
            gc = parts[2]
            simple_upper = parse_hex(parts[12])
            simple_lower = parse_hex(parts[13])
            simple_title = parse_hex(parts[14])

            if name.endswith(", First>"):
                pending_range_start = cp
                pending_range_gc = gc
                continue
            elif name.endswith(", Last>"):
                assert pending_range_start is not None
                for r_cp in range(pending_range_start, cp + 1):
                    gc_by_cp[r_cp] = pending_range_gc
                pending_range_start = None
                pending_range_gc = None
                continue

            gc_by_cp[cp] = gc
            if simple_upper is not None:
                upper_by_cp[cp] = simple_upper
            if simple_lower is not None:
                lower_by_cp[cp] = simple_lower
            if simple_title is not None:
                title_by_cp[cp] = simple_title

    return gc_by_cp, upper_by_cp, lower_by_cp, title_by_cp


def parse_white_space(path):
    """Return a set of codepoints with the White_Space property per
    PropList.txt."""
    out = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            range_str, _, prop = stripped.partition(";")
            if prop.strip() != "White_Space":
                continue
            range_str = range_str.strip()
            if ".." in range_str:
                a, b = range_str.split("..")
                lo, hi = int(a, 16), int(b, 16)
                for cp in range(lo, hi + 1):
                    out.add(cp)
            else:
                out.add(int(range_str, 16))
    return out


def build_property_bytes(gc_by_cp, white_space):
    """Materialise the full 0x110000-byte property array. Each byte is
    `GC_index | (White_Space ? 0x20 : 0)`."""
    cn_idx = GC_TO_INDEX["Cn"]
    arr = bytearray(TOTAL_CODEPOINTS)
    for cp in range(TOTAL_CODEPOINTS):
        gc = gc_by_cp.get(cp, "Cn")
        idx = GC_TO_INDEX[gc]
        byte = idx
        if cp in white_space:
            byte |= WHITE_SPACE_BIT
        arr[cp] = byte
    return arr


def build_two_level_table(props):
    """Slice props into PAGE_SIZE chunks and dedup; return (stage1,
    unique_pages) where stage1[i] = index of props[i*PAGE_SIZE...]
    in unique_pages."""
    unique = []
    page_index = {}
    stage1 = []
    for page_no in range(NUM_PAGES):
        page = bytes(props[page_no * PAGE_SIZE:(page_no + 1) * PAGE_SIZE])
        if page not in page_index:
            page_index[page] = len(unique)
            unique.append(page)
        stage1.append(page_index[page])
    return stage1, unique


def build_case_table(upper_by_cp, lower_by_cp, title_by_cp):
    """Build the sparse simple-case-mapping table. One row per
    codepoint with any non-identity mapping; deltas stored as signed
    32-bit ints (most fit in int16 but a handful of mappings cross
    the 16-bit boundary, so just use 32-bit and skip the dictionary
    indirection).

    Per UAX #44, an empty Simple_Titlecase_Mapping defaults to
    Simple_Uppercase_Mapping (not to the codepoint itself); current
    UCD snapshots always emit both columns explicitly but this
    fallback keeps the generator spec-correct against future
    snapshots that might omit the duplicate."""
    rows = []
    cps = set(upper_by_cp) | set(lower_by_cp) | set(title_by_cp)
    for cp in sorted(cps):
        u = upper_by_cp.get(cp, cp)
        l = lower_by_cp.get(cp, cp)
        t = title_by_cp.get(cp, upper_by_cp.get(cp, cp))
        rows.append((cp, u - cp, l - cp, t - cp))
    return rows


def emit(out_path, ucd_dir, stage1, pages, cases):
    """Render the .inc file. Stage-1 entries are stage-2-page indices
    (16-bit); stage-2 pages are 256-byte char arrays. The case table
    is a sorted RUnicodePropsCaseEntry array."""
    page_bytes = sum(len(p) for p in pages)
    stage1_bytes = len(stage1) * 2
    case_bytes = len(cases) * (4 + 4 + 4 + 4)  # cp + 3 deltas, 32-bit each.

    lines = []
    add = lines.append

    add(f"/* AUTO-GENERATED by tools/gen_unicode_props.py - do not edit by hand.")
    add(f" *")
    add(f" * Source: UCD {ucd_dir.name} (UnicodeData.txt + PropList.txt).")
    add(f" *")
    add(f" * Layout:")
    add(f" *   - Two-level codepoint property table (General_Category + White_Space")
    add(f" *     flag): stage-1 is a {len(stage1)}-entry uint16_t array indexing")
    add(f" *     into {len(pages)} unique stage-2 pages of {PAGE_SIZE} bytes each.")
    add(f" *     Each stage-2 byte packs GC into the low 5 bits and a White_Space")
    add(f" *     flag at bit 5.")
    add(f" *   - Sparse simple-case-mapping table sorted by codepoint:")
    add(f" *     {len(cases)} entries, each carrying signed deltas to apply for")
    add(f" *     simple_uppercase / simple_lowercase / simple_titlecase. Runtime")
    add(f" *     binary-searches by codepoint; codepoints not present have")
    add(f" *     identity mappings.")
    add(f" *")
    add(f" * Sizes:")
    add(f" *   stage-1: {stage1_bytes} bytes")
    add(f" *   stage-2: {page_bytes} bytes ({len(pages)} pages * {PAGE_SIZE} bytes)")
    add(f" *   cases:   {case_bytes} bytes ({len(cases)} entries)")
    add(f" *   total:   {stage1_bytes + page_bytes + case_bytes} bytes")
    add(f" */")
    add("")
    add(f"#define R_UNICODE_PROPS_UCD_VERSION  \"{ucd_dir.name}\"")
    add(f"#define R_UNICODE_PROPS_PAGE_SIZE    {PAGE_SIZE}")
    add(f"#define R_UNICODE_PROPS_NUM_PAGES    {len(pages)}")
    add(f"#define R_UNICODE_PROPS_GC_MASK      0x1f")
    add(f"#define R_UNICODE_PROPS_WHITE_SPACE  0x20")
    add("")
    add("/* General_Category 5-bit encoding. Indices into this table */")
    add("/* are the low 5 bits of each stage-2 byte. */")
    for i, gc in enumerate(GC_CODES):
        add(f"#define R_UNICODE_GC_{gc.upper():<3} {i:>2}u")
    add("")

    add("/* Stage-2 unique pages (each 256 bytes). */")
    add(f"static const ruint8 g__unicode_props_pages[{len(pages)}][R_UNICODE_PROPS_PAGE_SIZE] = {{")
    for page in pages:
        add("  {")
        for j in range(0, PAGE_SIZE, 16):
            add("    " + ", ".join(f"0x{b:02x}" for b in page[j:j+16]) + ",")
        add("  },")
    add("};")
    add("")

    add("/* Stage-1 page indices. */")
    add(f"static const ruint16 g__unicode_props_stage1[{len(stage1)}] = {{")
    for j in range(0, len(stage1), 16):
        add("  " + ", ".join(str(x) for x in stage1[j:j+16]) + ",")
    add("};")
    add("")

    add("/* Sparse simple-case-mapping table, sorted by codepoint. */")
    add("typedef struct {")
    add("  ruint32 cp;")
    add("  rint32 upper_delta;")
    add("  rint32 lower_delta;")
    add("  rint32 title_delta;")
    add("} RUnicodePropsCaseEntry;")
    add("")
    add(f"static const RUnicodePropsCaseEntry g__unicode_props_cases[{len(cases)}] = {{")
    for cp, du, dl, dt in cases:
        add(f"  {{ 0x{cp:06x}, {du:>7}, {dl:>7}, {dt:>7} }},")
    add("};")
    add("")

    Path(out_path).write_text("\n".join(lines) + "\n")


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    ucd_dir = Path(argv[1])
    out = argv[2]

    gc_by_cp, upper_by_cp, lower_by_cp, title_by_cp = parse_unicode_data(
        ucd_dir / "UnicodeData.txt")
    white_space = parse_white_space(ucd_dir / "PropList.txt")

    props = build_property_bytes(gc_by_cp, white_space)
    stage1, pages = build_two_level_table(props)
    cases = build_case_table(upper_by_cp, lower_by_cp, title_by_cp)

    emit(out, ucd_dir, stage1, pages, cases)

    stage1_bytes = len(stage1) * 2
    page_bytes = sum(len(p) for p in pages)
    case_bytes = len(cases) * 16
    total = stage1_bytes + page_bytes + case_bytes
    print(f"UCD {ucd_dir.name}")
    print(f"  stage-1: {stage1_bytes:>6} bytes ({len(stage1)} entries)")
    print(f"  stage-2: {page_bytes:>6} bytes ({len(pages)} unique pages of {PAGE_SIZE} bytes)")
    print(f"  cases:   {case_bytes:>6} bytes ({len(cases)} entries)")
    print(f"  total:   {total:>6} bytes ({total / 1024.0:.1f} KiB)")


if __name__ == "__main__":
    main(sys.argv)
