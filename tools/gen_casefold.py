#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
gen_casefold.py — Generate SaltyFS case-folding table from Unicode CaseFolding.txt.

Reads the official Unicode 15.1.0 `CaseFolding.txt` (committed at
`tools/data/CaseFolding-15.1.txt`), keeps only the **Common** (`C`) and
**Simple** (`S`) status entries — which are the 1:1 codepoint mappings usable
without changing UTF-8 byte length in the 1:1 sense required by SaltyFS —
and emits a sorted Rust array into
`lib/trona/substrate/casefold_table.rs`.

Full (`F`, 1→many) and Turkic (`T`, language-specific) entries are
intentionally dropped: see `docs/design/saltyfs.md` for why SaltyFS v1 only
applies Simple Case-Folding.

Usage:
    python3 tools/gen_casefold.py

The script is deterministic: running it twice produces byte-identical output.
Both the input `CaseFolding-15.1.txt` and the generated `casefold_table.rs`
are committed so that builds do not require network access and stay
reproducible.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INPUT = REPO_ROOT / "tools" / "data" / "CaseFolding-15.1.txt"
OUTPUT = REPO_ROOT / "lib" / "trona" / "substrate" / "casefold_table.rs"


def parse_case_folding(path: Path) -> list[tuple[int, int]]:
    """Parse CaseFolding.txt and return [(source_cp, target_cp), ...] for C+S only."""
    pairs: list[tuple[int, int]] = []
    line_re = re.compile(
        r"^([0-9A-Fa-f]+);\s*([CSFT]);\s*([0-9A-Fa-f ]+);"
    )
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = line_re.match(line)
            if not m:
                continue
            status = m.group(2)
            if status not in ("C", "S"):
                # F (Full) folds to multiple codepoints — can't represent as (u32,u32).
                # T (Turkic) is language-specific — out of scope.
                continue
            src = int(m.group(1), 16)
            mapping = m.group(3).split()
            if len(mapping) != 1:
                # Defensive: C/S should always be 1:1.
                continue
            tgt = int(mapping[0], 16)
            pairs.append((src, tgt))
    pairs.sort(key=lambda p: p[0])
    return pairs


def format_header(count: int, source: str) -> str:
    return f"""// SPDX-License-Identifier: GPL-2.0-only
// Generated from {source} — DO NOT EDIT.
//
// Run `python3 tools/gen_casefold.py` to regenerate.
//
// This table carries Unicode 15.1.0 Simple Case-Folding pairs (status C+S
// from CaseFolding.txt). Full (F) and Turkic (T) mappings are omitted by
// design — see docs/design/saltyfs.md for the rationale.
//
// Entries are sorted by source codepoint to enable binary search.
// Total entries: {count}

pub(crate) const CASEFOLD_TABLE: &[(u32, u32)] = &[
"""


def format_entry(src: int, tgt: int) -> str:
    return f"    (0x{src:04X}, 0x{tgt:04X}),\n"


def format_footer() -> str:
    return "];\n"


def main() -> int:
    if not INPUT.exists():
        print(f"error: {INPUT} not found", file=sys.stderr)
        print(
            "Download from https://www.unicode.org/Public/15.1.0/ucd/CaseFolding.txt",
            file=sys.stderr,
        )
        return 1

    pairs = parse_case_folding(INPUT)
    if not pairs:
        print("error: no C/S case-folding pairs parsed", file=sys.stderr)
        return 1

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as f:
        f.write(format_header(len(pairs), INPUT.name))
        for src, tgt in pairs:
            f.write(format_entry(src, tgt))
        f.write(format_footer())

    print(f"wrote {OUTPUT} ({len(pairs)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
