"""M4: an sstripped file gets the same profile as the original.

usage: python3 -I tests/oracle/sstrip_oracle.py DUMPER WORKDIR ROOT... [--details FILE]

Every ELF under ROOT that has sections is sstripped (tests/oracle/sstrip.py) into WORKDIR and
both are profiled. Compared: type, kind, machine, class, byte order, judged, canary, nx, pie,
relro, fortify, static, fortified, fortifiable, interp, soname, needed, path, imports and
dangerous functions. Not compared, because sstrip removes what they report: stripped, the
section evidence, and canary/fortify/fortified/fortifiable of static files, which only .symtab
can answer (they must become unknown, which is checked instead). Imports and dangerous
functions of a file without PT_DYNAMIC (read from .dynsym alone, as in a ppc64 vmlinux) are not
compared either: without sections nothing locates that table. Exits 1 on any difference.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elfdump import dump, find_elves  # noqa: E402
from sstrip import sstrip  # noqa: E402

SAME = ("type", "kind", "machine", "class", "big_endian", "arch_tested", "judged", "nx", "pie", "relro",
        "static", "interp", "soname", "needed", "path", "import", "danger")
SYMBOLS = ("canary", "fortify", "fortified", "fortifiable")

def has_sections(data: bytes) -> bool:
    is64, order = data[4] == 2, "little" if data[5] == 1 else "big"
    at = 60 if is64 else 48
    return int.from_bytes(data[at : at + 2], order) != 0

def has_dynamic(data: bytes) -> bool:
    is64, order = data[4] == 2, "little" if data[5] == 1 else "big"
    phoff = int.from_bytes(data[32:40] if is64 else data[28:32], order)
    size = int.from_bytes(data[54:56] if is64 else data[42:44], order)
    count = int.from_bytes(data[56:58] if is64 else data[44:46], order)
    return any(int.from_bytes(data[phoff + i * size : phoff + i * size + 4], order) == 2 for i in range(count))

def compare(before: dict, after: dict, dynamic: bool) -> list[str]:
    fields = SAME if dynamic else tuple(k for k in SAME if k not in ("import", "danger"))
    diffs = [f"{k} {before.get(k)!r} -> {after.get(k)!r}" for k in fields if before.get(k) != after.get(k)]
    if before.get("static") == "yes" and before.get("judged") == "1":
        diffs += [f"{k} {after.get(k)!r}, want unknown" for k in ("canary", "fortify") if after.get(k) != "unknown"]
    else:
        diffs += [f"{k} {before.get(k)!r} -> {after.get(k)!r}" for k in SYMBOLS if before.get(k) != after.get(k)]
    return diffs

def main() -> int:
    args = sys.argv[1:]
    details = None
    if "--details" in args:
        at = args.index("--details")
        details = Path(args[at + 1])
        del args[at : at + 2]
    dumper, work = Path(args[0]), Path(args[1])
    work.mkdir(parents=True, exist_ok=True)
    pairs = []
    for i, path in enumerate(find_elves([Path(a) for a in args[2:]])):
        data = path.read_bytes()
        if len(data) < 64 or data[4] not in (1, 2) or data[5] not in (1, 2) or not has_sections(data):
            continue
        try:
            stripped = sstrip(data)
        except (ValueError, IndexError, __import__("struct").error):
            continue
        target = work / f"{i}.elf"
        target.write_bytes(stripped)
        pairs.append((path, target, has_dynamic(data)))
    before = dump(dumper, [p for p, _, _ in pairs])
    after = dump(dumper, [t for _, t, _ in pairs])
    lines = []
    for path, target, dynamic in pairs:
        for diff in compare(before[str(path)], after[str(target)], dynamic):
            lines.append(f"{path}\t{diff}")
    for _, target, _ in pairs:
        target.unlink()
    print(f"sstripped {len(pairs)} differing {len({line.split(chr(9))[0] for line in lines})}")
    if details:
        details.write_text("\n".join(lines) + "\n")
    return 1 if lines else 0

if __name__ == "__main__":
    sys.exit(main())
