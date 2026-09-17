"""M2: elfsec against `readelf -hlWd --dyn-syms` on every ELF under the given roots.

usage: python3 -I tests/oracle/readelf_oracle.py DUMPER ROOT... [--details FILE]

Files without sections (sstrip) add `readelf -D -s`, which sizes the table from the
hash tables. Compares, file by file: e_type; PT_INTERP; the index of PT_GNU_STACK, PT_GNU_RELRO and
PT_INTERP and the X flag of PT_GNU_STACK; BIND_NOW; DT_NEEDED in order; RPATH and RUNPATH
entries in order; the set of undefined dynamic symbol names. Exits 1 on any difference.
"""

import os
import re
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elfdump import dump, find_elves  # noqa: E402

TYPES = {"REL": "1", "EXEC": "2", "DYN": "3", "CORE": "4"}
SEGMENT = re.compile(r"^\s+(\S+)\s+0x\S+\s+0x\S+\s+0x\S+\s+0x\S+\s+0x\S+\s(...)\s+\S+$")
SYMBOL = re.compile(r"^\s*\d+: \S+\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+\[[^\]]*\])?\s+(\S+)\s+(\S+)")
DYNAMIC = re.compile(r"^\s*0x[0-9a-f]+ \((\w+)\)\s+(.*)$")
ENV = dict(os.environ, LC_ALL="C")

def run_readelf(*args: str) -> str:
    return subprocess.run(["readelf", *args], capture_output=True, text=True, errors="replace", env=ENV).stdout

def readelf(path: Path) -> dict:
    out = run_readelf("-hlWd", "--dyn-syms", str(path))
    if "There are no sections in this file." in run_readelf("-SW", str(path)):
        out += run_readelf("-WDs", str(path))
    facts: dict = {"segments": [], "needed": [], "path": [], "imports": set(), "bind_now": False}
    in_segments = False
    for line in out.splitlines():
        _header(line, facts)
        if line.startswith("Program Headers:"):
            in_segments = True
        elif in_segments and (m := SEGMENT.match(line)):
            facts["segments"].append((m.group(1), m.group(2)))
        elif "[Requesting program interpreter: " in line:
            facts["interp"] = line.split("interpreter: ", 1)[1].rstrip("]")
        elif m := DYNAMIC.match(line):
            _dynamic(m.group(1), m.group(2), facts)
        elif m := SYMBOL.match(line):
            if m.group(1) == "UND" and m.group(2) != "<corrupt>":
                facts["imports"].add(m.group(2).split("@", 1)[0])
    return facts

def _header(line: str, facts: dict) -> None:
    if line.strip().startswith("Type:") and "type" not in facts:
        facts["type"] = TYPES.get(line.split(":", 1)[1].split()[0], "?")

def _dynamic(tag: str, value: str, facts: dict) -> None:
    if tag == "NEEDED":
        facts["needed"].append(value.split("[", 1)[1].rsplit("]", 1)[0])
    elif tag in ("RPATH", "RUNPATH"):
        facts["path"].extend(value.split("[", 1)[1].rsplit("]", 1)[0].split(":"))
    elif tag == "BIND_NOW" or (tag == "FLAGS" and "BIND_NOW" in value.split()):
        facts["bind_now"] = True
    elif tag == "FLAGS_1" and "NOW" in value.split():
        facts["bind_now"] = True

def first(segments: list, kind: str) -> int | None:
    return next((i for i, (k, _) in enumerate(segments) if k == kind), None)

def compare(ours: dict, theirs: dict) -> list[tuple[str, str]]:
    diffs = []

    def check(field: str, a: object, b: object) -> None:
        if a != b:
            diffs.append((field, f"elfsec={a!r} readelf={b!r}"))

    check("type", ours.get("type"), theirs.get("type"))
    check("interp", ours.get("interp") or None, theirs.get("interp"))
    check("needed", ours["needed"], theirs["needed"])
    check("path", [entry for _, entry in ours["path"]], theirs["path"])
    check("imports", set(ours["import"]), theirs["imports"])
    if ours.get("judged") == "1":
        _check_segments(ours, theirs, check)
    return diffs

def _check_segments(ours: dict, theirs: dict, check) -> None:
    segments = theirs["segments"]
    ev = ours["ev"]
    stack, relro, interp = first(segments, "GNU_STACK"), first(segments, "GNU_RELRO"), first(segments, "INTERP")
    check("gnu_stack", ev["nx"][1] if ev["nx"][0] == 2 else None, stack)
    if stack is not None:
        check("stack_exec", ours["nx"] == "no", "E" in segments[stack][1])
    check("gnu_relro", ev["relro"][1] if ev["relro"][0] == 2 else None, relro)
    check("interp_segment", ev["static"][1] if ev["static"][0] == 2 else None, interp)
    check("bind_now", ev["bind_now"][0] == 3, theirs["bind_now"])

def main() -> int:
    args = sys.argv[1:]
    details = None
    if "--details" in args:
        at = args.index("--details")
        details = Path(args[at + 1])
        del args[at : at + 2]
    dumper, roots = Path(args[0]), [Path(a) for a in args[1:]]
    paths = find_elves(roots)
    ours = dump(dumper, paths)
    with ThreadPoolExecutor(os.cpu_count()) as pool:
        theirs = dict(zip(paths, pool.map(readelf, paths)))
    fields: Counter[str] = Counter()
    lines = []
    for path in paths:
        profile = ours[str(path)]
        if profile.get("status") != "ok":
            fields["status"] += 1
            lines.append(f"{path}\tstatus\t{profile.get('status')}")
            continue
        for field, text in compare(profile, theirs[path]):
            fields[field] += 1
            lines.append(f"{path}\t{field}\t{text}")
    differing = len({line.split("\t", 1)[0] for line in lines})
    print(f"files {len(paths)} differing {differing}")
    for field, count in sorted(fields.items()):
        print(f"  {field}: {count}")
    if details:
        details.write_text("\n".join(lines) + "\n")
    return 1 if lines else 0

if __name__ == "__main__":
    sys.exit(main())
