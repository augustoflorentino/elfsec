"""M3: elfsec against checksec 3.x on every ELF under the given roots.

usage: python3 -I tests/oracle/checksec_oracle.py DUMPER CHECKSEC ROOT[=LIBC]... [--details FILE]

LIBC is the C library of that root, which checksec needs to judge FORTIFY offline.

Only images elfsec judges (executables, PIE, shared libraries) are compared; kernels, modules,
boot loaders, objects and cores are not judged by design and are counted apart. Compares
canary, NX, PIE, RELRO and FORTIFY (yes/no). Prints the agreement per field; exits 1 when any
field is under 99% once the known checksec faults are set apart. Each disagreement is
explained only by a condition checked on the file itself:

- symtab-address: the file has no sections and the PT_LOAD holding DT_SYMTAB has p_vaddr !=
  p_offset. checksec 3.2.0 (FunctionsFromSymbolTable) reads DT_SYMTAB and DT_STRTAB as file
  offsets, so it reads the wrong bytes and misses the canary import.
- defines: the file defines (does not import) a canary or _chk symbol, as a C library does.
  checksec counts defined symbols; elfsec judges what the file calls, and a definition says
  nothing about how the file was built.
- chk-list: every _chk function the file imports is outside the 18 checksec 3.2.0 knows
  (fortify.go supportedFuncs), e.g. __poll_chk or __read_chk.
- static-unknown: a static file without .symtab; elfsec answers unknown on purpose (nothing
  left to read), checksec answers no.
- static-symtab: a static file with .symtab that defines _chk functions; checksec 3.2.0 reads
  only .dynsym for FORTIFY.
- empty-dynamic: a dynamic file whose PT_DYNAMIC maps no bytes (a separate debug file); there
  is no import table to read, elfsec answers unknown, checksec no.
- relro-segment: the file has no PT_GNU_RELRO but asks for bind-now; checksec 3.2.0 calls
  that Full RELRO, though nothing is made read-only after relocation.
"""

import re
import struct

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elfdump import dump, find_elves  # noqa: E402

FIELDS = ("canary", "nx", "pie", "relro", "fortify")
DEFINED = re.compile(
    r"^\s*\d+: \S+\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+\[[^\]]*\])?\s+(?!UND)\S+\s+(__stack_chk_\w+|__\w+_chk)\b"
)

CHECKSEC_CHK = {
    "__memcpy_chk", "__memmove_chk", "__mempcpy_chk", "__memset_chk", "__stpcpy_chk", "__stpncpy_chk",
    "__strcat_chk", "__strcpy_chk", "__strncat_chk", "__strncpy_chk", "__snprintf_chk", "__sprintf_chk",
    "__vsnprintf_chk", "__vsprintf_chk", "__fprintf_chk", "__printf_chk", "__vfprintf_chk", "__vprintf_chk",
}
GNU_RELRO = 0x6474E552

def _segments(data: bytes) -> list[tuple[int, int, int, int]]:
    is64, order = data[4] == 2, "<" if data[5] == 1 else ">"
    phoff = struct.unpack_from(order + ("Q" if is64 else "I"), data, 32 if is64 else 28)[0]
    size, count = struct.unpack_from(order + "HH", data, 54 if is64 else 42)
    found = []
    for i in range(count):
        if is64:
            kind, _, offset, vaddr, _, filesz = struct.unpack_from(order + "IIQQQQ", data, phoff + i * size)
        else:
            kind, offset, vaddr, _, filesz = struct.unpack_from(order + "IIIII", data, phoff + i * size)
        found.append((kind, offset, vaddr, filesz))
    return found

def symtab_address(path: Path) -> bool:
    data = path.read_bytes()
    is64, order = data[4] == 2, "<" if data[5] == 1 else ">"
    if struct.unpack_from(order + "H", data, 60 if is64 else 48)[0]:
        return False
    segments = _segments(data)
    dynamic = next((s for s in segments if s[0] == 2), None)
    symtab, step = None, 16 if is64 else 8
    for at in range(dynamic[1], dynamic[1] + dynamic[3], step) if dynamic else ():
        tag, value = struct.unpack_from(order + ("qQ" if is64 else "iI"), data, at)
        symtab = value if tag == 6 else symtab
    load = next((s for s in segments if s[0] == 1 and symtab is not None and s[2] <= symtab < s[2] + s[3]), None)
    return load is not None and load[1] != load[2]

def defines(path: Path, field: str) -> bool:
    out = subprocess.run(["readelf", "-WDs", str(path)], capture_output=True, text=True,
                         errors="replace", env={"LC_ALL": "C", "PATH": "/usr/bin"}).stdout
    names = {m.group(1) for line in out.splitlines() if (m := DEFINED.match(line))}
    if field == "canary":
        return any(n.startswith("__stack_chk_") for n in names)
    return any(not n.startswith("__stack_chk_") for n in names)

def bind_now(path: Path) -> bool:
    out = subprocess.run(["readelf", "-dW", str(path)], capture_output=True, text=True,
                         errors="replace", env={"LC_ALL": "C", "PATH": "/usr/bin"}).stdout
    return any(("(BIND_NOW)" in line) or ("(FLAGS)" in line and "BIND_NOW" in line)
               or ("(FLAGS_1)" in line and " NOW" in line) for line in out.splitlines())

def explain(path: Path, field: str, profile: dict, other: str) -> str | None:
    mine = profile[field]
    if field == "canary" and mine == "yes" and other == "no" and symtab_address(path):
        return "symtab-address"
    if field in ("canary", "fortify") and mine == "no" and other == "yes" and defines(path, field):
        return "defines"
    chk = {n for n in profile["import"] if n.endswith("_chk") and not n.startswith("__stack_chk_")}
    if field == "fortify" and mine == "yes" and other == "no" and chk and not chk & CHECKSEC_CHK:
        return "chk-list"
    if mine == "unknown" and other == "no" and profile["static"] == "yes" and profile["stripped"] == "yes":
        return "static-unknown"
    if field == "fortify" and mine == "yes" and other == "no" and profile["static"] == "yes":
        if profile["stripped"] == "no" and not profile["import"]:
            return "static-symtab"
    if mine == "unknown" and other == "no" and profile["static"] == "no":
        if any(s[0] == 2 and s[3] == 0 for s in _segments(path.read_bytes())):
            return "empty-dynamic"
    if field == "relro" and mine == "none" and other == "full" and bind_now(path):
        if all(s[0] != GNU_RELRO for s in _segments(path.read_bytes())):
            return "relro-segment"
    return None

def checksec(binary: Path, paths: list[Path], libc: str | None = None) -> dict[str, dict]:
    extra = ["--libc", libc] if libc else []
    out = subprocess.run(
        [str(binary), "listfile", "-", "--output", "json", "--no-banner", "--no-warnings", "--color", "never", *extra],
        input="\n".join(map(str, paths)) + "\n", capture_output=True, text=True, errors="replace",
    ).stdout
    return {entry["name"]: {k: v["value"] for k, v in entry["checks"].items()} for entry in json.loads(out)}

def theirs(checks: dict) -> dict[str, str]:
    return {
        "canary": {"Canary Found": "yes", "No Canary Found": "no"}.get(checks.get("canary"), "?"),
        "nx": {"NX enabled": "yes", "NX disabled": "no", "No GNU_STACK": "no"}.get(checks.get("nx"), "?"),
        "pie": {"PIE Enabled": "yes", "DSO": "yes", "Static PIE": "yes", "PIE Disabled": "no"}.get(
            checks.get("pie"), "?"
        ),
        "relro": {"Full RELRO": "full", "Partial RELRO": "partial", "No RELRO": "none"}.get(checks.get("relro"), "?"),
        "fortify": {"Yes": "yes", "No": "no"}.get(checks.get("fortify_source"), "?"),
    }

def main() -> int:
    args = sys.argv[1:]
    details = None
    if "--details" in args:
        at = args.index("--details")
        details = Path(args[at + 1])
        del args[at : at + 2]
    dumper, binary = Path(args[0]), Path(args[1])
    paths, reference, ours = [], {}, {}
    for arg in args[2:]:
        root, _, libc = arg.partition("=")
        found = find_elves([Path(root)])
        mine = dump(dumper, found)
        judged_here = [p for p in found if mine[str(p)].get("judged") == "1"]
        for start in range(0, len(judged_here), 500):
            reference.update(checksec(binary, judged_here[start : start + 500], libc or None))
        paths += found
        ours.update(mine)
    judged = [p for p in paths if ours[str(p)].get("judged") == "1"]
    agree: Counter[str] = Counter()
    explained: Counter[tuple[str, str]] = Counter()
    lines = []
    for path in judged:
        mine, other = ours[str(path)], theirs(reference.get(str(path), {}))
        for field in FIELDS:
            if mine[field] == other[field]:
                agree[field] += 1
                continue
            reason = explain(path, field, mine, other[field])
            explained[field, reason or "unexplained"] += 1
            lines.append(f"{path}\t{field}\telfsec={mine[field]} checksec={other[field]}\t{reason or 'unexplained'}")
    total = len(judged)
    print(f"files {len(paths)} judged {total} not judged {len(paths) - total}")
    failed = False
    for field in FIELDS:
        raw = 100.0 * agree[field] / total if total else 100.0
        compared = total - sum(n for (f, r), n in explained.items() if f == field and r != "unexplained")
        share = 100.0 * agree[field] / compared if compared else 100.0
        failed |= share < 99.0
        reasons = ", ".join(f"{r} {n}" for (f, r), n in sorted(explained.items()) if f == field)
        print(f"  {field}: raw {agree[field]}/{total} = {raw:.2f}%; "
              f"without explained {agree[field]}/{compared} = {share:.2f}%" + (f" ({reasons})" if reasons else ""))
    if details:
        details.write_text("\n".join(lines) + "\n")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
