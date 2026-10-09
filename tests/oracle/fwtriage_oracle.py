"""M1: the profile of fwtriage (analyzers/hardening.py) against the one of elfsec, file by file.

usage: FWTRIAGE/.venv/bin/python tests/oracle/fwtriage_oracle.py DUMPER FWTRIAGE WORKDIR [ROOT...]

FWTRIAGE is a checkout of fwtriage with its environment installed. Two sets of ELF files are
compared: every ELF the fwtriage corpus (tests/corpus/scenarios.py) puts in front of the hardening
analyzer while each scenario is scanned, plus every combination of the corpus ELF writer's Profile
(tests/corpus/writers/elf.py), written to WORKDIR; and every ELF under each ROOT. For
each file fwtriage gives a BinaryProfile or None (not judged) and elfsec a profile.

Each difference is put under one of the rules in divergencias.txt (items 1-6) when the file shows
that rule's cause; what no rule explains is printed and makes the exit status 1.
"""

import hashlib
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elfdump import dump, find_elves  # noqa: E402

ARCH = "6"  # ELFS_SRC_ARCH
FIELDS = ("canary", "nx", "pie", "relro", "fortify", "static")

def corpus_elves(fwtriage: Path, workdir: Path) -> dict[Path, object]:
    """Scans every corpus scenario and keeps what the hardening analyzer said about each ELF."""
    sys.path.insert(0, str(fwtriage))
    from fwtriage.analyzers import hardening
    from fwtriage.app import scan
    from fwtriage.model import Policy
    from tests.corpus.scenarios import SCENARIOS

    seen: dict[Path, object] = {}
    original = hardening.profile

    def capture(entry, artifact):
        result = original(entry, artifact)
        if entry.data[:4] == b"\x7fELF":
            name = f"{hashlib.sha256(entry.data).hexdigest()[:16]}-{Path(entry.path).name}"
            out = workdir / name
            out.write_bytes(entry.data)
            seen[out] = result
        return result

    hardening.profile = capture
    try:
        for scenario in SCENARIOS:
            image = workdir / f"{scenario.name}.image"
            image.write_bytes(scenario.build())
            scan(image, Policy(limits=scenario.limits))
            image.unlink()
    finally:
        hardening.profile = original
    seen.update(writer_elves(workdir))
    return seen

def writer_elves(workdir: Path) -> dict[Path, object]:
    """Every combination of the corpus writer's switches, each with four import lists."""
    from itertools import product

    from fwtriage.analyzers.hardening import profile
    from fwtriage.model import Entry
    from fwtriage.model.vfs import EntryKind
    from tests.corpus.writers.elf import Profile, executable

    imports = (("__stack_chk_fail", "printf"), ("strcpy", "system"), (), ("__printf_chk", "__stack_chk_guard"))
    seen: dict[Path, object] = {}
    for n, (flags, names) in enumerate(product(product((False, True), repeat=7), imports)):
        pie, nx, relro, bind_now, gnu_hash, static, bare = flags
        data = executable(Profile(pie, nx, relro, bind_now, names, gnu_hash, static, bare))
        out = workdir / f"writer-{n:03d}"
        out.write_bytes(data)
        seen[out] = profile(Entry(path=f"/bin/writer-{n:03d}", kind=EntryKind.FILE, data=data), "writer")
    return seen

def root_elves(roots: list[Path]) -> dict[Path, object]:
    from fwtriage.analyzers.hardening import profile
    from fwtriage.model import Entry
    from fwtriage.model.vfs import EntryKind

    seen: dict[Path, object] = {}
    for path in find_elves(roots):
        seen[path] = profile(Entry(path=str(path), kind=EntryKind.FILE, data=path.read_bytes()), "root")
    return seen

def fw_answers(b) -> dict[str, str]:
    yes = {True: "yes", False: "no"}
    return {
        "canary": yes[b.canary], "nx": yes[b.nx], "pie": yes[b.pie], "relro": b.relro,
        "fortify": yes[b.fortify], "static": yes[b.static],
    }

def field_cause(name: str, fw: str, el: dict) -> str | None:
    """The rule of divergencias.txt that explains a field difference, or None."""
    if name in ("canary", "fortify") and el.get("static") == "yes":
        return "2 static: read from .symtab or unknown"
    if name == "nx" and el["ev"].get("nx", ("",))[0] == int(ARCH) and fw == "no":
        return "4 nx: architecture default"
    if name in ("canary", "fortify") and el.get(name) == "unknown" and fw == "no" and not el["import"]:
        return "6 no readable symbol table: unknown"
    return None

def judged_cause(fw, el: dict) -> str | None:
    if fw is None and el.get("kind") == "shared library":
        return "1 shared library judged"
    if fw is not None and el.get("kind") == "bare metal":
        return "3 bare metal rule"
    return None

def compare(seen: dict[Path, object], profiles: dict[str, dict], causes: Counter, agree: Counter) -> list[str]:
    unexplained = []
    for path, fw in seen.items():
        el = profiles.get(str(path), {})
        judged = el.get("judged") == "1"
        if (fw is not None) != judged:
            cause = judged_cause(fw, el)
            causes[cause or "unexplained"] += 1
            if cause is None:
                unexplained.append(f"{path}\tjudged: fwtriage {fw is not None}, elfsec {judged} ({el.get('kind')})")
            continue
        if fw is None:
            agree["both unjudged"] += 1
            continue
        for name, value in fw_answers(fw).items():
            mine = el.get(name)
            if mine == value:
                agree[name] += 1
                continue
            cause = field_cause(name, value, el)
            causes[cause or "unexplained"] += 1
            if cause is None:
                unexplained.append(f"{path}\t{name}: fwtriage {value}, elfsec {mine}")
    return unexplained

def main(args: list[str]) -> int:
    if len(args) < 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    dumper, fwtriage, workdir = Path(args[0]), Path(args[1]), Path(args[2])
    workdir.mkdir(parents=True, exist_ok=True)
    seen = corpus_elves(fwtriage, workdir)
    print("corpus ELF files", len(seen), "judged by fwtriage", sum(v is not None for v in seen.values()))
    rooted = root_elves([Path(a) for a in args[3:]])
    print("root ELF files", len(rooted), "judged by fwtriage", sum(v is not None for v in rooted.values()))
    seen.update(rooted)
    profiles = dump(dumper, list(seen))
    causes: Counter = Counter()
    agree: Counter = Counter()
    unexplained = compare(seen, profiles, causes, agree)
    print("agree", dict(sorted(agree.items())))
    print("differ", dict(sorted(causes.items())))
    for line in unexplained[:50]:
        print("UNEXPLAINED:", line)
    return 1 if unexplained else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
