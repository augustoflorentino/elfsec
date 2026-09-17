"""Runs tests/elfs_dump on many files and parses its output into dicts."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def find_elves(roots: list[Path]) -> list[Path]:
    found = []
    for root in roots:
        for path in sorted(root.rglob("*")) if root.is_dir() else [root]:
            if path.is_file() and not path.is_symlink():
                try:
                    with path.open("rb") as f:
                        if f.read(4) == b"\x7fELF":
                            found.append(path)
                except OSError:
                    pass
    return found

def dump(dumper: Path, paths: list[Path]) -> dict[str, dict]:
    text = subprocess.run(
        [str(dumper)], input="\n".join(map(str, paths)) + "\n", capture_output=True, text=True,
        errors="replace", check=True,
    ).stdout
    profiles: dict[str, dict] = {}
    current: dict = {}
    for line in text.splitlines():
        key, _, rest = line.partition(" ")
        if key == "file":
            current = {"needed": [], "path": [], "import": [], "danger": [], "ev": {}}
            profiles[rest] = current
        elif key in ("needed", "import"):
            current[key].append(rest)
        elif key == "path":
            flags, _, entry = rest.partition(" ")
            current["path"].append((int(flags, 16), entry))
        elif key == "danger":
            current["danger"].append(rest)
        elif key == "ev":
            what, source, index, offset = rest.split()
            current["ev"][what] = (int(source), int(index), int(offset))
        elif key != "end":
            current[key] = rest
    return profiles
