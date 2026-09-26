"""M5: kernels, kernel modules and boot loaders are classified and never judged.

usage: python3 -I tests/oracle/classify_oracle.py DUMPER ROOT...

Every ELF under ROOT is profiled. A file is expected to be left unjudged when its path says what
it is, independently of the library: a name ending in .ko, a vmlinux, a U-Boot image, an OpenSBI
firmware, or anything under /boot/. (Not /lib/modules/ as a whole: its build/ directory holds
userland tools such as modpost and objtool, which are judged.) Prints the count of each kind, the
unjudged files that the path rule does not name (to be read by hand), and every file the path
rule names that was judged. Exits 1 when any such file was judged, or when a file of kind kernel,
kernel module, bare metal, relocatable or core was judged.
"""

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elfdump import dump, find_elves  # noqa: E402

UNJUDGED_PATH = re.compile(r"\.ko$|vmlinu[xz]|u-?boot|opensbi|/boot/", re.IGNORECASE)
UNJUDGED_KINDS = {"kernel", "kernel module", "bare metal", "relocatable", "core"}

def main(args: list[str]) -> int:
    if len(args) < 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    profiles = dump(Path(args[0]), find_elves([Path(a) for a in args[1:]]))
    kinds: Counter = Counter()
    unjudged: Counter = Counter()
    wrong, unnamed = [], []
    for path, p in sorted(profiles.items()):
        if "kind" not in p:
            continue
        judged = p.get("judged") == "1"
        kinds[p["kind"]] += 1
        named = bool(UNJUDGED_PATH.search(path))
        if judged and (named or p["kind"] in UNJUDGED_KINDS):
            wrong.append(f"{path}\t{p['kind']}")
        if not judged:
            unjudged[p["kind"]] += 1
            if not named:
                unnamed.append(f"{path}\t{p['kind']}")
    print("files", sum(kinds.values()))
    print("kinds", dict(sorted(kinds.items())))
    print("not judged", dict(sorted(unjudged.items())))
    for line in unnamed:
        print("not judged, not named by path:", line)
    for line in wrong:
        print("JUDGED:", line)
    print("judged kernels, modules or boot loaders", len(wrong))
    return 1 if wrong else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
