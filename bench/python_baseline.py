"""G9: the Python that elfsec replaces, timed the way bench/throughput.c times elfsec.

usage: FWTRIAGE/.venv/bin/python bench/python_baseline.py FWTRIAGE < LIST

Each file is read once, then profiled by fwtriage's analyzers/hardening.py profile() five times;
the fastest run counts. Prints the median and 90th percentile per file and the sum, in process
CPU time, as throughput.c does.
"""

import statistics
import sys
import time
from pathlib import Path

def main(args: list[str]) -> int:
    if len(args) != 1:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    sys.path.insert(0, args[0])
    from fwtriage.analyzers.hardening import profile
    from fwtriage.model import Entry
    from fwtriage.model.vfs import EntryKind

    best = []
    for line in sys.stdin:
        path = line.rstrip("\n")
        if not path:
            continue
        entry = Entry(path=path, kind=EntryKind.FILE, data=Path(path).read_bytes())
        runs = []
        for _ in range(5):
            start = time.process_time()
            profile(entry, "bench")
            runs.append(time.process_time() - start)
        best.append(min(runs))
    best.sort()
    print("files", len(best))
    print(
        f"in memory: median {statistics.median(best) * 1e6:.2f} us, "
        f"p90 {best[len(best) * 9 // 10] * 1e6:.2f} us, sum {sum(best) * 1e3:.1f} ms"
    )
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
