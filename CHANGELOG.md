# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 0.5.0 - 2026-10-15

- the profile reports AArch64 GCS (guarded control stack, `gcs`) from the same GNU property note
  as BTI and PAC; it takes a byte of `reserved1`, the size of `elfs_profile_t` does not change
- CET and BTI/PAC/GCS are checked against shared objects built by gcc 16 and clang (zig 0.16)
  with and without `-fcf-protection` and `-mbranch-protection` (`tests/vectors`)
- benchmarks: `bench/throughput.c` (median 6 us per `/usr/bin` file) and
  `bench/python_baseline.py`; the fwtriage parity oracle `tests/oracle/fwtriage_oracle.py`

## 0.3.0 - 2026-09-26

- the profile reports Intel CET (`ibt`, `shstk`) on x86 and BTI and PAC (`bti`, `pac`) on
  AArch64, read from the GNU property note, with the property as evidence (`ev_property`);
  without the note they are `ELFS_UNKNOWN`, on other architectures `ELFS_NA`
- the new fields take space from `reserved`: the size of `elfs_profile_t` does not change, and
  code built against 0.1.0 keeps working

## 0.1.0 - 2026-09-26

First release.

- `elfs_open` and `elfs_profile` read an ELF32 or ELF64 image of either byte order from memory
  and report the stack protector, non-executable stack, PIE, RELRO, FORTIFY (with counts),
  static linking and stripping, each with the record it came from
- images are classified as executable, PIE, shared library, relocatable object, kernel module,
  kernel, bare metal or core dump; only the first three are judged
- `elfs_needed`, `elfs_search_path`, `elfs_import` and `elfs_dangerous` walk the dependencies,
  the `RPATH`/`RUNPATH` entries with their risk flags, the imported symbols and the imports in
  the dangerous table
- works without a section header table, from segments and the dynamic table
- every count read from the image is bounded (`ELFS_MAX_*`); reaching a bound or meeting a
  damaged table is a warning in the profile, never a failure
