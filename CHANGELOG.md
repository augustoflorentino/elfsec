# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

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
