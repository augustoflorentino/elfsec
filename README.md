# elfsec

Reads an ELF image from memory and tells which build and link protections it carries (stack
protector, non-executable stack, PIE, RELRO, FORTIFY), what it imports, what it needs to run
(interpreter, `DT_NEEDED`, soname, `RPATH`/`RUNPATH`) and where each answer came from. It is
checksec as a C library: a scanner, package manager, CI job or firmware tool calls it without
running a script or a process.

- reads ELF32 and ELF64, little and big endian, with or without a section header table (an
  `sstrip`ped binary gives the same answer, from segments and the dynamic table alone)
- only userland programs and libraries are judged; kernels, kernel modules, boot loaders,
  bare-metal firmware, object files and core dumps are classified and left unjudged
- nothing in the image is trusted: every offset and count is checked against the buffer and the
  work per image is bounded; damage or an exceeded bound is a warning, not an error
- C99, no dependencies, at most two allocations, the image is never copied

## Build and install

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build
cmake --install build --prefix /usr/local
```

Use it from CMake:

```cmake
find_package(elfsec REQUIRED)
target_link_libraries(app PRIVATE elfsec::elfsec)
```

Or with pkg-config:

```sh
cc app.c $(pkg-config --cflags --libs elfsec)
```

## Single-file form

`scripts/amalgamate.sh` writes `dist/elfsec/elfsec.h`. Copy it into your project and, in exactly
one `.c` file:

```c
#define ELFS_IMPLEMENTATION
#include "elfsec/elfsec.h"
```

Define `ELFS_STATIC` as well to keep every function private to that file.

## Usage

```c
elfs_elf_t *elf;
elfs_profile_t p;

if (elfs_open(data, len, NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, &p) == ELFS_OK) {
    if (p.judged && p.canary == ELFS_NO)
        printf("no stack protector (%s)\n", elfs_kind_name(p.kind));
}
elfs_destroy(elf);
```

[`examples/elfsec.c`](examples/elfsec.c) prints a checksec-style line per file, then the risky
search path entries and dangerous imports. The header `include/elfsec/elfsec.h` is the API
reference.

Conventions:

- every function that can fail returns `ELFS_OK` or an error code; `elfs_strerror` describes it
- `elfs_open` fails only when the file header is unusable; `elfs_destroy` accepts `NULL`
- the buffer is not copied and must outlive the handle; returned strings point into it and are
  pointer + length, not NUL-terminated
- pass your own allocator to `elfs_open`, or `NULL` for both functions to use `malloc`/`free`

## What the answers mean

Each protection is `ELFS_YES`, `ELFS_NO`, `ELFS_UNKNOWN` (the image does not say, or the part
that says it cannot be read) or `ELFS_NA` (the image is not judged). Every answer carries an
evidence record: the table it came from (segment, section, dynamic entry, symbol, note, header or
architecture), the record number and its file offset.

| field | yes when |
|---|---|
| `canary` | `__stack_chk_fail`, `__stack_chk_fail_local` or `__stack_chk_guard` is imported; for a static program, named in `.symtab` (no `.symtab`: unknown) |
| `nx` | `PT_GNU_STACK` without `PF_X`; without that segment, yes on AArch64 and RISC-V, where Linux never makes the stack executable, and no elsewhere |
| `pie` | the kind is PIE |
| `relro` | none, partial (`PT_GNU_RELRO`) or full (`PT_GNU_RELRO` and `DT_BIND_NOW`, `DF_BIND_NOW` or `DF_1_NOW`) |
| `fortify` | at least one `_chk` function other than the canary symbols is imported (static: defined); `fortified` counts them and `fortifiable` adds the imports that have a `_chk` form in glibc 2.43 (85 names; `__fdelt_chk` is left out, it backs `FD_SET`) |
| `static_linked` | an executable without `PT_INTERP` |
| `stripped` | no `.symtab` section |

### Classification

| kind | rule, in this order |
|---|---|
| core | `ET_CORE` |
| kernel module | `ET_REL` with `.modinfo` or `.gnu.linkonce.this_module` |
| relocatable | any other `ET_REL` |
| kernel | no interpreter, and a `__ksymtab`, `__ksymtab_strings` or `__ex_table` section or a note named `Linux` (vmlinux, and the vDSO built with it) |
| bare metal | no interpreter, no `DT_NEEDED`, no soname, and one of: a `__u_boot_list` section (U-Boot); no `PT_GNU_STACK` and at most one `PT_LOAD` or an entry in the upper half of the address space; none of the segments only a userland toolchain writes (`PT_PHDR`, `PT_TLS`, `PT_NOTE`, `PT_GNU_RELRO`, `PT_GNU_EH_FRAME`, `PT_GNU_PROPERTY`) |
| PIE | `ET_DYN` with `DF_1_PIE`, or with an interpreter and no soname |
| shared library | any other `ET_DYN` |
| executable | `ET_EXEC` |

Only executables, PIEs and shared libraries are judged. A program packed by UPX or a similar
packer is judged on the stub the packer wrote, not on the program inside.

### Dangerous imports

| class | functions | source |
|---|---|---|
| unbounded write | `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `wcscpy`, `wcscat` | Microsoft SDL `banned.h`; flawfinder |
| shell command | `system`, `popen` | flawfinder |
| predictable temporary file | `mktemp`, `tmpnam`, `tempnam` | flawfinder |

The table says what a binary calls, not that it is vulnerable.

### Search paths

Each `RPATH`/`RUNPATH` entry is reported with flags: relative to the working directory, empty
(which also means the working directory), or under `/tmp`, `/var/tmp` or `/dev/shm`, any of which
lets another user plant a library. Entries starting with `$ORIGIN` are flagged but not condemned.

## Limits

Per image the library reads at most 100 000 symbols per symbol table, 8 MiB of names, 4096
program headers, 65 536 section headers, 16 384 dynamic entries, 1024 notes and 1024 search path
entries (`ELFS_MAX_*`). Reaching one sets a warning bit and stops that part of the reading; the
profile is still returned. Of 12 819 ELF files checked (this machine's `/usr/bin` and `/usr/lib`
plus OpenWrt and Debian images for seven architectures), seven large Go programs reach the symbol
and name bounds, with the same profile as readelf and checksec give; nothing else reaches any.

Memory: a handle of under 1 KiB and one list of at most 873 728 bytes, both from the allocator
passed to `elfs_open`.

## Versioning

Semantic Versioning. Compatible releases bump the minor version; incompatible ones bump the
major version and the soname. See [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
