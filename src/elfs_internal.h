#ifndef ELFS_INTERNAL_H
#define ELFS_INTERNAL_H

#include "elfsec/elfsec.h"

#include <stddef.h>
#include <stdint.h>

#if defined(ELFS_STATIC) && defined(__GNUC__)
#define ELFS_INTERN static __attribute__((unused))
#elif defined(ELFS_STATIC)
#define ELFS_INTERN static
#else
#define ELFS_INTERN
#endif

#define ELFS_ET_REL 1
#define ELFS_ET_EXEC 2
#define ELFS_ET_DYN 3
#define ELFS_ET_CORE 4

#define ELFS_PT_LOAD 1
#define ELFS_PT_DYNAMIC 2
#define ELFS_PT_INTERP 3
#define ELFS_PT_NOTE 4
#define ELFS_PT_GNU_STACK 0x6474e551u
#define ELFS_PT_GNU_RELRO 0x6474e552u
#define ELFS_PF_X 1u

#define ELFS_SHT_SYMTAB 2
#define ELFS_SHT_NOBITS 8
#define ELFS_SHT_DYNSYM 11

#define ELFS_DT_NULL 0
#define ELFS_DT_NEEDED 1
#define ELFS_DT_HASH 4
#define ELFS_DT_STRTAB 5
#define ELFS_DT_SYMTAB 6
#define ELFS_DT_STRSZ 10
#define ELFS_DT_SYMENT 11
#define ELFS_DT_SONAME 14
#define ELFS_DT_RPATH 15
#define ELFS_DT_BIND_NOW 24
#define ELFS_DT_RUNPATH 29
#define ELFS_DT_FLAGS 30
#define ELFS_DT_GNU_HASH 0x6ffffef5u
#define ELFS_DT_FLAGS_1 0x6ffffffbu
#define ELFS_DT_MIPS_SYMTABNO 0x70000011u

#define ELFS_DF_BIND_NOW 0x8u
#define ELFS_DF_1_NOW 0x1u
#define ELFS_DF_1_PIE 0x08000000u

#define ELFS_STT_FUNC 2
#define ELFS_EM_ALPHA 0x9026u

enum {
    ELFS_TAG_STRTAB,
    ELFS_TAG_SYMTAB,
    ELFS_TAG_STRSZ,
    ELFS_TAG_SYMENT,
    ELFS_TAG_HASH,
    ELFS_TAG_GNU_HASH,
    ELFS_TAG_MIPS_SYMTABNO,
    ELFS_TAG_SONAME,
    ELFS_TAG_BIND_NOW,
    ELFS_TAG_FLAGS,
    ELFS_TAG_FLAGS_1,
    ELFS_TAG_COUNT
};

typedef struct elfs_tag {
    int present;
    uint32_t index;
    uint64_t value;
} elfs_tag_t;

typedef struct elfs_phdr {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t filesz;
} elfs_phdr_t;

typedef struct elfs_shdr {
    uint32_t name;
    uint32_t type;
    uint32_t link;
    uint32_t info;
    uint64_t offset;
    uint64_t size;
    uint64_t entsize;
} elfs_shdr_t;

typedef struct elfs_sym {
    uint32_t name;
    uint8_t info;
    uint16_t shndx;
} elfs_sym_t;

typedef struct elfs_strtab {
    uint64_t offset;
    uint64_t size;
} elfs_strtab_t;

typedef struct elfs_sections {
    int usable;
    int has_dynsym;
    elfs_shdr_t dynsym;
    int has_symtab;
    uint32_t symtab_index;
    elfs_shdr_t symtab;
    int kmod;
    uint32_t kmod_index;
    int kernel;
    uint32_t kernel_index;
} elfs_sections_t;

struct elfs_elf {
    elfs_alloc_fn alloc_fn;
    elfs_free_fn free_fn;
    void *alloc_ctx;
    const unsigned char *data;
    uint64_t len;
    int is64;
    int big;
    uint32_t type;
    uint64_t phoff;
    uint64_t phnum;
    uint32_t phentsize;
    uint64_t shoff;
    uint64_t shnum;
    uint32_t shentsize;
    uint64_t shstrndx;
    elfs_sections_t sections;
    int has_dynamic;
    uint32_t dyn_segment;
    uint64_t dyn_offset;
    uint64_t dyn_count;
    elfs_tag_t tags[ELFS_TAG_COUNT];
    int has_strtab;
    elfs_strtab_t strtab;
    int has_symbols;
    uint64_t sym_offset;
    uint64_t sym_count;
    uint64_t sym_entsize;
    uint64_t needed_tags;
    uint64_t path_tags;
    uint64_t path_strings;
    uint32_t *list;
    uint64_t danger_at;
    uint64_t needed_at;
    uint64_t path_at;
    uint64_t read_left;
    elfs_profile_t profile;
};

ELFS_INTERN int elfs_fits(const elfs_elf_t *elf, uint64_t offset, uint64_t size);
ELFS_INTERN uint32_t elfs_u16(const elfs_elf_t *elf, uint64_t offset);
ELFS_INTERN uint32_t elfs_u32(const elfs_elf_t *elf, uint64_t offset);
ELFS_INTERN uint64_t elfs_word(const elfs_elf_t *elf, uint64_t offset);
ELFS_INTERN int elfs_read_header(elfs_elf_t *elf);
ELFS_INTERN int elfs_phdr(const elfs_elf_t *elf, uint64_t i, elfs_phdr_t *out_phdr);
ELFS_INTERN int elfs_find_segment(const elfs_elf_t *elf, uint32_t type, uint64_t *out_index, elfs_phdr_t *out_phdr);
ELFS_INTERN uint64_t elfs_count_segments(const elfs_elf_t *elf, uint32_t type);
ELFS_INTERN int elfs_shdr(const elfs_elf_t *elf, uint64_t i, elfs_shdr_t *out_shdr);
ELFS_INTERN void elfs_read_sections(elfs_elf_t *elf);
ELFS_INTERN int elfs_address(const elfs_elf_t *elf, uint64_t address, uint64_t *out_offset);
ELFS_INTERN int elfs_string(elfs_elf_t *elf, const elfs_strtab_t *table, uint64_t at, const char **out_str,
                            size_t *out_len);
ELFS_INTERN void elfs_peek_string(const elfs_elf_t *elf, const elfs_strtab_t *table, uint64_t at,
                                  const char **out_str, size_t *out_len);
ELFS_INTERN void elfs_sym(const elfs_elf_t *elf, uint64_t offset, elfs_sym_t *out_sym);
ELFS_INTERN int elfs_has_linux_note(const elfs_elf_t *elf, elfs_evidence_t *out_ev);

ELFS_INTERN void elfs_read_dynamic(elfs_elf_t *elf);
ELFS_INTERN int elfs_dyn_entry(const elfs_elf_t *elf, uint64_t i, int64_t *out_tag, uint64_t *out_value);
ELFS_INTERN int elfs_read_imports(elfs_elf_t *elf);
ELFS_INTERN void elfs_symbol_at(const elfs_elf_t *elf, uint32_t index, elfs_symbol_t *out_symbol);
ELFS_INTERN uint32_t elfs_danger_of(const char *name, size_t name_len);
ELFS_INTERN int elfs_is_fortified(const char *name, size_t name_len);
ELFS_INTERN int elfs_is_fortifiable(const char *name, size_t name_len);
ELFS_INTERN int elfs_is_canary(const char *name, size_t name_len);
ELFS_INTERN void elfs_scan_paths(elfs_elf_t *elf);
ELFS_INTERN int elfs_path_entry(const elfs_elf_t *elf, size_t i, const char **out_path, size_t *out_len,
                                uint32_t *out_flags);

ELFS_INTERN void elfs_build_profile(elfs_elf_t *elf);

#endif
