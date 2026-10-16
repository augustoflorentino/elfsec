#ifndef ELFSEC_H
#define ELFSEC_H

#include <stddef.h>
#include <stdint.h>

#if defined(ELFS_STATIC) && defined(__GNUC__)
#define ELFS_API static __attribute__((unused))
#elif defined(ELFS_STATIC)
#define ELFS_API static
#elif defined(_WIN32) && defined(ELFS_BUILD_SHARED)
#define ELFS_API __declspec(dllexport)
#elif defined(_WIN32) && defined(ELFS_SHARED)
#define ELFS_API __declspec(dllimport)
#elif defined(__GNUC__) && defined(ELFS_BUILD_SHARED)
#define ELFS_API __attribute__((visibility("default")))
#else
#define ELFS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ELFS_OK 0
#define ELFS_ERR_ARG 1
#define ELFS_ERR_NOMEM 2
#define ELFS_ERR_FORMAT 3

#define ELFS_MAX_SYMBOLS 100000u
#define ELFS_MAX_READ (8u * 1024u * 1024u)
#define ELFS_MAX_SEGMENTS 4096u
#define ELFS_MAX_SECTIONS 65536u
#define ELFS_MAX_DYNAMIC 16384u
#define ELFS_MAX_NOTES 1024u
#define ELFS_MAX_PATHS 1024u

#define ELFS_NO 0
#define ELFS_YES 1
#define ELFS_UNKNOWN 2
#define ELFS_NA 3

#define ELFS_KIND_UNKNOWN 0
#define ELFS_KIND_EXEC 1
#define ELFS_KIND_PIE 2
#define ELFS_KIND_SHARED 3
#define ELFS_KIND_RELOC 4
#define ELFS_KIND_KMOD 5
#define ELFS_KIND_KERNEL 6
#define ELFS_KIND_BARE 7
#define ELFS_KIND_CORE 8

#define ELFS_RELRO_NONE 0
#define ELFS_RELRO_PARTIAL 1
#define ELFS_RELRO_FULL 2

#define ELFS_WARN_TRUNCATED 0x01u
#define ELFS_WARN_SYMBOL_BUDGET 0x02u
#define ELFS_WARN_BUDGET 0x04u
#define ELFS_WARN_DYNAMIC 0x08u
#define ELFS_WARN_SECTIONS 0x10u
#define ELFS_WARN_SYMBOLS 0x20u
#define ELFS_WARN_NAME 0x40u
#define ELFS_WARN_SEGMENTS 0x80u

#define ELFS_SRC_NONE 0
#define ELFS_SRC_HEADER 1
#define ELFS_SRC_SEGMENT 2
#define ELFS_SRC_DYNAMIC 3
#define ELFS_SRC_SYMBOL 4
#define ELFS_SRC_SECTION 5
#define ELFS_SRC_ARCH 6
#define ELFS_SRC_SYMTAB 7
#define ELFS_SRC_NOTE 8

#define ELFS_PATH_RUNPATH 0x01u
#define ELFS_PATH_RELATIVE 0x02u
#define ELFS_PATH_EMPTY 0x04u
#define ELFS_PATH_WORLD_WRITABLE 0x08u
#define ELFS_PATH_ORIGIN 0x10u

#define ELFS_DANGER_NONE 0
#define ELFS_DANGER_UNBOUNDED 1
#define ELFS_DANGER_COMMAND 2
#define ELFS_DANGER_TEMPFILE 3

#define ELFS_EM_386 3
#define ELFS_EM_MIPS 8
#define ELFS_EM_PPC 20
#define ELFS_EM_PPC64 21
#define ELFS_EM_S390 22
#define ELFS_EM_ARM 40
#define ELFS_EM_X86_64 62
#define ELFS_EM_AARCH64 183
#define ELFS_EM_RISCV 243

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define ELFS_SIZE_CHECK(name, cond) _Static_assert(cond, #name)
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define ELFS_SIZE_CHECK(name, cond) static_assert(cond, #name)
#else
#define ELFS_SIZE_CHECK(name, cond) typedef char elfs_size_check_##name[(cond) ? 1 : -1]
#endif

typedef struct elfs_evidence {
    uint32_t source;
    uint32_t index;
    uint64_t offset;
} elfs_evidence_t;

ELFS_SIZE_CHECK(evidence, sizeof(elfs_evidence_t) == 16);

typedef struct elfs_profile {
    uint32_t kind;
    uint32_t machine;
    uint8_t elf_class;
    uint8_t big_endian;
    uint8_t arch_tested;
    uint8_t judged;
    uint8_t canary;
    uint8_t nx;
    uint8_t pie;
    uint8_t relro;
    uint8_t fortify;
    uint8_t static_linked;
    uint8_t stripped;
    uint8_t reserved0;
    uint32_t fortified;
    uint32_t fortifiable;
    uint32_t needed_count;
    uint32_t import_count;
    uint32_t danger_count;
    uint32_t path_count;
    uint32_t path_flags;
    uint32_t warnings;
    uint32_t type;
    uint64_t entry;
    const char *interp;
    size_t interp_len;
    const char *soname;
    size_t soname_len;
    elfs_evidence_t ev_kind;
    elfs_evidence_t ev_canary;
    elfs_evidence_t ev_nx;
    elfs_evidence_t ev_pie;
    elfs_evidence_t ev_relro;
    elfs_evidence_t ev_bind_now;
    elfs_evidence_t ev_fortify;
    elfs_evidence_t ev_static;
    elfs_evidence_t ev_stripped;
    uint8_t ibt;
    uint8_t shstk;
    uint8_t bti;
    uint8_t pac;
    uint8_t gcs;
    uint8_t reserved1[3];
    elfs_evidence_t ev_property;
    uint32_t reserved[10];
} elfs_profile_t;

ELFS_SIZE_CHECK(profile, sizeof(elfs_profile_t) == 272 + 4 * sizeof(void *));

typedef struct elfs_symbol {
    const char *name;
    size_t name_len;
    uint64_t offset;
    uint32_t index;
    uint32_t danger;
    uint8_t bind;
    uint8_t type;
    uint8_t reserved0[2];
    uint32_t reserved[5];
} elfs_symbol_t;

ELFS_SIZE_CHECK(symbol, sizeof(elfs_symbol_t) == 40 + 2 * sizeof(void *));

typedef struct elfs_elf elfs_elf_t;

typedef void *(*elfs_alloc_fn)(void *ctx, size_t size);
typedef void (*elfs_free_fn)(void *ctx, void *ptr);

ELFS_API int elfs_open(const unsigned char *data, size_t data_len, elfs_alloc_fn alloc_fn, elfs_free_fn free_fn,
                       void *alloc_ctx, elfs_elf_t **out_elf);
ELFS_API void elfs_destroy(elfs_elf_t *elf);

ELFS_API int elfs_profile(const elfs_elf_t *elf, elfs_profile_t *out_profile);

ELFS_API int elfs_needed(const elfs_elf_t *elf, size_t i, const char **out_name, size_t *out_name_len);

ELFS_API int elfs_search_path(const elfs_elf_t *elf, size_t i, const char **out_path, size_t *out_path_len,
                              uint32_t *out_flags);

ELFS_API int elfs_import(const elfs_elf_t *elf, size_t i, elfs_symbol_t *out_symbol);

ELFS_API int elfs_dangerous(const elfs_elf_t *elf, size_t i, elfs_symbol_t *out_symbol);

ELFS_API const char *elfs_kind_name(uint32_t kind);
ELFS_API const char *elfs_machine_name(uint32_t machine);
ELFS_API const char *elfs_danger_name(uint32_t danger);
ELFS_API const char *elfs_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif
