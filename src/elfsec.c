#include "elfs_internal.h"

#include <stdlib.h>
#include <string.h>

static void *elfs_default_alloc(void *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

static void elfs_default_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

static int elfs_analyze(elfs_elf_t *elf)
{
    int status = elfs_read_header(elf);

    if (status != ELFS_OK)
        return status;
    elfs_read_sections(elf);
    elfs_read_dynamic(elf);
    status = elfs_read_imports(elf);
    if (status != ELFS_OK)
        return status;
    elfs_build_profile(elf);
    return ELFS_OK;
}

int elfs_open(const unsigned char *data, size_t data_len, elfs_alloc_fn alloc_fn, elfs_free_fn free_fn,
              void *alloc_ctx, elfs_elf_t **out_elf)
{
    elfs_elf_t *elf;
    int status;

    if (out_elf != NULL)
        *out_elf = NULL;
    if (out_elf == NULL || (data == NULL && data_len > 0) || (alloc_fn == NULL) != (free_fn == NULL))
        return ELFS_ERR_ARG;
    if (alloc_fn == NULL) {
        alloc_fn = elfs_default_alloc;
        free_fn = elfs_default_free;
    }
    elf = alloc_fn(alloc_ctx, sizeof(*elf));
    if (elf == NULL)
        return ELFS_ERR_NOMEM;
    memset(elf, 0, sizeof(*elf));
    elf->alloc_fn = alloc_fn;
    elf->free_fn = free_fn;
    elf->alloc_ctx = alloc_ctx;
    elf->data = data;
    elf->len = data_len;
    elf->read_left = ELFS_MAX_READ;
    status = elfs_analyze(elf);
    if (status != ELFS_OK) {
        elfs_destroy(elf);
        return status;
    }
    *out_elf = elf;
    return ELFS_OK;
}

void elfs_destroy(elfs_elf_t *elf)
{
    if (elf == NULL)
        return;
    if (elf->list != NULL)
        elf->free_fn(elf->alloc_ctx, elf->list);
    elf->free_fn(elf->alloc_ctx, elf);
}

int elfs_profile(const elfs_elf_t *elf, elfs_profile_t *out_profile)
{
    if (elf == NULL || out_profile == NULL)
        return ELFS_ERR_ARG;
    *out_profile = elf->profile;
    return ELFS_OK;
}

int elfs_needed(const elfs_elf_t *elf, size_t i, const char **out_name, size_t *out_name_len)
{
    int64_t tag;
    uint64_t value;

    if (elf == NULL || out_name == NULL || out_name_len == NULL || i >= elf->profile.needed_count)
        return ELFS_ERR_ARG;
    elfs_dyn_entry(elf, elf->list[elf->needed_at + i], &tag, &value);
    elfs_peek_string(elf, &elf->strtab, value, out_name, out_name_len);
    return ELFS_OK;
}

int elfs_search_path(const elfs_elf_t *elf, size_t i, const char **out_path, size_t *out_path_len,
                     uint32_t *out_flags)
{
    if (elf == NULL || out_path == NULL || out_path_len == NULL || out_flags == NULL ||
        i >= elf->profile.path_count)
        return ELFS_ERR_ARG;
    return elfs_path_entry(elf, i, out_path, out_path_len, out_flags) ? ELFS_OK : ELFS_ERR_ARG;
}

int elfs_import(const elfs_elf_t *elf, size_t i, elfs_symbol_t *out_symbol)
{
    if (elf == NULL || out_symbol == NULL || i >= elf->profile.import_count)
        return ELFS_ERR_ARG;
    elfs_symbol_at(elf, elf->list[i], out_symbol);
    return ELFS_OK;
}

int elfs_dangerous(const elfs_elf_t *elf, size_t i, elfs_symbol_t *out_symbol)
{
    if (elf == NULL || out_symbol == NULL || i >= elf->profile.danger_count)
        return ELFS_ERR_ARG;
    elfs_symbol_at(elf, elf->list[elf->danger_at + i], out_symbol);
    return ELFS_OK;
}

const char *elfs_kind_name(uint32_t kind)
{
    static const char *const names[] = {"unknown", "executable", "pie", "shared library", "relocatable",
                                        "kernel module", "kernel", "bare metal", "core dump"};

    return kind < sizeof(names) / sizeof(names[0]) ? names[kind] : "unknown";
}

const char *elfs_machine_name(uint32_t machine)
{
    switch (machine) {
    case ELFS_EM_386:
        return "x86";
    case ELFS_EM_MIPS:
        return "mips";
    case ELFS_EM_PPC:
        return "powerpc";
    case ELFS_EM_PPC64:
        return "powerpc64";
    case ELFS_EM_S390:
        return "s390";
    case ELFS_EM_ARM:
        return "arm";
    case ELFS_EM_X86_64:
        return "x86_64";
    case ELFS_EM_AARCH64:
        return "aarch64";
    case ELFS_EM_RISCV:
        return "riscv";
    default:
        return "other";
    }
}

const char *elfs_danger_name(uint32_t danger)
{
    switch (danger) {
    case ELFS_DANGER_UNBOUNDED:
        return "unbounded write";
    case ELFS_DANGER_COMMAND:
        return "shell command";
    case ELFS_DANGER_TEMPFILE:
        return "predictable temporary file";
    default:
        return "none";
    }
}

const char *elfs_strerror(int status)
{
    switch (status) {
    case ELFS_OK:
        return "ok";
    case ELFS_ERR_ARG:
        return "invalid argument";
    case ELFS_ERR_NOMEM:
        return "out of memory";
    case ELFS_ERR_FORMAT:
        return "not an ELF image or unusable file header";
    default:
        return "unknown status";
    }
}
