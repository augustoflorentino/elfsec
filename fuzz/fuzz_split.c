#include "elfsec/elfsec.h"

#include <stdint.h>
#include <string.h>

static size_t touch(const char *text, size_t len)
{
    size_t sum = 0, i;

    for (i = 0; i < len; i++)
        sum += (unsigned char)text[i];
    return sum;
}

static size_t walk(const elfs_elf_t *elf, const elfs_profile_t *p)
{
    elfs_symbol_t sym;
    const char *name;
    size_t len, i, sum = touch(p->interp, p->interp_len) + touch(p->soname, p->soname_len);
    uint32_t flags;

    for (i = 0; i < p->needed_count && elfs_needed(elf, i, &name, &len) == ELFS_OK; i++)
        sum += touch(name, len);
    for (i = 0; i < p->path_count && elfs_search_path(elf, i, &name, &len, &flags) == ELFS_OK; i++)
        sum += touch(name, len) + flags;
    for (i = 0; i < p->import_count && elfs_import(elf, i, &sym) == ELFS_OK; i++)
        sum += touch(sym.name, sym.name_len);
    for (i = 0; i < p->danger_count && elfs_dangerous(elf, i, &sym) == ELFS_OK; i++)
        sum += touch(sym.name, sym.name_len);
    return sum + strlen(elfs_kind_name(p->kind)) + strlen(elfs_machine_name(p->machine));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static volatile size_t sink;
    elfs_elf_t *elf = NULL;
    elfs_profile_t p;

    if (elfs_open(data, size, NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, &p) == ELFS_OK)
        sink += walk(elf, &p);
    elfs_destroy(elf);
    return 0;
}
