#include <elfsec/elfsec.h>

#include <stdio.h>
#include <stdlib.h>

static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *data = NULL;
    size_t cap = 0, len = 0, got;

    if (f == NULL)
        return NULL;
    do {
        if (len == cap) {
            unsigned char *bigger = realloc(data, cap = cap ? cap * 2 : 1 << 16);

            if (bigger == NULL) {
                free(data);
                fclose(f);
                return NULL;
            }
            data = bigger;
        }
        got = fread(data + len, 1, cap - len, f);
        len += got;
    } while (got > 0);
    fclose(f);
    *out_len = len;
    return data;
}

static const char *answer(uint8_t v, const char *yes, const char *no)
{
    switch (v) {
    case ELFS_YES:
        return yes;
    case ELFS_NO:
        return no;
    case ELFS_UNKNOWN:
        return "Unknown";
    default:
        return "N/A";
    }
}

static const char *relro(uint8_t v)
{
    static const char *const names[] = {"No RELRO", "Partial RELRO", "Full RELRO", "N/A"};

    return v < 4 ? names[v] : "?";
}

static void print_details(const elfs_elf_t *elf, const elfs_profile_t *p)
{
    elfs_symbol_t sym;
    const char *path;
    size_t len, i;
    uint32_t flags;

    for (i = 0; i < p->path_count && elfs_search_path(elf, i, &path, &len, &flags) == ELFS_OK; i++) {
        if (flags & (ELFS_PATH_RELATIVE | ELFS_PATH_EMPTY | ELFS_PATH_WORLD_WRITABLE))
            printf("  %s entry \"%.*s\" can be planted by another user\n",
                   flags & ELFS_PATH_RUNPATH ? "RUNPATH" : "RPATH", (int)len, path);
    }
    if (p->ibt != ELFS_NA)
        printf("  CET: IBT %s, SHSTK %s\n", answer(p->ibt, "yes", "no"), answer(p->shstk, "yes", "no"));
    if (p->bti != ELFS_NA)
        printf("  BTI %s, PAC %s, GCS %s\n", answer(p->bti, "yes", "no"), answer(p->pac, "yes", "no"),
               answer(p->gcs, "yes", "no"));
    for (i = 0; i < p->danger_count && elfs_dangerous(elf, i, &sym) == ELFS_OK; i++)
        printf("  imports %.*s (%s)\n", (int)sym.name_len, sym.name, elfs_danger_name(sym.danger));
    if (p->warnings)
        printf("  image is damaged or over a bound (warnings 0x%02x)\n", (unsigned)p->warnings);
}

static int report(const char *path)
{
    size_t len = 0;
    unsigned char *data = read_file(path, &len);
    elfs_elf_t *elf = NULL;
    elfs_profile_t p;
    int status;

    if (data == NULL) {
        fprintf(stderr, "%s: cannot read\n", path);
        return 1;
    }
    status = elfs_open(data, len, NULL, NULL, NULL, &elf);
    if (status == ELFS_OK)
        status = elfs_profile(elf, &p);
    if (status != ELFS_OK) {
        fprintf(stderr, "%s: %s\n", path, elfs_strerror(status));
        elfs_destroy(elf);
        free(data);
        return 1;
    }
    printf("%-14s %-13s %-12s %-12s %-13s %3u/%-3u %-10s %-15s %s\n", relro(p.relro),
           answer(p.canary, "Canary found", "No canary"), answer(p.nx, "NX enabled", "NX disabled"),
           answer(p.pie, "PIE enabled", "No PIE"), answer(p.fortify, "Fortified", "Not fortified"),
           (unsigned)p.fortified, (unsigned)p.fortifiable, elfs_machine_name(p.machine), elfs_kind_name(p.kind),
           path);
    print_details(elf, &p);
    elfs_destroy(elf);
    free(data);
    return 0;
}

int main(int argc, char **argv)
{
    int i, failed = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE...\n", argv[0]);
        return 2;
    }
    printf("%-14s %-13s %-12s %-12s %-13s %-7s %-10s %-15s %s\n", "RELRO", "STACK CANARY", "NX", "PIE",
           "FORTIFY", "FORT", "MACHINE", "KIND", "FILE");
    for (i = 1; i < argc; i++)
        failed |= report(argv[i]);
    return failed;
}
