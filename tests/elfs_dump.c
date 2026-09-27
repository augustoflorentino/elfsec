#include "elfsec/elfsec.h"

#include <stdio.h>
#include <stdlib.h>

static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *data = NULL;
    size_t cap = 0;
    size_t len = 0;
    size_t got;

    if (f == NULL)
        return NULL;
    do {
        if (len == cap) {
            unsigned char *grown = realloc(data, cap = cap ? cap * 2 : 65536);

            if (grown == NULL) {
                free(data);
                fclose(f);
                return NULL;
            }
            data = grown;
        }
        got = fread(data + len, 1, cap - len, f);
        len += got;
    } while (got > 0);
    fclose(f);
    *out_len = len;
    return data;
}

static const char *tri(unsigned v)
{
    static const char *const names[] = {"no", "yes", "unknown", "na"};

    return v < 4 ? names[v] : "?";
}

static void print_ev(const char *what, const elfs_evidence_t *ev)
{
    printf("ev %s %u %u %llu\n", what, ev->source, ev->index, (unsigned long long)ev->offset);
}

static void print_profile(const elfs_profile_t *p)
{
    static const char *const relro[] = {"none", "partial", "full", "n/a"};

    printf("type %u\nkind %s\nmachine %u %s\nclass %u\nbig_endian %u\narch_tested %u\njudged %u\n", p->type, elfs_kind_name(p->kind),
           p->machine, elfs_machine_name(p->machine), p->elf_class, p->big_endian, p->arch_tested, p->judged);
    printf("canary %s\nnx %s\npie %s\nrelro %s\nfortify %s\nstatic %s\nstripped %s\n", tri(p->canary), tri(p->nx),
           tri(p->pie), relro[p->relro % 4], tri(p->fortify), tri(p->static_linked), tri(p->stripped));
    printf("ibt %s\nshstk %s\nbti %s\npac %s\n", tri(p->ibt), tri(p->shstk), tri(p->bti), tri(p->pac));
    printf("fortified %u\nfortifiable %u\nwarnings 0x%x\nentry 0x%llx\n", p->fortified, p->fortifiable, p->warnings,
           (unsigned long long)p->entry);
    if (p->interp != NULL)
        printf("interp %.*s\n", (int)p->interp_len, p->interp);
    if (p->soname != NULL)
        printf("soname %.*s\n", (int)p->soname_len, p->soname);
    print_ev("kind", &p->ev_kind);
    print_ev("canary", &p->ev_canary);
    print_ev("nx", &p->ev_nx);
    print_ev("pie", &p->ev_pie);
    print_ev("relro", &p->ev_relro);
    print_ev("bind_now", &p->ev_bind_now);
    print_ev("fortify", &p->ev_fortify);
    print_ev("static", &p->ev_static);
    print_ev("stripped", &p->ev_stripped);
    print_ev("property", &p->ev_property);
}

static void print_lists(const elfs_elf_t *elf, const elfs_profile_t *p)
{
    elfs_symbol_t sym;
    const char *s;
    size_t len;
    uint32_t flags;
    size_t i;

    for (i = 0; i < p->needed_count && elfs_needed(elf, i, &s, &len) == ELFS_OK; i++)
        printf("needed %.*s\n", (int)len, s);
    for (i = 0; i < p->path_count && elfs_search_path(elf, i, &s, &len, &flags) == ELFS_OK; i++)
        printf("path 0x%x %.*s\n", flags, (int)len, s);
    for (i = 0; i < p->import_count && elfs_import(elf, i, &sym) == ELFS_OK; i++)
        printf("import %.*s\n", (int)sym.name_len, sym.name);
    for (i = 0; i < p->danger_count && elfs_dangerous(elf, i, &sym) == ELFS_OK; i++)
        printf("danger %s %.*s\n", elfs_danger_name(sym.danger), (int)sym.name_len, sym.name);
}

static void dump(const char *path)
{
    elfs_elf_t *elf = NULL;
    elfs_profile_t p;
    unsigned char *data;
    size_t len = 0;
    int status;

    printf("file %s\n", path);
    data = read_file(path, &len);
    if (data == NULL) {
        printf("status unreadable\nend\n");
        return;
    }
    status = elfs_open(data, len, NULL, NULL, NULL, &elf);
    printf("status %s\n", status == ELFS_OK ? "ok" : elfs_strerror(status));
    if (status == ELFS_OK && elfs_profile(elf, &p) == ELFS_OK) {
        print_profile(&p);
        print_lists(elf, &p);
    }
    elfs_destroy(elf);
    free(data);
    printf("end\n");
}

int main(int argc, char **argv)
{
    char line[4096];
    int i;

    for (i = 1; i < argc; i++)
        dump(argv[i]);
    if (argc > 1)
        return 0;
    while (fgets(line, sizeof(line), stdin) != NULL) {
        size_t n = 0;

        while (line[n] != '\0' && line[n] != '\n')
            n++;
        line[n] = '\0';
        if (n > 0)
            dump(line);
    }
    return 0;
}
