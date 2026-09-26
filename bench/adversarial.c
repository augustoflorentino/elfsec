#define _POSIX_C_SOURCE 200809L
#include "elfsec/elfsec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    unsigned char *d;
    size_t len;
} image_t;

static void put(image_t *m, size_t at, uint64_t v, unsigned n)
{
    unsigned i;

    for (i = 0; i < n && at + i < m->len; i++)
        m->d[at + i] = (unsigned char)(v >> (8 * i));
}

static void header(image_t *m, uint16_t type, uint64_t phnum, uint64_t shoff, uint64_t shnum)
{
    memcpy(m->d, "\177ELF\2\1\1", 7);
    put(m, 16, type, 2);
    put(m, 18, 62, 2);
    put(m, 32, 64, 8);
    put(m, 40, shoff, 8);
    put(m, 54, 56, 2);
    put(m, 56, phnum >= 0xffff ? 0xffff : phnum, 2);
    put(m, 58, 64, 2);
    put(m, 60, shnum >= 0xff00 ? 0 : shnum, 2);
    if (shoff && (phnum >= 0xffff || shnum >= 0xff00)) {
        put(m, shoff + 32, shnum >= 0xff00 ? shnum : 0, 8);
        put(m, shoff + 44, phnum, 4);
    }
}

static void segment(image_t *m, uint64_t i, uint32_t type, uint64_t offset, uint64_t size)
{
    size_t at = 64 + (size_t)i * 56;

    put(m, at, type, 4);
    put(m, at + 4, 6, 4);
    put(m, at + 8, offset, 8);
    put(m, at + 16, offset, 8);
    put(m, at + 32, size, 8);
    put(m, at + 40, size, 8);
}

static void many_notes(image_t *m)
{
    uint64_t n = (m->len / 4 - 64) / 56, i;

    header(m, 2, n, m->len - 64, 1);
    for (i = 0; i < n; i++)
        segment(m, i, 4, 0, m->len);
}

static void dynamic_names(image_t *m, int64_t tag)
{
    size_t half = m->len / 2, at;

    header(m, 3, 3, 0, 0);
    segment(m, 0, 1, 0, m->len);
    segment(m, 1, 2, 256, half - 256);
    segment(m, 2, 3, 256 + 16 * 4, 1);
    for (at = 256; at + 16 <= half; at += 16) {
        put(m, at, (uint64_t)tag, 8);
        put(m, at + 8, (at / 16) % 4096, 8);
    }
    put(m, 256, 5, 8);
    put(m, 264, half, 8);
    put(m, 272, 10, 8);
    put(m, 280, m->len - half, 8);
    memset(m->d + half, tag == 29 ? ':' : 'a', m->len - half);
}

static void many_symbols(image_t *m)
{
    size_t at;

    header(m, 3, 3, 0, 0);
    segment(m, 0, 1, 0, m->len);
    segment(m, 1, 2, 256, 96);
    segment(m, 2, 3, 512, 8);
    put(m, 256, 4, 8);
    put(m, 264, 1024, 8);
    put(m, 272, 5, 8);
    put(m, 280, 16, 8);
    put(m, 288, 6, 8);
    put(m, 296, 2048, 8);
    put(m, 304, 10, 8);
    put(m, 312, m->len, 8);
    put(m, 1024, 1, 4);
    put(m, 1028, 0xffffffffu, 4);
    for (at = 2048 + 24; at + 24 <= m->len; at += 24)
        put(m, at, 32, 4);
}

static void gnu_hash_chain(image_t *m)
{
    header(m, 3, 3, 0, 0);
    segment(m, 0, 1, 0, m->len);
    segment(m, 1, 2, 256, 64);
    segment(m, 2, 3, 512, 8);
    put(m, 256, 0x6ffffef5u, 8);
    put(m, 264, 1024, 8);
    put(m, 272, 6, 8);
    put(m, 280, 4096, 8);
    put(m, 1024, (m->len - 2048) / 4, 4);
    put(m, 1028, 1, 4);
    put(m, 1032, 0, 4);
    memset(m->d + 1040, 0x02, m->len - 1040);
}

static void many_sections(image_t *m)
{
    size_t n = (m->len - 4096) / 64, i;

    memset(m->d, 'a', m->len);
    header(m, 2, 0, 4096, n);
    put(m, 62, 1, 2);
    for (i = 1; i < n; i++) {
        put(m, 4096 + i * 64, 0, 4);
        put(m, 4096 + i * 64 + 4, i == 1 ? 3 : 2, 4);
        put(m, 4096 + i * 64 + 24, i == 1 ? 0 : 4096, 8);
        put(m, 4096 + i * 64 + 32, i == 1 ? 4096 : m->len - 4096, 8);
        put(m, 4096 + i * 64 + 40, 1, 4);
        put(m, 4096 + i * 64 + 56, 24, 8);
    }
}

static size_t walk(const elfs_elf_t *elf, const elfs_profile_t *p)
{
    elfs_symbol_t sym;
    const char *s;
    size_t len, i, sum = 0;
    uint32_t flags;

    for (i = 0; i < p->needed_count && elfs_needed(elf, i, &s, &len) == ELFS_OK; i++)
        sum += len;
    for (i = 0; i < p->path_count && elfs_search_path(elf, i, &s, &len, &flags) == ELFS_OK; i++)
        sum += len;
    for (i = 0; i < p->import_count && elfs_import(elf, i, &sym) == ELFS_OK; i++)
        sum += sym.name_len;
    for (i = 0; i < p->danger_count && elfs_dangerous(elf, i, &sym) == ELFS_OK; i++)
        sum += sym.name_len;
    return sum;
}

static double seconds(void)
{
    struct timespec t;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static double once(image_t *m, elfs_profile_t *p, size_t *sum, double *out_open_ms)
{
    elfs_elf_t *elf = NULL;
    double start = seconds(), opened, total;

    memset(p, 0, sizeof(*p));
    *sum = 0;
    if (elfs_open(m->d, m->len, NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, p) == ELFS_OK) {
        opened = seconds();
        *sum = walk(elf, p);
    } else {
        opened = seconds();
    }
    total = (seconds() - start) * 1e3;
    *out_open_ms = (opened - start) * 1e3;
    elfs_destroy(elf);
    return total;
}

static int run(const char *name, image_t *m, void (*build)(image_t *))
{
    elfs_profile_t p;
    double ms = 1e9, open_ms = 0, t, o;
    size_t sum = 0;
    int r;

    memset(m->d, 0, m->len);
    build(m);
    for (r = 0; r < 5; r++) {
        if ((t = once(m, &p, &sum, &o)) < ms) {
            ms = t;
            open_ms = o;
        }
    }
    printf("%-16s %8.3f ms (open %.3f)  warnings 0x%02x  walked %zu\n", name, ms, open_ms, (unsigned)p.warnings,
           sum);
    return ms < 10.0;
}

static void needed(image_t *m) { dynamic_names(m, 1); }
static void runpath(image_t *m) { dynamic_names(m, 29); }

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        void (*build)(image_t *);
    } cases[] = {{"notes", many_notes},          {"needed", needed},     {"runpath", runpath},
                 {"symbols", many_symbols},      {"gnu-hash-chain", gnu_hash_chain},
                 {"sections", many_sections}};
    image_t m;
    size_t i;
    int ok = 1;

    m.len = (size_t)(argc > 1 ? atoi(argv[1]) : 64) << 20;
    if ((m.d = malloc(m.len)) == NULL)
        return 2;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (argc <= 2 || strcmp(argv[2], cases[i].name) == 0)
            ok &= run(cases[i].name, &m, cases[i].build);
    }
    free(m.d);
    puts(ok ? "all under 10 ms" : "OVER 10 ms");
    return ok ? 0 : 1;
}
