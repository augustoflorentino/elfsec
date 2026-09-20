#ifndef ELFS_IMAGE_H
#define ELFS_IMAGE_H

#include <stdint.h>
#include <string.h>

#define IMG_SIZE 0x1100u
#define IMG_PHOFF 0x40u
#define IMG_INTERP 0x280u
#define IMG_DYNSTR 0x540u
#define IMG_DYNSYM 0x300u
#define IMG_HASH 0x840u
#define IMG_DYNAMIC 0x940u
#define IMG_NOTE 0xac0u
#define IMG_SYMTAB 0xb00u
#define IMG_STRTAB 0xc80u
#define IMG_SHSTRTAB 0xd80u
#define IMG_SHOFF 0xe80u
#define IMG_EXTRA 0x2c0u

enum { HASH_NONE, HASH_SYSV, HASH_GNU, HASH_GNU_EMPTY_BFD, HASH_MIPS };
enum { NOW_NONE, NOW_TAG, NOW_FLAGS, NOW_FLAGS_1 };
enum { STACK_NONE, STACK_RW, STACK_RWX };

typedef struct {
    int is64, big;
    uint16_t type, machine;
    uint64_t base, entry;
    const char *interp;
    int stack, relro, now, df_1_pie, note_linux, phdr, extra_loads;
    int dynamic;
    int hash;
    int sections;
    const char *soname, *rpath, *runpath;
    const char *needed[4];
    const char *imports[12];
    const char *defined[4];
    const char *extra[3];
    const char *symtab[4];
} img_spec_t;

typedef struct {
    unsigned char d[IMG_SIZE];
    const img_spec_t *s;
    uint32_t phnum, dynnum, nsyms, dynstr_len;
} img_t;

static void img_put(img_t *m, uint64_t at, uint64_t v, unsigned n)
{
    unsigned i;

    for (i = 0; i < n; i++)
        m->d[at + (m->s->big ? n - 1 - i : i)] = (unsigned char)(v >> (8 * i));
}

static void img_word(img_t *m, uint64_t at, uint64_t v)
{
    img_put(m, at, v, m->s->is64 ? 8 : 4);
}

static uint32_t img_str(img_t *m, uint64_t table, uint32_t *len, const char *s)
{
    uint32_t at = *len;

    memcpy(m->d + table + at, s, strlen(s) + 1);
    *len += (uint32_t)strlen(s) + 1;
    return at;
}

static void img_header(img_t *m)
{
    const img_spec_t *s = m->s;

    memcpy(m->d, "\177ELF", 4);
    m->d[4] = (unsigned char)(s->is64 ? 2 : 1);
    m->d[5] = (unsigned char)(s->big ? 2 : 1);
    m->d[6] = 1;
    img_put(m, 16, s->type, 2);
    img_put(m, 18, s->machine, 2);
    img_put(m, 20, 1, 4);
    img_word(m, 24, s->entry);
    img_word(m, s->is64 ? 32 : 28, IMG_PHOFF);
    img_put(m, s->is64 ? 52 : 40, s->is64 ? 64 : 52, 2);
    img_put(m, s->is64 ? 54 : 42, s->is64 ? 56 : 32, 2);
    img_put(m, s->is64 ? 56 : 44, m->phnum, 2);
    img_put(m, s->is64 ? 58 : 46, s->is64 ? 64 : 40, 2);
}

static void img_segment(img_t *m, uint32_t type, uint32_t flags, uint64_t offset, uint64_t size)
{
    uint64_t at = IMG_PHOFF + (uint64_t)m->phnum * (m->s->is64 ? 56 : 32);
    uint64_t vaddr = m->s->base + offset;

    if (m->s->is64) {
        img_put(m, at, type, 4);
        img_put(m, at + 4, flags, 4);
        img_put(m, at + 8, offset, 8);
        img_put(m, at + 16, vaddr, 8);
        img_put(m, at + 24, vaddr, 8);
        img_put(m, at + 32, size, 8);
        img_put(m, at + 40, size, 8);
        img_put(m, at + 48, type == 1 ? 0x1000 : 8, 8);
    } else {
        img_put(m, at, type, 4);
        img_put(m, at + 4, offset, 4);
        img_put(m, at + 8, vaddr, 4);
        img_put(m, at + 12, vaddr, 4);
        img_put(m, at + 16, size, 4);
        img_put(m, at + 20, size, 4);
        img_put(m, at + 24, flags, 4);
        img_put(m, at + 28, type == 1 ? 0x1000 : 8, 4);
    }
    m->phnum++;
}

static void img_symbol(img_t *m, uint64_t table, uint32_t index, uint32_t name, int defined)
{
    uint64_t at = table + (uint64_t)index * (m->s->is64 ? 24 : 16);
    unsigned char info = 0x12;

    if (m->s->is64) {
        img_put(m, at, name, 4);
        m->d[at + 4] = info;
        img_put(m, at + 6, defined ? 1 : 0, 2);
        img_put(m, at + 8, defined ? 0x100 + index : 0, 8);
    } else {
        img_put(m, at, name, 4);
        img_put(m, at + 4, defined ? 0x100 + index : 0, 4);
        m->d[at + 12] = info;
        img_put(m, at + 14, defined ? 1 : 0, 2);
    }
}

static void img_dyn(img_t *m, uint64_t tag, uint64_t value)
{
    uint64_t at = IMG_DYNAMIC + (uint64_t)m->dynnum * (m->s->is64 ? 16 : 8);

    img_word(m, at, tag);
    img_word(m, at + (m->s->is64 ? 8 : 4), value);
    m->dynnum++;
}

static void img_symbols(img_t *m)
{
    uint32_t i;

    m->nsyms = 1;
    m->dynstr_len = 1;
    for (i = 0; i < 12 && m->s->imports[i]; i++)
        img_symbol(m, IMG_DYNSYM, m->nsyms++, img_str(m, IMG_DYNSTR, &m->dynstr_len, m->s->imports[i]), 0);
    for (i = 0; i < 4 && m->s->defined[i]; i++)
        img_symbol(m, IMG_DYNSYM, m->nsyms++, img_str(m, IMG_DYNSTR, &m->dynstr_len, m->s->defined[i]), 1);
}

static void img_hash(img_t *m)
{
    if (m->s->hash == HASH_SYSV) {
        img_put(m, IMG_HASH, 1, 4);
        img_put(m, IMG_HASH + 4, m->nsyms, 4);
        img_dyn(m, 4, m->s->base + IMG_HASH);
    } else if (m->s->hash == HASH_GNU || m->s->hash == HASH_GNU_EMPTY_BFD) {
        img_put(m, IMG_HASH, 1, 4);
        img_put(m, IMG_HASH + 4, m->s->hash == HASH_GNU ? m->nsyms : 1, 4);
        img_put(m, IMG_HASH + 8, 1, 4);
        img_put(m, IMG_HASH + 12, 6, 4);
        img_dyn(m, 0x6ffffef5u, m->s->base + IMG_HASH);
    } else if (m->s->hash == HASH_MIPS) {
        img_dyn(m, 0x70000011u, m->nsyms);
    }
}

static void img_dynamic(img_t *m)
{
    const img_spec_t *s = m->s;
    uint64_t flags_1 = (s->now == NOW_FLAGS_1 ? 1u : 0u) | (s->df_1_pie ? 0x08000000u : 0u);
    uint32_t i;

    img_symbols(m);
    for (i = 0; i < 4 && s->needed[i]; i++)
        img_dyn(m, 1, img_str(m, IMG_DYNSTR, &m->dynstr_len, s->needed[i]));
    if (s->soname)
        img_dyn(m, 14, img_str(m, IMG_DYNSTR, &m->dynstr_len, s->soname));
    if (s->rpath)
        img_dyn(m, 15, img_str(m, IMG_DYNSTR, &m->dynstr_len, s->rpath));
    if (s->runpath)
        img_dyn(m, 29, img_str(m, IMG_DYNSTR, &m->dynstr_len, s->runpath));
    img_hash(m);
    img_dyn(m, 5, s->base + IMG_DYNSTR);
    img_dyn(m, 6, s->base + IMG_DYNSYM);
    img_dyn(m, 10, m->dynstr_len);
    img_dyn(m, 11, s->is64 ? 24 : 16);
    if (s->now == NOW_TAG)
        img_dyn(m, 24, 0);
    if (s->now == NOW_FLAGS)
        img_dyn(m, 30, 8);
    if (flags_1)
        img_dyn(m, 0x6ffffffbu, flags_1);
    img_dyn(m, 0, 0);
}

static void img_note(img_t *m)
{
    img_put(m, IMG_NOTE, 6, 4);
    img_put(m, IMG_NOTE + 4, 4, 4);
    img_put(m, IMG_NOTE + 8, 0x100, 4);
    memcpy(m->d + IMG_NOTE + 12, "Linux", 6);
}

static void img_segments(img_t *m)
{
    const img_spec_t *s = m->s;
    int i;

    if (s->phdr)
        img_segment(m, 6, 4, IMG_PHOFF, 10u * (s->is64 ? 56 : 32));
    if (s->interp)
        img_segment(m, 3, 4, IMG_INTERP, strlen(s->interp) + 1);
    img_segment(m, 1, 5, 0, IMG_SIZE);
    for (i = 0; i < s->extra_loads; i++)
        img_segment(m, 1, 6, IMG_SYMTAB, 0x80);
    if (s->dynamic)
        img_segment(m, 2, 6, IMG_DYNAMIC, (uint64_t)m->dynnum * (s->is64 ? 16 : 8));
    if (s->note_linux)
        img_segment(m, 4, 4, IMG_NOTE, 24);
    if (s->stack)
        img_segment(m, 0x6474e551u, s->stack == STACK_RWX ? 7 : 6, 0, 0);
    if (s->relro)
        img_segment(m, 0x6474e552u, 4, IMG_DYNAMIC, 0x100);
}

static void img_section(img_t *m, uint32_t index, uint32_t name, uint32_t type, uint64_t offset, uint64_t size,
                        uint32_t link, uint64_t entsize)
{
    uint64_t at = IMG_SHOFF + (uint64_t)index * (m->s->is64 ? 64 : 40);

    img_put(m, at, name, 4);
    img_put(m, at + 4, type, 4);
    if (m->s->is64) {
        img_put(m, at + 16, m->s->base + offset, 8);
        img_put(m, at + 24, offset, 8);
        img_put(m, at + 32, size, 8);
        img_put(m, at + 40, link, 4);
        img_put(m, at + 56, entsize, 8);
    } else {
        img_put(m, at + 12, m->s->base + offset, 4);
        img_put(m, at + 16, offset, 4);
        img_put(m, at + 20, size, 4);
        img_put(m, at + 24, link, 4);
        img_put(m, at + 36, entsize, 4);
    }
}

static uint32_t img_static_symtab(img_t *m, uint32_t *n, uint32_t *names)
{
    uint32_t strlen_ = 1, count = 1, i, name;

    for (i = 0; i < 4 && m->s->symtab[i]; i++) {
        name = img_str(m, IMG_STRTAB, &strlen_, m->s->symtab[i]);
        img_symbol(m, IMG_SYMTAB, count++, name, 1);
    }
    img_section(m, *n, img_str(m, IMG_SHSTRTAB, names, ".symtab"), 2, IMG_SYMTAB,
                (uint64_t)count * (m->s->is64 ? 24 : 16), *n + 1, m->s->is64 ? 24 : 16);
    ++*n;
    name = img_str(m, IMG_SHSTRTAB, names, ".strtab");
    img_section(m, *n, name, 3, IMG_STRTAB, strlen_, 0, 0);
    return ++*n;
}

static void img_sections(img_t *m)
{
    const img_spec_t *s = m->s;
    uint32_t names = 1, n = 1, i, name;

    if (s->dynamic) {
        img_section(m, n, img_str(m, IMG_SHSTRTAB, &names, ".dynsym"), 11, IMG_DYNSYM,
                    (uint64_t)m->nsyms * (s->is64 ? 24 : 16), n + 1, s->is64 ? 24 : 16);
        n++;
        img_section(m, n, img_str(m, IMG_SHSTRTAB, &names, ".dynstr"), 3, IMG_DYNSTR, m->dynstr_len, 0, 0);
        n++;
    }
    for (i = 0; i < 3 && s->extra[i]; i++)
        img_section(m, n++, img_str(m, IMG_SHSTRTAB, &names, s->extra[i]), 1, IMG_EXTRA, 16, 0, 0);
    if (s->symtab[0])
        img_static_symtab(m, &n, &names);
    name = img_str(m, IMG_SHSTRTAB, &names, ".shstrtab");
    img_section(m, n, name, 3, IMG_SHSTRTAB, names, 0, 0);
    img_word(m, s->is64 ? 40 : 32, IMG_SHOFF);
    img_put(m, s->is64 ? 60 : 48, n + 1, 2);
    img_put(m, s->is64 ? 62 : 50, n, 2);
}

static void img_build(img_t *m, const img_spec_t *s)
{
    memset(m, 0, sizeof(*m));
    m->s = s;
    if (s->interp)
        memcpy(m->d + IMG_INTERP, s->interp, strlen(s->interp) + 1);
    if (s->dynamic)
        img_dynamic(m);
    if (s->note_linux)
        img_note(m);
    img_segments(m);
    if (s->sections)
        img_sections(m);
    img_header(m);
}

#endif
