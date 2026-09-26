#include "elfsec/elfsec.h"
#include "elfs_image.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#define HAVE_MMAP 1
#endif

#define CHECK(cond)                                                               \
    do {                                                                          \
        if (!(cond)) {                                                            \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond);     \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

#define STR_IS(ptr, len, text) ((len) == strlen(text) && memcmp((ptr), (text), (len)) == 0)

typedef struct {
    int remaining;
    int live;
    size_t largest;
} failing_alloc_t;

static void *failing_alloc(void *ctx, size_t size)
{
    failing_alloc_t *fa = ctx;

    if (fa->remaining-- == 0)
        return NULL;
    fa->live++;
    fa->largest = size > fa->largest ? size : fa->largest;
    return malloc(size);
}

static void failing_free(void *ctx, void *ptr)
{
    failing_alloc_t *fa = ctx;

    fa->live--;
    free(ptr);
}

static img_spec_t hardened(int is64, int big)
{
    img_spec_t s;

    memset(&s, 0, sizeof(s));
    s.is64 = is64;
    s.big = big;
    s.type = 3;
    s.machine = is64 ? ELFS_EM_X86_64 : ELFS_EM_386;
    s.entry = 0x400;
    s.interp = "/lib/ld.so.1";
    s.stack = STACK_RW;
    s.relro = 1;
    s.now = NOW_FLAGS_1;
    s.df_1_pie = 1;
    s.phdr = 1;
    s.dynamic = 1;
    s.hash = HASH_SYSV;
    s.sections = 1;
    s.needed[0] = "libc.so.6";
    s.needed[1] = "libm.so.6";
    s.runpath = "$ORIGIN/../lib::lib:/tmp/x";
    s.imports[0] = "__stack_chk_fail";
    s.imports[1] = "__memcpy_chk";
    s.imports[2] = "strcpy";
    s.imports[3] = "system";
    s.imports[4] = "printf";
    s.imports[5] = "mktemp";
    s.defined[0] = "main";
    return s;
}

static void open_spec(const img_spec_t *s, img_t *m, elfs_elf_t **elf, elfs_profile_t *p)
{
    img_build(m, s);
    CHECK(elfs_open(m->d, sizeof(m->d), NULL, NULL, NULL, elf) == ELFS_OK);
    CHECK(elfs_profile(*elf, p) == ELFS_OK);
}

static void check_hardened(const elfs_profile_t *p, int is64, int big)
{
    CHECK(p->kind == ELFS_KIND_PIE && p->judged == 1 && p->type == 3);
    CHECK(p->elf_class == (is64 ? 64 : 32) && p->big_endian == big && p->arch_tested == 1);
    CHECK(p->canary == ELFS_YES && p->nx == ELFS_YES && p->pie == ELFS_YES);
    CHECK(p->relro == ELFS_RELRO_FULL && p->fortify == ELFS_YES && p->static_linked == ELFS_NO);
    CHECK(p->stripped == ELFS_YES && p->warnings == 0 && p->entry == 0x400);
    CHECK(p->fortified == 1 && p->fortifiable == 3);
    CHECK(p->needed_count == 2 && p->import_count == 6 && p->danger_count == 3 && p->path_count == 4);
    CHECK(STR_IS(p->interp, p->interp_len, "/lib/ld.so.1") && p->soname == NULL);
    CHECK(p->ev_kind.source == ELFS_SRC_DYNAMIC && p->ev_canary.source == ELFS_SRC_SYMBOL);
    CHECK(p->ev_canary.index == 1 && p->ev_canary.offset == IMG_DYNSYM + (is64 ? 24u : 16u));
    CHECK(p->ev_nx.source == ELFS_SRC_SEGMENT && p->ev_relro.source == ELFS_SRC_SEGMENT);
    CHECK(p->ev_bind_now.source == ELFS_SRC_DYNAMIC && p->ev_fortify.index == 2);
    CHECK(p->ev_static.source == ELFS_SRC_SEGMENT && p->ev_static.index == 1);
    CHECK(p->path_flags == (ELFS_PATH_RUNPATH | ELFS_PATH_ORIGIN | ELFS_PATH_EMPTY | ELFS_PATH_RELATIVE |
                            ELFS_PATH_WORLD_WRITABLE));
}

static void check_lists(const elfs_elf_t *elf, int is64)
{
    static const char *const paths[] = {"$ORIGIN/../lib", "", "lib", "/tmp/x"};
    static const uint32_t flags[] = {ELFS_PATH_ORIGIN, ELFS_PATH_EMPTY, ELFS_PATH_RELATIVE,
                                     ELFS_PATH_WORLD_WRITABLE};
    elfs_symbol_t sym;
    const char *name;
    size_t len, i;
    uint32_t f;

    CHECK(elfs_needed(elf, 0, &name, &len) == ELFS_OK && STR_IS(name, len, "libc.so.6"));
    CHECK(elfs_needed(elf, 1, &name, &len) == ELFS_OK && STR_IS(name, len, "libm.so.6"));
    for (i = 0; i < 4; i++) {
        CHECK(elfs_search_path(elf, i, &name, &len, &f) == ELFS_OK && STR_IS(name, len, paths[i]));
        CHECK(f == (flags[i] | ELFS_PATH_RUNPATH));
    }
    CHECK(elfs_import(elf, 2, &sym) == ELFS_OK && STR_IS(sym.name, sym.name_len, "strcpy"));
    CHECK(sym.index == 3 && sym.offset == IMG_DYNSYM + 3u * (is64 ? 24u : 16u));
    CHECK(sym.danger == ELFS_DANGER_UNBOUNDED && sym.bind == 1 && sym.type == 2);
    CHECK(elfs_dangerous(elf, 0, &sym) == ELFS_OK && STR_IS(sym.name, sym.name_len, "strcpy"));
    CHECK(elfs_dangerous(elf, 1, &sym) == ELFS_OK && sym.danger == ELFS_DANGER_COMMAND);
    CHECK(elfs_dangerous(elf, 2, &sym) == ELFS_OK && sym.danger == ELFS_DANGER_TEMPFILE);
    CHECK(elfs_import(elf, 6, &sym) == ELFS_ERR_ARG && elfs_dangerous(elf, 3, &sym) == ELFS_ERR_ARG);
    CHECK(elfs_needed(elf, 2, &name, &len) == ELFS_ERR_ARG);
    CHECK(elfs_search_path(elf, 4, &name, &len, &f) == ELFS_ERR_ARG);
}

static void test_hardened_every_layout(void)
{
    int is64, big;

    for (is64 = 0; is64 < 2; is64++) {
        for (big = 0; big < 2; big++) {
            img_spec_t s = hardened(is64, big);
            elfs_elf_t *elf;
            elfs_profile_t p;
            img_t m;

            open_spec(&s, &m, &elf, &p);
            check_hardened(&p, is64, big);
            check_lists(elf, is64);
            elfs_destroy(elf);
        }
    }
}

static void test_weak_executable(void)
{
    img_spec_t s = hardened(1, 0);
    elfs_elf_t *elf;
    elfs_profile_t p;
    img_t m;

    s.type = 2;
    s.base = 0x400000;
    s.stack = STACK_RWX;
    s.relro = 0;
    s.now = NOW_NONE;
    s.df_1_pie = 0;
    s.runpath = NULL;
    s.rpath = "/opt/lib";
    s.imports[0] = "gets";
    s.imports[1] = "puts";
    open_spec(&s, &m, &elf, &p);
    CHECK(p.kind == ELFS_KIND_EXEC && p.judged == 1 && p.pie == ELFS_NO && p.ev_pie.source == ELFS_SRC_HEADER);
    CHECK(p.nx == ELFS_NO && p.ev_nx.source == ELFS_SRC_SEGMENT && p.relro == ELFS_RELRO_NONE);
    CHECK(p.canary == ELFS_NO && p.fortify == ELFS_NO && p.fortified == 0 && p.fortifiable == 3);
    CHECK(p.path_count == 1 && p.path_flags == 0 && p.danger_count == 4);
    elfs_destroy(elf);
}

static void test_relro_and_bind_now(void)
{
    static const int nows[] = {NOW_NONE, NOW_TAG, NOW_FLAGS, NOW_FLAGS_1};
    static const uint8_t want[] = {ELFS_RELRO_PARTIAL, ELFS_RELRO_FULL, ELFS_RELRO_FULL, ELFS_RELRO_FULL};
    size_t i;

    for (i = 0; i < 4; i++) {
        img_spec_t s = hardened(1, 0);
        elfs_elf_t *elf;
        elfs_profile_t p;
        img_t m;

        s.now = nows[i];
        open_spec(&s, &m, &elf, &p);
        CHECK(p.relro == want[i] && p.kind == ELFS_KIND_PIE);
        CHECK((p.ev_bind_now.source == ELFS_SRC_DYNAMIC) == (i != 0));
        elfs_destroy(elf);
    }
}

static void test_nx_default(void)
{
    static const uint16_t machines[] = {ELFS_EM_AARCH64, ELFS_EM_RISCV, ELFS_EM_MIPS, ELFS_EM_X86_64};
    static const uint8_t want[] = {ELFS_YES, ELFS_YES, ELFS_NO, ELFS_NO};
    size_t i;

    for (i = 0; i < 4; i++) {
        img_spec_t s = hardened(1, 0);
        elfs_elf_t *elf;
        elfs_profile_t p;
        img_t m;

        s.machine = machines[i];
        s.stack = STACK_NONE;
        open_spec(&s, &m, &elf, &p);
        CHECK(p.nx == want[i]);
        CHECK(p.ev_nx.source == (want[i] == ELFS_YES ? ELFS_SRC_ARCH : ELFS_SRC_NONE));
        elfs_destroy(elf);
    }
}

static void test_shared_library(void)
{
    img_spec_t s = hardened(1, 1);
    elfs_elf_t *elf;
    elfs_profile_t p;
    img_t m;

    s.interp = NULL;
    s.df_1_pie = 0;
    s.now = NOW_FLAGS;
    s.soname = "libfoo.so.1";
    open_spec(&s, &m, &elf, &p);
    CHECK(p.kind == ELFS_KIND_SHARED && p.judged == 1 && p.pie == ELFS_YES && p.static_linked == ELFS_NO);
    CHECK(STR_IS(p.soname, p.soname_len, "libfoo.so.1") && p.interp == NULL && p.relro == ELFS_RELRO_FULL);
    elfs_destroy(elf);
}

static uint32_t kind_of(const img_spec_t *s, elfs_profile_t *p)
{
    elfs_elf_t *elf;
    img_t m;

    open_spec(s, &m, &elf, p);
    elfs_destroy(elf);
    return p->kind;
}

static img_spec_t bare(uint16_t type)
{
    img_spec_t s;

    memset(&s, 0, sizeof(s));
    s.is64 = 1;
    s.type = type;
    s.machine = ELFS_EM_AARCH64;
    s.sections = 1;
    return s;
}

static void test_not_judged(void)
{
    img_spec_t s = bare(1);
    elfs_profile_t p;

    CHECK(kind_of(&s, &p) == ELFS_KIND_RELOC && p.judged == 0 && p.canary == ELFS_NA && p.nx == ELFS_NA);
    s.extra[0] = ".modinfo";
    CHECK(kind_of(&s, &p) == ELFS_KIND_KMOD && p.ev_kind.source == ELFS_SRC_SECTION && p.relro == ELFS_NA);
    s = bare(4);
    CHECK(kind_of(&s, &p) == ELFS_KIND_CORE && p.pie == ELFS_NA);
    s = bare(2);
    s.stack = STACK_RW;
    s.phdr = 1;
    s.extra[0] = "__ksymtab";
    CHECK(kind_of(&s, &p) == ELFS_KIND_KERNEL && p.fortify == ELFS_NA);
    s.extra[0] = NULL;
    s.note_linux = 1;
    CHECK(kind_of(&s, &p) == ELFS_KIND_KERNEL && p.ev_kind.source == ELFS_SRC_NOTE);
    s = bare(2);
    s.stack = STACK_RW;
    s.phdr = 1;
    s.extra[0] = ".u_boot_list";
    CHECK(kind_of(&s, &p) == ELFS_KIND_BARE && p.ev_kind.source == ELFS_SRC_SECTION);
    s = bare(2);
    CHECK(kind_of(&s, &p) == ELFS_KIND_BARE && p.judged == 0);
    s.stack = STACK_RW;
    s.extra_loads = 1;
    CHECK(kind_of(&s, &p) == ELFS_KIND_BARE);
    s.stack = STACK_NONE;
    s.entry = (uint64_t)1 << 63;
    s.phdr = 1;
    CHECK(kind_of(&s, &p) == ELFS_KIND_BARE);
}

static void test_static(void)
{
    img_spec_t s = bare(2);
    elfs_profile_t p;

    s.stack = STACK_RW;
    s.phdr = 1;
    s.base = 0x400000;
    CHECK(kind_of(&s, &p) == ELFS_KIND_EXEC && p.judged == 1 && p.static_linked == ELFS_YES);
    CHECK(p.canary == ELFS_UNKNOWN && p.fortify == ELFS_UNKNOWN && p.stripped == ELFS_YES);
    CHECK(p.ev_static.source == ELFS_SRC_NONE);
    s.symtab[0] = "__stack_chk_fail";
    s.symtab[1] = "__memcpy_chk";
    s.symtab[2] = "main";
    CHECK(kind_of(&s, &p) == ELFS_KIND_EXEC && p.canary == ELFS_YES && p.fortify == ELFS_YES);
    CHECK(p.ev_canary.source == ELFS_SRC_SYMTAB && p.ev_canary.index == 1 && p.fortified == 1);
    CHECK(p.stripped == ELFS_NO && p.ev_stripped.source == ELFS_SRC_SECTION);
    s.symtab[0] = "main";
    s.symtab[1] = NULL;
    CHECK(kind_of(&s, &p) == ELFS_KIND_EXEC && p.canary == ELFS_NO && p.fortify == ELFS_NO);
    s.type = 3;
    s.dynamic = 1;
    s.df_1_pie = 1;
    s.hash = HASH_SYSV;
    CHECK(kind_of(&s, &p) == ELFS_KIND_PIE && p.static_linked == ELFS_YES && p.canary == ELFS_NO);
    s.df_1_pie = 0;
    CHECK(kind_of(&s, &p) == ELFS_KIND_SHARED && p.static_linked == ELFS_NO);
}

static void test_symbol_count_sources(void)
{
    static const int hashes[] = {HASH_SYSV, HASH_GNU, HASH_GNU_EMPTY_BFD, HASH_MIPS, HASH_NONE};
    size_t i;

    for (i = 0; i < 5; i++) {
        img_spec_t s = hardened(0, 1);
        elfs_elf_t *elf;
        elfs_profile_t p;
        img_t m;

        s.sections = 0;
        s.hash = hashes[i];
        if (s.hash == HASH_MIPS)
            s.machine = ELFS_EM_MIPS;
        open_spec(&s, &m, &elf, &p);
        CHECK(p.import_count == 6 && p.canary == ELFS_YES && p.danger_count == 3);
        CHECK((p.warnings & ~(uint32_t)ELFS_WARN_NAME) == 0);
        elfs_destroy(elf);
    }
}

static void test_open_arguments(void)
{
    img_spec_t s = hardened(1, 0);
    elfs_elf_t *elf = (elfs_elf_t *)&s;
    failing_alloc_t fa = {0, 0, 0};
    img_t m;

    img_build(&m, &s);
    CHECK(elfs_open(NULL, 10, NULL, NULL, NULL, &elf) == ELFS_ERR_ARG && elf == NULL);
    CHECK(elfs_open(m.d, sizeof(m.d), NULL, NULL, NULL, NULL) == ELFS_ERR_ARG);
    CHECK(elfs_open(m.d, sizeof(m.d), failing_alloc, NULL, &fa, &elf) == ELFS_ERR_ARG);
    CHECK(elfs_open(m.d, sizeof(m.d), NULL, failing_free, &fa, &elf) == ELFS_ERR_ARG);
    CHECK(elfs_open(m.d, 0, NULL, NULL, NULL, &elf) == ELFS_ERR_FORMAT);
    CHECK(elfs_open(m.d, 40, NULL, NULL, NULL, &elf) == ELFS_ERR_FORMAT);
    m.d[4] = 3;
    CHECK(elfs_open(m.d, sizeof(m.d), NULL, NULL, NULL, &elf) == ELFS_ERR_FORMAT);
    m.d[4] = 2;
    m.d[5] = 0;
    CHECK(elfs_open(m.d, sizeof(m.d), NULL, NULL, NULL, &elf) == ELFS_ERR_FORMAT);
    m.d[5] = 1;
    m.d[0] = 0;
    CHECK(elfs_open(m.d, sizeof(m.d), NULL, NULL, NULL, &elf) == ELFS_ERR_FORMAT);
    elfs_destroy(NULL);
}

static void test_accessor_arguments(void)
{
    img_spec_t s = hardened(1, 0);
    elfs_elf_t *elf;
    elfs_profile_t p;
    elfs_symbol_t sym;
    const char *name;
    size_t len;
    uint32_t f;
    img_t m;

    open_spec(&s, &m, &elf, &p);
    CHECK(elfs_profile(NULL, &p) == ELFS_ERR_ARG && elfs_profile(elf, NULL) == ELFS_ERR_ARG);
    CHECK(elfs_needed(NULL, 0, &name, &len) == ELFS_ERR_ARG && elfs_needed(elf, 0, NULL, &len) == ELFS_ERR_ARG);
    CHECK(elfs_needed(elf, 0, &name, NULL) == ELFS_ERR_ARG);
    CHECK(elfs_search_path(elf, 0, &name, &len, NULL) == ELFS_ERR_ARG);
    CHECK(elfs_search_path(NULL, 0, &name, &len, &f) == ELFS_ERR_ARG);
    CHECK(elfs_import(NULL, 0, &sym) == ELFS_ERR_ARG && elfs_import(elf, 0, NULL) == ELFS_ERR_ARG);
    CHECK(elfs_dangerous(NULL, 0, &sym) == ELFS_ERR_ARG && elfs_dangerous(elf, 0, NULL) == ELFS_ERR_ARG);
    elfs_destroy(elf);
}

static void test_names(void)
{
    uint32_t i;

    for (i = 0; i <= 9; i++)
        CHECK(elfs_kind_name(i) != NULL && elfs_danger_name(i) != NULL);
    CHECK(strcmp(elfs_kind_name(ELFS_KIND_PIE), "pie") == 0);
    CHECK(strcmp(elfs_kind_name(ELFS_KIND_KMOD), "kernel module") == 0);
    CHECK(strcmp(elfs_danger_name(ELFS_DANGER_COMMAND), "shell command") == 0);
    CHECK(strcmp(elfs_machine_name(ELFS_EM_AARCH64), "aarch64") == 0);
    CHECK(elfs_machine_name(0xffff) != NULL && elfs_machine_name(ELFS_EM_S390) != NULL);
    for (i = 0; i <= 4; i++)
        CHECK(elfs_strerror((int)i) != NULL);
    CHECK(elfs_strerror(-1) != NULL);
}

static void test_allocation_failure(void)
{
    img_spec_t s = hardened(1, 0);
    img_t m;
    int n, opened = 0;

    img_build(&m, &s);
    for (n = 0; !opened; n++) {
        failing_alloc_t fa = {0, 0, 0};
        elfs_elf_t *elf = NULL;
        int status;

        fa.remaining = n;
        status = elfs_open(m.d, sizeof(m.d), failing_alloc, failing_free, &fa, &elf);
        CHECK(status == ELFS_OK || status == ELFS_ERR_NOMEM);
        CHECK(status == ELFS_OK || (elf == NULL && fa.live == 0));
        opened = status == ELFS_OK;
        elfs_destroy(elf);
        CHECK(fa.live == 0);
        CHECK(fa.largest < 1024 || n > 1);
    }
    CHECK(n == 3);
}

static void test_corrupt_tables(void)
{
    img_spec_t s = hardened(1, 0);
    elfs_elf_t *elf;
    elfs_profile_t p;
    img_t m;

    img_build(&m, &s);
    img_put(&m, IMG_HASH + 4, 0x7fffffff, 4);
    m.d[60] = 0;
    CHECK(elfs_open(m.d, sizeof(m.d), NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, &p) == ELFS_OK);
    CHECK(p.warnings & (ELFS_WARN_TRUNCATED | ELFS_WARN_SYMBOL_BUDGET));
    elfs_destroy(elf);
    img_build(&m, &s);
    img_put(&m, 40, 0xfffffff0u, 8);
    CHECK(elfs_open(m.d, sizeof(m.d), NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, &p) == ELFS_OK);
    CHECK(p.warnings & ELFS_WARN_SECTIONS);
    CHECK(p.import_count == 6);
    elfs_destroy(elf);
    img_build(&m, &s);
    img_put(&m, 32, 0xfffffff0u, 8);
    CHECK(elfs_open(m.d, sizeof(m.d), NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, &p) == ELFS_OK);
    CHECK(p.warnings & ELFS_WARN_SEGMENTS);
    elfs_destroy(elf);
}

static void test_truncation(void)
{
    static const int layouts[][2] = {{0, 0}, {1, 1}};
    size_t k, len;

    for (k = 0; k < 2; k++) {
        img_spec_t s = hardened(layouts[k][0], layouts[k][1]);
        img_t m;
#ifdef HAVE_MMAP
        size_t page = (size_t)sysconf(_SC_PAGESIZE);
        size_t span = (IMG_SIZE + page - 1) / page * page;
        unsigned char *map = mmap(NULL, span + page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        CHECK(map != MAP_FAILED && mprotect(map + span, page, PROT_NONE) == 0);
#endif
        s.sections = (int)k;
        img_build(&m, &s);
        for (len = 0; len <= IMG_SIZE; len++) {
            const unsigned char *data = m.d;
            elfs_elf_t *elf = NULL;
            elfs_profile_t p;
            size_t header = layouts[k][0] ? 64 : 52;
            int status;
#ifdef HAVE_MMAP
            memcpy(map + span - len, m.d, len);
            data = map + span - len;
#endif
            status = elfs_open(data, len, NULL, NULL, NULL, &elf);
            CHECK(status == (len < header ? ELFS_ERR_FORMAT : ELFS_OK));
            if (status == ELFS_OK) {
                CHECK(elfs_profile(elf, &p) == ELFS_OK && p.import_count <= 6);
                CHECK(len == IMG_SIZE || p.warnings != 0 || p.kind != ELFS_KIND_PIE);
            }
            elfs_destroy(elf);
        }
#ifdef HAVE_MMAP
        munmap(map, span + page);
#endif
    }
}

static void put_le(unsigned char *d, size_t at, uint64_t v, unsigned n)
{
    unsigned i;

    for (i = 0; i < n; i++)
        d[at + i] = (unsigned char)(v >> (8 * i));
}

static void bound_segment(unsigned char *d, uint64_t i, uint32_t type, uint64_t offset, uint64_t size)
{
    size_t at = 64 + (size_t)i * 56;

    put_le(d, at, type, 4);
    put_le(d, at + 8, offset, 8);
    put_le(d, at + 16, offset, 8);
    put_le(d, at + 32, size, 8);
    put_le(d, at + 40, size, 8);
}

static unsigned char *bound_image(size_t len, uint16_t type, uint64_t phnum)
{
    unsigned char *d = calloc(1, len);

    CHECK(d != NULL);
    memcpy(d, "\177ELF\2\1\1", 7);
    put_le(d, 16, type, 2);
    put_le(d, 18, 62, 2);
    put_le(d, 32, 64, 8);
    put_le(d, 54, 56, 2);
    put_le(d, 56, phnum, 2);
    put_le(d, 58, 64, 2);
    bound_segment(d, 0, 1, 0, len);
    return d;
}

static uint32_t bound_warnings(const unsigned char *d, size_t len, elfs_profile_t *p)
{
    elfs_elf_t *elf;

    CHECK(elfs_open(d, len, NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, p) == ELFS_OK);
    elfs_destroy(elf);
    return p->warnings;
}

static void test_table_bounds(void)
{
    size_t len = (ELFS_MAX_SECTIONS + 16) * 64;
    unsigned char *d = bound_image(len, 2, 0xffff);
    elfs_profile_t p;
    size_t i;

    put_le(d, 40, 64, 8);
    put_le(d, 60, 0, 2);
    put_le(d, 64 + 32, ELFS_MAX_SECTIONS + 8, 8);
    put_le(d, 64 + 44, ELFS_MAX_SEGMENTS + 8, 4);
    CHECK(bound_warnings(d, len, &p) & ELFS_WARN_BUDGET);
    free(d);
    d = bound_image(len, 3, 2);
    bound_segment(d, 1, 2, 0x1000, (ELFS_MAX_DYNAMIC + 8) * 16);
    CHECK(bound_warnings(d, len, &p) & ELFS_WARN_BUDGET);
    free(d);
    d = bound_image(len, 2, 2);
    bound_segment(d, 1, 4, 0x1000, (ELFS_MAX_NOTES + 8) * 12);
    CHECK(bound_warnings(d, len, &p) & ELFS_WARN_BUDGET);
    for (i = 0; i < 2; i++)
        bound_segment(d, 1 + i, 4, 0x1000 + i * ELFS_MAX_NOTES * 12, ELFS_MAX_NOTES * 12);
    put_le(d, 56, 3, 2);
    CHECK(bound_warnings(d, len, &p) & ELFS_WARN_BUDGET);
    free(d);
}

static void test_path_bound(void)
{
    size_t len = 0x10000, i, plen;
    unsigned char *d = bound_image(len, 3, 2);
    const char *path;
    elfs_elf_t *elf;
    elfs_profile_t p;
    uint32_t flags;

    bound_segment(d, 1, 2, 0x1000, 4 * 16);
    put_le(d, 0x1000, 5, 8);
    put_le(d, 0x1008, 0x2000, 8);
    put_le(d, 0x1010, 10, 8);
    put_le(d, 0x1018, 0x8000, 8);
    put_le(d, 0x1020, 29, 8);
    put_le(d, 0x1028, 1, 8);
    for (i = 0; i < ELFS_MAX_PATHS + 8; i++)
        memcpy(d + 0x2001 + 3 * i, "/a:", 3);
    d[0x2001 + 3 * (ELFS_MAX_PATHS + 8) - 1] = 0;
    CHECK(elfs_open(d, len, NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, &p) == ELFS_OK);
    CHECK(p.path_count == ELFS_MAX_PATHS && (p.warnings & ELFS_WARN_BUDGET));
    CHECK(elfs_search_path(elf, ELFS_MAX_PATHS - 1, &path, &plen, &flags) == ELFS_OK);
    CHECK(STR_IS(path, plen, "/a") && path == (const char *)d + 0x2001 + 3 * (ELFS_MAX_PATHS - 1));
    CHECK(flags == ELFS_PATH_RUNPATH);
    CHECK(elfs_search_path(elf, ELFS_MAX_PATHS, &path, &plen, &flags) == ELFS_ERR_ARG);
    elfs_destroy(elf);
    free(d);
}

static void test_gnu_hash_bound(void)
{
    size_t len = 0x10000;
    unsigned char *d = bound_image(len, 3, 2);
    elfs_profile_t p;

    bound_segment(d, 1, 2, 0x1000, 3 * 16);
    put_le(d, 0x1000, 0x6ffffef5u, 8);
    put_le(d, 0x1008, 0x2000, 8);
    put_le(d, 0x1010, 6, 8);
    put_le(d, 0x1018, 0x3000, 8);
    put_le(d, 0x2000, ELFS_MAX_SYMBOLS + 1, 4);
    put_le(d, 0x2004, 1, 4);
    CHECK(bound_warnings(d, len, &p) & ELFS_WARN_SYMBOLS);
    CHECK(p.import_count == 0);
    free(d);
}

int main(void)
{
    test_hardened_every_layout();
    test_weak_executable();
    test_relro_and_bind_now();
    test_nx_default();
    test_shared_library();
    test_not_judged();
    test_static();
    test_symbol_count_sources();
    test_open_arguments();
    test_accessor_arguments();
    test_names();
    test_allocation_failure();
    test_corrupt_tables();
    test_truncation();
    test_table_bounds();
    test_path_bound();
    test_gnu_hash_bound();
    puts("ok");
    return 0;
}
