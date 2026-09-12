#include "elfs_internal.h"

#include <string.h>

typedef struct elfs_segments {
    int has_interp;
    uint64_t interp_index;
    elfs_phdr_t interp;
    int has_stack;
    uint64_t stack_index;
    elfs_phdr_t stack;
    int has_relro;
    uint64_t relro_index;
    uint64_t loads;
    uint64_t userland;
} elfs_segments_t;

static void elfs_set_ev(elfs_evidence_t *ev, uint32_t source, uint64_t index, uint64_t offset)
{
    ev->source = source;
    ev->index = (uint32_t)index;
    ev->offset = offset;
}

static void elfs_segment_ev(const elfs_elf_t *elf, elfs_evidence_t *ev, uint64_t index)
{
    elfs_set_ev(ev, ELFS_SRC_SEGMENT, index, elf->phoff + index * elf->phentsize);
}

static void elfs_section_ev(const elfs_elf_t *elf, elfs_evidence_t *ev, uint64_t index)
{
    elfs_set_ev(ev, ELFS_SRC_SECTION, index, elf->shoff + index * elf->shentsize);
}

static void elfs_dynamic_ev(const elfs_elf_t *elf, elfs_evidence_t *ev, int slot)
{
    uint64_t index = elf->tags[slot].index;

    elfs_set_ev(ev, ELFS_SRC_DYNAMIC, index, elf->dyn_offset + index * (elf->is64 ? 16 : 8));
}

static int elfs_userland_segment(uint32_t type)
{
    return type == ELFS_PT_PHDR || type == ELFS_PT_TLS || type == ELFS_PT_NOTE || type == ELFS_PT_GNU_RELRO ||
           type == ELFS_PT_GNU_EH_FRAME || type == ELFS_PT_GNU_PROPERTY;
}

static void elfs_note_segment(elfs_segments_t *s, const elfs_phdr_t *ph, uint64_t i)
{
    if (ph->type == ELFS_PT_LOAD)
        s->loads++;
    if (elfs_userland_segment(ph->type))
        s->userland++;
    if (ph->type == ELFS_PT_INTERP && !s->has_interp) {
        s->has_interp = 1;
        s->interp_index = i;
        s->interp = *ph;
    }
    if (ph->type == ELFS_PT_GNU_STACK && !s->has_stack) {
        s->has_stack = 1;
        s->stack_index = i;
        s->stack = *ph;
    }
    if (ph->type == ELFS_PT_GNU_RELRO && !s->has_relro) {
        s->has_relro = 1;
        s->relro_index = i;
    }
}

static void elfs_read_segments(const elfs_elf_t *elf, elfs_segments_t *out_segments)
{
    elfs_phdr_t ph;
    uint64_t i;

    memset(out_segments, 0, sizeof(*out_segments));
    for (i = 0; elfs_phdr(elf, i, &ph); i++)
        elfs_note_segment(out_segments, &ph, i);
}

static void elfs_read_interp(elfs_elf_t *elf, const elfs_segments_t *s)
{
    const unsigned char *start;
    const unsigned char *nul;
    uint64_t size;

    if (!s->has_interp)
        return;
    if (!elfs_fits(elf, s->interp.offset, 0)) {
        elf->profile.warnings |= ELFS_WARN_TRUNCATED;
        return;
    }
    size = elf->len - s->interp.offset;
    if (s->interp.filesz > size)
        elf->profile.warnings |= ELFS_WARN_TRUNCATED;
    size = s->interp.filesz < size ? s->interp.filesz : size;
    start = elf->data + s->interp.offset;
    nul = size ? memchr(start, 0, (size_t)size) : NULL;
    elf->profile.interp = (const char *)start;
    elf->profile.interp_len = nul ? (size_t)(nul - start) : (size_t)size;
}

static int elfs_arch_tested(uint32_t machine)
{
    switch (machine) {
    case ELFS_EM_386:
    case ELFS_EM_MIPS:
    case ELFS_EM_PPC:
    case ELFS_EM_PPC64:
    case ELFS_EM_S390:
    case ELFS_EM_ARM:
    case ELFS_EM_X86_64:
    case ELFS_EM_AARCH64:
    case ELFS_EM_RISCV:
        return 1;
    default:
        return 0;
    }
}

static int elfs_is_kernel(const elfs_elf_t *elf, elfs_evidence_t *ev)
{
    if (elf->sections.kernel) {
        elfs_section_ev(elf, ev, elf->sections.kernel_index);
        return 1;
    }
    return elfs_has_linux_note(elf, ev);
}

static uint32_t elfs_kind_dyn(const elfs_elf_t *elf, const elfs_segments_t *s, elfs_evidence_t *ev)
{
    const elfs_tag_t *flags_1 = &elf->tags[ELFS_TAG_FLAGS_1];

    if (flags_1->present && (flags_1->value & ELFS_DF_1_PIE)) {
        elfs_dynamic_ev(elf, ev, ELFS_TAG_FLAGS_1);
        return ELFS_KIND_PIE;
    }
    if (elf->tags[ELFS_TAG_SONAME].present) {
        elfs_dynamic_ev(elf, ev, ELFS_TAG_SONAME);
        return ELFS_KIND_SHARED;
    }
    if (s->has_interp) {
        elfs_segment_ev(elf, ev, s->interp_index);
        return ELFS_KIND_PIE;
    }
    elfs_set_ev(ev, ELFS_SRC_HEADER, 0, 0);
    return ELFS_KIND_SHARED;
}

static int elfs_is_bare(const elfs_elf_t *elf, const elfs_segments_t *s, elfs_evidence_t *ev)
{
    uint64_t upper = elf->is64 ? (uint64_t)1 << 63 : (uint64_t)1 << 31;

    if (elf->sections.uboot) {
        elfs_section_ev(elf, ev, elf->sections.uboot_index);
        return 1;
    }
    elfs_set_ev(ev, ELFS_SRC_NONE, 0, 0);
    if (!s->has_stack && (s->loads <= 1 || elf->profile.entry >= upper))
        return 1;
    return s->userland == 0;
}

static uint32_t elfs_kind_exec(const elfs_elf_t *elf, const elfs_segments_t *s, elfs_evidence_t *ev)
{
    if (s->has_interp) {
        elfs_segment_ev(elf, ev, s->interp_index);
        return ELFS_KIND_EXEC;
    }
    elfs_set_ev(ev, ELFS_SRC_HEADER, 0, 0);
    return ELFS_KIND_EXEC;
}

static uint32_t elfs_kind_loadable(const elfs_elf_t *elf, const elfs_segments_t *s, elfs_evidence_t *ev)
{
    int alone = !s->has_interp && elf->needed_tags == 0 && !elf->tags[ELFS_TAG_SONAME].present;

    if (!s->has_interp && elfs_is_kernel(elf, ev))
        return ELFS_KIND_KERNEL;
    if (alone && elfs_is_bare(elf, s, ev))
        return ELFS_KIND_BARE;
    return elf->type == ELFS_ET_DYN ? elfs_kind_dyn(elf, s, ev) : elfs_kind_exec(elf, s, ev);
}

static uint32_t elfs_classify(const elfs_elf_t *elf, const elfs_segments_t *s, elfs_evidence_t *ev)
{
    elfs_set_ev(ev, ELFS_SRC_HEADER, 0, 0);
    switch (elf->type) {
    case ELFS_ET_CORE:
        return ELFS_KIND_CORE;
    case ELFS_ET_REL:
        if (!elf->sections.kmod)
            return ELFS_KIND_RELOC;
        elfs_section_ev(elf, ev, elf->sections.kmod_index);
        return ELFS_KIND_KMOD;
    case ELFS_ET_EXEC:
    case ELFS_ET_DYN:
        return elfs_kind_loadable(elf, s, ev);
    default:
        return ELFS_KIND_UNKNOWN;
    }
}

static void elfs_not_judged(elfs_profile_t *p)
{
    p->canary = p->nx = p->pie = p->fortify = p->static_linked = p->stripped = ELFS_NA;
    p->relro = ELFS_RELRO_NONE;
    memset(&p->ev_canary, 0, sizeof(p->ev_canary));
    memset(&p->ev_fortify, 0, sizeof(p->ev_fortify));
}

static void elfs_judge_nx(elfs_elf_t *elf, const elfs_segments_t *s)
{
    elfs_profile_t *p = &elf->profile;

    if (s->has_stack) {
        p->nx = (s->stack.flags & ELFS_PF_X) ? ELFS_NO : ELFS_YES;
        elfs_segment_ev(elf, &p->ev_nx, s->stack_index);
        return;
    }
    if (p->machine == ELFS_EM_AARCH64 || p->machine == ELFS_EM_RISCV) {
        p->nx = ELFS_YES;
        elfs_set_ev(&p->ev_nx, ELFS_SRC_ARCH, p->machine, 0);
        return;
    }
    p->nx = ELFS_NO;
}

static int elfs_bind_now(const elfs_elf_t *elf, elfs_evidence_t *ev)
{
    const elfs_tag_t *t = elf->tags;

    if (t[ELFS_TAG_BIND_NOW].present) {
        elfs_dynamic_ev(elf, ev, ELFS_TAG_BIND_NOW);
        return 1;
    }
    if (t[ELFS_TAG_FLAGS].present && (t[ELFS_TAG_FLAGS].value & ELFS_DF_BIND_NOW)) {
        elfs_dynamic_ev(elf, ev, ELFS_TAG_FLAGS);
        return 1;
    }
    if (t[ELFS_TAG_FLAGS_1].present && (t[ELFS_TAG_FLAGS_1].value & ELFS_DF_1_NOW)) {
        elfs_dynamic_ev(elf, ev, ELFS_TAG_FLAGS_1);
        return 1;
    }
    return 0;
}

static void elfs_judge_relro(elfs_elf_t *elf, const elfs_segments_t *s)
{
    elfs_profile_t *p = &elf->profile;
    int now = elfs_bind_now(elf, &p->ev_bind_now);

    if (!s->has_relro) {
        p->relro = ELFS_RELRO_NONE;
        return;
    }
    elfs_segment_ev(elf, &p->ev_relro, s->relro_index);
    p->relro = now ? ELFS_RELRO_FULL : ELFS_RELRO_PARTIAL;
}

static void elfs_note_static_symbol(elfs_elf_t *elf, const elfs_sym_t *sym, const char *name, size_t len,
                                    uint64_t i)
{
    elfs_profile_t *p = &elf->profile;
    const elfs_shdr_t *tab = &elf->sections.symtab;

    if (elfs_is_canary(name, len) && p->ev_canary.source == ELFS_SRC_NONE)
        elfs_set_ev(&p->ev_canary, ELFS_SRC_SYMTAB, i, tab->offset + i * tab->entsize);
    if ((sym->info & 0xf) != ELFS_STT_FUNC || !elfs_is_fortified(name, len))
        return;
    p->fortified++;
    if (p->ev_fortify.source == ELFS_SRC_NONE)
        elfs_set_ev(&p->ev_fortify, ELFS_SRC_SYMTAB, i, tab->offset + i * tab->entsize);
}

static int elfs_static_strings(const elfs_elf_t *elf, elfs_strtab_t *out_names)
{
    elfs_shdr_t sh;

    if (!elfs_shdr(elf, elf->sections.symtab.link, &sh) || !elfs_fits(elf, sh.offset, 0))
        return 0;
    out_names->offset = sh.offset;
    out_names->size = sh.size < elf->len - sh.offset ? sh.size : elf->len - sh.offset;
    return 1;
}

static uint64_t elfs_static_count(elfs_elf_t *elf)
{
    const elfs_shdr_t *tab = &elf->sections.symtab;
    uint64_t count;

    if (tab->entsize < (uint64_t)(elf->is64 ? 24 : 16) || !elfs_fits(elf, tab->offset, 0))
        return 0;
    count = tab->size / tab->entsize;
    if (count > ELFS_MAX_SYMBOLS) {
        count = ELFS_MAX_SYMBOLS;
        elf->profile.warnings |= ELFS_WARN_SYMBOL_BUDGET;
    }
    if (count > (elf->len - tab->offset) / tab->entsize) {
        count = (elf->len - tab->offset) / tab->entsize;
        elf->profile.warnings |= ELFS_WARN_TRUNCATED;
    }
    return count;
}

static int elfs_scan_static(elfs_elf_t *elf)
{
    const elfs_shdr_t *tab = &elf->sections.symtab;
    elfs_strtab_t names;
    elfs_sym_t sym;
    const char *name;
    size_t len;
    uint64_t count;
    uint64_t i;

    if (!elf->sections.has_symtab || !elfs_static_strings(elf, &names))
        return 0;
    count = elfs_static_count(elf);
    for (i = 1; i < count; i++) {
        elfs_sym(elf, tab->offset + i * tab->entsize, &sym);
        if (sym.shndx != 0 && sym.name != 0 && elfs_string(elf, &names, sym.name, &name, &len))
            elfs_note_static_symbol(elf, &sym, name, len, i);
    }
    elf->profile.fortifiable = elf->profile.fortified;
    return 1;
}

static void elfs_judge_symbols(elfs_elf_t *elf, int known)
{
    elfs_profile_t *p = &elf->profile;

    if (!known) {
        p->canary = p->fortify = ELFS_UNKNOWN;
        return;
    }
    p->canary = p->ev_canary.source != ELFS_SRC_NONE ? ELFS_YES : ELFS_NO;
    p->fortify = p->fortified > 0 ? ELFS_YES : ELFS_NO;
}

static void elfs_judge(elfs_elf_t *elf, const elfs_segments_t *s)
{
    elfs_profile_t *p = &elf->profile;
    int is_static = p->kind != ELFS_KIND_SHARED && !s->has_interp;

    elfs_judge_nx(elf, s);
    elfs_judge_relro(elf, s);
    p->pie = p->kind == ELFS_KIND_EXEC ? ELFS_NO : ELFS_YES;
    p->ev_pie = p->kind == ELFS_KIND_PIE ? p->ev_kind : p->ev_pie;
    if (p->kind != ELFS_KIND_PIE)
        elfs_set_ev(&p->ev_pie, ELFS_SRC_HEADER, 0, 0);
    p->static_linked = is_static ? ELFS_YES : ELFS_NO;
    if (s->has_interp)
        elfs_segment_ev(elf, &p->ev_static, s->interp_index);
    p->stripped = elf->sections.has_symtab ? ELFS_NO : ELFS_YES;
    if (elf->sections.has_symtab)
        elfs_section_ev(elf, &p->ev_stripped, elf->sections.symtab_index);
    if (is_static) {
        p->fortified = p->fortifiable = 0;
        memset(&p->ev_canary, 0, sizeof(p->ev_canary));
        memset(&p->ev_fortify, 0, sizeof(p->ev_fortify));
        elfs_judge_symbols(elf, elfs_scan_static(elf));
        return;
    }
    elfs_judge_symbols(elf, elf->has_symbols);
}

void elfs_build_profile(elfs_elf_t *elf)
{
    elfs_profile_t *p = &elf->profile;
    elfs_segments_t s;

    elfs_read_segments(elf, &s);
    elfs_read_interp(elf, &s);
    p->arch_tested = (uint8_t)elfs_arch_tested(p->machine);
    p->kind = elfs_classify(elf, &s, &p->ev_kind);
    p->judged = p->kind == ELFS_KIND_EXEC || p->kind == ELFS_KIND_PIE || p->kind == ELFS_KIND_SHARED;
    if (!p->judged) {
        elfs_not_judged(p);
        return;
    }
    elfs_judge(elf, &s);
}
