#include "elfs_internal.h"

#include <string.h>

#define ELFS_PN_XNUM 0xffffu
#define ELFS_SHN_XINDEX 0xffffu

int elfs_fits(const elfs_elf_t *elf, uint64_t offset, uint64_t size)
{
    return offset <= elf->len && size <= elf->len - offset;
}

uint32_t elfs_u16(const elfs_elf_t *elf, uint64_t offset)
{
    const unsigned char *p = elf->data + offset;

    if (elf->big)
        return (uint32_t)p[0] << 8 | p[1];
    return (uint32_t)p[1] << 8 | p[0];
}

uint32_t elfs_u32(const elfs_elf_t *elf, uint64_t offset)
{
    const unsigned char *p = elf->data + offset;

    if (elf->big)
        return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0];
}

uint64_t elfs_word(const elfs_elf_t *elf, uint64_t offset)
{
    uint64_t hi;
    uint64_t lo;

    if (!elf->is64)
        return elfs_u32(elf, offset);
    hi = elfs_u32(elf, offset + (elf->big ? 0 : 4));
    lo = elfs_u32(elf, offset + (elf->big ? 4 : 0));
    return hi << 32 | lo;
}

static uint64_t elfs_table_bytes(uint64_t count, uint32_t entsize)
{
    return count > UINT64_MAX / (entsize ? entsize : 1) ? UINT64_MAX : count * entsize;
}

static void elfs_read_header_fields(elfs_elf_t *elf)
{
    uint64_t w = elf->is64 ? 8 : 4;

    elf->type = elfs_u16(elf, 16);
    elf->profile.type = elf->type;
    elf->profile.machine = elfs_u16(elf, 18);
    elf->profile.entry = elfs_word(elf, 24);
    elf->phoff = elfs_word(elf, 24 + w);
    elf->shoff = elfs_word(elf, 24 + 2 * w);
    elf->phentsize = elfs_u16(elf, 24 + 3 * w + 6);
    elf->phnum = elfs_u16(elf, 24 + 3 * w + 8);
    elf->shentsize = elfs_u16(elf, 24 + 3 * w + 10);
    elf->shnum = elfs_u16(elf, 24 + 3 * w + 12);
    elf->shstrndx = elfs_u16(elf, 24 + 3 * w + 14);
}

static void elfs_read_extended_counts(elfs_elf_t *elf)
{
    elfs_shdr_t zero;
    int need = elf->phnum == ELFS_PN_XNUM || elf->shnum == 0 || elf->shstrndx == ELFS_SHN_XINDEX;

    if (!need || elf->shoff == 0)
        return;
    elf->shnum = elf->shnum ? elf->shnum : 1;
    if (!elfs_shdr(elf, 0, &zero)) {
        elf->shnum = 0;
        return;
    }
    if (elf->shnum == 1 && zero.size != 0)
        elf->shnum = zero.size;
    if (elf->phnum == ELFS_PN_XNUM)
        elf->phnum = zero.info;
    if (elf->shstrndx == ELFS_SHN_XINDEX)
        elf->shstrndx = zero.link;
}

static void elfs_check_tables(elfs_elf_t *elf)
{
    uint32_t want_ph = elf->is64 ? 56 : 32;
    uint32_t want_sh = elf->is64 ? 64 : 40;

    if (elf->phnum != 0 && (elf->phentsize < want_ph || !elfs_fits(elf, elf->phoff,
                                                                    elfs_table_bytes(elf->phnum, elf->phentsize)))) {
        elf->phnum = 0;
        elf->profile.warnings |= ELFS_WARN_SEGMENTS;
    }
    if (elf->shoff == 0)
        elf->shnum = 0;
    if (elf->shnum != 0 && (elf->shentsize < want_sh || !elfs_fits(elf, elf->shoff,
                                                                    elfs_table_bytes(elf->shnum, elf->shentsize)))) {
        elf->shnum = 0;
        elf->profile.warnings |= ELFS_WARN_SECTIONS;
    }
    if (elf->phnum > ELFS_MAX_SEGMENTS) {
        elf->phnum = ELFS_MAX_SEGMENTS;
        elf->profile.warnings |= ELFS_WARN_BUDGET;
    }
    if (elf->shnum > ELFS_MAX_SECTIONS) {
        elf->shnum = ELFS_MAX_SECTIONS;
        elf->profile.warnings |= ELFS_WARN_BUDGET;
    }
}

int elfs_read_header(elfs_elf_t *elf)
{
    const unsigned char *d = elf->data;

    if (elf->len < 52 || memcmp(d, "\177ELF", 4) != 0)
        return ELFS_ERR_FORMAT;
    if ((d[4] != 1 && d[4] != 2) || (d[5] != 1 && d[5] != 2))
        return ELFS_ERR_FORMAT;
    elf->is64 = d[4] == 2;
    elf->big = d[5] == 2;
    if (elf->is64 && elf->len < 64)
        return ELFS_ERR_FORMAT;
    elf->profile.elf_class = elf->is64 ? 64 : 32;
    elf->profile.big_endian = (uint8_t)elf->big;
    elfs_read_header_fields(elf);
    elf->shentsize = elf->shentsize ? elf->shentsize : (elf->is64 ? 64 : 40);
    elfs_read_extended_counts(elf);
    elfs_check_tables(elf);
    return ELFS_OK;
}

int elfs_phdr(const elfs_elf_t *elf, uint64_t i, elfs_phdr_t *out_phdr)
{
    uint64_t at = elf->phoff + i * elf->phentsize;

    if (i >= elf->phnum)
        return 0;
    out_phdr->type = elfs_u32(elf, at);
    if (elf->is64) {
        out_phdr->flags = elfs_u32(elf, at + 4);
        out_phdr->offset = elfs_word(elf, at + 8);
        out_phdr->vaddr = elfs_word(elf, at + 16);
        out_phdr->filesz = elfs_word(elf, at + 32);
    } else {
        out_phdr->offset = elfs_u32(elf, at + 4);
        out_phdr->vaddr = elfs_u32(elf, at + 8);
        out_phdr->filesz = elfs_u32(elf, at + 16);
        out_phdr->flags = elfs_u32(elf, at + 24);
    }
    return 1;
}

int elfs_find_segment(const elfs_elf_t *elf, uint32_t type, uint64_t *out_index, elfs_phdr_t *out_phdr)
{
    uint64_t i;

    for (i = 0; elfs_phdr(elf, i, out_phdr); i++) {
        if (out_phdr->type == type) {
            *out_index = i;
            return 1;
        }
    }
    return 0;
}

uint64_t elfs_count_segments(const elfs_elf_t *elf, uint32_t type)
{
    elfs_phdr_t ph;
    uint64_t count = 0;
    uint64_t i;

    for (i = 0; elfs_phdr(elf, i, &ph); i++)
        count += ph.type == type;
    return count;
}

int elfs_shdr(const elfs_elf_t *elf, uint64_t i, elfs_shdr_t *out_shdr)
{
    uint64_t at = elf->shoff + i * elf->shentsize;
    uint64_t w = elf->is64 ? 8 : 4;

    if (i >= elf->shnum || !elfs_fits(elf, at, elf->is64 ? 64 : 40))
        return 0;
    out_shdr->name = elfs_u32(elf, at);
    out_shdr->type = elfs_u32(elf, at + 4);
    out_shdr->offset = elfs_word(elf, at + 8 + 2 * w);
    out_shdr->size = elfs_word(elf, at + 8 + 3 * w);
    out_shdr->link = elfs_u32(elf, at + 8 + 4 * w);
    out_shdr->info = elfs_u32(elf, at + 12 + 4 * w);
    out_shdr->entsize = elfs_word(elf, at + 16 + 5 * w);
    return 1;
}

static int elfs_is(const char *name, size_t len, const char *want)
{
    return len == strlen(want) && memcmp(name, want, len) == 0;
}

static int elfs_kernel_section(const char *name, size_t len)
{
    return elfs_is(name, len, "__ksymtab") || elfs_is(name, len, "__ksymtab_strings") ||
           elfs_is(name, len, "__ex_table");
}

static int elfs_kmod_section(const char *name, size_t len)
{
    return elfs_is(name, len, ".modinfo") || elfs_is(name, len, ".gnu.linkonce.this_module");
}

static int elfs_uboot_section(const char *name, size_t len)
{
    return elfs_is(name, len, "__u_boot_list") || elfs_is(name, len, ".u_boot_list");
}

static void elfs_note_section(elfs_elf_t *elf, const elfs_strtab_t *names, uint32_t i, const elfs_shdr_t *sh)
{
    elfs_sections_t *s = &elf->sections;
    const char *name;
    size_t len;

    if (sh->type == ELFS_SHT_DYNSYM && !s->has_dynsym) {
        s->has_dynsym = 1;
        s->dynsym = *sh;
    } else if (sh->type == ELFS_SHT_SYMTAB && !s->has_symtab) {
        s->has_symtab = 1;
        s->symtab_index = i;
        s->symtab = *sh;
    }
    if (names == NULL || !elfs_string(elf, names, sh->name, &name, &len))
        return;
    if (!s->kmod && elfs_kmod_section(name, len)) {
        s->kmod = 1;
        s->kmod_index = i;
    }
    if (!s->kernel && elfs_kernel_section(name, len)) {
        s->kernel = 1;
        s->kernel_index = i;
    }
    if (!s->uboot && elfs_uboot_section(name, len)) {
        s->uboot = 1;
        s->uboot_index = i;
    }
}

static int elfs_section_names(const elfs_elf_t *elf, elfs_strtab_t *out_names)
{
    elfs_shdr_t sh;

    if (elf->shstrndx == 0 || !elfs_shdr(elf, elf->shstrndx, &sh) || sh.type == ELFS_SHT_NOBITS)
        return 0;
    if (!elfs_fits(elf, sh.offset, 0))
        return 0;
    out_names->offset = sh.offset;
    out_names->size = sh.size < elf->len - sh.offset ? sh.size : elf->len - sh.offset;
    return 1;
}

void elfs_read_sections(elfs_elf_t *elf)
{
    elfs_strtab_t names;
    elfs_strtab_t *named;
    elfs_shdr_t sh;
    uint64_t i;

    if (elf->shnum == 0)
        return;
    named = elfs_section_names(elf, &names) ? &names : NULL;
    if (named == NULL)
        elf->profile.warnings |= ELFS_WARN_SECTIONS;
    elf->sections.usable = 1;
    for (i = 1; i < elf->shnum && elfs_shdr(elf, i, &sh); i++)
        elfs_note_section(elf, named, (uint32_t)i, &sh);
}

int elfs_address(const elfs_elf_t *elf, uint64_t address, uint64_t *out_offset)
{
    elfs_phdr_t ph;
    uint64_t i;

    for (i = 0; elfs_phdr(elf, i, &ph); i++) {
        if (ph.type != ELFS_PT_LOAD || address < ph.vaddr || address - ph.vaddr >= ph.filesz)
            continue;
        if (ph.offset > UINT64_MAX - (address - ph.vaddr))
            continue;
        *out_offset = ph.offset + (address - ph.vaddr);
        return 1;
    }
    return 0;
}

int elfs_string(elfs_elf_t *elf, const elfs_strtab_t *table, uint64_t at, const char **out_str, size_t *out_len)
{
    const unsigned char *start;
    const unsigned char *nul;
    uint64_t room;

    if (at >= table->size) {
        elf->profile.warnings |= ELFS_WARN_NAME;
        return 0;
    }
    room = table->size - at;
    if (room > elf->read_left) {
        room = elf->read_left;
        elf->profile.warnings |= ELFS_WARN_BUDGET;
    }
    start = elf->data + table->offset + at;
    nul = room ? memchr(start, 0, (size_t)room) : NULL;
    if (nul == NULL) {
        elf->read_left -= room;
        elf->profile.warnings |= room == table->size - at ? ELFS_WARN_NAME : 0;
        return 0;
    }
    elf->read_left -= (uint64_t)(nul - start) + 1;
    *out_str = (const char *)start;
    *out_len = (size_t)(nul - start);
    return 1;
}

void elfs_sym(const elfs_elf_t *elf, uint64_t offset, elfs_sym_t *out_sym)
{
    out_sym->name = elfs_u32(elf, offset);
    if (elf->is64) {
        out_sym->info = elf->data[offset + 4];
        out_sym->shndx = (uint16_t)elfs_u16(elf, offset + 6);
    } else {
        out_sym->info = elf->data[offset + 12];
        out_sym->shndx = (uint16_t)elfs_u16(elf, offset + 14);
    }
}

static int elfs_note_named_linux(elfs_elf_t *elf, const elfs_phdr_t *ph, elfs_evidence_t *out_ev, uint32_t *left)
{
    uint64_t at = ph->offset;
    uint64_t end = ph->offset + ph->filesz;
    uint32_t n;

    for (n = 0; at <= end && end - at >= 12; n++) {
        uint64_t namesz = elfs_u32(elf, at);
        uint64_t descsz = elfs_u32(elf, at + 4);
        uint64_t step = 12 + ((namesz + 3) & ~(uint64_t)3) + ((descsz + 3) & ~(uint64_t)3);

        if (*left == 0) {
            elf->profile.warnings |= ELFS_WARN_BUDGET;
            return 0;
        }
        (*left)--;
        if (namesz == 6 && end - at >= 18 && memcmp(elf->data + at + 12, "Linux", 6) == 0) {
            out_ev->source = ELFS_SRC_NOTE;
            out_ev->index = n;
            out_ev->offset = at;
            return 1;
        }
        if (step > end - at)
            break;
        at += step;
    }
    return 0;
}

int elfs_has_linux_note(elfs_elf_t *elf, elfs_evidence_t *out_ev)
{
    elfs_phdr_t ph;
    uint32_t left = ELFS_MAX_NOTES;
    uint64_t i;

    for (i = 0; elfs_phdr(elf, i, &ph); i++) {
        if (ph.type != ELFS_PT_NOTE || !elfs_fits(elf, ph.offset, ph.filesz))
            continue;
        if (elfs_note_named_linux(elf, &ph, out_ev, &left))
            return 1;
    }
    return 0;
}

void elfs_peek_string(const elfs_elf_t *elf, const elfs_strtab_t *table, uint64_t at, const char **out_str,
                      size_t *out_len)
{
    const unsigned char *start = elf->data + table->offset + at;
    const unsigned char *nul = memchr(start, 0, (size_t)(table->size - at));

    *out_str = (const char *)start;
    *out_len = nul ? (size_t)(nul - start) : 0;
}
