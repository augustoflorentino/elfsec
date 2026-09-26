#include "elfs_internal.h"

#include <string.h>

static const uint32_t elfs_tag_codes[ELFS_TAG_COUNT] = {
    ELFS_DT_STRTAB, ELFS_DT_SYMTAB,   ELFS_DT_STRSZ, ELFS_DT_SYMENT, ELFS_DT_HASH,    ELFS_DT_GNU_HASH,
    ELFS_DT_MIPS_SYMTABNO, ELFS_DT_SONAME, ELFS_DT_BIND_NOW, ELFS_DT_FLAGS, ELFS_DT_FLAGS_1,
};

static const struct {
    const char *name;
    uint8_t len;
    uint8_t meaning;
} elfs_names[] = {
    {"__stack_chk_fail", 16, ELFS_NAME_CANARY},
    {"__stack_chk_fail_local", 22, ELFS_NAME_CANARY},
    {"__stack_chk_guard", 17, ELFS_NAME_CANARY},
    {"asprintf", 8, ELFS_NAME_FORTIFIABLE},
    {"confstr", 7, ELFS_NAME_FORTIFIABLE},
    {"dprintf", 7, ELFS_NAME_FORTIFIABLE},
    {"explicit_bzero", 14, ELFS_NAME_FORTIFIABLE},
    {"fgets", 5, ELFS_NAME_FORTIFIABLE},
    {"fgets_unlocked", 14, ELFS_NAME_FORTIFIABLE},
    {"fgetws", 6, ELFS_NAME_FORTIFIABLE},
    {"fgetws_unlocked", 15, ELFS_NAME_FORTIFIABLE},
    {"fprintf", 7, ELFS_NAME_FORTIFIABLE},
    {"fread", 5, ELFS_NAME_FORTIFIABLE},
    {"fread_unlocked", 14, ELFS_NAME_FORTIFIABLE},
    {"fwprintf", 8, ELFS_NAME_FORTIFIABLE},
    {"getcwd", 6, ELFS_NAME_FORTIFIABLE},
    {"getdomainname", 13, ELFS_NAME_FORTIFIABLE},
    {"getgroups", 9, ELFS_NAME_FORTIFIABLE},
    {"gethostname", 11, ELFS_NAME_FORTIFIABLE},
    {"getlogin_r", 10, ELFS_NAME_FORTIFIABLE},
    {"gets", 4, ELFS_DANGER_UNBOUNDED | ELFS_NAME_FORTIFIABLE},
    {"getwd", 5, ELFS_NAME_FORTIFIABLE},
    {"inet_ntop", 9, ELFS_NAME_FORTIFIABLE},
    {"inet_pton", 9, ELFS_NAME_FORTIFIABLE},
    {"longjmp", 7, ELFS_NAME_FORTIFIABLE},
    {"mbsnrtowcs", 10, ELFS_NAME_FORTIFIABLE},
    {"mbsrtowcs", 9, ELFS_NAME_FORTIFIABLE},
    {"mbstowcs", 8, ELFS_NAME_FORTIFIABLE},
    {"memcpy", 6, ELFS_NAME_FORTIFIABLE},
    {"memmove", 7, ELFS_NAME_FORTIFIABLE},
    {"mempcpy", 7, ELFS_NAME_FORTIFIABLE},
    {"memset", 6, ELFS_NAME_FORTIFIABLE},
    {"memset_explicit", 15, ELFS_NAME_FORTIFIABLE},
    {"mktemp", 6, ELFS_DANGER_TEMPFILE},
    {"obstack_printf", 14, ELFS_NAME_FORTIFIABLE},
    {"obstack_vprintf", 15, ELFS_NAME_FORTIFIABLE},
    {"poll", 4, ELFS_NAME_FORTIFIABLE},
    {"popen", 5, ELFS_DANGER_COMMAND},
    {"ppoll", 5, ELFS_NAME_FORTIFIABLE},
    {"pread", 5, ELFS_NAME_FORTIFIABLE},
    {"pread64", 7, ELFS_NAME_FORTIFIABLE},
    {"printf", 6, ELFS_NAME_FORTIFIABLE},
    {"ptsname_r", 9, ELFS_NAME_FORTIFIABLE},
    {"read", 4, ELFS_NAME_FORTIFIABLE},
    {"readlink", 8, ELFS_NAME_FORTIFIABLE},
    {"readlinkat", 10, ELFS_NAME_FORTIFIABLE},
    {"realpath", 8, ELFS_NAME_FORTIFIABLE},
    {"recv", 4, ELFS_NAME_FORTIFIABLE},
    {"recvfrom", 8, ELFS_NAME_FORTIFIABLE},
    {"snprintf", 8, ELFS_NAME_FORTIFIABLE},
    {"sprintf", 7, ELFS_DANGER_UNBOUNDED | ELFS_NAME_FORTIFIABLE},
    {"stpcpy", 6, ELFS_NAME_FORTIFIABLE},
    {"stpncpy", 7, ELFS_NAME_FORTIFIABLE},
    {"strcat", 6, ELFS_DANGER_UNBOUNDED | ELFS_NAME_FORTIFIABLE},
    {"strcpy", 6, ELFS_DANGER_UNBOUNDED | ELFS_NAME_FORTIFIABLE},
    {"strlcat", 7, ELFS_NAME_FORTIFIABLE},
    {"strlcpy", 7, ELFS_NAME_FORTIFIABLE},
    {"strncat", 7, ELFS_NAME_FORTIFIABLE},
    {"strncpy", 7, ELFS_NAME_FORTIFIABLE},
    {"swprintf", 8, ELFS_NAME_FORTIFIABLE},
    {"syslog", 6, ELFS_NAME_FORTIFIABLE},
    {"system", 6, ELFS_DANGER_COMMAND},
    {"tempnam", 7, ELFS_DANGER_TEMPFILE},
    {"tmpnam", 6, ELFS_DANGER_TEMPFILE},
    {"ttyname_r", 9, ELFS_NAME_FORTIFIABLE},
    {"vasprintf", 9, ELFS_NAME_FORTIFIABLE},
    {"vdprintf", 8, ELFS_NAME_FORTIFIABLE},
    {"vfprintf", 8, ELFS_NAME_FORTIFIABLE},
    {"vfwprintf", 9, ELFS_NAME_FORTIFIABLE},
    {"vprintf", 7, ELFS_NAME_FORTIFIABLE},
    {"vsnprintf", 9, ELFS_NAME_FORTIFIABLE},
    {"vsprintf", 8, ELFS_DANGER_UNBOUNDED | ELFS_NAME_FORTIFIABLE},
    {"vswprintf", 9, ELFS_NAME_FORTIFIABLE},
    {"vsyslog", 7, ELFS_NAME_FORTIFIABLE},
    {"vwprintf", 8, ELFS_NAME_FORTIFIABLE},
    {"wcpcpy", 6, ELFS_NAME_FORTIFIABLE},
    {"wcpncpy", 7, ELFS_NAME_FORTIFIABLE},
    {"wcrtomb", 7, ELFS_NAME_FORTIFIABLE},
    {"wcscat", 6, ELFS_DANGER_UNBOUNDED | ELFS_NAME_FORTIFIABLE},
    {"wcscpy", 6, ELFS_DANGER_UNBOUNDED | ELFS_NAME_FORTIFIABLE},
    {"wcslcat", 7, ELFS_NAME_FORTIFIABLE},
    {"wcslcpy", 7, ELFS_NAME_FORTIFIABLE},
    {"wcsncat", 7, ELFS_NAME_FORTIFIABLE},
    {"wcsncpy", 7, ELFS_NAME_FORTIFIABLE},
    {"wcsnrtombs", 10, ELFS_NAME_FORTIFIABLE},
    {"wcsrtombs", 9, ELFS_NAME_FORTIFIABLE},
    {"wcstombs", 8, ELFS_NAME_FORTIFIABLE},
    {"wctomb", 6, ELFS_NAME_FORTIFIABLE},
    {"wmemcpy", 7, ELFS_NAME_FORTIFIABLE},
    {"wmemmove", 8, ELFS_NAME_FORTIFIABLE},
    {"wmempcpy", 8, ELFS_NAME_FORTIFIABLE},
    {"wmemset", 7, ELFS_NAME_FORTIFIABLE},
    {"wprintf", 7, ELFS_NAME_FORTIFIABLE},
};

static int elfs_compare(const char *name, size_t name_len, const char *entry, size_t entry_len)
{
    int order = memcmp(name, entry, name_len < entry_len ? name_len : entry_len);

    if (order != 0)
        return order;
    return name_len < entry_len ? -1 : name_len > entry_len;
}

uint32_t elfs_name_meaning(const char *name, size_t name_len)
{
    size_t lo = 0;
    size_t hi = sizeof(elfs_names) / sizeof(elfs_names[0]);

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int order = elfs_compare(name, name_len, elfs_names[mid].name, elfs_names[mid].len);

        if (order == 0)
            return elfs_names[mid].meaning;
        if (order < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return 0;
}

int elfs_is_fortified(const char *name, size_t name_len)
{
    return name_len > 4 && memcmp(name + name_len - 4, "_chk", 4) == 0 &&
           !(elfs_name_meaning(name, name_len) & ELFS_NAME_CANARY);
}

int elfs_dyn_entry(const elfs_elf_t *elf, uint64_t i, int64_t *out_tag, uint64_t *out_value)
{
    uint64_t size = elf->is64 ? 16 : 8;
    uint64_t at = elf->dyn_offset + i * size;

    if (i >= elf->dyn_count)
        return 0;
    if (elf->is64)
        *out_tag = (int64_t)elfs_word(elf, at);
    else
        *out_tag = (int32_t)elfs_u32(elf, at);
    *out_value = elfs_word(elf, at + size / 2);
    return 1;
}

static void elfs_note_tag(elfs_elf_t *elf, int64_t tag, uint64_t value, uint64_t i)
{
    int slot;

    if (tag == ELFS_DT_NEEDED)
        elf->needed_tags++;
    if (tag == ELFS_DT_RPATH || tag == ELFS_DT_RUNPATH)
        elf->path_tags++;
    for (slot = 0; slot < ELFS_TAG_COUNT; slot++) {
        if ((uint64_t)tag != elfs_tag_codes[slot] || elf->tags[slot].present)
            continue;
        elf->tags[slot].present = 1;
        elf->tags[slot].index = (uint32_t)i;
        elf->tags[slot].value = value;
    }
}

static void elfs_scan_tags(elfs_elf_t *elf)
{
    int64_t tag;
    uint64_t value;
    uint64_t i;

    for (i = 0; elfs_dyn_entry(elf, i, &tag, &value); i++) {
        if (tag == ELFS_DT_NULL)
            break;
        elfs_note_tag(elf, tag, value, i);
    }
    elf->dyn_count = i;
}

void elfs_read_dynamic(elfs_elf_t *elf)
{
    elfs_phdr_t ph;
    uint64_t index;
    uint64_t size = elf->is64 ? 16 : 8;
    uint64_t room;

    if (!elfs_find_segment(elf, ELFS_PT_DYNAMIC, &index, &ph))
        return;
    if (!elfs_fits(elf, ph.offset, 0)) {
        elf->profile.warnings |= ELFS_WARN_TRUNCATED;
        return;
    }
    room = elf->len - ph.offset;
    if (ph.filesz > room)
        elf->profile.warnings |= ELFS_WARN_TRUNCATED;
    elf->has_dynamic = 1;
    elf->dyn_segment = (uint32_t)index;
    elf->dyn_offset = ph.offset;
    elf->dyn_count = (ph.filesz < room ? ph.filesz : room) / size;
    if (elf->dyn_count > ELFS_MAX_DYNAMIC) {
        elf->dyn_count = ELFS_MAX_DYNAMIC;
        elf->profile.warnings |= ELFS_WARN_BUDGET;
    }
    elfs_scan_tags(elf);
}

static int elfs_tag_offset(const elfs_elf_t *elf, int slot, uint64_t *out_offset)
{
    return elf->tags[slot].present && elfs_address(elf, elf->tags[slot].value, out_offset);
}

static void elfs_locate_strtab(elfs_elf_t *elf)
{
    uint64_t offset;
    uint64_t room;

    if (!elf->tags[ELFS_TAG_STRTAB].present)
        return;
    if (!elfs_tag_offset(elf, ELFS_TAG_STRTAB, &offset) || !elfs_fits(elf, offset, 0)) {
        elf->profile.warnings |= ELFS_WARN_DYNAMIC;
        return;
    }
    room = elf->len - offset;
    elf->strtab.offset = offset;
    elf->strtab.size = room;
    if (elf->tags[ELFS_TAG_STRSZ].present && elf->tags[ELFS_TAG_STRSZ].value <= room)
        elf->strtab.size = elf->tags[ELFS_TAG_STRSZ].value;
    else
        elf->profile.warnings |= elf->tags[ELFS_TAG_STRSZ].present ? ELFS_WARN_TRUNCATED : ELFS_WARN_DYNAMIC;
    elf->has_strtab = 1;
}

static uint64_t elfs_hash_count(const elfs_elf_t *elf)
{
    uint64_t offset;
    int wide = elf->is64 && (elf->profile.machine == ELFS_EM_S390 || elf->profile.machine == ELFS_EM_ALPHA);

    if (!elfs_tag_offset(elf, ELFS_TAG_HASH, &offset))
        return 0;
    if (wide)
        return elfs_fits(elf, offset, 16) ? elfs_word(elf, offset + 8) : 0;
    return elfs_fits(elf, offset, 8) ? elfs_u32(elf, offset + 4) : 0;
}

static uint64_t elfs_gnu_chain_end(const elfs_elf_t *elf, uint64_t chains, uint64_t symoffset, uint64_t last)
{
    uint64_t i;

    for (i = last; i - last <= ELFS_MAX_SYMBOLS; i++) {
        uint64_t at = chains + (i - symoffset) * 4;

        if (!elfs_fits(elf, at, 4))
            return 0;
        if (elfs_u32(elf, at) & 1)
            return i + 1;
    }
    return i;
}

static uint64_t elfs_gnu_hash_count(const elfs_elf_t *elf)
{
    uint64_t offset;
    uint64_t nbuckets, symoffset, buckets, last = 0, i;

    if (!elfs_tag_offset(elf, ELFS_TAG_GNU_HASH, &offset) || !elfs_fits(elf, offset, 16))
        return 0;
    nbuckets = elfs_u32(elf, offset);
    symoffset = elfs_u32(elf, offset + 4);
    buckets = offset + 16 + (uint64_t)elfs_u32(elf, offset + 8) * (elf->is64 ? 8 : 4);
    if (nbuckets > ELFS_MAX_SYMBOLS || !elfs_fits(elf, buckets, nbuckets * 4))
        return 0;
    for (i = 0; i < nbuckets; i++) {
        uint64_t bucket = elfs_u32(elf, buckets + i * 4);

        last = bucket > last ? bucket : last;
    }
    if (last == 0)
        return symoffset > 1 ? symoffset : 0;
    if (last < symoffset)
        return 0;
    return elfs_gnu_chain_end(elf, buckets + nbuckets * 4, symoffset, last);
}

static uint64_t elfs_symbol_count(const elfs_elf_t *elf)
{
    const elfs_shdr_t *dynsym = &elf->sections.dynsym;
    uint64_t count;
    uint64_t mips = elf->tags[ELFS_TAG_MIPS_SYMTABNO].value;

    if (elf->sections.has_dynsym && dynsym->offset == elf->sym_offset)
        return dynsym->size / elf->sym_entsize;
    if ((count = elfs_hash_count(elf)) != 0)
        return count;
    if (elf->tags[ELFS_TAG_MIPS_SYMTABNO].present && mips != 0)
        return mips;
    if ((count = elfs_gnu_hash_count(elf)) != 0)
        return count;
    if (elf->has_strtab && elf->strtab.offset > elf->sym_offset)
        return (elf->strtab.offset - elf->sym_offset) / elf->sym_entsize;
    return 0;
}

static void elfs_bound_symbols(elfs_elf_t *elf)
{
    uint64_t room = (elf->len - elf->sym_offset) / elf->sym_entsize;

    if (elf->sym_count > ELFS_MAX_SYMBOLS) {
        elf->sym_count = ELFS_MAX_SYMBOLS;
        elf->profile.warnings |= ELFS_WARN_SYMBOL_BUDGET;
    }
    if (elf->sym_count > room) {
        elf->sym_count = room;
        elf->profile.warnings |= ELFS_WARN_TRUNCATED;
    }
    elf->has_symbols = elf->has_strtab;
    if (!elf->has_strtab)
        elf->profile.warnings |= ELFS_WARN_SYMBOLS;
}

static void elfs_locate_symbols(elfs_elf_t *elf)
{
    uint64_t least = elf->is64 ? 24 : 16;

    if (!elf->tags[ELFS_TAG_SYMTAB].present)
        return;
    elf->sym_entsize = elf->tags[ELFS_TAG_SYMENT].present ? elf->tags[ELFS_TAG_SYMENT].value : least;
    if (elf->sym_entsize < least || elf->sym_entsize > 4096 ||
        !elfs_tag_offset(elf, ELFS_TAG_SYMTAB, &elf->sym_offset) || !elfs_fits(elf, elf->sym_offset, 0)) {
        elf->profile.warnings |= ELFS_WARN_SYMBOLS;
        return;
    }
    elf->sym_count = elfs_symbol_count(elf);
    if (elf->sym_count == 0) {
        elf->profile.warnings |= ELFS_WARN_SYMBOLS;
        return;
    }
    elfs_bound_symbols(elf);
}

static void elfs_locate_from_sections(elfs_elf_t *elf)
{
    const elfs_shdr_t *dynsym = &elf->sections.dynsym;
    elfs_shdr_t names;
    uint64_t least = elf->is64 ? 24 : 16;

    if (elf->has_dynamic || !elf->sections.has_dynsym || dynsym->entsize < least || dynsym->entsize > 4096)
        return;
    if (!elfs_shdr(elf, dynsym->link, &names) || !elfs_fits(elf, names.offset, 0) ||
        !elfs_fits(elf, dynsym->offset, 0))
        return;
    elf->strtab.offset = names.offset;
    elf->strtab.size = names.size < elf->len - names.offset ? names.size : elf->len - names.offset;
    elf->has_strtab = 1;
    elf->sym_offset = dynsym->offset;
    elf->sym_entsize = dynsym->entsize;
    elf->sym_count = dynsym->size / dynsym->entsize;
    elfs_bound_symbols(elf);
}

static int elfs_allocate_lists(elfs_elf_t *elf)
{
    uint64_t slots = 2 * elf->sym_count + elf->needed_tags + (elf->path_tags ? 2 * ELFS_MAX_PATHS : 0);

    if (slots == 0)
        return ELFS_OK;
    elf->list = elf->alloc_fn(elf->alloc_ctx, (size_t)slots * sizeof(uint32_t));
    if (elf->list == NULL)
        return ELFS_ERR_NOMEM;
    elf->danger_at = elf->sym_count;
    elf->needed_at = 2 * elf->sym_count;
    elf->path_at = elf->needed_at + elf->needed_tags;
    return ELFS_OK;
}

static void elfs_note_import(elfs_elf_t *elf, uint32_t index, const char *name, size_t len)
{
    elfs_profile_t *p = &elf->profile;
    uint64_t at = elf->sym_offset + (uint64_t)index * elf->sym_entsize;

    uint32_t meaning = elfs_name_meaning(name, len);
    uint32_t entry = index | (meaning & ELFS_NAME_DANGER) << ELFS_DANGER_SHIFT;

    elf->list[p->import_count++] = entry;
    if (meaning & ELFS_NAME_DANGER)
        elf->list[elf->danger_at + p->danger_count++] = entry;
    if ((meaning & ELFS_NAME_CANARY) && p->ev_canary.source == ELFS_SRC_NONE) {
        p->ev_canary.source = ELFS_SRC_SYMBOL;
        p->ev_canary.index = index;
        p->ev_canary.offset = at;
    }
    if (elfs_is_fortified(name, len)) {
        p->fortified++;
        if (p->ev_fortify.source == ELFS_SRC_NONE) {
            p->ev_fortify.source = ELFS_SRC_SYMBOL;
            p->ev_fortify.index = index;
            p->ev_fortify.offset = at;
        }
    } else if (meaning & ELFS_NAME_FORTIFIABLE) {
        p->fortifiable++;
    }
}

static void elfs_scan_imports(elfs_elf_t *elf)
{
    elfs_sym_t sym;
    const char *name;
    size_t len;
    uint64_t i;

    for (i = 1; elf->has_symbols && i < elf->sym_count; i++) {
        elfs_sym(elf, elf->sym_offset + i * elf->sym_entsize, &sym);
        if (sym.shndx != 0 || sym.name == 0)
            continue;
        if (elfs_string(elf, &elf->strtab, sym.name, &name, &len))
            elfs_note_import(elf, (uint32_t)i, name, len);
    }
    elf->profile.fortifiable += elf->profile.fortified;
}

static void elfs_scan_needed(elfs_elf_t *elf)
{
    const char *name;
    size_t len;
    int64_t tag;
    uint64_t value;
    uint64_t i;

    for (i = 0; elf->has_strtab && elfs_dyn_entry(elf, i, &tag, &value); i++) {
        if (tag != ELFS_DT_NEEDED || !elfs_string(elf, &elf->strtab, value, &name, &len))
            continue;
        elf->list[elf->needed_at + elf->profile.needed_count++] = (uint32_t)i;
    }
}

static void elfs_read_soname(elfs_elf_t *elf)
{
    const char *name;
    size_t len;
    elfs_tag_t *tag = &elf->tags[ELFS_TAG_SONAME];

    if (!tag->present || !elf->has_strtab || !elfs_string(elf, &elf->strtab, tag->value, &name, &len))
        return;
    elf->profile.soname = name;
    elf->profile.soname_len = len;
}

int elfs_read_imports(elfs_elf_t *elf)
{
    int status;

    elfs_locate_strtab(elf);
    elfs_locate_symbols(elf);
    elfs_locate_from_sections(elf);
    status = elfs_allocate_lists(elf);
    if (status != ELFS_OK)
        return status;
    elfs_read_soname(elf);
    elfs_scan_imports(elf);
    elfs_scan_needed(elf);
    elfs_scan_paths(elf);
    return ELFS_OK;
}

void elfs_symbol_at(const elfs_elf_t *elf, uint32_t entry, elfs_symbol_t *out_symbol)
{
    elfs_sym_t sym;
    uint32_t index = entry & ((1u << ELFS_DANGER_SHIFT) - 1);
    uint64_t at = elf->sym_offset + (uint64_t)index * elf->sym_entsize;

    memset(out_symbol, 0, sizeof(*out_symbol));
    elfs_sym(elf, at, &sym);
    elfs_peek_string(elf, &elf->strtab, sym.name, &out_symbol->name, &out_symbol->name_len);
    out_symbol->offset = at;
    out_symbol->index = index;
    out_symbol->danger = entry >> ELFS_DANGER_SHIFT;
    out_symbol->bind = (uint8_t)(sym.info >> 4);
    out_symbol->type = (uint8_t)(sym.info & 0xf);
}

static int elfs_starts_with(const char *s, size_t len, const char *prefix)
{
    size_t n = strlen(prefix);

    return len >= n && memcmp(s, prefix, n) == 0;
}

static int elfs_under(const char *s, size_t len, const char *dir)
{
    size_t n = strlen(dir);

    return elfs_starts_with(s, len, dir) && (len == n || s[n] == '/');
}

static uint32_t elfs_path_flags(const char *s, size_t len, int64_t tag)
{
    uint32_t flags = tag == ELFS_DT_RUNPATH ? ELFS_PATH_RUNPATH : 0;

    if (len == 0)
        return flags | ELFS_PATH_EMPTY;
    if (elfs_starts_with(s, len, "$ORIGIN") || elfs_starts_with(s, len, "${ORIGIN}"))
        return flags | ELFS_PATH_ORIGIN;
    if (s[0] != '/')
        return flags | ELFS_PATH_RELATIVE;
    if (elfs_under(s, len, "/tmp") || elfs_under(s, len, "/var/tmp") || elfs_under(s, len, "/dev/shm"))
        flags |= ELFS_PATH_WORLD_WRITABLE;
    return flags;
}

static void elfs_split_path(elfs_elf_t *elf, uint64_t dyn_index, uint64_t at, const char *s, size_t len,
                            int64_t tag)
{
    elfs_profile_t *p = &elf->profile;
    size_t start = 0;
    size_t i;

    for (i = 0; i <= len; i++) {
        if (i < len && s[i] != ':')
            continue;
        if (p->path_count == ELFS_MAX_PATHS || at + start > UINT32_MAX) {
            p->warnings |= ELFS_WARN_BUDGET;
            return;
        }
        elf->list[elf->path_at + 2 * p->path_count] = (uint32_t)dyn_index;
        elf->list[elf->path_at + 2 * p->path_count + 1] = (uint32_t)(at + start);
        p->path_count++;
        p->path_flags |= elfs_path_flags(s + start, i - start, tag);
        start = i + 1;
    }
}

void elfs_scan_paths(elfs_elf_t *elf)
{
    const char *s;
    size_t len;
    int64_t tag;
    uint64_t value;
    uint64_t i;

    for (i = 0; elf->has_strtab && elfs_dyn_entry(elf, i, &tag, &value); i++) {
        if ((tag != ELFS_DT_RPATH && tag != ELFS_DT_RUNPATH) || !elfs_string(elf, &elf->strtab, value, &s, &len))
            continue;
        elfs_split_path(elf, i, value, s, len, tag);
    }
}

int elfs_path_entry(const elfs_elf_t *elf, size_t i, const char **out_path, size_t *out_len, uint32_t *out_flags)
{
    const char *s;
    size_t len = 0;
    int64_t tag;
    uint64_t value;

    if (i >= elf->profile.path_count)
        return 0;
    elfs_dyn_entry(elf, elf->list[elf->path_at + 2 * i], &tag, &value);
    s = (const char *)elf->data + elf->strtab.offset + elf->list[elf->path_at + 2 * i + 1];
    while (s[len] != ':' && s[len] != '\0')
        len++;
    *out_path = s;
    *out_len = len;
    *out_flags = elfs_path_flags(s, len, tag);
    return 1;
}
