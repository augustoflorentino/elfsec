#include "elfs_internal.h"

#include <string.h>

static const uint32_t elfs_tag_codes[ELFS_TAG_COUNT] = {
    ELFS_DT_STRTAB, ELFS_DT_SYMTAB,   ELFS_DT_STRSZ, ELFS_DT_SYMENT, ELFS_DT_HASH,    ELFS_DT_GNU_HASH,
    ELFS_DT_MIPS_SYMTABNO, ELFS_DT_SONAME, ELFS_DT_BIND_NOW, ELFS_DT_FLAGS, ELFS_DT_FLAGS_1,
};

static const char *const elfs_fortifiable[] = {
    "asprintf",   "confstr",        "dprintf",         "explicit_bzero", "fgets",      "fgets_unlocked",
    "fgetws",     "fgetws_unlocked", "fprintf",        "fread",          "fread_unlocked", "fwprintf",
    "getcwd",     "getdomainname",  "getgroups",       "gethostname",    "getlogin_r", "gets",
    "getwd",      "inet_ntop",      "inet_pton",       "longjmp",        "mbsnrtowcs", "mbsrtowcs",
    "mbstowcs",   "memcpy",         "memmove",         "mempcpy",        "memset",     "memset_explicit",
    "obstack_printf", "obstack_vprintf", "poll",       "ppoll",          "pread",      "pread64",
    "printf",     "ptsname_r",      "read",            "readlink",       "readlinkat", "realpath",
    "recv",       "recvfrom",       "snprintf",        "sprintf",        "stpcpy",     "stpncpy",
    "strcat",     "strcpy",         "strlcat",         "strlcpy",        "strncat",    "strncpy",
    "swprintf",   "syslog",         "ttyname_r",       "vasprintf",      "vdprintf",   "vfprintf",
    "vfwprintf",  "vprintf",        "vsnprintf",       "vsprintf",       "vswprintf",  "vsyslog",
    "vwprintf",   "wcpcpy",         "wcpncpy",         "wcrtomb",        "wcscat",     "wcscpy",
    "wcslcat",    "wcslcpy",        "wcsncat",         "wcsncpy",        "wcsnrtombs", "wcsrtombs",
    "wcstombs",   "wctomb",         "wmemcpy",         "wmemmove",       "wmempcpy",   "wmemset",
    "wprintf",
};

static const struct {
    const char *name;
    uint32_t danger;
} elfs_dangers[] = {
    {"gets", ELFS_DANGER_UNBOUNDED},    {"mktemp", ELFS_DANGER_TEMPFILE},  {"popen", ELFS_DANGER_COMMAND},
    {"sprintf", ELFS_DANGER_UNBOUNDED}, {"strcat", ELFS_DANGER_UNBOUNDED}, {"strcpy", ELFS_DANGER_UNBOUNDED},
    {"system", ELFS_DANGER_COMMAND},    {"tempnam", ELFS_DANGER_TEMPFILE}, {"tmpnam", ELFS_DANGER_TEMPFILE},
    {"vsprintf", ELFS_DANGER_UNBOUNDED}, {"wcscat", ELFS_DANGER_UNBOUNDED}, {"wcscpy", ELFS_DANGER_UNBOUNDED},
};

static int elfs_compare(const char *name, size_t name_len, const char *entry)
{
    size_t entry_len = strlen(entry);
    int order = memcmp(name, entry, name_len < entry_len ? name_len : entry_len);

    if (order != 0)
        return order;
    return name_len < entry_len ? -1 : name_len > entry_len;
}

static int elfs_find_name(const char *const *table, size_t count, size_t stride, const char *name, size_t name_len)
{
    size_t lo = 0;
    size_t hi = count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const char *entry = *(const char *const *)((const char *)table + mid * stride);
        int order = elfs_compare(name, name_len, entry);

        if (order == 0)
            return (int)mid;
        if (order < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return -1;
}

uint32_t elfs_danger_of(const char *name, size_t name_len)
{
    int at = elfs_find_name(&elfs_dangers[0].name, sizeof(elfs_dangers) / sizeof(elfs_dangers[0]),
                            sizeof(elfs_dangers[0]), name, name_len);

    return at < 0 ? ELFS_DANGER_NONE : elfs_dangers[at].danger;
}

int elfs_is_canary(const char *name, size_t name_len)
{
    return elfs_compare(name, name_len, "__stack_chk_fail") == 0 ||
           elfs_compare(name, name_len, "__stack_chk_guard") == 0 ||
           elfs_compare(name, name_len, "__stack_chk_fail_local") == 0;
}

int elfs_is_fortified(const char *name, size_t name_len)
{
    return name_len > 4 && memcmp(name + name_len - 4, "_chk", 4) == 0 && !elfs_is_canary(name, name_len);
}

int elfs_is_fortifiable(const char *name, size_t name_len)
{
    size_t count = sizeof(elfs_fortifiable) / sizeof(elfs_fortifiable[0]);

    return elfs_find_name(elfs_fortifiable, count, sizeof(elfs_fortifiable[0]), name, name_len) >= 0;
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
    if (elf->dyn_count > ELFS_MAX_SYMBOLS) {
        elf->dyn_count = ELFS_MAX_SYMBOLS;
        elf->profile.warnings |= ELFS_WARN_DYNAMIC;
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
    if (!elfs_fits(elf, buckets, nbuckets * 4))
        return 0;
    for (i = 0; i < nbuckets; i++) {
        uint64_t bucket = elfs_u32(elf, buckets + i * 4);

        last = bucket > last ? bucket : last;
    }
    if (last == 0 || last < symoffset)
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
    uint64_t slots = 2 * elf->sym_count + elf->needed_tags + elf->path_tags;

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

    elf->list[p->import_count++] = index;
    if (elfs_danger_of(name, len) != ELFS_DANGER_NONE)
        elf->list[elf->danger_at + p->danger_count++] = index;
    if (elfs_is_canary(name, len) && p->ev_canary.source == ELFS_SRC_NONE) {
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
    } else if (elfs_is_fortifiable(name, len)) {
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

void elfs_symbol_at(const elfs_elf_t *elf, uint32_t index, elfs_symbol_t *out_symbol)
{
    elfs_sym_t sym;
    uint64_t at = elf->sym_offset + (uint64_t)index * elf->sym_entsize;

    memset(out_symbol, 0, sizeof(*out_symbol));
    elfs_sym(elf, at, &sym);
    elfs_peek_string(elf, &elf->strtab, sym.name, &out_symbol->name, &out_symbol->name_len);
    out_symbol->offset = at;
    out_symbol->index = index;
    out_symbol->danger = elfs_danger_of(out_symbol->name, out_symbol->name_len);
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

typedef int (*elfs_path_visit)(void *ctx, const char *path, size_t len, uint32_t flags);

static int elfs_split_path(const char *s, size_t len, int64_t tag, elfs_path_visit visit, void *ctx)
{
    size_t start = 0;
    size_t i;

    for (i = 0; i <= len; i++) {
        if (i < len && s[i] != ':')
            continue;
        if (visit(ctx, s + start, i - start, elfs_path_flags(s + start, i - start, tag)))
            return 1;
        start = i + 1;
    }
    return 0;
}

static int elfs_count_path(void *ctx, const char *path, size_t len, uint32_t flags)
{
    elfs_profile_t *p = ctx;

    (void)path;
    (void)len;
    p->path_count++;
    p->path_flags |= flags;
    return 0;
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
        elf->list[elf->path_at + elf->path_strings++] = (uint32_t)i;
        elfs_split_path(s, len, tag, elfs_count_path, &elf->profile);
    }
}

typedef struct elfs_path_pick {
    size_t remaining;
    const char *path;
    size_t len;
    uint32_t flags;
} elfs_path_pick_t;

static int elfs_pick_path(void *ctx, const char *path, size_t len, uint32_t flags)
{
    elfs_path_pick_t *pick = ctx;

    if (pick->remaining-- != 0)
        return 0;
    pick->path = path;
    pick->len = len;
    pick->flags = flags;
    return 1;
}

int elfs_path_entry(const elfs_elf_t *elf, size_t i, const char **out_path, size_t *out_len, uint32_t *out_flags)
{
    elfs_path_pick_t pick = {0, NULL, 0, 0};
    const char *s;
    size_t len;
    int64_t tag;
    uint64_t value;
    uint64_t k;

    pick.remaining = i;
    for (k = 0; k < elf->path_strings; k++) {
        elfs_dyn_entry(elf, elf->list[elf->path_at + k], &tag, &value);
        elfs_peek_string(elf, &elf->strtab, value, &s, &len);
        if (elfs_split_path(s, len, tag, elfs_pick_path, &pick)) {
            *out_path = pick.path;
            *out_len = pick.len;
            *out_flags = pick.flags;
            return 1;
        }
    }
    return 0;
}
