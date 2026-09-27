#include "elfs_internal.h"

#include <string.h>

#define ELFS_NT_GNU_PROPERTY_TYPE_0 5u
#define ELFS_PROPERTY_AARCH64_FEATURE_1_AND 0xc0000000u
#define ELFS_PROPERTY_X86_FEATURE_1_AND 0xc0000002u

static uint64_t elfs_align_up(uint64_t size, uint64_t align)
{
    return (size + align - 1) & ~(align - 1);
}

static int elfs_property_note(const elfs_elf_t *elf, const elfs_phdr_t *ph, uint64_t *out_desc, uint64_t *out_size)
{
    uint64_t align = ph->align == 8 ? 8 : 4;
    uint64_t at = ph->offset;
    uint64_t end = ph->offset + ph->filesz;
    uint32_t n;

    for (n = 0; n < ELFS_MAX_NOTES && end - at >= 12; n++) {
        uint64_t namesz = elfs_u32(elf, at);
        uint64_t descsz = elfs_u32(elf, at + 4);
        uint64_t head = elfs_align_up(12 + namesz, align);
        uint64_t step = elfs_align_up(head + descsz, align);

        if (head > end - at)
            return 0;
        if (namesz == 4 && elfs_u32(elf, at + 8) == ELFS_NT_GNU_PROPERTY_TYPE_0 &&
            memcmp(elf->data + at + 12, "GNU", 4) == 0 && descsz <= end - at - head) {
            *out_desc = at + head;
            *out_size = descsz;
            return 1;
        }
        if (step > end - at)
            return 0;
        at += step;
    }
    return 0;
}

static uint32_t elfs_feature_bits(const elfs_elf_t *elf, uint64_t at, uint64_t size, uint32_t want, uint64_t *out_at)
{
    uint64_t align = elf->is64 ? 8 : 4;
    uint32_t n;

    for (n = 0; n < ELFS_MAX_NOTES && size >= 8; n++) {
        uint32_t type = elfs_u32(elf, at);
        uint64_t datasz = elfs_u32(elf, at + 4);
        uint64_t step = 8 + elfs_align_up(datasz, align);

        if (datasz > size - 8)
            return 0;
        if (type == want && datasz >= 4) {
            *out_at = at;
            return elfs_u32(elf, at + 8);
        }
        if (step > size)
            return 0;
        at += step;
        size -= step;
    }
    return 0;
}

static void elfs_set_pair(uint8_t *first, uint8_t *second, int noted, uint32_t bits)
{
    *first = !noted ? ELFS_UNKNOWN : (bits & 1u) ? ELFS_YES : ELFS_NO;
    *second = !noted ? ELFS_UNKNOWN : (bits & 2u) ? ELFS_YES : ELFS_NO;
}

void elfs_judge_property(elfs_elf_t *elf)
{
    elfs_profile_t *p = &elf->profile;
    int x86 = p->machine == ELFS_EM_386 || p->machine == ELFS_EM_X86_64;
    uint32_t want = x86 ? ELFS_PROPERTY_X86_FEATURE_1_AND : ELFS_PROPERTY_AARCH64_FEATURE_1_AND;
    uint32_t bits = 0;
    uint64_t desc, size, at, i;
    elfs_phdr_t ph;
    int noted = 0;

    p->ibt = p->shstk = p->bti = p->pac = ELFS_NA;
    if (!x86 && p->machine != ELFS_EM_AARCH64)
        return;
    for (i = 0; !noted && elfs_phdr(elf, i, &ph); i++) {
        if ((ph.type != ELFS_PT_GNU_PROPERTY && ph.type != ELFS_PT_NOTE) || !elfs_fits(elf, ph.offset, ph.filesz) ||
            !elfs_property_note(elf, &ph, &desc, &size))
            continue;
        noted = 1;
        at = desc;
        bits = elfs_feature_bits(elf, desc, size, want, &at);
        p->ev_property.source = ELFS_SRC_SEGMENT;
        p->ev_property.index = (uint32_t)i;
        p->ev_property.offset = at;
    }
    elfs_set_pair(x86 ? &p->ibt : &p->bti, x86 ? &p->shstk : &p->pac, noted, bits);
}
