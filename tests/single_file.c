#define ELFS_IMPLEMENTATION
#include "elfsec/elfsec.h"
#include "elfs_image.h"

int main(void)
{
    img_spec_t s;
    img_t m;
    elfs_elf_t *elf = NULL;
    elfs_profile_t p;
    int status;

    memset(&s, 0, sizeof(s));
    s.is64 = 1;
    s.type = 3;
    s.machine = ELFS_EM_X86_64;
    s.interp = "/lib/ld.so.1";
    s.stack = STACK_RW;
    s.phdr = 1;
    s.dynamic = 1;
    s.hash = HASH_SYSV;
    s.df_1_pie = 1;
    s.imports[0] = "__stack_chk_fail";
    img_build(&m, &s);
    status = elfs_open(m.d, sizeof(m.d), NULL, NULL, NULL, &elf);
    if (status == ELFS_OK)
        status = elfs_profile(elf, &p);
    if (status == ELFS_OK && (p.kind != ELFS_KIND_PIE || p.canary != ELFS_YES || elfs_strerror(status) == NULL))
        status = ELFS_ERR_FORMAT;
    elfs_destroy(elf);
    return status == ELFS_OK ? 0 : 1;
}
