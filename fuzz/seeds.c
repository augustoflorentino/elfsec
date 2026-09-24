#include "../tests/elfs_image.h"

#include <stdio.h>
#include <string.h>

static int write_seed(const char *dir, int n, const img_spec_t *s)
{
    char path[4096];
    img_t m;
    FILE *f;
    int ok;

    img_build(&m, s);
    if (snprintf(path, sizeof(path), "%s/seed-%02d.elf", dir, n) >= (int)sizeof(path))
        return 0;
    if ((f = fopen(path, "wb")) == NULL)
        return 0;
    ok = fwrite(m.d, 1, sizeof(m.d), f) == sizeof(m.d);
    return fclose(f) == 0 && ok;
}

static img_spec_t dynamic_spec(int variant)
{
    img_spec_t s;

    memset(&s, 0, sizeof(s));
    s.is64 = variant & 1;
    s.big = (variant >> 1) & 1;
    s.sections = (variant >> 2) & 1;
    s.hash = 1 + (variant >> 3) % 4;
    s.type = 3;
    s.machine = s.hash == HASH_MIPS ? 8 : 62;
    s.interp = "/lib/ld.so.1";
    s.stack = STACK_RW;
    s.relro = 1;
    s.now = NOW_FLAGS_1;
    s.df_1_pie = 1;
    s.phdr = 1;
    s.dynamic = 1;
    s.needed[0] = "libc.so.6";
    s.runpath = "$ORIGIN::/tmp";
    s.imports[0] = "__stack_chk_fail";
    s.imports[1] = "__memcpy_chk";
    s.imports[2] = "system";
    s.defined[0] = "main";
    return s;
}

int main(int argc, char **argv)
{
    static const char *const extra[] = {".modinfo", "__ksymtab", ".u_boot_list"};
    img_spec_t s;
    int n, i;

    if (argc != 2) {
        fprintf(stderr, "usage: %s DIR\n", argv[0]);
        return 2;
    }
    for (n = 0; n < 32; n++) {
        s = dynamic_spec(n);
        if (!write_seed(argv[1], n, &s))
            return 1;
    }
    for (i = 0; i < 3; i++, n++) {
        memset(&s, 0, sizeof(s));
        s.is64 = 1;
        s.type = (uint16_t)(i == 0 ? 1 : 2);
        s.machine = 183;
        s.sections = 1;
        s.stack = STACK_RW;
        s.extra[0] = extra[i];
        s.symtab[0] = "__stack_chk_fail";
        if (!write_seed(argv[1], n, &s))
            return 1;
    }
    return 0;
}
