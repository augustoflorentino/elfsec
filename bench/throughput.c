#define _POSIX_C_SOURCE 200809L
#include "elfsec/elfsec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static double seconds(void)
{
    struct timespec t;

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static double wall(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static unsigned char *load(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *d = NULL;
    long size;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (size = ftell(f)) > 0 && fseek(f, 0, SEEK_SET) == 0 &&
        (d = malloc((size_t)size)) != NULL && fread(d, 1, (size_t)size, f) != (size_t)size) {
        free(d);
        d = NULL;
    }
    fclose(f);
    *out_len = d != NULL ? (size_t)size : 0;
    return d;
}

static size_t profile(const unsigned char *d, size_t len);

static size_t mapped(const char *path)
{
    struct stat st;
    void *d;
    size_t sum = 0;
    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return 0;
    if (fstat(fd, &st) == 0 && st.st_size > 0 &&
        (d = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) != MAP_FAILED) {
        sum = profile(d, (size_t)st.st_size);
        munmap(d, (size_t)st.st_size);
    }
    close(fd);
    return sum;
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

static size_t profile(const unsigned char *d, size_t len)
{
    elfs_elf_t *elf = NULL;
    elfs_profile_t p;
    size_t sum = 0;

    if (elfs_open(d, len, NULL, NULL, NULL, &elf) == ELFS_OK && elfs_profile(elf, &p) == ELFS_OK)
        sum = walk(elf, &p) + p.judged;
    elfs_destroy(elf);
    return sum;
}

static double best_of_five(const unsigned char *d, size_t len, size_t *sum)
{
    double best = 1e9, start, t;
    int r;

    for (r = 0; r < 5; r++) {
        start = seconds();
        *sum += profile(d, len);
        if ((t = seconds() - start) < best)
            best = t;
    }
    return best;
}

static int by_value(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;

    return (x > y) - (x < y);
}

static size_t read_list(char ***out)
{
    char line[4096], **paths = NULL, **grown;
    size_t n = 0, cap = 0, len;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        len = strcspn(line, "\n");
        line[len] = '\0';
        if (len == 0)
            continue;
        if (n == cap) {
            if ((grown = realloc(paths, (cap = cap ? 2 * cap : 1024) * sizeof(*paths))) == NULL)
                break;
            paths = grown;
        }
        if ((paths[n] = malloc(len + 1)) == NULL)
            break;
        memcpy(paths[n++], line, len + 1);
    }
    *out = paths;
    return n;
}

int main(void)
{
    char **paths;
    size_t n = read_list(&paths), i, done = 0, len, sum = 0;
    double *best = malloc((n ? n : 1) * sizeof(double)), total = 0, start, start_wall;
    unsigned char *d;

    if (best == NULL)
        return 1;
    for (i = 0; i < n; i++) {
        if ((d = load(paths[i], &len)) == NULL)
            continue;
        total += best[done++] = best_of_five(d, len, &sum);
        free(d);
    }
    qsort(best, done, sizeof(double), by_value);
    printf("files %zu\nin memory: median %.2f us, p90 %.2f us, sum %.1f ms\n", done,
           done ? best[done / 2] * 1e6 : 0.0, done ? best[done * 9 / 10] * 1e6 : 0.0, total * 1e3);
    start = seconds();
    start_wall = wall();
    for (i = 0; i < n; i++) {
        sum += mapped(paths[i]);
        free(paths[i]);
    }
    printf("end to end (mmap + profile): %.1f ms CPU, %.1f ms wall\nchecksum %zu\n", (seconds() - start) * 1e3,
           (wall() - start_wall) * 1e3, sum);
    free(paths);
    free(best);
    return 0;
}
