#include <elfsec/elfsec.h>

#include <stdio.h>

static int print_line(void *ctx, const unsigned char *piece, size_t piece_len)
{
    int *line = ctx;

    printf("%d: %.*s\n", ++*line, (int)piece_len, (const char *)piece);
    return 0;
}

int main(void)
{
    static const char text[] = "first\nsecond\nthird";
    elfs_buf_t *buf = NULL;
    int line = 0;
    int status;

    status = elfs_buf_create(NULL, NULL, NULL, &buf);
    if (status == ELFS_OK)
        status = elfs_buf_append(buf, (const unsigned char *)text, sizeof(text) - 1);
    if (status == ELFS_OK)
        status = elfs_buf_split(buf, '\n', print_line, &line);
    elfs_buf_destroy(buf);
    if (status != ELFS_OK) {
        fprintf(stderr, "error: %s\n", elfs_strerror(status));
        return 1;
    }
    return 0;
}
