#define ELFS_IMPLEMENTATION
#include "elfsec/elfsec.h"

static int count_piece(void *ctx, const unsigned char *piece, size_t piece_len)
{
    (void)piece;
    (void)piece_len;
    (*(int *)ctx)++;
    return 0;
}

int main(void)
{
    elfs_buf_t *buf = NULL;
    int pieces = 0;
    int status;

    status = elfs_buf_create(NULL, NULL, NULL, &buf);
    if (status == ELFS_OK)
        status = elfs_buf_append(buf, (const unsigned char *)"a\nb", 3);
    if (status == ELFS_OK)
        status = elfs_buf_split(buf, '\n', count_piece, &pieces);
    if (elfs_buf_len(buf) != 3 || elfs_buf_data(buf) == NULL || elfs_strerror(status) == NULL)
        status = ELFS_ERR_ARG;
    elfs_buf_destroy(buf);
    return status == ELFS_OK && pieces == 2 ? 0 : 1;
}
