#include "elfsec/elfsec.h"

#include <stdint.h>

static int consume_piece(void *ctx, const unsigned char *piece, size_t piece_len)
{
    size_t *total = ctx;

    *total += piece_len + (piece_len > 0 ? piece[0] : 0);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    elfs_buf_t *buf = NULL;
    size_t total = 0;

    if (elfs_buf_create(NULL, NULL, NULL, &buf) != ELFS_OK)
        return 0;
    if (elfs_buf_append(buf, data, size) == ELFS_OK && size > 0)
        elfs_buf_split(buf, data[0], consume_piece, &total);
    elfs_buf_destroy(buf);
    return 0;
}
