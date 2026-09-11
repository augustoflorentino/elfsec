#ifndef ELFSEC_H
#define ELFSEC_H

#include <stddef.h>

#if defined(ELFS_STATIC) && defined(__GNUC__)
#define ELFS_API static __attribute__((unused))
#elif defined(ELFS_STATIC)
#define ELFS_API static
#elif defined(_WIN32) && defined(ELFS_BUILD_SHARED)
#define ELFS_API __declspec(dllexport)
#elif defined(_WIN32) && defined(ELFS_SHARED)
#define ELFS_API __declspec(dllimport)
#elif defined(__GNUC__) && defined(ELFS_BUILD_SHARED)
#define ELFS_API __attribute__((visibility("default")))
#else
#define ELFS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ELFS_OK 0
#define ELFS_ERR_ARG 1
#define ELFS_ERR_NOMEM 2

typedef struct elfs_buf elfs_buf_t;

typedef void *(*elfs_alloc_fn)(void *ctx, size_t size);
typedef void (*elfs_free_fn)(void *ctx, void *ptr);
typedef int (*elfs_piece_fn)(void *ctx, const unsigned char *piece, size_t piece_len);

ELFS_API int elfs_buf_create(elfs_alloc_fn alloc_fn, elfs_free_fn free_fn, void *alloc_ctx, elfs_buf_t **out_buf);
ELFS_API void elfs_buf_destroy(elfs_buf_t *buf);
ELFS_API int elfs_buf_append(elfs_buf_t *buf, const unsigned char *data, size_t data_len);
ELFS_API size_t elfs_buf_len(const elfs_buf_t *buf);
ELFS_API const unsigned char *elfs_buf_data(const elfs_buf_t *buf);
ELFS_API int elfs_buf_split(const elfs_buf_t *buf, unsigned char sep, elfs_piece_fn piece_fn, void *piece_ctx);
ELFS_API const char *elfs_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif
