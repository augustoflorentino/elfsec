# elfsec

DESCRICAO

## Build and install

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build
cmake --install build --prefix /usr/local
```

Use it from CMake:

```cmake
find_package(elfsec REQUIRED)
target_link_libraries(app PRIVATE elfsec::elfsec)
```

Or with pkg-config:

```sh
cc app.c $(pkg-config --cflags --libs elfsec)
```

## Single-file form

`scripts/amalgamate.sh` writes `dist/elfsec/elfsec.h`. Copy it into your project and, in exactly
one `.c` file:

```c
#define ELFS_IMPLEMENTATION
#include "elfsec/elfsec.h"
```

Define `ELFS_STATIC` as well to keep every function private to that file.

## Usage

See [`examples/basic.c`](examples/basic.c). The header `include/elfsec/elfsec.h` is the
API reference.

Conventions:

- every function that can fail returns `ELFS_OK` or an error code; `elfs_strerror` describes it
- what `elfs_x_create` returns is released only by `elfs_x_destroy`, which accepts `NULL`
- functions never take ownership of their arguments; returned pointers belong to the library
- pass your own allocator to `elfs_buf_create`, or `NULL` for `malloc`/`free`

## Versioning

Semantic Versioning. Compatible releases bump the minor version; incompatible ones bump the
major version and the soname. See [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
