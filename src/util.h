/* util.h -- IO, atomic writes, and bounds-checked serialization.
 *
 * The reader (rbuf) never trusts a length from its input: every get checks the
 * remaining bytes first and fails closed.  This is the backbone of "your own
 * code stays safe when it reads data an attacker wrote".
 */
#ifndef VAULTFS_UTIL_H
#define VAULTFS_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* ---- growable output buffer ---- */
typedef struct {
    uint8_t *data;
    size_t len, cap;
    int err;
} vbuf;

void vbuf_init(vbuf *b);
void vbuf_free(vbuf *b);
void vbuf_put(vbuf *b, const void *p, size_t n);
void vbuf_u8(vbuf *b, uint8_t v);
void vbuf_u32(vbuf *b, uint32_t v);
void vbuf_u64(vbuf *b, uint64_t v);
void vbuf_bytes(vbuf *b, const void *p, size_t n);   /* u32 length prefix + bytes */
void vbuf_str(vbuf *b, const char *s);               /* length-prefixed string */

/* ---- bounds-checked input reader ---- */
typedef struct {
    const uint8_t *data;
    size_t len, pos;
    int err;              /* set to 1 on any out-of-bounds read */
} rbuf;

void rbuf_init(rbuf *r, const uint8_t *data, size_t len);
int  rbuf_get(rbuf *r, void *out, size_t n);         /* 0 ok, -1 err */
uint8_t  rbuf_u8(rbuf *r);
uint32_t rbuf_u32(rbuf *r);
uint64_t rbuf_u64(rbuf *r);
/* reads a u32 length then returns a pointer into the buffer (no copy); sets
 * *n. Returns NULL on bounds error. The returned pointer is valid as long as
 * the underlying buffer is. */
const uint8_t *rbuf_bytes(rbuf *r, size_t *n);
/* reads a length-prefixed string into out (NUL-terminated, truncated to
 * out_cap-1). Returns 0 on success. */
int rbuf_str(rbuf *r, char *out, size_t out_cap);

/* ---- filesystem helpers ---- */
/* Atomic replace: write to a temp file in the same dir, fsync, rename, fsync
 * dir.  A crash leaves either the old file or the new file, never a partial. */
int vf_write_atomic(const char *path, const uint8_t *data, size_t n);
/* Read an entire file (size-capped). Caller frees *out. Returns 0 on success. */
int vf_read_file(const char *path, uint8_t **out, size_t *n, size_t max);
int vf_mkdirs(const char *path);                      /* mkdir -p */
int vf_exists(const char *path);
int vf_unlink(const char *path);

#endif
