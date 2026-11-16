#define _GNU_SOURCE
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/random.h>

/* ---------------- vbuf ---------------- */
void vbuf_init(vbuf *b) { b->data = NULL; b->len = b->cap = 0; b->err = 0; }
void vbuf_free(vbuf *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }

static void vbuf_grow(vbuf *b, size_t need) {
    if (b->len + need <= b->cap) return;
    size_t nc = b->cap ? b->cap * 2 : 256;
    while (nc < b->len + need) nc *= 2;
    uint8_t *nd = realloc(b->data, nc);
    if (!nd) { b->err = 1; return; }
    b->data = nd; b->cap = nc;
}
void vbuf_put(vbuf *b, const void *p, size_t n) {
    vbuf_grow(b, n);
    if (b->err) return;
    memcpy(b->data + b->len, p, n);
    b->len += n;
}
void vbuf_u8(vbuf *b, uint8_t v) { vbuf_put(b, &v, 1); }
void vbuf_u32(vbuf *b, uint32_t v) {
    uint8_t t[4] = { v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff };
    vbuf_put(b, t, 4);
}
void vbuf_u64(vbuf *b, uint64_t v) {
    uint8_t t[8];
    for (int i = 0; i < 8; i++) t[i] = (v >> (8 * i)) & 0xff;
    vbuf_put(b, t, 8);
}
void vbuf_bytes(vbuf *b, const void *p, size_t n) { vbuf_u32(b, (uint32_t)n); vbuf_put(b, p, n); }
void vbuf_str(vbuf *b, const char *s) { vbuf_bytes(b, s, strlen(s)); }

/* ---------------- rbuf ---------------- */
void rbuf_init(rbuf *r, const uint8_t *data, size_t len) {
    r->data = data; r->len = len; r->pos = 0; r->err = 0;
}
int rbuf_get(rbuf *r, void *out, size_t n) {
    if (r->err || r->pos + n > r->len || r->pos + n < r->pos) { r->err = 1; return -1; }
    if (out) memcpy(out, r->data + r->pos, n);
    r->pos += n;
    return 0;
}
uint8_t rbuf_u8(rbuf *r) { uint8_t v = 0; rbuf_get(r, &v, 1); return v; }
uint32_t rbuf_u32(rbuf *r) {
    uint8_t t[4] = {0}; if (rbuf_get(r, t, 4)) return 0;
    return (uint32_t)t[0] | ((uint32_t)t[1] << 8) | ((uint32_t)t[2] << 16) | ((uint32_t)t[3] << 24);
}
uint64_t rbuf_u64(rbuf *r) {
    uint8_t t[8] = {0}; if (rbuf_get(r, t, 8)) return 0;
    uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)t[i] << (8 * i);
    return v;
}
const uint8_t *rbuf_bytes(rbuf *r, size_t *n) {
    uint32_t ln = rbuf_u32(r);
    if (r->err || r->pos + ln > r->len || r->pos + ln < r->pos) { r->err = 1; return NULL; }
    const uint8_t *p = r->data + r->pos;
    r->pos += ln;
    *n = ln;
    return p;
}
int rbuf_str(rbuf *r, char *out, size_t out_cap) {
    size_t n = 0;
    const uint8_t *p = rbuf_bytes(r, &n);
    if (!p) return -1;
    size_t c = n < out_cap - 1 ? n : out_cap - 1;
    memcpy(out, p, c);
    out[c] = 0;
    return 0;
}

/* ---------------- fs helpers ---------------- */
static int fsync_dir(const char *path) {
    char *dup = strdup(path);
    if (!dup) return -1;
    char *slash = strrchr(dup, '/');
    const char *dir = ".";
    if (slash) { *slash = 0; dir = dup[0] ? dup : "/"; }
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    free(dup);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc;
}

int vf_write_atomic(const char *path, const uint8_t *data, size_t n) {
    char tmp[4096];
    unsigned r = 0;
    int fd;
    /* unique temp name in the same directory */
    for (int attempt = 0; attempt < 16; attempt++) {
        if (getrandom(&r, sizeof r, 0) != (ssize_t)sizeof r) r = (unsigned)(getpid() ^ attempt);
        snprintf(tmp, sizeof tmp, "%s.tmp.%08x", path, r);
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST) return -1;
    }
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, data + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; close(fd); unlink(tmp); return -1; }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    if (close(fd) != 0) { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    fsync_dir(path);
    return 0;
}

int vf_read_file(const char *path, uint8_t **out, size_t *n, size_t max) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    if ((size_t)st.st_size > max) { close(fd); return -1; }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = malloc(sz ? sz : 1);
    if (!buf) { close(fd); return -1; }
    size_t off = 0;
    while (off < sz) {
        ssize_t rd = read(fd, buf + off, sz - off);
        if (rd < 0) { if (errno == EINTR) continue; free(buf); close(fd); return -1; }
        if (rd == 0) break;
        off += (size_t)rd;
    }
    close(fd);
    *out = buf; *n = off;
    return 0;
}

int vf_mkdirs(const char *path) {
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s", path);
    size_t len = strlen(tmp);
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = 0;
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
    return 0;
}

int vf_exists(const char *path) { struct stat st; return stat(path, &st) == 0; }
int vf_unlink(const char *path) { return unlink(path); }
