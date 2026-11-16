/* vault.c -- VaultFS engine.
 *
 * On-disk layout of a volume (all inside the untrusted backing directory):
 *
 *   VAULTFS        public header: magic, format version, 16-byte volume id
 *   keyring.bin    per-user unlock records (see below); needed before the VMK
 *   catalog.enc    AES-256-GCM(VMK) over the filesystem tree + metadata
 *   objects/<hex>  each file block, AES-256-GCM(file key), content-opaque name
 *
 * Trusted state kept OUTSIDE the backing directory:
 *
 *   <anchor_dir>/<volid>.anchor   { volume_id, version_counter, sha256(catalog.enc) }
 *
 * Unlock chain:  password --scrypt--> UKEK --AEAD--> user X25519 private key
 *                --sealed-box--> VMK --AEAD--> catalog --sealed-box(per file)--> file keys
 *
 * Every ciphertext is authenticated (GCM).  The monotonic version_counter lives
 * inside the VMK-authenticated catalog and is checked against the trusted anchor
 * on unlock, so rolling the whole backing directory back to an older copy is
 * detected.  All attacker-supplied lengths are bounds-checked (util.c rbuf).
 */
#define _GNU_SOURCE
#include "../include/vaultfs.h"
#include "crypto.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#define SCRYPT_N (1u << 15)
#define SCRYPT_R 8
#define SCRYPT_P 1
#define MAX_CATALOG (128u * 1024 * 1024)
#define MAX_KEYRING (16u * 1024 * 1024)
#define MAX_OBJECT  (VF_BLOCK_SIZE + 64)
#define CAT_MAGIC   "VFSCAT1"
#define HDR_MAGIC   "VAULTFS1"

typedef struct { uint8_t id[16]; uint32_t plen; } block_t;
typedef struct { uint32_t user; uint8_t *wrap; size_t wrap_len; } fkwrap_t;

typedef struct {
    char name[64];
    uint8_t salt[VF_SALT_LEN];
    uint64_t N; uint32_t r, p;
    uint8_t pub[32];
    uint8_t priv_nonce[VF_NONCE_LEN], priv_tag[VF_TAG_LEN], priv_ct[32];
    uint8_t *vmk_wrap; size_t vmk_wrap_len;
    uint8_t role;  /* 1 = admin */
} user_t;

typedef struct {
    uint64_t ino, parent;
    char name[VF_MAX_NAME + 1];
    uint8_t type;
    uint32_t mode;
    uint32_t owner;
    uint64_t size, mtime;
    fkwrap_t *wraps; size_t nwraps;
    block_t *blocks; size_t nblocks;
} inode_t;

struct vault {
    char backing[2048];
    char anchor_path[2560];
    uint8_t volume_id[16];
    uint64_t version, next_ino;
    user_t *users; size_t nusers;
    inode_t *inodes; size_t ninodes;
    uint8_t vmk[32]; int unlocked;
    uint32_t cur_user; uint8_t cur_priv[32]; int have_priv;
    int autocommit;
};

/* ------------------------------------------------------------------ */
static const char *HEXD = "0123456789abcdef";
static void tohex(const uint8_t *in, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) { out[2*i] = HEXD[in[i] >> 4]; out[2*i+1] = HEXD[in[i] & 15]; }
    out[2*n] = 0;
}
static void path_join(char *out, size_t cap, const char *a, const char *b) {
    snprintf(out, cap, "%s/%s", a, b);
}
static void object_path(vault_t *v, const uint8_t id[16], char *out, size_t cap) {
    char hex[33]; tohex(id, 16, hex);
    snprintf(out, cap, "%s/objects/%s", v->backing, hex);
}
static uint64_t now_sec(void) { return (uint64_t)time(NULL); }

/* Best-effort: pin in-struct secrets (VMK, current private key) into RAM so
 * they are not swapped to disk while the program runs. */
static void try_mlock_self(vault_t *v) { (void)mlock(v, sizeof *v); }

/* ---- user / inode lookup ---- */
static user_t *find_user(vault_t *v, const char *name) {
    for (size_t i = 0; i < v->nusers; i++)
        if (strcmp(v->users[i].name, name) == 0) return &v->users[i];
    return NULL;
}
static int user_index(vault_t *v, user_t *u) { return (int)(u - v->users); }
static inode_t *get_inode(vault_t *v, uint64_t ino) {
    for (size_t i = 0; i < v->ninodes; i++) if (v->inodes[i].ino == ino) return &v->inodes[i];
    return NULL;
}
static inode_t *find_child(vault_t *v, uint64_t parent, const char *name) {
    for (size_t i = 0; i < v->ninodes; i++)
        if (v->inodes[i].parent == parent && v->inodes[i].ino != v->inodes[i].parent
            && strcmp(v->inodes[i].name, name) == 0)
            return &v->inodes[i];
    return NULL;
}

/* Resolve an absolute path to an inode. Returns inode or NULL (sets *err). */
static inode_t *resolve(vault_t *v, const char *path, int *err) {
    if (err) *err = VF_OK;
    if (!path || path[0] != '/') { if (err) *err = VF_ERR_INVAL; return NULL; }
    inode_t *cur = get_inode(v, 1);  /* root */
    char comp[VF_MAX_NAME + 1];
    const char *p = path + 1;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if (len == 0) { p = slash ? slash + 1 : p + len; continue; }
        if (len > VF_MAX_NAME) { if (err) *err = VF_ERR_INVAL; return NULL; }
        memcpy(comp, p, len); comp[len] = 0;
        if (cur->type != VF_T_DIR) { if (err) *err = VF_ERR_NOTDIR; return NULL; }
        inode_t *child = find_child(v, cur->ino, comp);
        if (!child) { if (err) *err = VF_ERR_NOENT; return NULL; }
        cur = child;
        p = slash ? slash + 1 : p + len;
    }
    return cur;
}
/* Split "/a/b/c" -> parent inode of c (/a/b) and leaf name "c". */
static int split_parent(vault_t *v, const char *path, inode_t **parent, char *leaf) {
    size_t L = strlen(path);
    if (L == 0 || path[0] != '/') return VF_ERR_INVAL;
    const char *slash = strrchr(path, '/');
    size_t llen = strlen(slash + 1);
    if (llen == 0 || llen > VF_MAX_NAME) return VF_ERR_INVAL;
    strcpy(leaf, slash + 1);
    char dir[2048];
    size_t dlen = (size_t)(slash - path);
    if (dlen == 0) { strcpy(dir, "/"); } else { memcpy(dir, path, dlen); dir[dlen] = 0; }
    int err; inode_t *pp = resolve(v, dir, &err);
    if (!pp) return err;
    if (pp->type != VF_T_DIR) return VF_ERR_NOTDIR;
    *parent = pp;
    return VF_OK;
}

/* ------------------------------------------------------------------ */
/* serialization                                                       */
static void ser_user(vbuf *b, user_t *u) {
    vbuf_str(b, u->name);
    vbuf_put(b, u->salt, VF_SALT_LEN);
    vbuf_u64(b, u->N); vbuf_u32(b, u->r); vbuf_u32(b, u->p);
    vbuf_put(b, u->pub, 32);
    vbuf_put(b, u->priv_nonce, VF_NONCE_LEN);
    vbuf_put(b, u->priv_tag, VF_TAG_LEN);
    vbuf_put(b, u->priv_ct, 32);
    vbuf_bytes(b, u->vmk_wrap, u->vmk_wrap_len);
    vbuf_u8(b, u->role);
}
static int deser_user(rbuf *r, user_t *u) {
    memset(u, 0, sizeof *u);
    if (rbuf_str(r, u->name, sizeof u->name)) return -1;
    if (rbuf_get(r, u->salt, VF_SALT_LEN)) return -1;
    u->N = rbuf_u64(r); u->r = rbuf_u32(r); u->p = rbuf_u32(r);
    if (rbuf_get(r, u->pub, 32)) return -1;
    if (rbuf_get(r, u->priv_nonce, VF_NONCE_LEN)) return -1;
    if (rbuf_get(r, u->priv_tag, VF_TAG_LEN)) return -1;
    if (rbuf_get(r, u->priv_ct, 32)) return -1;
    size_t n; const uint8_t *w = rbuf_bytes(r, &n);
    if (!w) return -1;
    u->vmk_wrap = malloc(n ? n : 1); if (!u->vmk_wrap) return -1;
    memcpy(u->vmk_wrap, w, n); u->vmk_wrap_len = n;
    u->role = rbuf_u8(r);
    return r->err ? -1 : 0;
}
/* keyring.bin = magic + nusers + users[] */
static int serialize_keyring(vault_t *v, vbuf *b) {
    vbuf_put(b, "VFSKEY1", 7);
    vbuf_u32(b, (uint32_t)v->nusers);
    for (size_t i = 0; i < v->nusers; i++) ser_user(b, &v->users[i]);
    return b->err ? -1 : 0;
}
static int load_keyring(vault_t *v, const uint8_t *data, size_t len) {
    rbuf r; rbuf_init(&r, data, len);
    char magic[7]; if (rbuf_get(&r, magic, 7) || memcmp(magic, "VFSKEY1", 7)) return VF_ERR_FORMAT;
    uint32_t n = rbuf_u32(&r);
    if (n > VF_MAX_USERS) return VF_ERR_FORMAT;
    v->users = calloc(n ? n : 1, sizeof(user_t));
    if (!v->users) return VF_ERR_NOMEM;
    for (uint32_t i = 0; i < n; i++) {
        if (deser_user(&r, &v->users[i])) return VF_ERR_FORMAT;
    }
    v->nusers = n;
    return r.err ? VF_ERR_FORMAT : VF_OK;
}

/* catalog body (pre-encryption) */
static int serialize_catalog(vault_t *v, const uint8_t keyring_hash[32], vbuf *b) {
    vbuf_put(b, CAT_MAGIC, 7);
    vbuf_put(b, v->volume_id, 16);
    vbuf_u64(b, v->version);
    vbuf_u64(b, v->next_ino);
    vbuf_put(b, keyring_hash, 32);
    vbuf_u32(b, (uint32_t)v->ninodes);
    for (size_t i = 0; i < v->ninodes; i++) {
        inode_t *n = &v->inodes[i];
        vbuf_u64(b, n->ino); vbuf_u64(b, n->parent);
        vbuf_str(b, n->name);
        vbuf_u8(b, n->type); vbuf_u32(b, n->mode); vbuf_u32(b, n->owner);
        vbuf_u64(b, n->size); vbuf_u64(b, n->mtime);
        if (n->type == VF_T_FILE) {
            vbuf_u32(b, (uint32_t)n->nwraps);
            for (size_t k = 0; k < n->nwraps; k++) {
                vbuf_u32(b, n->wraps[k].user);
                vbuf_bytes(b, n->wraps[k].wrap, n->wraps[k].wrap_len);
            }
            vbuf_u32(b, (uint32_t)n->nblocks);
            for (size_t k = 0; k < n->nblocks; k++) {
                vbuf_put(b, n->blocks[k].id, 16);
                vbuf_u32(b, n->blocks[k].plen);
            }
        }
    }
    return b->err ? -1 : 0;
}
static int deserialize_catalog(vault_t *v, const uint8_t *data, size_t len,
                               uint8_t keyring_hash_out[32]) {
    rbuf r; rbuf_init(&r, data, len);
    char magic[7];
    if (rbuf_get(&r, magic, 7) || memcmp(magic, CAT_MAGIC, 7)) return VF_ERR_FORMAT;
    uint8_t vid[16]; if (rbuf_get(&r, vid, 16)) return VF_ERR_FORMAT;
    if (memcmp(vid, v->volume_id, 16) != 0) return VF_ERR_TAMPER;
    v->version = rbuf_u64(&r);
    v->next_ino = rbuf_u64(&r);
    if (rbuf_get(&r, keyring_hash_out, 32)) return VF_ERR_FORMAT;
    uint32_t nn = rbuf_u32(&r);
    if (r.err || nn > 1000000) return VF_ERR_FORMAT;
    v->inodes = calloc(nn ? nn : 1, sizeof(inode_t));
    if (!v->inodes) return VF_ERR_NOMEM;
    for (uint32_t i = 0; i < nn; i++) {
        inode_t *n = &v->inodes[i];
        n->ino = rbuf_u64(&r); n->parent = rbuf_u64(&r);
        if (rbuf_str(&r, n->name, sizeof n->name)) return VF_ERR_FORMAT;
        n->type = rbuf_u8(&r); n->mode = rbuf_u32(&r); n->owner = rbuf_u32(&r);
        n->size = rbuf_u64(&r); n->mtime = rbuf_u64(&r);
        if (n->type == VF_T_FILE) {
            uint32_t nw = rbuf_u32(&r);
            if (r.err || nw > 100000) return VF_ERR_FORMAT;
            n->wraps = calloc(nw ? nw : 1, sizeof(fkwrap_t));
            if (!n->wraps) return VF_ERR_NOMEM;
            for (uint32_t k = 0; k < nw; k++) {
                n->wraps[k].user = rbuf_u32(&r);
                size_t wl; const uint8_t *w = rbuf_bytes(&r, &wl);
                if (!w) return VF_ERR_FORMAT;
                n->wraps[k].wrap = malloc(wl ? wl : 1);
                if (!n->wraps[k].wrap) return VF_ERR_NOMEM;
                memcpy(n->wraps[k].wrap, w, wl); n->wraps[k].wrap_len = wl;
            }
            n->nwraps = nw;
            uint32_t nb = rbuf_u32(&r);
            if (r.err || nb > 100000000) return VF_ERR_FORMAT;
            n->blocks = calloc(nb ? nb : 1, sizeof(block_t));
            if (!n->blocks) return VF_ERR_NOMEM;
            for (uint32_t k = 0; k < nb; k++) {
                if (rbuf_get(&r, n->blocks[k].id, 16)) return VF_ERR_FORMAT;
                n->blocks[k].plen = rbuf_u32(&r);
            }
            n->nblocks = nb;
        }
    }
    v->ninodes = nn;
    return r.err ? VF_ERR_FORMAT : VF_OK;
}

/* ------------------------------------------------------------------ */
/* anchor (trusted rollback counter)                                   */
static void anchor_path_for(const char *anchor_dir, const uint8_t vid[16],
                            char *out, size_t cap) {
    char hex[33]; tohex(vid, 16, hex);
    snprintf(out, cap, "%s/%s.anchor", anchor_dir, hex);
}
static int write_anchor(vault_t *v, const uint8_t cat_hash[32]) {
    vbuf b; vbuf_init(&b);
    vbuf_put(&b, "VFSANC1", 7);
    vbuf_put(&b, v->volume_id, 16);
    vbuf_u64(&b, v->version);
    vbuf_put(&b, cat_hash, 32);
    int rc = b.err ? VF_ERR_NOMEM : vf_write_atomic(v->anchor_path, b.data, b.len);
    vbuf_free(&b);
    return rc ? VF_ERR_IO : VF_OK;
}
/* returns 0 and fills *version,*hash if anchor exists; 1 if missing; <0 error */
static int read_anchor(vault_t *v, uint64_t *version, uint8_t hash[32], uint8_t vid[16]) {
    uint8_t *d; size_t n;
    if (vf_read_file(v->anchor_path, &d, &n, 4096) != 0) return 1;
    rbuf r; rbuf_init(&r, d, n);
    char magic[7]; int rc = -1;
    if (rbuf_get(&r, magic, 7) || memcmp(magic, "VFSANC1", 7)) goto out;
    if (rbuf_get(&r, vid, 16)) goto out;
    *version = rbuf_u64(&r);
    if (rbuf_get(&r, hash, 32)) goto out;
    rc = r.err ? -1 : 0;
out:
    free(d);
    return rc;
}

/* ------------------------------------------------------------------ */
/* commit: serialize + encrypt catalog, write keyring if needed, anchor */
static int commit_internal(vault_t *v, int keyring_changed) {
    if (!v->unlocked) return VF_ERR_AUTH;
    uint8_t keyring_hash[32];
    if (keyring_changed) {
        vbuf kb; vbuf_init(&kb);
        if (serialize_keyring(v, &kb)) { vbuf_free(&kb); return VF_ERR_NOMEM; }
        char kp[2100]; path_join(kp, sizeof kp, v->backing, "keyring.bin");
        int rc = vf_write_atomic(kp, kb.data, kb.len);
        if (!rc) vf_sha256(kb.data, kb.len, keyring_hash);
        vbuf_free(&kb);
        if (rc) return VF_ERR_IO;
    } else {
        /* recompute from current keyring file */
        char kp[2100]; path_join(kp, sizeof kp, v->backing, "keyring.bin");
        uint8_t *kd; size_t kn;
        if (vf_read_file(kp, &kd, &kn, MAX_KEYRING) != 0) return VF_ERR_IO;
        vf_sha256(kd, kn, keyring_hash); free(kd);
    }

    v->version += 1;
    vbuf cb; vbuf_init(&cb);
    if (serialize_catalog(v, keyring_hash, &cb)) { vbuf_free(&cb); return VF_ERR_NOMEM; }

    /* AES-256-GCM(VMK), AAD = volume_id||"CATALOG".  The version counter lives
     * inside the authenticated plaintext body, so it is protected by the GCM
     * tag without needing to be known before decryption. */
    uint8_t aad[16 + 7];
    memcpy(aad, v->volume_id, 16); memcpy(aad + 16, "CATALOG", 7);

    size_t ctlen = cb.len;
    uint8_t *out = malloc(VF_NONCE_LEN + VF_TAG_LEN + ctlen + 1);
    if (!out) { vbuf_free(&cb); return VF_ERR_NOMEM; }
    uint8_t *nonce = out, *tag = out + VF_NONCE_LEN, *ct = out + VF_NONCE_LEN + VF_TAG_LEN;
    int rc = VF_ERR_IO;
    if (vf_random(nonce, VF_NONCE_LEN) != 0) goto out;
    if (vf_aead_encrypt(v->vmk, nonce, aad, sizeof aad, cb.data, ctlen, ct, tag) != 0) goto out;
    size_t total = VF_NONCE_LEN + VF_TAG_LEN + ctlen;
    char cp[2100]; path_join(cp, sizeof cp, v->backing, "catalog.enc");
    if (vf_write_atomic(cp, out, total) != 0) goto out;
    uint8_t cat_hash[32]; vf_sha256(out, total, cat_hash);
    rc = write_anchor(v, cat_hash);
out:
    vbuf_free(&cb);
    vf_cleanse(out, VF_NONCE_LEN + VF_TAG_LEN + ctlen);
    free(out);
    return rc;
}
static int maybe_commit(vault_t *v) { return v->autocommit ? commit_internal(v, 0) : VF_OK; }

/* ------------------------------------------------------------------ */
/* object (block) IO                                                   */
static int object_write(vault_t *v, uint64_t ino, uint32_t block_index,
                        const uint8_t fk[32], const uint8_t *pt, uint32_t plen,
                        uint8_t id_out[16]) {
    if (vf_random(id_out, 16) != 0) return VF_ERR_IO;
    uint8_t aad[16 + 8 + 8];
    memcpy(aad, v->volume_id, 16);
    for (int i = 0; i < 8; i++) aad[16 + i] = (ino >> (8 * i)) & 0xff;
    for (int i = 0; i < 8; i++) aad[24 + i] = ((uint64_t)block_index >> (8 * i)) & 0xff;
    uint8_t buf[VF_NONCE_LEN + VF_TAG_LEN + VF_BLOCK_SIZE];
    uint8_t *nonce = buf, *tag = buf + VF_NONCE_LEN, *ct = buf + VF_NONCE_LEN + VF_TAG_LEN;
    if (vf_random(nonce, VF_NONCE_LEN) != 0) return VF_ERR_IO;
    if (vf_aead_encrypt(fk, nonce, aad, sizeof aad, pt, plen, ct, tag) != 0) return VF_ERR_IO;
    char op[2200]; object_path(v, id_out, op, sizeof op);
    if (vf_write_atomic(op, buf, VF_NONCE_LEN + VF_TAG_LEN + plen) != 0) return VF_ERR_IO;
    return VF_OK;
}
static int object_read(vault_t *v, uint64_t ino, uint32_t block_index,
                       const uint8_t fk[32], const block_t *blk, uint8_t *pt_out) {
    char op[2200]; object_path(v, blk->id, op, sizeof op);
    uint8_t *d; size_t n;
    if (vf_read_file(op, &d, &n, MAX_OBJECT) != 0) return VF_ERR_IO;
    if (n < VF_NONCE_LEN + VF_TAG_LEN) { free(d); return VF_ERR_TAMPER; }
    size_t ctlen = n - VF_NONCE_LEN - VF_TAG_LEN;
    if (ctlen != blk->plen) { free(d); return VF_ERR_TAMPER; }
    uint8_t aad[16 + 8 + 8];
    memcpy(aad, v->volume_id, 16);
    for (int i = 0; i < 8; i++) aad[16 + i] = (ino >> (8 * i)) & 0xff;
    for (int i = 0; i < 8; i++) aad[24 + i] = ((uint64_t)block_index >> (8 * i)) & 0xff;
    uint8_t *nonce = d, *tag = d + VF_NONCE_LEN, *ct = d + VF_NONCE_LEN + VF_TAG_LEN;
    int rc = vf_aead_decrypt(fk, nonce, aad, sizeof aad, ct, ctlen, tag, pt_out);
    free(d);
    return rc == 0 ? VF_OK : VF_ERR_TAMPER;
}

/* unwrap a file's key for the current user; VF_ERR_PERM if not authorized */
static int file_key(vault_t *v, inode_t *n, uint8_t fk[32]) {
    if (!v->have_priv) return VF_ERR_AUTH;
    for (size_t i = 0; i < n->nwraps; i++) {
        if (n->wraps[i].user == v->cur_user) {
            size_t ol;
            if (vf_seal_open(v->cur_priv, n->wraps[i].wrap, n->wraps[i].wrap_len, fk, &ol) == 0
                && ol == 32)
                return VF_OK;
            return VF_ERR_TAMPER;
        }
    }
    return VF_ERR_PERM;
}
/* wrap FK to a user's public key and append to the inode's wrap list */
static int add_wrap(inode_t *n, uint32_t user, const uint8_t pub[32], const uint8_t fk[32]) {
    uint8_t sealed[32 + VF_SEAL_OVERHEAD]; size_t sl;
    if (vf_seal(pub, fk, 32, sealed, &sl) != 0) return VF_ERR_IO;
    fkwrap_t *nw = realloc(n->wraps, (n->nwraps + 1) * sizeof(fkwrap_t));
    if (!nw) return VF_ERR_NOMEM;
    n->wraps = nw;
    n->wraps[n->nwraps].user = user;
    n->wraps[n->nwraps].wrap = malloc(sl);
    if (!n->wraps[n->nwraps].wrap) return VF_ERR_NOMEM;
    memcpy(n->wraps[n->nwraps].wrap, sealed, sl);
    n->wraps[n->nwraps].wrap_len = sl;
    n->nwraps++;
    return VF_OK;
}

/* ------------------------------------------------------------------ */
/* inode allocation                                                    */
static inode_t *new_inode(vault_t *v) {
    inode_t *ni = realloc(v->inodes, (v->ninodes + 1) * sizeof(inode_t));
    if (!ni) return NULL;
    v->inodes = ni;
    inode_t *n = &v->inodes[v->ninodes++];
    memset(n, 0, sizeof *n);
    n->ino = v->next_ino++;
    n->mtime = now_sec();
    return n;
}
static void free_inode_contents(inode_t *n) {
    for (size_t i = 0; i < n->nwraps; i++) free(n->wraps[i].wrap);
    free(n->wraps); free(n->blocks);
    n->wraps = NULL; n->blocks = NULL; n->nwraps = n->nblocks = 0;
}
static void remove_inode(vault_t *v, inode_t *n) {
    free_inode_contents(n);
    size_t idx = (size_t)(n - v->inodes);
    memmove(&v->inodes[idx], &v->inodes[idx + 1],
            (v->ninodes - idx - 1) * sizeof(inode_t));
    v->ninodes--;
}

/* ================================================================== */
/* public API                                                          */
/* ================================================================== */
int vault_format(const char *backing, const char *admin, const char *password) {
    if (!backing || !admin || !password) return VF_ERR_INVAL;
    if (strlen(admin) >= 64) return VF_ERR_INVAL;
    char objdir[2100]; path_join(objdir, sizeof objdir, backing, "objects");
    if (vf_mkdirs(objdir) != 0) return VF_ERR_IO;

    vault_t *v = calloc(1, sizeof *v);
    if (!v) return VF_ERR_NOMEM;
    snprintf(v->backing, sizeof v->backing, "%s", backing);
    v->autocommit = 1;
    if (vf_random(v->volume_id, 16) != 0) { free(v); return VF_ERR_IO; }
    v->version = 0; v->next_ino = 1;

    /* header */
    vbuf hb; vbuf_init(&hb);
    vbuf_put(&hb, HDR_MAGIC, 8); vbuf_put(&hb, v->volume_id, 16);
    char hp[2100]; path_join(hp, sizeof hp, backing, "VAULTFS");
    int rc = vf_write_atomic(hp, hb.data, hb.len); vbuf_free(&hb);
    if (rc) { free(v); return VF_ERR_IO; }

    /* VMK */
    if (vf_random(v->vmk, 32) != 0) { free(v); return VF_ERR_IO; }
    v->unlocked = 1;

    /* admin user */
    v->users = calloc(1, sizeof(user_t)); if (!v->users) { free(v); return VF_ERR_NOMEM; }
    user_t *u = &v->users[0]; v->nusers = 1;
    snprintf(u->name, sizeof u->name, "%s", admin);
    u->role = 1; u->N = SCRYPT_N; u->r = SCRYPT_R; u->p = SCRYPT_P;
    if (vf_random(u->salt, VF_SALT_LEN) != 0) goto fail;
    uint8_t priv[32], pub[32];
    if (vf_x25519_keypair(priv, pub) != 0) goto fail;
    memcpy(u->pub, pub, 32);
    uint8_t ukek[32];
    if (vf_scrypt(password, strlen(password), u->salt, VF_SALT_LEN, u->N, u->r, u->p, ukek, 32) != 0) goto fail;
    if (vf_random(u->priv_nonce, VF_NONCE_LEN) != 0) { vf_cleanse(ukek,32); goto fail; }
    if (vf_aead_encrypt(ukek, u->priv_nonce, NULL, 0, priv, 32, u->priv_ct, u->priv_tag) != 0) { vf_cleanse(ukek,32); goto fail; }
    vf_cleanse(ukek, 32);
    /* wrap VMK to admin pub */
    uint8_t sealed[32 + VF_SEAL_OVERHEAD]; size_t sl;
    if (vf_seal(pub, v->vmk, 32, sealed, &sl) != 0) goto fail;
    u->vmk_wrap = malloc(sl); if (!u->vmk_wrap) goto fail;
    memcpy(u->vmk_wrap, sealed, sl); u->vmk_wrap_len = sl;
    vf_cleanse(priv, 32);

    /* root inode */
    inode_t *root = new_inode(v); if (!root) goto fail;
    root->ino = 1; root->parent = 1; root->type = VF_T_DIR; root->mode = 0755;
    strcpy(root->name, "/");
    /* next_ino was bumped to 2 by new_inode via next_ino++ starting at 1 -> root got 1, next=2 */

    /* Default anchor beside the backing dir; real clients pass a trusted
     * anchor_dir to vault_open (see DESIGN.md "trusted state"). */
    snprintf(v->anchor_path, sizeof v->anchor_path, "%s/.vaultfs-anchor", backing);
    rc = commit_internal(v, 1);
    vault_close(v);
    return rc;
fail:
    vault_close(v);
    return VF_ERR_IO;
}

int vault_open(const char *backing, const char *anchor_dir, vault_t **out) {
    vault_t *v = calloc(1, sizeof *v);
    if (!v) return VF_ERR_NOMEM;
    snprintf(v->backing, sizeof v->backing, "%s", backing);
    v->autocommit = 1;

    char hp[2100]; path_join(hp, sizeof hp, backing, "VAULTFS");
    uint8_t *hd; size_t hn;
    if (vf_read_file(hp, &hd, &hn, 64) != 0) { free(v); return VF_ERR_IO; }
    if (hn < 24 || memcmp(hd, HDR_MAGIC, 8) != 0) { free(hd); free(v); return VF_ERR_FORMAT; }
    memcpy(v->volume_id, hd + 8, 16); free(hd);

    if (anchor_dir && anchor_dir[0]) {
        if (vf_mkdirs(anchor_dir) != 0) { free(v); return VF_ERR_IO; }
        anchor_path_for(anchor_dir, v->volume_id, v->anchor_path, sizeof v->anchor_path);
    } else {
        snprintf(v->anchor_path, sizeof v->anchor_path, "%s/.vaultfs-anchor", backing);
    }

    char kp[2100]; path_join(kp, sizeof kp, backing, "keyring.bin");
    uint8_t *kd; size_t kn;
    if (vf_read_file(kp, &kd, &kn, MAX_KEYRING) != 0) { free(v); return VF_ERR_IO; }
    int rc = load_keyring(v, kd, kn); free(kd);
    if (rc != VF_OK) { vault_close(v); return rc; }
    *out = v;
    return VF_OK;
}

int vault_unlock(vault_t *v, const char *user, const char *password) {
    user_t *u = find_user(v, user);
    if (!u) return VF_ERR_AUTH;
    uint8_t ukek[32], priv[32];
    if (vf_scrypt(password, strlen(password), u->salt, VF_SALT_LEN, u->N, u->r, u->p, ukek, 32) != 0)
        return VF_ERR_IO;
    int rc = vf_aead_decrypt(ukek, u->priv_nonce, NULL, 0, u->priv_ct, 32, u->priv_tag, priv);
    vf_cleanse(ukek, 32);
    if (rc != 0) return VF_ERR_AUTH;               /* wrong password */
    /* open VMK */
    size_t vl;
    if (vf_seal_open(priv, u->vmk_wrap, u->vmk_wrap_len, v->vmk, &vl) != 0 || vl != 32) {
        vf_cleanse(priv, 32); return VF_ERR_TAMPER;
    }
    memcpy(v->cur_priv, priv, 32); v->have_priv = 1;
    v->cur_user = (uint32_t)user_index(v, u);
    vf_cleanse(priv, 32);
    v->unlocked = 1;
    try_mlock_self(v);

    /* load + decrypt catalog */
    char cp[2100]; path_join(cp, sizeof cp, v->backing, "catalog.enc");
    uint8_t *cd; size_t cn;
    if (vf_read_file(cp, &cd, &cn, MAX_CATALOG) != 0) return VF_ERR_IO;
    if (cn < VF_NONCE_LEN + VF_TAG_LEN) { free(cd); return VF_ERR_TAMPER; }
    uint8_t cat_hash[32]; vf_sha256(cd, cn, cat_hash);
    size_t ctlen = cn - VF_NONCE_LEN - VF_TAG_LEN;
    uint8_t *pt = malloc(ctlen ? ctlen : 1);
    if (!pt) { free(cd); return VF_ERR_NOMEM; }
    uint8_t *nonce = cd, *tag = cd + VF_NONCE_LEN, *ct = cd + VF_NONCE_LEN + VF_TAG_LEN;
    /* AAD = volume_id || "CATALOG" (version lives in the authenticated body) */
    uint8_t aad[16 + 7];
    memcpy(aad, v->volume_id, 16); memcpy(aad + 16, "CATALOG", 7);
    rc = vf_aead_decrypt(v->vmk, nonce, aad, sizeof aad, ct, ctlen, tag, pt);
    free(cd);
    if (rc != 0) { free(pt); return VF_ERR_TAMPER; }
    uint8_t keyring_hash[32];
    rc = deserialize_catalog(v, pt, ctlen, keyring_hash);
    vf_cleanse(pt, ctlen); free(pt);
    if (rc != VF_OK) return rc;

    /* authenticate keyring under VMK */
    uint8_t *kd2; size_t kn2; char kp2[2100];
    path_join(kp2, sizeof kp2, v->backing, "keyring.bin");
    if (vf_read_file(kp2, &kd2, &kn2, MAX_KEYRING) != 0) return VF_ERR_IO;
    uint8_t kh[32]; vf_sha256(kd2, kn2, kh); free(kd2);
    if (!vf_ct_eq(kh, keyring_hash, 32)) return VF_ERR_TAMPER;

    /* rollback check against trusted anchor */
    uint64_t av; uint8_t ah[32], avid[16];
    int ar = read_anchor(v, &av, ah, avid);
    if (ar == 0) {
        if (memcmp(avid, v->volume_id, 16) != 0) return VF_ERR_TAMPER;
        if (v->version < av) return VF_ERR_ROLLBACK;
        if (v->version == av && !vf_ct_eq(cat_hash, ah, 32)) return VF_ERR_ROLLBACK;
        if (v->version > av) write_anchor(v, cat_hash);   /* advance */
    } else if (ar == 1) {
        write_anchor(v, cat_hash);                          /* trust on first use */
    } else {
        return VF_ERR_IO;
    }
    return VF_OK;
}

void vault_close(vault_t *v) {
    if (!v) return;
    vf_cleanse(v->vmk, 32);
    vf_cleanse(v->cur_priv, 32);
    for (size_t i = 0; i < v->nusers; i++) free(v->users[i].vmk_wrap);
    free(v->users);
    for (size_t i = 0; i < v->ninodes; i++) free_inode_contents(&v->inodes[i]);
    free(v->inodes);
    vf_cleanse(v, sizeof *v);
    free(v);
}

const char *vault_strerror(int code) {
    switch (code) {
    case VF_OK: return "ok";
    case VF_ERR_IO: return "I/O error";
    case VF_ERR_AUTH: return "authentication failed (wrong password)";
    case VF_ERR_ROLLBACK: return "rollback detected: stored data is older than last seen";
    case VF_ERR_TAMPER: return "tampering detected: data failed authentication";
    case VF_ERR_PERM: return "permission denied";
    case VF_ERR_NOENT: return "no such file or directory";
    case VF_ERR_EXIST: return "already exists";
    case VF_ERR_NOTDIR: return "not a directory";
    case VF_ERR_ISDIR: return "is a directory";
    case VF_ERR_NOTEMPTY: return "directory not empty";
    case VF_ERR_INVAL: return "invalid argument";
    case VF_ERR_RANGE: return "out of range";
    case VF_ERR_NOMEM: return "out of memory";
    case VF_ERR_FORMAT: return "not a vault / bad format";
    default: return "unknown error";
    }
}

const char *vault_current_user(vault_t *v) {
    if (!v->have_priv) return NULL;
    return v->users[v->cur_user].name;
}

/* included from the rest of the implementation */
#include "vault_ops.c"
