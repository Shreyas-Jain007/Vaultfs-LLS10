/* vault_ops.c -- included at the end of vault.c (shares its statics & types). */

#include <dirent.h>

static int is_admin(vault_t *v) { return v->have_priv && v->users[v->cur_user].role == 1; }

/* ---------------- user management ---------------- */
int vault_adduser(vault_t *v, const char *name, const char *password) {
    if (!v->unlocked) return VF_ERR_AUTH;
    if (!is_admin(v)) return VF_ERR_PERM;
    if (strlen(name) >= 64) return VF_ERR_INVAL;
    if (find_user(v, name)) return VF_ERR_EXIST;
    if (v->nusers >= VF_MAX_USERS) return VF_ERR_RANGE;

    user_t *nu = realloc(v->users, (v->nusers + 1) * sizeof(user_t));
    if (!nu) return VF_ERR_NOMEM;
    v->users = nu;
    user_t *u = &v->users[v->nusers];
    memset(u, 0, sizeof *u);
    snprintf(u->name, sizeof u->name, "%s", name);
    u->role = 0; u->N = SCRYPT_N; u->r = SCRYPT_R; u->p = SCRYPT_P;
    uint8_t priv[32], pub[32], ukek[32];
    int rc = VF_ERR_IO;
    if (vf_random(u->salt, VF_SALT_LEN) != 0) goto out;
    if (vf_x25519_keypair(priv, pub) != 0) goto out;
    memcpy(u->pub, pub, 32);
    if (vf_scrypt(password, strlen(password), u->salt, VF_SALT_LEN, u->N, u->r, u->p, ukek, 32) != 0) goto out;
    if (vf_random(u->priv_nonce, VF_NONCE_LEN) != 0) goto out;
    if (vf_aead_encrypt(ukek, u->priv_nonce, NULL, 0, priv, 32, u->priv_ct, u->priv_tag) != 0) goto out;
    uint8_t sealed[32 + VF_SEAL_OVERHEAD]; size_t sl;
    if (vf_seal(pub, v->vmk, 32, sealed, &sl) != 0) goto out;
    u->vmk_wrap = malloc(sl); if (!u->vmk_wrap) { rc = VF_ERR_NOMEM; goto out; }
    memcpy(u->vmk_wrap, sealed, sl); u->vmk_wrap_len = sl;
    v->nusers++;
    rc = commit_internal(v, 1);
out:
    vf_cleanse(priv, 32); vf_cleanse(ukek, 32);
    return rc;
}

int vault_deluser(vault_t *v, const char *name) {
    if (!v->unlocked) return VF_ERR_AUTH;
    if (!is_admin(v)) return VF_ERR_PERM;
    user_t *u = find_user(v, name);
    if (!u) return VF_ERR_NOENT;
    int idx = user_index(v, u);
    if ((uint32_t)idx == v->cur_user) return VF_ERR_INVAL;  /* can't remove self */
    /* count remaining admins */
    int admins = 0;
    for (size_t i = 0; i < v->nusers; i++) if (v->users[i].role == 1) admins++;
    if (u->role == 1 && admins <= 1) return VF_ERR_INVAL;

    free(u->vmk_wrap);
    memmove(&v->users[idx], &v->users[idx + 1], (v->nusers - idx - 1) * sizeof(user_t));
    v->nusers--;
    if (v->cur_user > (uint32_t)idx) v->cur_user--;

    /* rotate the VMK so the removed user (and anyone who copied old ciphertext)
     * cannot read anything written from now on. Re-wrap to remaining users and
     * re-encrypt the catalog (one object) under the new VMK -- not the volume. */
    uint8_t newvmk[32];
    if (vf_random(newvmk, 32) != 0) return VF_ERR_IO;
    for (size_t i = 0; i < v->nusers; i++) {
        uint8_t sealed[32 + VF_SEAL_OVERHEAD]; size_t sl;
        if (vf_seal(v->users[i].pub, newvmk, 32, sealed, &sl) != 0) { vf_cleanse(newvmk,32); return VF_ERR_IO; }
        uint8_t *w = malloc(sl); if (!w) { vf_cleanse(newvmk,32); return VF_ERR_NOMEM; }
        memcpy(w, sealed, sl);
        free(v->users[i].vmk_wrap);
        v->users[i].vmk_wrap = w; v->users[i].vmk_wrap_len = sl;
    }
    memcpy(v->vmk, newvmk, 32);
    vf_cleanse(newvmk, 32);
    return commit_internal(v, 1);
}

int vault_passwd(vault_t *v, const char *newpassword) {
    if (!v->have_priv) return VF_ERR_AUTH;
    user_t *u = &v->users[v->cur_user];
    uint8_t ukek[32];
    if (vf_random(u->salt, VF_SALT_LEN) != 0) return VF_ERR_IO;
    if (vf_scrypt(newpassword, strlen(newpassword), u->salt, VF_SALT_LEN, u->N, u->r, u->p, ukek, 32) != 0)
        return VF_ERR_IO;
    if (vf_random(u->priv_nonce, VF_NONCE_LEN) != 0) { vf_cleanse(ukek,32); return VF_ERR_IO; }
    int rc = vf_aead_encrypt(ukek, u->priv_nonce, NULL, 0, v->cur_priv, 32, u->priv_ct, u->priv_tag);
    vf_cleanse(ukek, 32);
    if (rc != 0) return VF_ERR_IO;
    return commit_internal(v, 1);
}

int vault_list_users(vault_t *v, char names[][64], int max) {
    int n = 0;
    for (size_t i = 0; i < v->nusers && n < max; i++)
        snprintf(names[n++], 64, "%s", v->users[i].name);
    return n;
}

/* ---------------- namespace ---------------- */
static void fill_stat(vault_t *v, inode_t *n, vf_stat *st) {
    snprintf(st->name, sizeof st->name, "%s", n->name);
    st->ino = n->ino; st->type = n->type; st->mode = n->mode;
    st->size = n->size; st->mtime = n->mtime;
    const char *on = (n->owner < v->nusers) ? v->users[n->owner].name : "?";
    snprintf(st->owner, sizeof st->owner, "%s", on);
}

int vault_getattr(vault_t *v, const char *path, vf_stat *st) {
    int err; inode_t *n = resolve(v, path, &err);
    if (!n) return err;
    fill_stat(v, n, st);
    return VF_OK;
}

int vault_mkdir(vault_t *v, const char *path, uint32_t mode) {
    if (!v->have_priv) return VF_ERR_AUTH;
    inode_t *parent; char leaf[VF_MAX_NAME + 1];
    int rc = split_parent(v, path, &parent, leaf);
    if (rc) return rc;
    if (find_child(v, parent->ino, leaf)) return VF_ERR_EXIST;
    uint64_t pino = parent->ino;
    inode_t *n = new_inode(v);
    if (!n) return VF_ERR_NOMEM;
    n->parent = pino; n->type = VF_T_DIR; n->mode = mode & 0777;
    n->owner = v->cur_user;
    snprintf(n->name, sizeof n->name, "%s", leaf);
    return maybe_commit(v);
}

int vault_rmdir(vault_t *v, const char *path) {
    if (!v->have_priv) return VF_ERR_AUTH;
    int err; inode_t *n = resolve(v, path, &err);
    if (!n) return err;
    if (n->ino == 1) return VF_ERR_PERM;
    if (n->type != VF_T_DIR) return VF_ERR_NOTDIR;
    for (size_t i = 0; i < v->ninodes; i++)
        if (v->inodes[i].parent == n->ino && v->inodes[i].ino != n->ino) return VF_ERR_NOTEMPTY;
    remove_inode(v, n);
    return maybe_commit(v);
}

int vault_create(vault_t *v, const char *path, uint32_t mode) {
    if (!v->have_priv) return VF_ERR_AUTH;
    inode_t *parent; char leaf[VF_MAX_NAME + 1];
    int rc = split_parent(v, path, &parent, leaf);
    if (rc) return rc;
    if (find_child(v, parent->ino, leaf)) return VF_ERR_EXIST;
    uint64_t pino = parent->ino;
    inode_t *n = new_inode(v);
    if (!n) return VF_ERR_NOMEM;
    n->parent = pino; n->type = VF_T_FILE; n->mode = mode & 0777;
    n->owner = v->cur_user; n->size = 0;
    snprintf(n->name, sizeof n->name, "%s", leaf);
    /* generate a fresh file key, wrapped to the owner only */
    uint8_t fk[32];
    if (vf_random(fk, 32) != 0) { remove_inode(v, n); return VF_ERR_IO; }
    rc = add_wrap(n, v->cur_user, v->users[v->cur_user].pub, fk);
    vf_cleanse(fk, 32);
    if (rc) { remove_inode(v, n); return rc; }
    return maybe_commit(v);
}

int vault_unlink(vault_t *v, const char *path) {
    if (!v->have_priv) return VF_ERR_AUTH;
    int err; inode_t *n = resolve(v, path, &err);
    if (!n) return err;
    if (n->type == VF_T_DIR) return VF_ERR_ISDIR;
    remove_inode(v, n);
    int rc = maybe_commit(v);
    return rc;
}

int vault_chmod(vault_t *v, const char *path, uint32_t mode) {
    if (!v->have_priv) return VF_ERR_AUTH;
    int err; inode_t *n = resolve(v, path, &err);
    if (!n) return err;
    n->mode = mode & 0777; n->mtime = now_sec();
    return maybe_commit(v);
}

static int is_ancestor(vault_t *v, uint64_t anc, uint64_t node) {
    uint64_t cur = node;
    for (int i = 0; i < 100000; i++) {
        if (cur == anc) return 1;
        inode_t *n = get_inode(v, cur);
        if (!n || cur == 1) return 0;
        cur = n->parent;
    }
    return 0;
}

int vault_rename(vault_t *v, const char *from, const char *to) {
    if (!v->have_priv) return VF_ERR_AUTH;
    int err; inode_t *src = resolve(v, from, &err);
    if (!src) return err;
    if (src->ino == 1) return VF_ERR_PERM;
    inode_t *dparent; char leaf[VF_MAX_NAME + 1];
    int rc = split_parent(v, to, &dparent, leaf);
    if (rc) return rc;
    if (src->type == VF_T_DIR && is_ancestor(v, src->ino, dparent->ino))
        return VF_ERR_INVAL;                         /* no cycles */
    inode_t *existing = find_child(v, dparent->ino, leaf);
    uint64_t sino = src->ino, dpino = dparent->ino;
    if (existing) {
        if (existing->type == VF_T_DIR) return VF_ERR_ISDIR;
        remove_inode(v, existing);
        src = get_inode(v, sino);                     /* array may have moved */
        dparent = get_inode(v, dpino);
    }
    src->parent = dpino;
    snprintf(src->name, sizeof src->name, "%s", leaf);
    src->mtime = now_sec();
    return maybe_commit(v);
}

int vault_readdir(vault_t *v, const char *path, vf_stat *entries, int max) {
    int err; inode_t *d = resolve(v, path, &err);
    if (!d) return err;
    if (d->type != VF_T_DIR) return VF_ERR_NOTDIR;
    int n = 0;
    for (size_t i = 0; i < v->ninodes && n < max; i++) {
        if (v->inodes[i].parent == d->ino && v->inodes[i].ino != 1
            && v->inodes[i].ino != d->ino)
            fill_stat(v, &v->inodes[i], &entries[n++]);
    }
    return n;
}

/* ---------------- file IO ---------------- */
static int grow_blocks(inode_t *n, size_t count) {
    if (count <= n->nblocks) return 0;
    block_t *nb = realloc(n->blocks, count * sizeof(block_t));
    if (!nb) return -1;
    n->blocks = nb;
    return 0;
}

int vault_read(vault_t *v, const char *path, uint64_t off, uint8_t *buf, size_t n) {
    int err; inode_t *in = resolve(v, path, &err);
    if (!in) return err;
    if (in->type != VF_T_FILE) return VF_ERR_ISDIR;
    uint8_t fk[32];
    int rc = file_key(v, in, fk);
    if (rc) return rc;
    if (off >= in->size) { vf_cleanse(fk, 32); return 0; }
    if (off + n > in->size) n = in->size - off;
    size_t done = 0;
    uint8_t pt[VF_BLOCK_SIZE];
    while (done < n) {
        uint64_t pos = off + done;
        uint32_t bi = (uint32_t)(pos / VF_BLOCK_SIZE);
        uint32_t bo = (uint32_t)(pos % VF_BLOCK_SIZE);
        size_t chunk = VF_BLOCK_SIZE - bo;
        if (chunk > n - done) chunk = n - done;
        memset(pt, 0, VF_BLOCK_SIZE);
        if (bi < in->nblocks) {
            rc = object_read(v, in->ino, bi, fk, &in->blocks[bi], pt);
            if (rc) { vf_cleanse(fk, 32); return rc; }
        }
        memcpy(buf + done, pt + bo, chunk);
        done += chunk;
    }
    vf_cleanse(fk, 32);
    vf_cleanse(pt, sizeof pt);
    return (int)done;
}

int vault_write(vault_t *v, const char *path, uint64_t off, const uint8_t *buf, size_t n) {
    if (!v->have_priv) return VF_ERR_AUTH;
    int err; inode_t *in = resolve(v, path, &err);
    if (!in) return err;
    if (in->type != VF_T_FILE) return VF_ERR_ISDIR;
    uint8_t fk[32];
    int rc = file_key(v, in, fk);
    if (rc) return rc;

    if (n == 0) { vf_cleanse(fk, 32); return 0; }
    uint64_t end = off + n;
    uint32_t last_blk = (uint32_t)((end - 1) / VF_BLOCK_SIZE);
    uint32_t start_blk = (uint32_t)(off / VF_BLOCK_SIZE);
    size_t needed = last_blk + 1;
    size_t old_nblocks = in->nblocks;
    size_t new_count = needed > old_nblocks ? needed : old_nblocks;  /* never shrink */
    if (grow_blocks(in, new_count)) { vf_cleanse(fk, 32); return VF_ERR_NOMEM; }
    for (size_t bi = old_nblocks; bi < new_count; bi++)
        memset(&in->blocks[bi], 0, sizeof(block_t));   /* plen 0 = empty slot */
    in->nblocks = new_count;

    uint8_t pt[VF_BLOCK_SIZE];
    /* zero-fill genuine hole blocks that lie entirely before the write region */
    for (size_t bi = old_nblocks; bi < start_blk; bi++) {
        memset(pt, 0, VF_BLOCK_SIZE);
        uint8_t id[16];
        rc = object_write(v, in->ino, (uint32_t)bi, fk, pt, VF_BLOCK_SIZE, id);
        if (rc) { vf_cleanse(fk, 32); return rc; }
        memcpy(in->blocks[bi].id, id, 16); in->blocks[bi].plen = VF_BLOCK_SIZE;
    }

    size_t done = 0;
    while (done < n) {
        uint64_t pos = off + done;
        uint32_t bi = (uint32_t)(pos / VF_BLOCK_SIZE);
        uint32_t bo = (uint32_t)(pos % VF_BLOCK_SIZE);
        size_t chunk = VF_BLOCK_SIZE - bo;
        if (chunk > n - done) chunk = n - done;
        memset(pt, 0, VF_BLOCK_SIZE);
        uint32_t cur_plen = 0;
        if (bi < old_nblocks) {                        /* pre-existing content */
            rc = object_read(v, in->ino, bi, fk, &in->blocks[bi], pt);
            if (rc) { vf_cleanse(fk, 32); return rc; }
            cur_plen = in->blocks[bi].plen;
        }
        memcpy(pt + bo, buf + done, chunk);
        uint32_t newplen = bo + (uint32_t)chunk;
        if (cur_plen > newplen) newplen = cur_plen;    /* keep tail of block */
        uint8_t id[16];
        rc = object_write(v, in->ino, bi, fk, pt, newplen, id);
        if (rc) { vf_cleanse(fk, 32); return rc; }
        memcpy(in->blocks[bi].id, id, 16); in->blocks[bi].plen = newplen;
        done += chunk;
    }
    if (end > in->size) in->size = end;
    in->mtime = now_sec();
    vf_cleanse(fk, 32);
    vf_cleanse(pt, sizeof pt);
    rc = maybe_commit(v);
    return rc ? rc : (int)n;
}

int vault_truncate(vault_t *v, const char *path, uint64_t size) {
    if (!v->have_priv) return VF_ERR_AUTH;
    int err; inode_t *in = resolve(v, path, &err);
    if (!in) return err;
    if (in->type != VF_T_FILE) return VF_ERR_ISDIR;
    uint8_t fk[32];
    int rc = file_key(v, in, fk);
    if (rc) return rc;
    size_t newnb = (size == 0) ? 0 : (size_t)((size - 1) / VF_BLOCK_SIZE + 1);
    if (size < in->size) {
        in->nblocks = newnb;
        if (newnb > 0) {
            uint32_t lastlen = (uint32_t)(size - (uint64_t)(newnb - 1) * VF_BLOCK_SIZE);
            uint8_t pt[VF_BLOCK_SIZE];
            uint32_t bi = (uint32_t)(newnb - 1);
            memset(pt, 0, VF_BLOCK_SIZE);
            rc = object_read(v, in->ino, bi, fk, &in->blocks[bi], pt);
            if (rc) { vf_cleanse(fk, 32); return rc; }
            uint8_t id[16];
            rc = object_write(v, in->ino, bi, fk, pt, lastlen, id);
            if (rc) { vf_cleanse(fk, 32); return rc; }
            memcpy(in->blocks[bi].id, id, 16); in->blocks[bi].plen = lastlen;
            vf_cleanse(pt, sizeof pt);
        }
        in->size = size;
    } else if (size > in->size) {
        vf_cleanse(fk, 32);
        /* extend by writing a zero at the new last byte */
        uint8_t z = 0;
        int w = vault_write(v, path, size - 1, &z, 1);
        return w < 0 ? w : VF_OK;
    }
    in->mtime = now_sec();
    vf_cleanse(fk, 32);
    return maybe_commit(v);
}

/* ---------------- sharing ---------------- */
static int require_owner(vault_t *v, inode_t *n) {
    if (n->owner == v->cur_user || is_admin(v)) return VF_OK;
    return VF_ERR_PERM;
}

int vault_share(vault_t *v, const char *path, const char *user) {
    if (!v->have_priv) return VF_ERR_AUTH;
    int err; inode_t *n = resolve(v, path, &err);
    if (!n) return err;
    if (n->type != VF_T_FILE) return VF_ERR_ISDIR;
    if ((err = require_owner(v, n))) return err;
    user_t *tu = find_user(v, user);
    if (!tu) return VF_ERR_NOENT;
    uint32_t tidx = (uint32_t)user_index(v, tu);
    for (size_t i = 0; i < n->nwraps; i++) if (n->wraps[i].user == tidx) return VF_OK;
    uint8_t fk[32];
    int rc = file_key(v, n, fk);
    if (rc) return rc;
    rc = add_wrap(n, tidx, tu->pub, fk);
    vf_cleanse(fk, 32);
    if (rc) return rc;
    return maybe_commit(v);
}

int vault_revoke(vault_t *v, const char *path, const char *user) {
    if (!v->have_priv) return VF_ERR_AUTH;
    int err; inode_t *n = resolve(v, path, &err);
    if (!n) return err;
    if (n->type != VF_T_FILE) return VF_ERR_ISDIR;
    if ((err = require_owner(v, n))) return err;
    user_t *tu = find_user(v, user);
    if (!tu) return VF_ERR_NOENT;
    uint32_t tidx = (uint32_t)user_index(v, tu);
    if (tidx == n->owner) return VF_ERR_INVAL;        /* can't revoke the owner */

    uint8_t oldfk[32], newfk[32];
    int rc = file_key(v, n, oldfk);
    if (rc) return rc;
    if (vf_random(newfk, 32) != 0) { vf_cleanse(oldfk,32); return VF_ERR_IO; }

    /* re-encrypt every block of THIS file under the new key (volume untouched) */
    uint8_t pt[VF_BLOCK_SIZE];
    for (size_t bi = 0; bi < n->nblocks; bi++) {
        memset(pt, 0, VF_BLOCK_SIZE);
        rc = object_read(v, n->ino, (uint32_t)bi, oldfk, &n->blocks[bi], pt);
        if (rc) { vf_cleanse(oldfk,32); vf_cleanse(newfk,32); return rc; }
        uint8_t id[16];
        uint32_t plen = n->blocks[bi].plen;
        rc = object_write(v, n->ino, (uint32_t)bi, newfk, pt, plen, id);
        if (rc) { vf_cleanse(oldfk,32); vf_cleanse(newfk,32); return rc; }
        memcpy(n->blocks[bi].id, id, 16);
    }
    vf_cleanse(pt, sizeof pt);
    vf_cleanse(oldfk, 32);

    /* rebuild the wrap list: everyone currently authorized except the revokee */
    fkwrap_t *old = n->wraps; size_t oldn = n->nwraps;
    n->wraps = NULL; n->nwraps = 0;
    for (size_t i = 0; i < oldn; i++) {
        if (old[i].user == tidx) continue;
        user_t *uu = &v->users[old[i].user];
        rc = add_wrap(n, old[i].user, uu->pub, newfk);
        if (rc) break;
    }
    for (size_t i = 0; i < oldn; i++) free(old[i].wrap);
    free(old);
    vf_cleanse(newfk, 32);
    if (rc) return rc;
    return maybe_commit(v);
}

int vault_list_access(vault_t *v, const char *path, char names[][64], int max) {
    int err; inode_t *n = resolve(v, path, &err);
    if (!n) return err;
    if (n->type != VF_T_FILE) return VF_ERR_ISDIR;
    int c = 0;
    for (size_t i = 0; i < n->nwraps && c < max; i++) {
        uint32_t ui = n->wraps[i].user;
        if (ui < v->nusers) snprintf(names[c++], 64, "%s", v->users[ui].name);
    }
    return c;
}

/* ---------------- durability / maintenance ---------------- */
int vault_commit(vault_t *v) { return commit_internal(v, 0); }

int vault_gc(vault_t *v, int *removed) {
    char objdir[2100]; path_join(objdir, sizeof objdir, v->backing, "objects");
    DIR *d = opendir(objdir);
    if (!d) return VF_ERR_IO;
    int rem = 0;
    struct dirent *de;
    char wanted[33];
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (strstr(de->d_name, ".tmp.")) continue;
        int referenced = 0;
        for (size_t i = 0; i < v->ninodes && !referenced; i++) {
            inode_t *n = &v->inodes[i];
            for (size_t b = 0; b < n->nblocks; b++) {
                tohex(n->blocks[b].id, 16, wanted);
                if (strcmp(wanted, de->d_name) == 0) { referenced = 1; break; }
            }
        }
        if (!referenced) {
            char op[4096]; snprintf(op, sizeof op, "%s/%s", objdir, de->d_name);
            if (unlink(op) == 0) rem++;
        }
    }
    closedir(d);
    if (removed) *removed = rem;
    return VF_OK;
}

int vault_path_of(vault_t *v, uint64_t ino, char *out, size_t cap) {
    if (ino == 1) { snprintf(out, cap, "/"); return VF_OK; }
    char parts[128][VF_MAX_NAME + 1];
    int np = 0; uint64_t cur = ino;
    while (cur != 1) {
        inode_t *n = get_inode(v, cur);
        if (!n) return VF_ERR_NOENT;
        if (np >= 128) return VF_ERR_RANGE;
        snprintf(parts[np++], VF_MAX_NAME + 1, "%s", n->name);
        cur = n->parent;
    }
    size_t pos = 0; out[0] = 0;
    for (int i = np - 1; i >= 0 && pos < cap; i--)
        pos += snprintf(out + pos, cap - pos, "/%s", parts[i]);
    return VF_OK;
}

int vault_getattr_ino(vault_t *v, uint64_t ino, vf_stat *st) {
    inode_t *n = get_inode(v, ino);
    if (!n) return VF_ERR_NOENT;
    fill_stat(v, n, st);
    return VF_OK;
}

int vault_readdir_ino(vault_t *v, uint64_t ino, vf_stat *entries, int max) {
    inode_t *d = get_inode(v, ino);
    if (!d) return VF_ERR_NOENT;
    if (d->type != VF_T_DIR) return VF_ERR_NOTDIR;
    int n = 0;
    for (size_t i = 0; i < v->ninodes && n < max; i++)
        if (v->inodes[i].parent == ino && v->inodes[i].ino != 1 && v->inodes[i].ino != ino)
            fill_stat(v, &v->inodes[i], &entries[n++]);
    return n;
}

int vault_fsck(vault_t *v) {
    for (size_t i = 0; i < v->ninodes; i++) {
        inode_t *n = &v->inodes[i];
        if (n->type != VF_T_FILE) continue;
        uint8_t fk[32];
        int have = (file_key(v, n, fk) == VF_OK);
        uint8_t pt[VF_BLOCK_SIZE];
        for (size_t b = 0; b < n->nblocks; b++) {
            char op[2200]; object_path(v, n->blocks[b].id, op, sizeof op);
            if (!vf_exists(op)) { if (have) vf_cleanse(fk,32); return VF_ERR_TAMPER; }
            if (have) {
                if (object_read(v, n->ino, (uint32_t)b, fk, &n->blocks[b], pt) != VF_OK) {
                    vf_cleanse(fk, 32); return VF_ERR_TAMPER;
                }
            }
        }
        if (have) vf_cleanse(fk, 32);
    }
    return VF_OK;
}
