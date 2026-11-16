/* vaultfs.h -- VaultFS engine public API.
 *
 * The engine implements an encrypted, authenticated, rollback-resistant,
 * multi-user object store with per-file sharing.  It is independent of FUSE:
 * the CLI and the FUSE layer are both thin clients of this API, which is what
 * lets the whole security core be tested without mounting.
 *
 * Threat model: the attacker controls every byte of the backing directory and
 * may keep and restore old copies of it, but has neither the user's password
 * nor access to the running process.  See DESIGN.md.
 */
#ifndef VAULTFS_H
#define VAULTFS_H

#include <stddef.h>
#include <stdint.h>

#define VF_BLOCK_SIZE   4096
#define VF_MAX_NAME     255
#define VF_MAX_USERS    256

/* error codes (0 = success, negative = failure) */
enum {
    VF_OK        =  0,
    VF_ERR_IO    = -1,   /* backing store IO error */
    VF_ERR_AUTH  = -2,   /* wrong password / cannot unlock */
    VF_ERR_ROLLBACK = -3,/* stored data is older than last seen (replay) */
    VF_ERR_TAMPER = -4,  /* authentication failed: data was altered */
    VF_ERR_PERM  = -5,   /* caller not permitted (not owner / not shared) */
    VF_ERR_NOENT = -6,
    VF_ERR_EXIST = -7,
    VF_ERR_NOTDIR = -8,
    VF_ERR_ISDIR = -9,
    VF_ERR_NOTEMPTY = -10,
    VF_ERR_INVAL = -11,
    VF_ERR_RANGE = -12,
    VF_ERR_NOMEM = -13,
    VF_ERR_FORMAT = -14, /* not a vault / bad format */
};

typedef struct vault vault_t;

/* directory entry type */
enum { VF_T_DIR = 1, VF_T_FILE = 2 };

typedef struct {
    char     name[VF_MAX_NAME + 1];
    uint64_t ino;
    uint8_t  type;
    uint32_t mode;
    uint64_t size;
    uint64_t mtime;
    char     owner[64];
} vf_stat;

/* ---- lifecycle ---- */
int  vault_format(const char *backing, const char *admin, const char *password);
int  vault_open(const char *backing, const char *anchor_dir, vault_t **out);
int  vault_unlock(vault_t *v, const char *user, const char *password);
void vault_close(vault_t *v);
const char *vault_strerror(int code);

/* ---- user management (admin only, except passwd_self) ---- */
int  vault_adduser(vault_t *v, const char *name, const char *password);
int  vault_deluser(vault_t *v, const char *name);
int  vault_passwd(vault_t *v, const char *newpassword);   /* change current user's pw */
int  vault_list_users(vault_t *v, char names[][64], int max);

/* ---- namespace ---- */
int  vault_getattr(vault_t *v, const char *path, vf_stat *st);
int  vault_mkdir(vault_t *v, const char *path, uint32_t mode);
int  vault_rmdir(vault_t *v, const char *path);
int  vault_create(vault_t *v, const char *path, uint32_t mode);
int  vault_unlink(vault_t *v, const char *path);
int  vault_rename(vault_t *v, const char *from, const char *to);
int  vault_truncate(vault_t *v, const char *path, uint64_t size);
int  vault_chmod(vault_t *v, const char *path, uint32_t mode);
/* readdir: fills entries, returns count or negative error. */
int  vault_readdir(vault_t *v, const char *path, vf_stat *entries, int max);

/* ---- file IO (content is encrypted per 4 KiB block) ---- */
int  vault_read(vault_t *v, const char *path, uint64_t off, uint8_t *buf, size_t n);
int  vault_write(vault_t *v, const char *path, uint64_t off, const uint8_t *buf, size_t n);

/* ---- sharing ---- */
int  vault_share(vault_t *v, const char *path, const char *user);
int  vault_revoke(vault_t *v, const char *path, const char *user);
/* list users who can access a file; returns count. */
int  vault_list_access(vault_t *v, const char *path, char names[][64], int max);

/* ---- durability ---- */
/* Persist all pending changes as one atomic, versioned commit and advance the
 * rollback anchor.  Most mutators auto-commit; call this after a batch. */
int  vault_commit(vault_t *v);

/* ---- maintenance ---- */
/* Garbage-collect backing objects no longer referenced by the catalog. */
int  vault_gc(vault_t *v, int *removed);
/* Verify every referenced object authenticates; returns VF_OK or VF_ERR_TAMPER. */
int  vault_fsck(vault_t *v);

/* current user's name (after unlock) */
const char *vault_current_user(vault_t *v);

/* ---- helpers for the FUSE layer (nodeid == engine inode number) ---- */
/* Reconstruct the absolute path of an inode. Root inode number is 1. */
int vault_path_of(vault_t *v, uint64_t ino, char *out, size_t cap);
/* getattr by inode number (fills st). */
int vault_getattr_ino(vault_t *v, uint64_t ino, vf_stat *st);
/* readdir by inode number. */
int vault_readdir_ino(vault_t *v, uint64_t ino, vf_stat *entries, int max);

#endif
