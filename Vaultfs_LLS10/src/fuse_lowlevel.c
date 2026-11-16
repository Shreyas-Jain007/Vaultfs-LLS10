/* fuse_lowlevel.c -- VaultFS mount layer, written directly against the raw
 * /dev/fuse kernel protocol (no libfuse).  It translates kernel VFS requests
 * into engine calls so that ordinary tools (cat, ls, cp, vim, git) operate on
 * the decrypted view while everything stored stays encrypted.
 *
 * nodeid == engine inode number (root = 1), so no separate node table is
 * needed.  The mount is obtained portably via the setuid helper fusermount3
 * (which passes back the /dev/fuse fd over a socket); if that is unavailable we
 * fall back to a direct mount(2) (works when running as root).
 */
#define _GNU_SOURCE
#include "../include/vaultfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/fuse.h>

static int g_fd = -1;
static vault_t *g_v;
static uid_t g_uid;
static gid_t g_gid;
static char g_mountpoint[1024];

/* ---- error mapping ---- */
static int to_errno(int rc) {
    switch (rc) {
    case VF_OK: return 0;
    case VF_ERR_NOENT: return -ENOENT;
    case VF_ERR_PERM: return -EACCES;
    case VF_ERR_EXIST: return -EEXIST;
    case VF_ERR_NOTDIR: return -ENOTDIR;
    case VF_ERR_ISDIR: return -EISDIR;
    case VF_ERR_NOTEMPTY: return -ENOTEMPTY;
    case VF_ERR_INVAL: return -EINVAL;
    case VF_ERR_RANGE: return -EFBIG;
    case VF_ERR_NOMEM: return -ENOMEM;
    default: return -EIO;   /* tamper, rollback, io, format */
    }
}

/* ---- reply helpers ---- */
static void send_out(uint64_t unique, int error, const void *data, size_t len) {
    struct fuse_out_header h;
    h.len = sizeof(h) + (error ? 0 : len);
    h.error = error;
    h.unique = unique;
    struct iovec iov[2] = { { &h, sizeof h }, { (void *)data, error ? 0 : len } };
    ssize_t rc = writev(g_fd, iov, 2);
    (void)rc;
}
static void send_err(uint64_t unique, int neg_errno) { send_out(unique, neg_errno, NULL, 0); }

/* ---- attribute filling ---- */
static void fill_attr(struct fuse_attr *a, const vf_stat *st) {
    memset(a, 0, sizeof *a);
    a->ino = st->ino;
    a->size = st->size;
    a->blocks = (st->size + 511) / 512;
    a->atime = a->mtime = a->ctime = st->mtime;
    a->mode = (st->type == VF_T_DIR ? (S_IFDIR | (st->mode & 0777))
                                    : (S_IFREG | (st->mode & 0777)));
    a->nlink = st->type == VF_T_DIR ? 2 : 1;
    a->uid = g_uid; a->gid = g_gid;
    a->blksize = VF_BLOCK_SIZE;
}
static void entry_from_stat(struct fuse_entry_out *e, const vf_stat *st) {
    memset(e, 0, sizeof *e);
    e->nodeid = st->ino;
    e->generation = 1;
    e->entry_valid = 1; e->attr_valid = 1;
    fill_attr(&e->attr, st);
}

/* ---- path reconstruction ---- */
static int node_path(uint64_t nodeid, char *out, size_t cap) {
    return vault_path_of(g_v, nodeid, out, cap);
}
/* child path = parent path + "/" + name (avoids a leading "//") */
static int child_path(uint64_t parent, const char *name, char *out, size_t cap) {
    char pp[1024];
    int rc = node_path(parent, pp, sizeof pp);
    if (rc) return rc;
    if (strcmp(pp, "/") == 0) snprintf(out, cap, "/%s", name);
    else snprintf(out, cap, "%s/%s", pp, name);
    return VF_OK;
}

/* ================= opcode handlers ================= */
static void do_lookup(struct fuse_in_header *h, const char *name) {
    char path[1152];
    if (child_path(h->nodeid, name, path, sizeof path)) { send_err(h->unique, -ENOENT); return; }
    vf_stat st;
    int rc = vault_getattr(g_v, path, &st);
    if (rc) { send_err(h->unique, to_errno(rc)); return; }
    struct fuse_entry_out e; entry_from_stat(&e, &st);
    send_out(h->unique, 0, &e, sizeof e);
}

static void do_getattr(struct fuse_in_header *h) {
    vf_stat st;
    int rc = vault_getattr_ino(g_v, h->nodeid, &st);
    if (rc) { send_err(h->unique, to_errno(rc)); return; }
    struct fuse_attr_out o; memset(&o, 0, sizeof o);
    o.attr_valid = 1; fill_attr(&o.attr, &st);
    send_out(h->unique, 0, &o, sizeof o);
}

static void do_setattr(struct fuse_in_header *h, struct fuse_setattr_in *in) {
    char path[1024];
    if (node_path(h->nodeid, path, sizeof path)) { send_err(h->unique, -ENOENT); return; }
    if (in->valid & FATTR_SIZE) {
        int rc = vault_truncate(g_v, path, in->size);
        if (rc) { send_err(h->unique, to_errno(rc)); return; }
    }
    if (in->valid & FATTR_MODE) {
        int rc = vault_chmod(g_v, path, in->mode & 0777);
        if (rc) { send_err(h->unique, to_errno(rc)); return; }
    }
    vf_stat st;
    int rc = vault_getattr_ino(g_v, h->nodeid, &st);
    if (rc) { send_err(h->unique, to_errno(rc)); return; }
    struct fuse_attr_out o; memset(&o, 0, sizeof o);
    o.attr_valid = 1; fill_attr(&o.attr, &st);
    send_out(h->unique, 0, &o, sizeof o);
}

static void do_open(struct fuse_in_header *h) {
    /* access is enforced by the engine on read/write; just return a handle */
    struct fuse_open_out o; memset(&o, 0, sizeof o);
    send_out(h->unique, 0, &o, sizeof o);
}

static void do_create(struct fuse_in_header *h, struct fuse_create_in *in, const char *name) {
    char path[1152];
    if (child_path(h->nodeid, name, path, sizeof path)) { send_err(h->unique, -ENOENT); return; }
    int rc = vault_create(g_v, path, in->mode & 0777);
    if (rc && rc != VF_ERR_EXIST) { send_err(h->unique, to_errno(rc)); return; }
    vf_stat st;
    rc = vault_getattr(g_v, path, &st);
    if (rc) { send_err(h->unique, to_errno(rc)); return; }
    struct { struct fuse_entry_out e; struct fuse_open_out o; } reply;
    memset(&reply, 0, sizeof reply);
    entry_from_stat(&reply.e, &st);
    send_out(h->unique, 0, &reply, sizeof reply);
}

static void do_mkdir(struct fuse_in_header *h, struct fuse_mkdir_in *in, const char *name) {
    char path[1152];
    if (child_path(h->nodeid, name, path, sizeof path)) { send_err(h->unique, -ENOENT); return; }
    int rc = vault_mkdir(g_v, path, in->mode & 0777);
    if (rc) { send_err(h->unique, to_errno(rc)); return; }
    vf_stat st; vault_getattr(g_v, path, &st);
    struct fuse_entry_out e; entry_from_stat(&e, &st);
    send_out(h->unique, 0, &e, sizeof e);
}

static void do_unlink_rmdir(struct fuse_in_header *h, const char *name, int isdir) {
    char path[1152];
    if (child_path(h->nodeid, name, path, sizeof path)) { send_err(h->unique, -ENOENT); return; }
    int rc = isdir ? vault_rmdir(g_v, path) : vault_unlink(g_v, path);
    send_err(h->unique, to_errno(rc));
}

static void do_rename(struct fuse_in_header *h, uint64_t newdir,
                      const char *oldname, const char *newname) {
    char from[1152], to[1152];
    if (child_path(h->nodeid, oldname, from, sizeof from)
        || child_path(newdir, newname, to, sizeof to)) { send_err(h->unique, -ENOENT); return; }
    int rc = vault_rename(g_v, from, to);
    send_err(h->unique, to_errno(rc));
}

static void do_read(struct fuse_in_header *h, struct fuse_read_in *in) {
    char path[1024];
    if (node_path(h->nodeid, path, sizeof path)) { send_err(h->unique, -ENOENT); return; }
    uint32_t size = in->size;
    if (size > 1u << 20) size = 1u << 20;
    uint8_t *buf = malloc(size ? size : 1);
    if (!buf) { send_err(h->unique, -ENOMEM); return; }
    int r = vault_read(g_v, path, in->offset, buf, size);
    if (r < 0) { free(buf); send_err(h->unique, to_errno(r)); return; }
    send_out(h->unique, 0, buf, (size_t)r);
    free(buf);
}

static void do_write(struct fuse_in_header *h, struct fuse_write_in *in, const uint8_t *data) {
    char path[1024];
    if (node_path(h->nodeid, path, sizeof path)) { send_err(h->unique, -ENOENT); return; }
    int w = vault_write(g_v, path, in->offset, data, in->size);
    if (w < 0) { send_err(h->unique, to_errno(w)); return; }
    struct fuse_write_out o; memset(&o, 0, sizeof o); o.size = (uint32_t)w;
    send_out(h->unique, 0, &o, sizeof o);
}

static void do_readdir(struct fuse_in_header *h, struct fuse_read_in *in) {
    vf_stat ents[4096];
    int n = vault_readdir_ino(g_v, h->nodeid, ents, 4096);
    if (n < 0) { send_err(h->unique, to_errno(n)); return; }

    /* synthetic "." and ".." precede the children */
    vf_stat self_st, dotdot;
    vault_getattr_ino(g_v, h->nodeid, &self_st);

    size_t cap = in->size; if (cap > 1u << 20) cap = 1u << 20;
    uint8_t *buf = calloc(1, cap ? cap : 1);
    if (!buf) { send_err(h->unique, -ENOMEM); return; }
    size_t used = 0;
    uint64_t idx = 0;

    /* build a combined list: index 0 = ".", 1 = "..", 2.. = children */
    for (int i = -2; i < n; i++) {
        idx++;
        if (idx <= in->offset) continue;   /* resume point */
        const char *nm; uint64_t ino; uint8_t dtype;
        if (i == -2) { nm = "."; ino = h->nodeid; dtype = 4; }
        else if (i == -1) { nm = ".."; ino = (h->nodeid == 1 ? 1 : 1); dtype = 4; }
        else { nm = ents[i].name; ino = ents[i].ino; dtype = ents[i].type == VF_T_DIR ? 4 : 8; }
        size_t namelen = strlen(nm);
        size_t entlen = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
        if (used + entlen > cap) break;
        struct fuse_dirent *de = (struct fuse_dirent *)(buf + used);
        de->ino = ino;
        de->off = idx;             /* opaque resume cookie */
        de->namelen = namelen;
        de->type = dtype;
        memcpy((char *)de + FUSE_NAME_OFFSET, nm, namelen);
        used += entlen;
    }
    (void)dotdot;
    send_out(h->unique, 0, buf, used);
    free(buf);
}

static void do_statfs(struct fuse_in_header *h) {
    struct fuse_statfs_out o; memset(&o, 0, sizeof o);
    o.st.blocks = 1u << 30; o.st.bfree = o.st.bavail = 1u << 29;
    o.st.files = 1u << 20; o.st.ffree = 1u << 19;
    o.st.bsize = VF_BLOCK_SIZE; o.st.namelen = VF_MAX_NAME; o.st.frsize = VF_BLOCK_SIZE;
    send_out(h->unique, 0, &o, sizeof o);
}

static void do_init(struct fuse_in_header *h, struct fuse_init_in *in) {
    struct fuse_init_out o; memset(&o, 0, sizeof o);
    o.major = FUSE_KERNEL_VERSION;
    o.minor = FUSE_KERNEL_MINOR_VERSION;
    o.max_readahead = in->max_readahead;
    o.max_write = 1u << 17;         /* 128 KiB */
    o.max_background = 16;
    o.congestion_threshold = 12;
    o.time_gran = 1;
    send_out(h->unique, 0, &o, sizeof o);
}

/* ================= dispatch loop ================= */
static int fuse_loop(void) {
    size_t bufsz = (1u << 17) + 4096;
    uint8_t *buf = malloc(bufsz);
    if (!buf) return -1;
    for (;;) {
        ssize_t n = read(g_fd, buf, bufsz);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == ENODEV) break;    /* unmounted */
            break;
        }
        if ((size_t)n < sizeof(struct fuse_in_header)) continue;
        struct fuse_in_header *h = (struct fuse_in_header *)buf;
        void *body = buf + sizeof(*h);
        switch (h->opcode) {
        case FUSE_INIT:    do_init(h, body); break;
        case FUSE_GETATTR: do_getattr(h); break;
        case FUSE_SETATTR: do_setattr(h, body); break;
        case FUSE_LOOKUP:  do_lookup(h, (char *)body); break;
        case FUSE_OPEN:
        case FUSE_OPENDIR: do_open(h); break;
        case FUSE_CREATE:  do_create(h, body, (char *)body + sizeof(struct fuse_create_in)); break;
        case FUSE_MKDIR:   do_mkdir(h, body, (char *)body + sizeof(struct fuse_mkdir_in)); break;
        case FUSE_UNLINK:  do_unlink_rmdir(h, (char *)body, 0); break;
        case FUSE_RMDIR:   do_unlink_rmdir(h, (char *)body, 1); break;
        case FUSE_RENAME: {
            struct fuse_rename_in *ri = body;
            char *on = (char *)body + sizeof(*ri);
            char *nn = on + strlen(on) + 1;
            do_rename(h, ri->newdir, on, nn);
            break;
        }
        case FUSE_RENAME2: {
            struct fuse_rename2_in *ri = body;
            char *on = (char *)body + sizeof(*ri);
            char *nn = on + strlen(on) + 1;
            do_rename(h, ri->newdir, on, nn);
            break;
        }
        case FUSE_READ:    do_read(h, body); break;
        case FUSE_WRITE:   do_write(h, body, (uint8_t *)body + sizeof(struct fuse_write_in)); break;
        case FUSE_READDIR: do_readdir(h, body); break;
        case FUSE_STATFS:  do_statfs(h); break;
        case FUSE_ACCESS:  send_err(h->unique, 0); break;
        case FUSE_FLUSH:
        case FUSE_FSYNC:
        case FUSE_FSYNCDIR:
        case FUSE_RELEASE:
        case FUSE_RELEASEDIR: send_err(h->unique, 0); break;
        case FUSE_FORGET:  break;                    /* no reply */
        case FUSE_BATCH_FORGET: break;               /* no reply */
        case FUSE_GETXATTR: send_err(h->unique, -ENODATA); break;
        case FUSE_LISTXATTR: {
            struct fuse_getxattr_in *gi = body;
            struct fuse_getxattr_out go; memset(&go, 0, sizeof go);
            if (gi->size == 0) send_out(h->unique, 0, &go, sizeof go);  /* length query: 0 */
            else send_out(h->unique, 0, "", 0);                         /* empty list */
            break;
        }
        case FUSE_SETXATTR:
        case FUSE_REMOVEXATTR: send_err(h->unique, -ENOSYS); break;
        default:           send_err(h->unique, -ENOSYS); break;
        }
    }
    free(buf);
    return 0;
}

/* ================= mount / unmount ================= */
static int recv_fd(int sock) {
    struct msghdr msg; memset(&msg, 0, sizeof msg);
    char c = 0; struct iovec io = { &c, 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf; msg.msg_controllen = sizeof cmsgbuf;
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    if (!cm || cm->cmsg_type != SCM_RIGHTS) return -1;
    int fd; memcpy(&fd, CMSG_DATA(cm), sizeof fd);
    return fd;
}

/* Obtain /dev/fuse via the setuid helper fusermount3 (portable, non-root). */
static int mount_via_helper(const char *mountpoint) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        close(sv[0]);
        char envfd[32]; snprintf(envfd, sizeof envfd, "%d", sv[1]);
        setenv("_FUSE_COMMFD", envfd, 1);
        char opts[256];
        snprintf(opts, sizeof opts,
                 "rootmode=40000,user_id=%u,group_id=%u,default_permissions",
                 (unsigned)g_uid, (unsigned)g_gid);
        execlp("fusermount3", "fusermount3", "-o", opts, "--", mountpoint, (char *)NULL);
        execlp("fusermount", "fusermount", "-o", opts, "--", mountpoint, (char *)NULL);
        _exit(127);
    }
    close(sv[1]);
    int fd = recv_fd(sv[0]);
    close(sv[0]);
    int status; waitpid(pid, &status, 0);
    return fd;
}

/* Fallback: direct mount(2) (requires CAP_SYS_ADMIN / root). */
static int mount_direct(const char *mountpoint) {
    int fd = open("/dev/fuse", O_RDWR);
    if (fd < 0) return -1;
    char opts[256];
    snprintf(opts, sizeof opts,
             "fd=%d,rootmode=40000,user_id=%u,group_id=%u,default_permissions",
             fd, (unsigned)g_uid, (unsigned)g_gid);
    if (mount("vaultfs", mountpoint, "fuse.vaultfs", MS_NOSUID | MS_NODEV, opts) != 0) {
        close(fd); return -1;
    }
    return fd;
}

static void do_unmount(void) {
    if (g_mountpoint[0] == 0) return;
    /* best effort: helper first, then umount2 */
    pid_t pid = fork();
    if (pid == 0) {
        execlp("fusermount3", "fusermount3", "-u", "-z", "--", g_mountpoint, (char *)NULL);
        execlp("fusermount", "fusermount", "-u", "-z", "--", g_mountpoint, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int st; waitpid(pid, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) umount2(g_mountpoint, MNT_DETACH);
    }
}

static void on_signal(int sig) { (void)sig; do_unmount(); _exit(0); }

int vaultfs_fuse_main(const char *backing, const char *anchor, const char *user,
                      const char *password, const char *mountpoint, int foreground) {
    (void)foreground;
    int rc = vault_open(backing, anchor, &g_v);
    if (rc) { fprintf(stderr, "vaultfs: open: %s\n", vault_strerror(rc)); return 1; }
    rc = vault_unlock(g_v, user, password);
    if (rc) { fprintf(stderr, "vaultfs: unlock: %s\n", vault_strerror(rc)); vault_close(g_v); return 1; }

    g_uid = getuid(); g_gid = getgid();
    snprintf(g_mountpoint, sizeof g_mountpoint, "%s", mountpoint);

    g_fd = mount_via_helper(mountpoint);
    if (g_fd < 0) g_fd = mount_direct(mountpoint);
    if (g_fd < 0) {
        fprintf(stderr, "vaultfs: mount failed: %s\n", strerror(errno));
        vault_close(g_v); return 1;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    fprintf(stderr, "vaultfs: mounted %s at %s as %s (Ctrl-C to unmount)\n",
            backing, mountpoint, user);

    fuse_loop();
    do_unmount();
    vault_close(g_v);
    return 0;
}
