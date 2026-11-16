/* cli.c -- VaultFS command-line tool.
 *
 * Auth: pass --user NAME; the password is read from $VAULTFS_PASSWORD if set,
 * otherwise prompted. The rollback anchor directory is --anchor DIR or
 * $VAULTFS_ANCHOR_DIR or $HOME/.config/vaultfs.
 */
#define _GNU_SOURCE
#include "../include/vaultfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int vaultfs_fuse_main(const char *backing, const char *anchor,
                      const char *user, const char *password,
                      const char *mountpoint, int foreground);

static const char *g_user = NULL;
static const char *g_anchor = NULL;

static const char *anchor_dir(void) {
    if (g_anchor) return g_anchor;
    const char *e = getenv("VAULTFS_ANCHOR_DIR");
    if (e) return e;
    static char buf[1024];
    const char *home = getenv("HOME");
    snprintf(buf, sizeof buf, "%s/.config/vaultfs", home ? home : "/tmp");
    return buf;
}

static const char *get_password(const char *prompt) {
    const char *e = getenv("VAULTFS_PASSWORD");
    if (e) return e;
    char *p = getpass(prompt);
    return p;
}
static const char *get_newpassword(const char *prompt) {
    const char *e = getenv("VAULTFS_NEWPASSWORD");
    if (e) return e;
    char *p = getpass(prompt);
    return p;
}

static int die(int code, const char *ctx) {
    fprintf(stderr, "vaultfs: %s: %s\n", ctx, vault_strerror(code));
    return 1;
}

static vault_t *open_unlock(const char *backing) {
    if (!g_user) { fprintf(stderr, "vaultfs: --user NAME required\n"); return NULL; }
    vault_t *v;
    int rc = vault_open(backing, anchor_dir(), &v);
    if (rc) { die(rc, "open"); return NULL; }
    rc = vault_unlock(v, g_user, get_password("Password: "));
    if (rc) { vault_close(v); die(rc, "unlock"); return NULL; }
    return v;
}

static int cmd_init(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: init <backing> <admin>\n"); return 1; }
    const char *pw = get_password("New admin password: ");
    int rc = vault_format(argv[0], argv[1], pw);
    if (rc) return die(rc, "init");
    printf("Initialized vault at %s (admin: %s)\n", argv[0], argv[1]);
    return 0;
}

static int put_file(vault_t *v, const char *vpath, const char *local) {
    FILE *f = strcmp(local, "-") ? fopen(local, "rb") : stdin;
    if (!f) { perror("open local"); return 1; }
    int rc = vault_create(v, vpath, 0644);
    if (rc == VF_ERR_EXIST) { rc = vault_truncate(v, vpath, 0); }
    if (rc) { if (f != stdin) fclose(f); return die(rc, "create"); }
    uint8_t buf[65536]; uint64_t off = 0; size_t r;
    while ((r = fread(buf, 1, sizeof buf, f)) > 0) {
        int w = vault_write(v, vpath, off, buf, r);
        if (w < 0) { if (f != stdin) fclose(f); return die(w, "write"); }
        off += r;
    }
    if (f != stdin) fclose(f);
    return 0;
}

static int get_file(vault_t *v, const char *vpath, const char *local) {
    vf_stat st;
    int rc = vault_getattr(v, vpath, &st);
    if (rc) return die(rc, "stat");
    FILE *f = (local && strcmp(local, "-")) ? fopen(local, "wb") : stdout;
    if (!f) { perror("open local"); return 1; }
    uint8_t buf[65536]; uint64_t off = 0;
    while (off < st.size) {
        size_t want = sizeof buf;
        if (want > st.size - off) want = st.size - off;
        int r = vault_read(v, vpath, off, buf, want);
        if (r < 0) { if (f != stdout) fclose(f); return die(r, "read"); }
        if (r == 0) break;
        fwrite(buf, 1, r, f);
        off += r;
    }
    if (f != stdout) fclose(f);
    return 0;
}

static void print_mode(uint32_t m, char t) {
    char s[11] = "----------";
    s[0] = t;
    const char *rwx = "rwxrwxrwx";
    for (int i = 0; i < 9; i++) if (m & (1 << (8 - i))) s[i + 1] = rwx[i];
    printf("%s", s);
}

int main(int argc, char **argv) {
    /* global flags */
    int i = 1;
    while (i < argc && strncmp(argv[i], "--", 2) == 0) {
        if (!strcmp(argv[i], "--user") && i + 1 < argc) { g_user = argv[++i]; }
        else if (!strcmp(argv[i], "--anchor") && i + 1 < argc) { g_anchor = argv[++i]; }
        else { fprintf(stderr, "unknown flag %s\n", argv[i]); return 1; }
        i++;
    }
    if (i >= argc) {
        fprintf(stderr,
            "usage: vaultfs [--user U] [--anchor DIR] CMD ...\n"
            "  init <backing> <admin>            create a volume\n"
            "  adduser <backing> <name>          add a user (admin)\n"
            "  deluser <backing> <name>          remove a user (admin)\n"
            "  passwd <backing>                  change your password\n"
            "  users <backing>                   list users\n"
            "  ls <backing> <path>               list a directory\n"
            "  mkdir <backing> <path>            make a directory\n"
            "  rmdir <backing> <path>            remove a directory\n"
            "  put <backing> <vpath> <local|->   write a file in\n"
            "  get <backing> <vpath> [local|-]   read a file out\n"
            "  rm <backing> <vpath>              remove a file\n"
            "  mv <backing> <from> <to>          rename\n"
            "  share <backing> <vpath> <user>    grant access\n"
            "  revoke <backing> <vpath> <user>   revoke access (rotates key)\n"
            "  access <backing> <vpath>          who can read this file\n"
            "  fsck <backing>                    verify integrity\n"
            "  gc <backing>                      drop unreferenced objects\n"
            "  mount <backing> <mountpoint>      mount as a folder (FUSE)\n");
        return 1;
    }
    const char *cmd = argv[i++];
    char **a = &argv[i];
    int na = argc - i;

    if (!strcmp(cmd, "init")) return cmd_init(na, a);

    if (!strcmp(cmd, "mount")) {
        if (na < 2) { fprintf(stderr, "usage: mount <backing> <mountpoint>\n"); return 1; }
        if (!g_user) { fprintf(stderr, "--user required\n"); return 1; }
        return vaultfs_fuse_main(a[0], anchor_dir(), g_user,
                                 get_password("Password: "), a[1], 1);
    }

    if (na < 1) { fprintf(stderr, "missing <backing>\n"); return 1; }
    const char *backing = a[0];

    if (!strcmp(cmd, "adduser")) {
        if (na < 2) { fprintf(stderr, "usage: adduser <backing> <name>\n"); return 1; }
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_adduser(v, a[1], get_newpassword("New user password: "));
        vault_close(v);
        if (rc) return die(rc, "adduser");
        printf("added user %s\n", a[1]); return 0;
    }
    if (!strcmp(cmd, "deluser")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_deluser(v, a[1]); vault_close(v);
        return rc ? die(rc, "deluser") : (printf("removed %s\n", a[1]), 0);
    }
    if (!strcmp(cmd, "passwd")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_passwd(v, get_newpassword("New password: ")); vault_close(v);
        return rc ? die(rc, "passwd") : (printf("password changed\n"), 0);
    }
    if (!strcmp(cmd, "users")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        char names[VF_MAX_USERS][64];
        int n = vault_list_users(v, names, VF_MAX_USERS); vault_close(v);
        for (int k = 0; k < n; k++) printf("%s\n", names[k]);
        return 0;
    }
    if (!strcmp(cmd, "ls")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        const char *path = na >= 2 ? a[1] : "/";
        vf_stat ents[4096];
        int n = vault_readdir(v, path, ents, 4096);
        if (n < 0) { vault_close(v); return die(n, "ls"); }
        for (int k = 0; k < n; k++) {
            print_mode(ents[k].mode, ents[k].type == VF_T_DIR ? 'd' : '-');
            printf(" %-8s %10llu  %s\n", ents[k].owner,
                   (unsigned long long)ents[k].size, ents[k].name);
        }
        vault_close(v); return 0;
    }
    if (!strcmp(cmd, "mkdir")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_mkdir(v, a[1], 0755); vault_close(v);
        return rc ? die(rc, "mkdir") : 0;
    }
    if (!strcmp(cmd, "rmdir")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_rmdir(v, a[1]); vault_close(v);
        return rc ? die(rc, "rmdir") : 0;
    }
    if (!strcmp(cmd, "put")) {
        if (na < 3) { fprintf(stderr, "usage: put <backing> <vpath> <local|->\n"); return 1; }
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = put_file(v, a[1], a[2]); vault_close(v); return rc;
    }
    if (!strcmp(cmd, "get")) {
        if (na < 2) { fprintf(stderr, "usage: get <backing> <vpath> [local|-]\n"); return 1; }
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = get_file(v, a[1], na >= 3 ? a[2] : "-"); vault_close(v); return rc;
    }
    if (!strcmp(cmd, "rm")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_unlink(v, a[1]); vault_close(v);
        return rc ? die(rc, "rm") : 0;
    }
    if (!strcmp(cmd, "mv")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_rename(v, a[1], a[2]); vault_close(v);
        return rc ? die(rc, "mv") : 0;
    }
    if (!strcmp(cmd, "share")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_share(v, a[1], a[2]); vault_close(v);
        return rc ? die(rc, "share") : (printf("shared %s with %s\n", a[1], a[2]), 0);
    }
    if (!strcmp(cmd, "revoke")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_revoke(v, a[1], a[2]); vault_close(v);
        return rc ? die(rc, "revoke") : (printf("revoked %s from %s\n", a[2], a[1]), 0);
    }
    if (!strcmp(cmd, "access")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        char names[VF_MAX_USERS][64];
        int n = vault_list_access(v, a[1], names, VF_MAX_USERS); vault_close(v);
        if (n < 0) return die(n, "access");
        for (int k = 0; k < n; k++) printf("%s\n", names[k]);
        return 0;
    }
    if (!strcmp(cmd, "fsck")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int rc = vault_fsck(v); vault_close(v);
        if (rc) return die(rc, "fsck");
        printf("fsck: all objects authenticate\n"); return 0;
    }
    if (!strcmp(cmd, "gc")) {
        vault_t *v = open_unlock(backing); if (!v) return 1;
        int removed = 0; int rc = vault_gc(v, &removed); vault_close(v);
        if (rc) return die(rc, "gc");
        printf("gc: removed %d unreferenced objects\n", removed); return 0;
    }
    fprintf(stderr, "unknown command: %s\n", cmd);
    return 1;
}
