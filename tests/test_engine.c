/* test_engine.c -- API-level tests for the VaultFS engine. */
#define _GNU_SOURCE
#include "../include/vaultfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define BACK "/tmp/vfs_test/back"
#define ANCH "/tmp/vfs_test/anchor"

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
                              else { printf("  ok: %s\n", msg); } } while (0)

static vault_t *unlock(const char *user, const char *pw) {
    vault_t *v;
    assert(vault_open(BACK, ANCH, &v) == VF_OK);
    int rc = vault_unlock(v, user, pw);
    if (rc != VF_OK) { vault_close(v); return NULL; }
    return v;
}

int main(void) {
    system("rm -rf /tmp/vfs_test && mkdir -p /tmp/vfs_test");

    printf("[format + auth]\n");
    assert(vault_format(BACK, "alice", "alicepw") == VF_OK);
    CHECK(unlock("alice", "wrongpw") == NULL, "wrong password refused");
    vault_t *v = unlock("alice", "alicepw");
    CHECK(v != NULL, "correct password unlocks");

    printf("[namespace + small file]\n");
    CHECK(vault_mkdir(v, "/docs", 0755) == VF_OK, "mkdir /docs");
    CHECK(vault_create(v, "/docs/a.txt", 0644) == VF_OK, "create file");
    const char *msg = "the quick brown fox";
    CHECK(vault_write(v, "/docs/a.txt", 0, (const uint8_t*)msg, strlen(msg)) == (int)strlen(msg), "write");
    uint8_t buf[64] = {0};
    int r = vault_read(v, "/docs/a.txt", 0, buf, sizeof buf);
    CHECK(r == (int)strlen(msg) && memcmp(buf, msg, r) == 0, "read back equals");

    printf("[multi-block file + partial IO]\n");
    size_t big = 10000;
    uint8_t *data = malloc(big), *out = malloc(big);
    for (size_t i = 0; i < big; i++) data[i] = (uint8_t)(i * 31 + 7);
    assert(vault_create(v, "/big.bin", 0644) == VF_OK);
    CHECK(vault_write(v, "/big.bin", 0, data, big) == (int)big, "write 10000 bytes (3 blocks)");
    CHECK(vault_read(v, "/big.bin", 0, out, big) == (int)big && memcmp(out, data, big) == 0, "full read equals");
    memset(out, 0, big);
    CHECK(vault_read(v, "/big.bin", 5000, out, 2000) == 2000 && memcmp(out, data+5000, 2000) == 0, "partial read at offset 5000");
    uint8_t patch[100]; for (int i=0;i<100;i++) patch[i]=0xEE;
    CHECK(vault_write(v, "/big.bin", 4090, patch, 100) == 100, "overwrite across block boundary");
    memcpy(data+4090, patch, 100);
    CHECK(vault_read(v, "/big.bin", 0, out, big) == (int)big && memcmp(out,data,big)==0, "read after overwrite equals");

    printf("[truncate]\n");
    CHECK(vault_truncate(v, "/big.bin", 100) == VF_OK, "truncate to 100");
    vf_stat st; vault_getattr(v, "/big.bin", &st);
    CHECK(st.size == 100, "size is 100");
    CHECK(vault_read(v, "/big.bin", 0, out, big) == 100, "read returns 100 bytes");
    CHECK(vault_truncate(v, "/big.bin", 9000) == VF_OK, "truncate grow to 9000");
    vault_getattr(v, "/big.bin", &st);
    CHECK(st.size == 9000, "size is 9000");
    memset(out,1,big); r = vault_read(v, "/big.bin", 200, out, 100);
    int allzero = 1; for (int i=0;i<r;i++) if (out[i]) allzero=0;
    CHECK(r==100 && allzero, "hole reads as zeros");

    printf("[rename + readdir]\n");
    CHECK(vault_rename(v, "/docs/a.txt", "/docs/b.txt") == VF_OK, "rename");
    vf_stat ents[16]; int n = vault_readdir(v, "/docs", ents, 16);
    int found = 0; for (int i=0;i<n;i++) if (!strcmp(ents[i].name,"b.txt")) found=1;
    CHECK(found, "readdir shows renamed file");
    CHECK(vault_getattr(v,"/docs/a.txt",&st)==VF_ERR_NOENT, "old name gone");

    printf("[fsck]\n");
    CHECK(vault_fsck(v) == VF_OK, "fsck clean");
    vault_close(v);

    printf("[multi-user: share and revoke]\n");
    v = unlock("alice", "alicepw");
    CHECK(vault_adduser(v, "bob", "bobpw") == VF_OK, "alice adds bob");
    assert(vault_create(v, "/secret.txt", 0600) == VF_OK);
    const char *s = "for bob's eyes";
    assert(vault_write(v, "/secret.txt", 0, (const uint8_t*)s, strlen(s)) == (int)strlen(s));
    CHECK(vault_share(v, "/secret.txt", "bob") == VF_OK, "alice shares with bob");
    vault_close(v);

    v = unlock("bob", "bobpw");
    CHECK(v != NULL, "bob unlocks with his own password");
    memset(buf,0,sizeof buf);
    r = vault_read(v, "/secret.txt", 0, buf, sizeof buf);
    CHECK(r == (int)strlen(s) && memcmp(buf,s,r)==0, "bob reads the shared file");
    vault_close(v);

    v = unlock("alice", "alicepw");
    CHECK(vault_revoke(v, "/secret.txt", "bob") == VF_OK, "alice revokes bob (rotates key)");
    vault_close(v);

    v = unlock("bob", "bobpw");
    r = vault_read(v, "/secret.txt", 0, buf, sizeof buf);
    CHECK(r == VF_ERR_PERM, "bob can no longer read the revoked file");
    vault_close(v);

    printf("[password change]\n");
    v = unlock("bob", "bobpw");
    CHECK(vault_passwd(v, "bobpw2") == VF_OK, "bob changes password");
    vault_close(v);
    CHECK(unlock("bob","bobpw")==NULL, "old password rejected");
    v = unlock("bob","bobpw2");
    CHECK(v != NULL, "new password works");
    vault_close(v);

    free(data); free(out);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL ENGINE TESTS PASSED", fails);
    return fails ? 1 : 0;
}
