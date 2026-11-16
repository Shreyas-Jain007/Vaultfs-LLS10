#include "crypto.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

int vf_random(void *buf, size_t n) {
    return RAND_bytes((unsigned char *)buf, (int)n) == 1 ? 0 : -1;
}

void vf_cleanse(void *buf, size_t n) { OPENSSL_cleanse(buf, n); }

int vf_ct_eq(const void *a, const void *b, size_t n) {
    return CRYPTO_memcmp(a, b, n) == 0 ? 1 : 0;
}

void vf_sha256(const uint8_t *data, size_t n, uint8_t out[32]) {
    SHA256(data, n, out);
}

int vf_scrypt(const char *pw, size_t pwlen,
              const uint8_t *salt, size_t saltlen,
              uint64_t N, uint32_t r, uint32_t p,
              uint8_t *out, size_t outlen) {
    int rc = -1;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    if (!kdf) return -1;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return -1;
    uint64_t n = N, rr = r, pp = p;
    /* scrypt needs a generous memory limit; set it high enough for our params. */
    uint64_t maxmem = 1024ULL * 1024 * 1024;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pw, pwlen),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, saltlen),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_SCRYPT_R, &rr),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_SCRYPT_P, &pp),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem),
        OSSL_PARAM_END
    };
    if (EVP_KDF_derive(ctx, out, outlen, params) == 1) rc = 0;
    EVP_KDF_CTX_free(ctx);
    return rc;
}

int vf_hkdf(const uint8_t *ikm, size_t ikmlen,
            const uint8_t *salt, size_t saltlen,
            const char *info, size_t infolen,
            uint8_t *out, size_t outlen) {
    int rc = -1;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return -1;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return -1;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikmlen),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, saltlen),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, infolen),
        OSSL_PARAM_END
    };
    if (EVP_KDF_derive(ctx, out, outlen, params) == 1) rc = 0;
    EVP_KDF_CTX_free(ctx);
    return rc;
}

int vf_aead_encrypt(const uint8_t key[VF_KEY_LEN], const uint8_t nonce[VF_NONCE_LEN],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *pt, size_t ptlen,
                    uint8_t *ct, uint8_t tag[VF_TAG_LEN]) {
    int rc = -1, len = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, VF_NONCE_LEN, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) != 1) goto out;
    if (aadlen && EVP_EncryptUpdate(c, NULL, &len, aad, (int)aadlen) != 1) goto out;
    if (ptlen && EVP_EncryptUpdate(c, ct, &len, pt, (int)ptlen) != 1) goto out;
    if (EVP_EncryptFinal_ex(c, ct + len, &len) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, VF_TAG_LEN, tag) != 1) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int vf_aead_decrypt(const uint8_t key[VF_KEY_LEN], const uint8_t nonce[VF_NONCE_LEN],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen,
                    const uint8_t tag[VF_TAG_LEN], uint8_t *pt) {
    int rc = -1, len = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, VF_NONCE_LEN, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) != 1) goto out;
    if (aadlen && EVP_DecryptUpdate(c, NULL, &len, aad, (int)aadlen) != 1) goto out;
    if (ctlen && EVP_DecryptUpdate(c, pt, &len, ct, (int)ctlen) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, VF_TAG_LEN, (void *)tag) != 1) goto out;
    /* Final verifies the tag; <=0 means authentication failed. */
    if (EVP_DecryptFinal_ex(c, pt + len, &len) <= 0) { rc = -1; goto out; }
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int vf_x25519_keypair(uint8_t priv[VF_X25519_PRV], uint8_t pub[VF_X25519_PUB]) {
    int rc = -1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) != 1) goto out;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) goto out;
    size_t l = VF_X25519_PRV;
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &l) != 1) goto out;
    l = VF_X25519_PUB;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &l) != 1) goto out;
    rc = 0;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

int vf_x25519_public_from_private(const uint8_t priv[VF_X25519_PRV],
                                  uint8_t pub[VF_X25519_PUB]) {
    int rc = -1;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                  priv, VF_X25519_PRV);
    if (!pkey) return -1;
    size_t l = VF_X25519_PUB;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &l) == 1) rc = 0;
    EVP_PKEY_free(pkey);
    return rc;
}

/* ECDH(priv, pub) -> shared secret (32 bytes). */
static int x25519_ecdh(const uint8_t priv[32], const uint8_t pub[32],
                       uint8_t out[32]) {
    int rc = -1;
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
    EVP_PKEY_CTX *ctx = NULL;
    if (!pk || !peer) goto out;
    ctx = EVP_PKEY_CTX_new(pk, NULL);
    if (!ctx) goto out;
    if (EVP_PKEY_derive_init(ctx) != 1) goto out;
    if (EVP_PKEY_derive_set_peer(ctx, peer) != 1) goto out;
    size_t l = 32;
    if (EVP_PKEY_derive(ctx, out, &l) != 1) goto out;
    rc = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(peer);
    return rc;
}

/* Sealed box layout: [eph_pub(32)][nonce(12)][tag(16)][ct(ptlen)].
 * key = HKDF(ecdh(eph_priv, recipient_pub), salt=eph_pub||recipient_pub). */
int vf_seal(const uint8_t recipient_pub[VF_X25519_PUB],
            const uint8_t *pt, size_t ptlen,
            uint8_t *out, size_t *outlen) {
    uint8_t eph_priv[32], eph_pub[32], shared[32], key[VF_KEY_LEN];
    int rc = -1;
    if (vf_x25519_keypair(eph_priv, eph_pub) != 0) goto out;
    if (x25519_ecdh(eph_priv, recipient_pub, shared) != 0) goto out;
    uint8_t salt[64];
    memcpy(salt, eph_pub, 32);
    memcpy(salt + 32, recipient_pub, 32);
    if (vf_hkdf(shared, 32, salt, 64, "vaultfs-seal", 12, key, VF_KEY_LEN) != 0) goto out;
    uint8_t *eph_out = out;
    uint8_t *nonce = out + 32;
    uint8_t *tag = out + 32 + VF_NONCE_LEN;
    uint8_t *ct = out + 32 + VF_NONCE_LEN + VF_TAG_LEN;
    memcpy(eph_out, eph_pub, 32);
    if (vf_random(nonce, VF_NONCE_LEN) != 0) goto out;
    if (vf_aead_encrypt(key, nonce, eph_pub, 32, pt, ptlen, ct, tag) != 0) goto out;
    *outlen = ptlen + VF_SEAL_OVERHEAD;
    rc = 0;
out:
    vf_cleanse(eph_priv, sizeof eph_priv);
    vf_cleanse(shared, sizeof shared);
    vf_cleanse(key, sizeof key);
    return rc;
}

int vf_seal_open(const uint8_t recipient_priv[VF_X25519_PRV],
                 const uint8_t *in, size_t inlen,
                 uint8_t *pt, size_t *ptlen) {
    if (inlen < VF_SEAL_OVERHEAD) return -1;
    uint8_t shared[32], key[VF_KEY_LEN];
    int rc = -1;
    const uint8_t *eph_pub = in;
    const uint8_t *nonce = in + 32;
    const uint8_t *tag = in + 32 + VF_NONCE_LEN;
    const uint8_t *ct = in + 32 + VF_NONCE_LEN + VF_TAG_LEN;
    size_t ctlen = inlen - VF_SEAL_OVERHEAD;
    if (x25519_ecdh(recipient_priv, eph_pub, shared) != 0) goto out;
    uint8_t rpub[32];
    if (vf_x25519_public_from_private(recipient_priv, rpub) != 0) goto out;
    uint8_t salt[64];
    memcpy(salt, eph_pub, 32);
    memcpy(salt + 32, rpub, 32);
    if (vf_hkdf(shared, 32, salt, 64, "vaultfs-seal", 12, key, VF_KEY_LEN) != 0) goto out;
    if (vf_aead_decrypt(key, nonce, eph_pub, 32, ct, ctlen, tag, pt) != 0) goto out;
    *ptlen = ctlen;
    rc = 0;
out:
    vf_cleanse(shared, sizeof shared);
    vf_cleanse(key, sizeof key);
    return rc;
}
