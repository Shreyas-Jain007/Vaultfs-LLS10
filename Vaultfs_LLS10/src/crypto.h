/* crypto.h -- VaultFS cryptographic primitives (thin wrappers over OpenSSL).
 *
 * Everything here is authenticated: we never decrypt-then-trust.  All AEAD is
 * AES-256-GCM; key derivation is scrypt; per-recipient key wrapping is an
 * X25519 sealed box (ECIES) with HKDF-SHA256.  Key material is wiped with
 * OPENSSL_cleanse.
 */
#ifndef VAULTFS_CRYPTO_H
#define VAULTFS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define VF_KEY_LEN    32   /* AES-256 / X25519 key */
#define VF_NONCE_LEN  12   /* GCM nonce */
#define VF_TAG_LEN    16   /* GCM tag */
#define VF_SALT_LEN   16
#define VF_X25519_PUB 32
#define VF_X25519_PRV 32
/* sealed box overhead: ephemeral pub + nonce + tag */
#define VF_SEAL_OVERHEAD (VF_X25519_PUB + VF_NONCE_LEN + VF_TAG_LEN)

/* CSPRNG. Returns 0 on success. */
int vf_random(void *buf, size_t n);

/* Constant-time wipe. */
void vf_cleanse(void *buf, size_t n);

/* Constant-time compare; returns 1 if equal, 0 otherwise. */
int vf_ct_eq(const void *a, const void *b, size_t n);

/* scrypt password hashing. Returns 0 on success. */
int vf_scrypt(const char *pw, size_t pwlen,
              const uint8_t *salt, size_t saltlen,
              uint64_t N, uint32_t r, uint32_t p,
              uint8_t *out, size_t outlen);

/* HKDF-SHA256. Returns 0 on success. */
int vf_hkdf(const uint8_t *ikm, size_t ikmlen,
            const uint8_t *salt, size_t saltlen,
            const char *info, size_t infolen,
            uint8_t *out, size_t outlen);

/* AES-256-GCM. nonce is VF_NONCE_LEN, tag is VF_TAG_LEN.
 * encrypt: writes ct (same length as pt) and tag. Returns 0 on success.
 * decrypt: verifies tag before writing pt. Returns 0 on success, -1 on auth
 * failure (pt is not trusted/!written on failure). */
int vf_aead_encrypt(const uint8_t key[VF_KEY_LEN], const uint8_t nonce[VF_NONCE_LEN],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *pt, size_t ptlen,
                    uint8_t *ct, uint8_t tag[VF_TAG_LEN]);
int vf_aead_decrypt(const uint8_t key[VF_KEY_LEN], const uint8_t nonce[VF_NONCE_LEN],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen,
                    const uint8_t tag[VF_TAG_LEN], uint8_t *pt);

/* X25519 keypair (raw 32-byte keys). Returns 0 on success. */
int vf_x25519_keypair(uint8_t priv[VF_X25519_PRV], uint8_t pub[VF_X25519_PUB]);

/* Derive the public key from a raw private key. */
int vf_x25519_public_from_private(const uint8_t priv[VF_X25519_PRV],
                                  uint8_t pub[VF_X25519_PUB]);

/* Sealed box: encrypt `ptlen` bytes to recipient public key.
 * out must be at least ptlen + VF_SEAL_OVERHEAD. Writes *outlen. 0 on success. */
int vf_seal(const uint8_t recipient_pub[VF_X25519_PUB],
            const uint8_t *pt, size_t ptlen,
            uint8_t *out, size_t *outlen);

/* Open a sealed box with recipient private key. pt must be >= inlen -
 * VF_SEAL_OVERHEAD. Writes *ptlen. Returns 0 on success, -1 on auth failure. */
int vf_seal_open(const uint8_t recipient_priv[VF_X25519_PRV],
                 const uint8_t *in, size_t inlen,
                 uint8_t *pt, size_t *ptlen);

/* SHA-256 convenience. */
void vf_sha256(const uint8_t *data, size_t n, uint8_t out[32]);

#endif
