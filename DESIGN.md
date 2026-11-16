# VaultFS — design and security rationale

## Threat model

The attacker has **full control of the backing directory** and can keep and
restore arbitrarily old copies of any or all of it. They do **not** have the
user's password and cannot observe or modify the running process. VaultFS must
deliver, against that attacker: confidentiality of contents (and names), tamper
detection, rollback detection, safe password handling, per-user access with
sharing and revocation, in-memory key hygiene, crash safety, and memory-safe
parsing of hostile input.

## On-disk layout (all untrusted)

```
VAULTFS        magic + format version + 16-byte volume id        (public)
keyring.bin    per-user unlock records                           (see below)
catalog.enc    AES-256-GCM(VMK) { tree, metadata, version, keyring-hash }
objects/<hex>  AES-256-GCM(file key) over one 4 KiB block; random name
```

Trusted state, kept outside the backing directory:

```
<anchor>/<volid>.anchor   { volume_id, version_counter, sha256(catalog.enc) }
```

## Key hierarchy

```
password ──scrypt(N=2^15,r=8,p=1)──▶ UKEK
UKEK ──AES-256-GCM──▶ user's X25519 private key           (in keyring.bin)
user private key ◀──sealed box── VMK                      (vmk_wrap in keyring.bin)
VMK ──AES-256-GCM──▶ catalog.enc  (directory tree, metadata, version counter)
file key ◀──sealed box── per authorized user              (wraps in the catalog)
file key ──AES-256-GCM──▶ each 4 KiB data block
```

A **sealed box** is ECIES over X25519: an ephemeral keypair, ECDH to the
recipient's public key, HKDF-SHA256 to an AES-256-GCM key, authenticated with
the ephemeral public key as additional data. It lets one secret (the VMK, or a
file key) be made readable by a chosen set of public keys without a shared
secret.

Why split `keyring.bin` from `catalog.enc`: unlocking must happen *before* the
VMK is known, so the per-user records that bootstrap the VMK cannot themselves be
under the VMK. Each keyring record is self-protecting — the private key is under
the password-derived UKEK, the VMK copy is a sealed box — so tampering with it
only makes unlock fail. To also catch *post-hoc* tampering with the user set, the
catalog stores `sha256(keyring.bin)` under the VMK and unlock verifies it.

## The four security properties, concretely

**Confidentiality (goal 2).** Contents are per-block AES-256-GCM; names and the
whole tree live only inside `catalog.enc`, also AES-256-GCM; object files have
random names and are padded to 4 KiB. Without the password nothing is readable;
an enrolled user without a given file's key cannot read that file even by reading
the raw objects, because the file key is sealed only to authorized users.

**Integrity / tamper detection (goal 3).** Every ciphertext carries a GCM tag.
Block AAD binds each block to `volume_id || inode || block_index`, so an attacker
cannot pass one authentic block off as another, or move it within or between
files. The catalog's tag protects the entire namespace. Any altered byte →
authentication failure → `EIO`, never silent acceptance.

**Rollback detection (goal 4).** The catalog carries a monotonic
`version_counter`, protected by the VMK tag. Each commit writes the new catalog
and then advances the trusted anchor `{volume_id, version, sha256(catalog.enc)}`.
On unlock VaultFS compares: a stored version **below** the anchor is a rollback
(an old whole-volume copy); an equal version with a different catalog hash is a
fork; a higher version advances the anchor. Because the counter is inside the
authenticated catalog, the attacker cannot forge a higher one; because the anchor
is on trusted storage, they cannot roll it back. This is the minimal trusted
monotonic state every anti-rollback design requires (a TPM/secure counter is the
hardware equivalent).

**Password protection (goal 5).** scrypt makes offline guessing expensive. A
wrong password yields a wrong UKEK, so the GCM-protected private key fails to
decrypt and unlock returns `VF_ERR_AUTH` — a clean refusal, no oracle. `passwd`
re-salts and re-encrypts only the user's private key; data is untouched.

## Multi-user, sharing, and revocation (goal 6)

Each file has a random **file key**. It is sealed to each authorized user's
public key and the wraps are stored in the catalog. `share` adds a wrap; opening
a file means unwrapping its key with your private key — so access is enforced
cryptographically, not merely by a permission bit.

`revoke user file` **rotates** the file key: it decrypts each block with the old
key and re-encrypts under a fresh key, then rebuilds the wrap set for everyone
except the revoked user. The revoked user keeps whatever plaintext they already
saw (unavoidable) but cannot read anything written afterwards, and only this one
file is re-encrypted — never the whole volume. `deluser` is the volume-level
analogue: it rotates the **VMK** (re-wrapping it to the remaining users and
re-encrypting only the catalog), so the removed user loses the ability to read
any future catalog.

## In-memory hygiene (goal 7)

Keys exist only in process memory, are `mlock`ed to avoid being swapped to disk,
and are wiped with `OPENSSL_cleanse` as soon as they are no longer needed
(including on `vault_close`). Nothing secret is written to logs or error
messages.

## Crash safety (goal 8)

Data blocks are **copy-on-write**: a block write creates a new random object and
only then is the catalog updated to point at it, so a crash before the catalog
commit leaves the previous content intact and the new object as a harmless
orphan (reclaimed by `gc`). The catalog and keyring are published by the standard
write-temp → `fsync` → `rename` → `fsync(dir)` dance, which is atomic, so a reader
always sees a complete previous or new version. Commit order is
objects → catalog → anchor, so every intermediate crash point leaves a consistent
committed state.

## Memory-safe parsing of hostile input (goal 9)

Everything read from the backing store is attacker-controlled. The deserializer
(`util.c`) is a bounds-checked reader: every field read first checks the
remaining length and fails closed on underflow or overflow, and every embedded
length is validated against the buffer before use. No length from the input is
ever trusted to size a copy. Decryption is always *authenticate-before-use*: a
block or catalog is parsed only after its GCM tag verifies, so a forged length or
structure never reaches the parser in the first place.

## Why no libfuse

The brief allows libfuse but requires the filesystem to be the author's own work.
VaultFS speaks the `/dev/fuse` kernel protocol directly: it maps each kernel
request (`LOOKUP`, `GETATTR`, `READ`, `WRITE`, `CREATE`, `READDIR`, `RENAME`, …)
onto the engine, using the inode number as the FUSE node id. The mount is
obtained through the setuid `fusermount3` helper (portable for non-root users),
with a direct `mount(2)` fallback for root. This removes a dependency and makes
the data path auditable end to end.

## Deliberate limitations

* **Metadata visibility among enrolled users.** The catalog key (VMK) is shared,
  so co-tenants see names and structure (never contents without the file key).
  Per-user catalogs would close this; against the *external* attacker everything
  is already encrypted.
* **Integrity vs. a malicious insider.** Integrity rests on the shared VMK, which
  is sufficient against the external attacker; per-user catalog signatures would
  extend it to insiders.
* **Size leakage.** Padding is to 4 KiB; size is revealed at block granularity.
* **Catalog rewrite per metadata commit.** Simple and crash-safe; a journaled
  B-tree would scale to very large trees.

Each is a conscious trade-off that keeps the core — confidentiality, integrity,
rollback resistance, and crash safety against the defined attacker — small,
auditable, and correct.
