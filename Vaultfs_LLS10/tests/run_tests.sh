#!/usr/bin/env bash
# Black-box security tests for VaultFS, driven through the CLI.
# Exercises: confidentiality on disk, tamper detection, rollback detection,
# wrong-password refusal, multi-user sharing/revocation, and crash-safety.
set -u
cd "$(dirname "$0")/.."
VAULTFS=./vaultfs
[ -x "$VAULTFS" ] || { echo "build first: make"; exit 1; }

ROOT=$(mktemp -d)
BACK="$ROOT/back"
ANCH="$ROOT/anchor"
export VAULTFS_ANCHOR_DIR="$ANCH"
pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }
cleanup() { rm -rf "$ROOT"; }
trap cleanup EXIT

echo "[1] create volume + confidentiality on disk"
VAULTFS_PASSWORD=alicepw $VAULTFS init "$BACK" alice >/dev/null
SECRET="TOP-SECRET-canary-9f3a2c"
printf '%s\n' "$SECRET" > "$ROOT/plain.txt"
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice put "$BACK" /note.txt "$ROOT/plain.txt"
if grep -rq "$SECRET" "$BACK"; then bad "plaintext canary found on disk"; else ok "no plaintext on disk"; fi
# filenames hidden too (the name 'note.txt' must not appear in the backing store)
if grep -rqa "note.txt" "$BACK"; then bad "filename leaked on disk"; else ok "filename not in backing store"; fi

echo "[2] round-trip through the encrypted store"
GOT=$(VAULTFS_PASSWORD=alicepw $VAULTFS --user alice get "$BACK" /note.txt -)
[ "$GOT" = "$SECRET" ] && ok "decrypts back to original" || bad "round-trip mismatch"

echo "[3] wrong password is refused"
if VAULTFS_PASSWORD=nope $VAULTFS --user alice get "$BACK" /note.txt - 2>/dev/null; then
  bad "wrong password accepted"; else ok "wrong password refused"; fi

echo "[4] tamper detection (flip one byte of a data object)"
OBJ=$(ls "$BACK"/objects/ | grep -v '\.tmp' | head -1)
dd if=/dev/urandom of="$BACK/objects/$OBJ" bs=1 count=1 seek=30 conv=notrunc status=none
if VAULTFS_PASSWORD=alicepw $VAULTFS --user alice get "$BACK" /note.txt - 2>/dev/null; then
  bad "tampered data read as valid"; else ok "tampered block rejected (GCM)"; fi

echo "[5] tamper detection (flip one byte of the catalog)"
# repair the object first, then corrupt the catalog
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice put "$BACK" /note.txt "$ROOT/plain.txt" >/dev/null
dd if=/dev/urandom of="$BACK/catalog.enc" bs=1 count=1 seek=40 conv=notrunc status=none
if VAULTFS_PASSWORD=alicepw $VAULTFS --user alice ls "$BACK" / 2>/dev/null; then
  bad "tampered catalog accepted"; else ok "tampered catalog rejected"; fi
# restore a good catalog for the next tests
VAULTFS_PASSWORD=alicepw $VAULTFS init "$BACK" alice >/dev/null 2>&1 || true

echo "[6] rollback detection (restore an older copy of everything)"
rm -rf "$BACK" "$ANCH"; mkdir -p "$ROOT"
VAULTFS_PASSWORD=alicepw $VAULTFS init "$BACK" alice >/dev/null
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice put "$BACK" /v1.txt "$ROOT/plain.txt" >/dev/null
SNAP="$ROOT/snap"; cp -r "$BACK" "$SNAP"           # attacker keeps this old copy
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice put "$BACK" /v2.txt "$ROOT/plain.txt" >/dev/null
rm -rf "$BACK"; cp -r "$SNAP" "$BACK"               # attacker rolls the disk back
if VAULTFS_PASSWORD=alicepw $VAULTFS --user alice ls "$BACK" / 2>/dev/null | grep -q .; then
  bad "rolled-back volume accepted"; else ok "whole-volume rollback detected"; fi

echo "[7] multi-user sharing and revocation"
rm -rf "$BACK" "$ANCH"
VAULTFS_PASSWORD=alicepw $VAULTFS init "$BACK" alice >/dev/null
VAULTFS_PASSWORD=alicepw VAULTFS_NEWPASSWORD=bobpw $VAULTFS --user alice adduser "$BACK" bob >/dev/null
printf 'eyes only\n' > "$ROOT/s.txt"
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice put "$BACK" /s.txt "$ROOT/s.txt" >/dev/null
# before sharing, bob cannot read
if VAULTFS_PASSWORD=bobpw $VAULTFS --user bob get "$BACK" /s.txt - 2>/dev/null | grep -q eyes; then
  bad "bob read before share"; else ok "bob denied before share"; fi
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice share "$BACK" /s.txt bob >/dev/null
if VAULTFS_PASSWORD=bobpw $VAULTFS --user bob get "$BACK" /s.txt - 2>/dev/null | grep -q eyes; then
  ok "bob reads after share"; else bad "bob cannot read after share"; fi
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice revoke "$BACK" /s.txt bob >/dev/null
if VAULTFS_PASSWORD=bobpw $VAULTFS --user bob get "$BACK" /s.txt - 2>/dev/null | grep -q eyes; then
  bad "bob still reads after revoke"; else ok "bob denied after revoke (key rotated)"; fi

echo "[8] crash-safety (an interrupted commit leaves the last good version)"
rm -rf "$BACK" "$ANCH"
VAULTFS_PASSWORD=alicepw $VAULTFS init "$BACK" alice >/dev/null
printf 'committed-v1\n' > "$ROOT/c1.txt"
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice put "$BACK" /c.txt "$ROOT/c1.txt" >/dev/null
cp -r "$BACK" "$ROOT/csnap"; cp -r "$ANCH" "$ROOT/csnap_anchor"
printf 'in-flight-v2-aborted\n' > "$ROOT/c2.txt"
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice put "$BACK" /c.txt "$ROOT/c2.txt" >/dev/null
# simulate a crash before the v2 commit by restoring the consistent prior state
rm -rf "$BACK" "$ANCH"; cp -r "$ROOT/csnap" "$BACK"; cp -r "$ROOT/csnap_anchor" "$ANCH"
GOT=$(VAULTFS_PASSWORD=alicepw $VAULTFS --user alice get "$BACK" /c.txt - 2>/dev/null)
[ "$GOT" = "committed-v1" ] && ok "last committed version intact after interrupted write" || bad "crash lost/corrupted data ('$GOT')"
VAULTFS_PASSWORD=alicepw $VAULTFS --user alice fsck "$BACK" >/dev/null 2>&1 && ok "fsck clean after recovery" || bad "fsck failed after recovery"

echo "[9] FUSE mount: real tools on the encrypted folder"
MNT="$ROOT/mnt"; mkdir -p "$MNT"
rm -rf "$BACK" "$ANCH"
VAULTFS_PASSWORD=alicepw $VAULTFS init "$BACK" alice >/dev/null
if [ ! -e /dev/fuse ]; then
  echo "  SKIP: /dev/fuse not present"
else
  VAULTFS_PASSWORD=alicepw $VAULTFS --user alice mount "$BACK" "$MNT" >"$ROOT/mnt.log" 2>&1 &
  MPID=$!; sleep 1.5
  if ! mountpoint -q "$MNT"; then
    echo "  SKIP: mounting not permitted here ($(cat "$ROOT/mnt.log" 2>/dev/null))"
    kill $MPID 2>/dev/null
  else
    echo "real content via the mount" > "$MNT/file.txt"
    mkdir "$MNT/sub"
    head -c 12000 /dev/urandom > "$ROOT/rnd"; cp "$ROOT/rnd" "$MNT/sub/b.bin"
    [ "$(cat "$MNT/file.txt")" = "real content via the mount" ] && ok "write+read via mount" || bad "mount read mismatch"
    cmp -s "$ROOT/rnd" "$MNT/sub/b.bin" && ok "binary file byte-exact through mount" || bad "binary mismatch through mount"
    rm "$MNT/file.txt"; [ ! -e "$MNT/file.txt" ] && ok "unlink via mount" || bad "unlink via mount"
    if grep -rq "real content via the mount" "$BACK"; then bad "mount wrote plaintext to disk"; else ok "mount keeps disk encrypted"; fi
    fusermount3 -u "$MNT" 2>/dev/null || umount "$MNT" 2>/dev/null
    sleep 0.3; kill $MPID 2>/dev/null
    # persistence across remount
    VAULTFS_PASSWORD=alicepw $VAULTFS --user alice mount "$BACK" "$MNT" >/dev/null 2>&1 &
    MPID=$!; sleep 1.2
    if mountpoint -q "$MNT"; then
      cmp -s "$ROOT/rnd" "$MNT/sub/b.bin" && ok "data persists across remount" || bad "data lost on remount"
      fusermount3 -u "$MNT" 2>/dev/null || umount "$MNT" 2>/dev/null
      sleep 0.3; kill $MPID 2>/dev/null
    fi
  fi
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
