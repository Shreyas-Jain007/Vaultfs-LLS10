#!/usr/bin/env bash
# VaultFS 5-minute demo. Run from the repo root after `make`.
# Shows: a real mounted folder, ciphertext on disk, tamper detection,
# rollback detection, and multi-user share/revoke.
set -e
cd "$(dirname "$0")/.."
D=$(mktemp -d)
export VAULTFS_ANCHOR_DIR="$D/anchor"
BACK="$D/back"; MNT="$D/mnt"; mkdir -p "$MNT"
say(){ echo; echo "### $*"; }

say "1. Create a volume (admin: alice)"
VAULTFS_PASSWORD=alicepw ./vaultfs init "$BACK" alice

say "2. Mount it as an ordinary folder and use real tools"
VAULTFS_PASSWORD=alicepw ./vaultfs --user alice mount "$BACK" "$MNT" & MP=$!; sleep 1.5
echo "quarterly numbers: 42" > "$MNT/report.txt"
mkdir "$MNT/photos"; head -c 8000 /dev/urandom > "$MNT/photos/img.bin"
ls -la "$MNT"; cat "$MNT/report.txt"

say "3. On disk it is only ciphertext (grep finds no plaintext)"
grep -r "quarterly numbers" "$BACK" && echo "LEAK" || echo "  -> nothing readable on disk"
ls "$BACK/objects" | head

say "4. Tamper with a stored block -> detected"
fusermount3 -u "$MNT" 2>/dev/null || umount "$MNT"; sleep 0.3; kill $MP 2>/dev/null || true
OBJ=$(ls "$BACK"/objects | grep -v tmp | head -1)
dd if=/dev/urandom of="$BACK/objects/$OBJ" bs=1 count=1 seek=25 conv=notrunc status=none
VAULTFS_PASSWORD=alicepw ./vaultfs --user alice fsck "$BACK" || echo "  -> fsck reports tampering"

say "5. Roll the whole disk back to an older copy -> detected"
rm -rf "$BACK" "$VAULTFS_ANCHOR_DIR"
VAULTFS_PASSWORD=alicepw ./vaultfs init "$BACK" alice >/dev/null
echo v1 > "$D/f"; VAULTFS_PASSWORD=alicepw ./vaultfs --user alice put "$BACK" /f "$D/f"
cp -r "$BACK" "$D/old"
echo v2 > "$D/f"; VAULTFS_PASSWORD=alicepw ./vaultfs --user alice put "$BACK" /f "$D/f"
rm -rf "$BACK"; cp -r "$D/old" "$BACK"       # attacker restores the old copy
VAULTFS_PASSWORD=alicepw ./vaultfs --user alice ls "$BACK" / || echo "  -> rollback rejected"

say "6. Multi-user: share then revoke"
rm -rf "$BACK" "$VAULTFS_ANCHOR_DIR"
VAULTFS_PASSWORD=alicepw ./vaultfs init "$BACK" alice >/dev/null
VAULTFS_PASSWORD=alicepw VAULTFS_NEWPASSWORD=bobpw ./vaultfs --user alice adduser "$BACK" bob
echo "for bob" > "$D/s"; VAULTFS_PASSWORD=alicepw ./vaultfs --user alice put "$BACK" /s.txt "$D/s"
echo "-- bob before share:"; VAULTFS_PASSWORD=bobpw ./vaultfs --user bob get "$BACK" /s.txt - || echo "  (denied)"
VAULTFS_PASSWORD=alicepw ./vaultfs --user alice share "$BACK" /s.txt bob
echo "-- bob after share:";  VAULTFS_PASSWORD=bobpw ./vaultfs --user bob get "$BACK" /s.txt -
VAULTFS_PASSWORD=alicepw ./vaultfs --user alice revoke "$BACK" /s.txt bob
echo "-- bob after revoke:"; VAULTFS_PASSWORD=bobpw ./vaultfs --user bob get "$BACK" /s.txt - || echo "  (denied, key rotated)"

echo; echo "### done"; rm -rf "$D"
