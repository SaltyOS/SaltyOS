#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IN_FILE="$ROOT_DIR/build/userspace.elf"
OUT_FILE="$ROOT_DIR/build/initrd.img"

if [ ! -f "$IN_FILE" ]; then
    echo "Error: $IN_FILE not found"
    exit 1
fi

ROOT_DIR="${ROOT_DIR}" python3 - <<'PY'
import os
import time

root = os.environ.get("ROOT_DIR")
if not root:
    raise SystemExit("ROOT_DIR not set")
input_path = os.path.join(root, 'build', 'userspace.elf')
output_path = os.path.join(root, 'build', 'initrd.img')

with open(input_path, 'rb') as f:
    data = f.read()

# CPIO newc helpers

def pad4(n: int) -> int:
    return (4 - (n % 4)) % 4


def write_entry(out, name: str, data: bytes, mode: int, mtime: int) -> None:
    namesize = len(name) + 1
    filesize = len(data)
    fields = [
        0,          # ino
        mode,
        0,          # uid
        0,          # gid
        1,          # nlink
        mtime,
        filesize,
        0,          # devmajor
        0,          # devminor
        0,          # rdevmajor
        0,          # rdevminor
        namesize,
        0,          # check
    ]
    header = "070701" + "".join(f"{v:08x}" for v in fields)
    out.write(header.encode('ascii'))
    out.write(name.encode('ascii') + b"\x00")
    out.write(b"\x00" * pad4(110 + namesize))
    out.write(data)
    out.write(b"\x00" * pad4(filesize))


with open(output_path, 'wb') as out:
    now = int(time.time())
    # /init entry
    write_entry(out, "init", data, 0o100755, now)
    # Trailer
    write_entry(out, "TRAILER!!!", b"", 0, now)

print(f"initrd: {output_path} ({os.path.getsize(output_path)} bytes)")
PY
