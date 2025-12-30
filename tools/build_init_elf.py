#!/usr/bin/env python3
import argparse
import os
import struct

USER_CODE_VA = 0x4000_0000
ELF_SEGMENT_OFFSET = 0x1000
ELF_SEGMENT_ALIGN = 0x1000
ELF_INIT_MSG_OFFSET = 0x200
ELF_INIT_MSG = b"init: ok\n"
ELF_INIT_CODE = bytes([
    0x13, 0x05, 0x10, 0x00, 0xb7, 0x05, 0x00, 0x40, 0x93, 0x85, 0x05, 0x20, 0x13, 0x06,
    0x90, 0x00, 0x93, 0x08, 0x00, 0x04, 0x73, 0x00, 0x00, 0x00, 0x93, 0x08, 0xd0, 0x05,
    0x13, 0x05, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0x6f, 0x00, 0x00, 0x00,
])


def build_init_elf() -> bytes:
    segment_size = ELF_INIT_MSG_OFFSET + len(ELF_INIT_MSG)
    image_size = ELF_SEGMENT_OFFSET + segment_size
    buf = bytearray(image_size)

    buf[0:4] = b"\x7fELF"
    buf[4] = 2  # ELFCLASS64
    buf[5] = 1  # ELFDATA2LSB
    buf[6] = 1  # EV_CURRENT
    buf[7] = 0  # SYSV
    for i in range(8, 16):
        buf[i] = 0

    offset = 16
    buf[offset:offset + 2] = struct.pack("<H", 2)  # ET_EXEC
    offset += 2
    buf[offset:offset + 2] = struct.pack("<H", 243)  # EM_RISCV
    offset += 2
    buf[offset:offset + 4] = struct.pack("<I", 1)
    offset += 4
    buf[offset:offset + 8] = struct.pack("<Q", USER_CODE_VA)
    offset += 8
    buf[offset:offset + 8] = struct.pack("<Q", 64)  # e_phoff
    offset += 8
    buf[offset:offset + 8] = struct.pack("<Q", 0)
    offset += 8
    buf[offset:offset + 4] = struct.pack("<I", 0)
    offset += 4
    buf[offset:offset + 2] = struct.pack("<H", 64)
    offset += 2
    buf[offset:offset + 2] = struct.pack("<H", 56)
    offset += 2
    buf[offset:offset + 2] = struct.pack("<H", 1)
    offset += 2
    buf[offset:offset + 2] = struct.pack("<H", 0)
    offset += 2
    buf[offset:offset + 2] = struct.pack("<H", 0)
    offset += 2
    buf[offset:offset + 2] = struct.pack("<H", 0)

    phoff = 64
    buf[phoff:phoff + 4] = struct.pack("<I", 1)  # PT_LOAD
    buf[phoff + 4:phoff + 8] = struct.pack("<I", 0x7)  # PF_R|PF_W|PF_X
    buf[phoff + 8:phoff + 16] = struct.pack("<Q", ELF_SEGMENT_OFFSET)
    buf[phoff + 16:phoff + 24] = struct.pack("<Q", USER_CODE_VA)
    buf[phoff + 24:phoff + 32] = struct.pack("<Q", USER_CODE_VA)
    buf[phoff + 32:phoff + 40] = struct.pack("<Q", segment_size)
    buf[phoff + 40:phoff + 48] = struct.pack("<Q", segment_size)
    buf[phoff + 48:phoff + 56] = struct.pack("<Q", ELF_SEGMENT_ALIGN)

    buf[ELF_SEGMENT_OFFSET:ELF_SEGMENT_OFFSET + len(ELF_INIT_CODE)] = ELF_INIT_CODE
    msg_start = ELF_SEGMENT_OFFSET + ELF_INIT_MSG_OFFSET
    buf[msg_start:msg_start + len(ELF_INIT_MSG)] = ELF_INIT_MSG

    return bytes(buf)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build minimal /init ELF image for Aurora.")
    parser.add_argument("--out", default="build/init.elf", help="output ELF path")
    args = parser.parse_args()

    data = build_init_elf()
    out_path = args.out
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"Wrote {out_path} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
