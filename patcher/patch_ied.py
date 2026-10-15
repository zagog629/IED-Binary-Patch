#!/usr/bin/env python3
"""
Binary patcher: Immersive Equipment Displays 1.7.4 (AE build) -> Skyrim SE/AE 1.7.104 (1.7.99+).

Usage:
    python patch_ied.py <original ImmersiveEquipmentDisplays.dll> <output dll>

The input must be the unmodified IED 1.7.4 DLL ("for 1.6.629 and newer", Nexus file 62001-1-7-4).
Its SHA-256 is checked before anything is written, and the result is checked against the
known-good output hash. Only the Python standard library is needed.

Every patch asserts the original bytes before overwriting them, so the script refuses to touch
a DLL that isn't the exact build it was written for.
"""
import argparse
import hashlib
import struct
import sys

INPUT_SHA256 = "e12da86be6c3412e1ad91ef7c12d51067f19e023a8d4ef8ec703ee43acedc38c"
OUTPUT_SHA256 = "a23de5607d642437fe312e879b5ba5d4cc7fdb741c0652e0d945668516febcda"

# Assembled from cave.asm (nasm -f bin cave.asm). Loaded at RVA 0x38D4B0 in .text slack space.
CAVE_RVA = 0x38D4B0
CAVE_HEX = (
    "395c244c0f845462f2ff83fb020f852866f2ff837c244c050f851d66f2ffba5000000041b801000000488d4d90"
    "e83efbeaff41b804000000488d542440488d4d90e81adbd3ff41b804000000488d542440488d4d90e806dbd3ff"
    "41b804000000488d542474488d4d90e8f2dad3ff488b459048634804f6440da0060f85ba65f2ff48637424744885"
    "f60f8eac65f2ff4881fe000000010f879f65f2ff4889742450488d5424504c89f1e8124af1ff31ff41b804000000"
    "488d54247c488d4d90e89cdad3ff8b44247c85c07434498b5608493b5610740e48893a488942084983460810eb1c"
    "48897c245048894424584c8d4c24584c8d4424504c89f1e82066f2ff48ffc74839f77ca8488b459048634804f644"
    "0da0060f852065f2ffe9fe64f2ff488d8180000000e9fe84c9ff"
)


class PE:
    def __init__(self, data):
        self.data = data
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        count = struct.unpack_from("<H", data, nt + 6)[0]
        opt = nt + 24
        self.datadir = opt + 112  # PE32+
        table = opt + struct.unpack_from("<H", data, nt + 20)[0]
        self.sections = {}
        for i in range(count):
            off = table + i * 40
            name = data[off:off + 8].rstrip(b"\0").decode()
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
            self.sections[name] = dict(hdr=off, vsize=vsize, va=va, rawsize=rawsize, rawptr=rawptr)

    def off(self, rva):
        for s in self.sections.values():
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                assert rva - s["va"] < s["rawsize"], f"RVA {rva:#x} has no file backing"
                return s["rawptr"] + (rva - s["va"])
        raise ValueError(f"RVA {rva:#x} not in any section")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("output")
    args = ap.parse_args()

    data = bytearray(open(args.input, "rb").read())
    sha = hashlib.sha256(data).hexdigest()
    if sha != INPUT_SHA256:
        sys.exit(f"Input SHA-256 {sha} does not match IED 1.7.4 ({INPUT_SHA256}). Refusing to patch.")
    pe = PE(data)
    cave = bytes.fromhex(CAVE_HEX)

    def patch(rva, old, new, what):
        old = bytes.fromhex(old) if isinstance(old, str) else old
        new = bytes.fromhex(new) if isinstance(new, str) else new
        o = pe.off(rva)
        assert bytes(data[o:o + len(old)]) == old, f"{what}: unexpected bytes at {rva:#x}"
        data[o:o + len(new)] = new
        print(f"  {rva:#09x}  {what}")

    rel32 = lambda nxt, to: struct.pack("<i", to - nxt)

    print("[1] SKSE version data")
    patch(0x4D0930 + 0x304, "00000000", "02000000", "versionIndependenceEx |= AddressLibraryV5")

    print("[2] Runtime guard (struct offsets below are 1.7.99+ only)")
    patch(0xA88B, "81790450270601", "81790430060701", "minimum runtime 1.6.629 -> 1.7.99")
    patch(0x3B3A68, b"Not supported on game versions prior to 1.6.629\0",
          b"Not supported on game versions prior to 1.7.99\0\0", "error message")

    print("[3] Address Library format-5 reader (code cave)")
    text = pe.sections[".text"]
    o = pe.off(CAVE_RVA)
    assert CAVE_RVA >= text["va"] + text["vsize"] and CAVE_RVA + len(cave) <= text["va"] + text["rawsize"]
    assert not any(data[o:o + len(cave)]), "cave area not empty"
    data[o:o + len(cave)] = cave
    struct.pack_into("<I", data, text["hdr"] + 8, text["rawsize"])
    patch(0x2B3704, "395c244c0f85dd030000", b"\xe9" + rel32(0x2B3709, CAVE_RVA) + b"\x90" * 5,
          "loader format check -> cave")
    grey_cave = CAVE_RVA + cave.index(bytes.fromhex("488d8180000000e9"))

    print("[4] Unwind data for the cave")
    rdata = pe.sections[".rdata"]
    unw_rva = (rdata["va"] + rdata["vsize"] + 3) & ~3
    src = pe.off(0x47A21C)  # UNWIND_INFO of the original loader function
    unw = bytes([0x01, 0x00, 0x0B, 0x00]) + bytes(data[src + 4:src + 28])  # same codes, no EH handler
    o = pe.off(unw_rva)
    assert not any(data[o:o + len(unw)])
    data[o:o + len(unw)] = unw
    struct.pack_into("<I", data, rdata["hdr"] + 8, unw_rva + len(unw) - rdata["va"])
    pdata = pe.sections[".pdata"]
    exc_rva, exc_size = struct.unpack_from("<II", data, pe.datadir + 3 * 8)
    o = pe.off(exc_rva + exc_size)
    assert not any(data[o:o + 12])
    struct.pack_into("<III", data, o, CAVE_RVA, grey_cave, unw_rva)
    struct.pack_into("<I", data, pe.datadir + 3 * 8 + 4, exc_size + 12)
    struct.pack_into("<I", data, pdata["hdr"] + 8, exc_size + 12)
    print(f"  RUNTIME_FUNCTION {CAVE_RVA:#x}-{grey_cave:#x} -> UNWIND_INFO {unw_rva:#x}")

    print("[5] Hook offsets that moved in the 1.7.x executable")
    patch(0x19FE, "b924040000", "b927040000", "SetWeapAdjAnimVar call   ID 15678 +0x424 -> +0x427")
    patch(0x1603EC, "b80b060000", "b81e060000", "Actor::Update light call ID 37348 +0x60B -> +0x61E")
    patch(0x168BE2, "be370c0000", "be490c0000", "task pool main-loop hook ID 36564 +0xC3C -> +0xC4E")
    patch(0x168DDC, "b8e6080000", "b8f8080000", "task pool ProcessLists hook ID 36564 +0x8E6 -> +0x8F8")

    print("[6] PlayerCharacter fields (+8 in 1.7.99)")
    for rva, old, new, what in [
        (0x22B90, "418b86c8040000", "418b86d0040000", "addedPerks.size  0x4C8 -> 0x4D0"),
        (0x22B9F, "498bbeb8040000", "498bbec0040000", "addedPerks.data  0x4B8 -> 0x4C0"),
        (0x3FF18, "8b82c8040000", "8b82d0040000", "addedPerks.size  0x4C8 -> 0x4D0"),
        (0x3FF26, "488b9ab8040000", "488b9ac0040000", "addedPerks.data  0x4B8 -> 0x4C0"),
        (0x400DB, "8b91c8040000", "8b91d0040000", "addedPerks.size  0x4C8 -> 0x4D0 (leaf fn)"),
        (0x400E5, "488b89b8040000", "488b89c0040000", "addedPerks.data  0x4B8 -> 0x4C0 (leaf fn)"),
        (0x25562, "8b911c090000", "8b9124090000", "lastRiddenHorseHandle 0x91C -> 0x924"),
        (0x2A946, "8b811c090000", "8b8124090000", "lastRiddenHorseHandle 0x91C -> 0x924"),
        (0x2BBB4, "8b911c090000", "8b9124090000", "lastRiddenHorseHandle 0x91C -> 0x924"),
        (0x15947D, "8b801c090000", "8b8024090000", "lastRiddenHorseHandle 0x91C -> 0x924"),
        (0x269C0, "488b80d00a0000", "488b80d80a0000", "currentLocation  0xAD0 -> 0xAD8"),
        (0x408BB, "0fb680e30b0000", "0fb680eb0b0000", "player flags     0xBE3 -> 0xBEB"),
        (0x40A95, "0fb680e30b0000", "0fb680eb0b0000", "player flags     0xBE3 -> 0xBEB"),
        (0x1F702, "f683e20b000008", "f683ea0b000008", "AI-driven flag   0xBE2 -> 0xBEA"),
        (0x1F71C, "f6830a0b000004", "f683120b000004", "hands-bound flag 0xB0A -> 0xB12"),
    ]:
        patch(rva, old, new, what)

    print("[7] BSGraphics::State default textures (+0x10 in 1.7.99)")
    patch(0x25ACA, "488d4158eb0a488d4168eb04488d4160",
          bytes.fromhex("488d4170eb0a") + b"\xe9" + rel32(0x25AD5, grey_cave) + b"\xcc" + bytes.fromhex("488d4178"),
          "black 0x70, grey 0x80 (via cave), white 0x78")
    patch(0x25AF9, "488d4160", "488d4178", "forced default -> white 0x78")

    print("[8] BGSDefaultObjectManager init flags (372 entries in 1.7.99)")
    patch(0x255F3, "80b81b0c000000", "80b85b0c000000", "kKeywordHorse flag 0xC1B -> 0xC5B")
    patch(0x2A3C0B, "80b81b0c000000", "80b85b0c000000", "kKeywordHorse flag 0xC1B -> 0xC5B")

    out = hashlib.sha256(data).hexdigest()
    open(args.output, "wb").write(data)
    print(f"\nwrote {args.output}\nsha256 {out}")
    if out != OUTPUT_SHA256:
        sys.exit("WARNING: output hash differs from the known-good build")
    print("matches known-good build")


if __name__ == "__main__":
    main()
