#!/usr/bin/env python3
"""
Check the patch's assumptions against your own copy of the game.

Usage:
    python verify_against_game.py <SkyrimSE.exe> <versionlib-1-7-104-0.bin> [ied_address_ids.txt]

Checks:
  1. every address-library ID IED requests resolves in the format-5 database
  2. every code hook site holds the instruction IED expects (with the patched offsets)
  3. the vtables IED detours have the expected RTTI class / sub-object offset
  4. spot checks that the game's own code uses the shifted 1.7.99 struct offsets

Requires: pip install pefile
"""
import os
import struct
import sys

import pefile

sys.path.insert(0, os.path.dirname(__file__))
from addrlib import load_v5  # noqa: E402

GAME_BASE = 0x140000000

HOOK_SITES = [  # (description, AE id, offset, expected bytes)
    ("RemoveAllBipedParts prologue", 15659, 0x0, "40 56 57 41 56 48 83 ec 30"),
    ("CreateWeaponNodes prologue", 19769, 0x0, "40 56 57 41 54 41 56"),
    ("REFR Load3D clone vcall", 19727, 0x1D1, "ff 90 50 02 00 00"),
    ("Anim update (ref) vcall", 20123, 0xAB, "ff 90 f8 03 00 00"),
    ("Anim update (player) vcall", 40521, 0xD0, "ff 90 f0 03 00 00"),
    ("ShaderReferenceEffect resume vcall", 34916, 0x84, "ff 90 e0 01 00 00"),
    ("SetWeapAdjAnimVar call [patched]", 15678, 0x427, "e8"),
    ("hkaLookupSkeletonBones call", 63854, 0x108, "e8"),
    ("REFR garbage collector call", 36459, 0x7A, "e8"),
    ("Reanimate state update call", 38820, 0x3F, "e8"),
    ("Armor update call", 24725, 0x1EF, "e8"),
    ("Toggle favorite call", 51848, 0x71B, "e8"),
    ("Cell attach GetExtraLight call", 19414, 0x149, "e8"),
    ("Player scene-move lights call", 40744, 0x6F5, "e8"),
    ("Player RefreshLights tail jump", 40572, 0x4C, "e9"),
    ("Actor::Update GetExtraLight call [patched]", 37348, 0x61E, "e8"),
    ("Player scene-move post call", 40744, 0x7A0, "e8"),
    ("Input event dispatch call", 68617, 0x7B, "e8"),
    ("Renderer init (D3D11) call", 77226, 0x275, "e8"),
    ("Present call", 77246, 0x9, "e8"),
    ("Task pool main-loop epilogue [patched]", 36564, 0xC4E, "4c 8d 9c 24 30 01 00 00"),
    ("Task pool ProcessLists call [patched]", 36564, 0x8F8, "e8"),
]

VTABLES = [  # (AE id, RTTI class, sub-object offset)
    (207511, b".?AVActor@@", 0x0), (207886, b".?AVCharacter@@", 0x0), (208040, b".?AVPlayerCharacter@@", 0x0),
    (207521, b".?AVActor@@", 0xB8), (207896, b".?AVCharacter@@", 0xB8), (208050, b".?AVPlayerCharacter@@", 0xB8),
]


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    exe, lib = sys.argv[1], sys.argv[2]
    ids_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(__file__), "..", "tests", "ied_address_ids.txt")

    pe = pefile.PE(exe, fast_load=True)
    img = pe.get_memory_mapped_image()
    db = load_v5(lib)
    offs = db["offs"]
    print(f"game {db['ver']}  address entries {db['cnt']}")
    failures = 0

    def addr(i):
        return offs[i] if i < len(offs) else 0

    # 1. IDs
    missing = []
    for line in open(ids_path):
        se, ae, *_ = line.split()
        if not addr(int(ae)):
            missing.append(int(ae))
    print(f"[1] address IDs: {'OK' if not missing else 'MISSING ' + str(missing)}")
    failures += bool(missing)

    # 2. hook sites
    bad = 0
    for desc, i, off, exp in HOOK_SITES:
        a = addr(i) + off
        e = bytes.fromhex(exp.replace(" ", ""))
        ok = img[a:a + len(e)] == e
        bad += not ok
        print(f"    {'OK ' if ok else 'BAD'} {desc:45s} ID {i}+{off:#x}")
    print(f"[2] hook sites: {len(HOOK_SITES) - bad}/{len(HOOK_SITES)} OK")
    failures += bad

    # 3. vtables via RTTI complete-object locator
    bad = 0
    for i, cls, sub in VTABLES:
        v = addr(i)
        col = struct.unpack_from("<Q", img, v - 8)[0] - GAME_BASE
        _, off, _, td = struct.unpack_from("<IIII", img, col)
        name = img[td + 0x10:td + 0x60].split(b"\0")[0]
        ok = name == cls and off == sub
        bad += not ok
        print(f"    {'OK ' if ok else 'BAD'} vtable ID {i}: {name.decode()} +{off:#x}")
    print(f"[3] vtables: {len(VTABLES) - bad}/{len(VTABLES)} OK")
    failures += bad

    # 4. struct offsets as used by the game itself
    pc_vtbl = addr(208040)
    getter = struct.unpack_from("<Q", img, pc_vtbl + 0x114 * 8)[0] - GAME_BASE
    checks = [
        ("PlayerCharacter::lastRiddenHorseHandle @0x924", img[getter:getter + 6] == bytes.fromhex("8b8124090000")),
        ("PlayerCharacter::currentLocation @0xAD8",
         bytes.fromhex("488b80d80a0000") in img[addr(19812):addr(19812) + 0x40]),
        ("BGSDefaultObjectManager kKeywordHorse flag @0xC5B",
         img.find(bytes.fromhex("80b85b0c000000"), 0x1000, 0x1000 + pe.sections[0].Misc_VirtualSize) > 0),
    ]
    init = addr(77513)  # BSGraphics::State default-texture setup (this == State singleton)
    blk = img[init:init + 0x900]
    checks.append(("BSGraphics::State white/grey textures @0x78/0x80",
                   bytes.fromhex("48894378") in blk           # mov [rbx+0x78], rax  (DefaultWhiteMap)
                   and bytes.fromhex("48898380000000") in blk))  # mov [rbx+0x80], rax  (DefaultGreyMap)
    for desc, ok in checks:
        failures += not ok
        print(f"    {'OK ' if ok else 'BAD'} {desc}")
    print(f"[4] struct spot checks done")

    print("\nALL CHECKS PASSED" if not failures else f"\n{failures} CHECK(S) FAILED")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
