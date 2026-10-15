# Immersive Equipment Displays → Skyrim 1.7.104 binary patch

An unofficial binary patch that ports the SKSE plugin [Immersive Equipment Displays](https://www.nexusmods.com/skyrimspecialedition/mods/62001) (IED) 1.7.4 to Skyrim Special/Anniversary Edition **1.7.104** (also valid for 1.7.99). This project patches the shipped x64 DLL directly.

The repository contains the patcher and the tools used to verify it. It does **not** contain the IED DLL, the game executable or Address Library files.

## Why the plugin broke

Skyrim 1.7.99 (August 2026) broke most native SKSE plugins in five separate ways, and IED hit all of them:

| # | Problem | Symptom |
|---|---------|---------|
| 1 | SKSE 2.3.x rejects plugins built before the new Address Library encoding unless they declare compatibility | "must be recompiled for new address library" |
| 2 | Address Library switched to a new **format 5** (flat `uint32` offset table). IED has its own reader that only understands the old delta-compressed format 2 | plugin can't resolve any game address |
| 3 | The executable was rebuilt, so a few code locations IED hooks moved inside their functions | memory-validation failure / "reported as incompatible during load" |
| 4 | `PlayerCharacter` gained a base class (`BSTEventSink<BSSystemEvent>`), shifting every field after `0x2D0` by +8 bytes | crash right after a save finishes loading |
| 5 | `BSGraphics::State` and `BGSDefaultObjectManager` changed layout | wrong or invalid textures / flags read |

## What the patch changes

All changes are listed with their RVAs in [`patcher/patch_ied.py`](patcher/patch_ied.py). Every write asserts the original bytes first.

- **SKSE declaration:** sets `kVersionIndependentEx_AddressLibraryV5` in `SKSEPlugin_Version`.
- **Format-5 reader:** a 300-byte x64 code cave ([`patcher/cave.asm`](patcher/cave.asm)) placed in the `.text` section's file-alignment slack. It is reached from the loader's format check, reads the header and offset table using IED's own `std::ifstream` and `std::vector` helpers, and rejoins the original code path. A new `RUNTIME_FUNCTION` and `UNWIND_INFO` are added so an exception thrown inside the cave still unwinds correctly. The old v1/v2 path is untouched.
- **Moved hook sites:**

  | Hook | Address Library ID | 1.6.x offset | 1.7.104 offset |
  |------|--------------------|--------------|----------------|
  | SetWeapAdjAnimVar call | 15678 | `+0x424` | `+0x427` |
  | Actor::Update GetExtraLight call | 37348 | `+0x60B` | `+0x61E` |
  | Task pool main-loop epilogue | 36564 | `+0xC3C` | `+0xC4E` |
  | Task pool ProcessLists call | 36564 | `+0x8E6` | `+0x8F8` |

- **Struct offsets:** 15 `PlayerCharacter` field accesses (perks, last ridden horse, current location, player flags), the three `BSGraphics::State` default textures, and two `BGSDefaultObjectManager` init-flag reads.
- **Runtime guard:** the plugin now refuses to load on anything older than 1.7.99, because the offsets above are wrong for older versions.

## How it was verified

- **Address IDs:** all 300 address IDs IED requests were checked against `versionlib-1-7-104-0.bin`.
- **Hook sites and vtables:** all 22 code hook sites and 6 detoured vtables were checked against the 1.7.104 executable. Vtables were matched by RTTI class name and sub-object offset ([`tools/verify_against_game.py`](tools/verify_against_game.py)).
- **Struct offsets:** each shifted offset was confirmed against the game's own code. For example, the virtual getter for the last-ridden horse reads `[rcx+0x924]`, and the default-texture initialiser writes `DefaultWhiteMap` and `DefaultGreyMap` to `State+0x78` and `+0x80`.
- **Loader emulation:** the patched loader was run under the [Unicorn](https://www.unicorn-engine.org/) emulator on the real format-5 file. It produced exactly the 435,162 non-zero entries. All 309 lookups resolved correctly through IED's own lookup code ([`tests/test_loader_emulation.py`](tests/test_loader_emulation.py)).
- **Full-code rescan:** every scan was re-run over the whole `.text` section, including leaf functions that have no `.pdata` entry. Missing those was the cause of the one in-game crash found during testing (fault offset `0x40100`, from the Windows Application event log).

## Usage

```
pip install pefile capstone unicorn       # only needed for the tools/tests
python patcher/patch_ied.py <path to original ImmersiveEquipmentDisplays.dll> ImmersiveEquipmentDisplays.dll
```

The input must be the unmodified IED 1.7.4 "for 1.6.629 and newer" DLL (SHA-256 `e12da86b…`). The output hash is checked against the known-good build. You also need SKSE64 2.3.1+ and Address Library v13.

Optional checks against your own game files:

```
python tools/verify_against_game.py "<Skyrim>/SkyrimSE.exe" "<Skyrim>/Data/SKSE/Plugins/versionlib-1-7-104-0.bin"
python tests/test_loader_emulation.py ImmersiveEquipmentDisplays.dll "<Skyrim>/Data/SKSE/Plugins/versionlib-1-7-104-0.bin"
```

## Repository layout

```
patcher/patch_ied.py              the patcher (standard library only)
patcher/cave.asm                  NASM source of the code caves
tools/addrlib.py                  Address Library parser (formats 2 and 5)
tools/verify_against_game.py      checks the patch's assumptions against SkyrimSE.exe
tests/test_loader_emulation.py    Unicorn emulation of the patched loader
tests/ied_address_ids.txt         the address IDs IED requests (extracted from the DLL)
```

## Credits

- [Immersive Equipment Displays](https://github.com/SlavicPotato/ied-dev) by SlavicPotato (MIT license)
- [SKSE64](https://github.com/ianpatt/skse64) by ianpatt, behippo and expired6978
- [Address Library for SKSE Plugins](https://www.nexusmods.com/skyrimspecialedition/mods/32444) by meh321
- [CommonLibSSE-NG](https://github.com/alandtse/CommonLibVR) contributors, whose reverse-engineering notes on the 1.7.99 layout changes were the starting point
- The reverse engineering and patch were developed with the help of Claude Opus 5.5 (Anthropic)

This project is not affiliated with or endorsed by the IED author, Bethesda or the SKSE team.
