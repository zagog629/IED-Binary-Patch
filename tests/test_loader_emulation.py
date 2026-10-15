#!/usr/bin/env python3
"""
Emulation test for the format-5 Address Library reader added by the patch.

Usage:
    python test_loader_emulation.py <patched ImmersiveEquipmentDisplays.dll> <versionlib-1-7-104-0.bin> [ied_address_ids.txt]

Runs the patched loader (code cave + IED's own loop epilogue) under the Unicorn CPU emulator against
your real versionlib file, with the C++ stream/vector helpers it calls stubbed in Python. Then it
resolves every address ID IED requests through IED's own lookup functions and compares the result
with the address read directly from the file. Also checks the old v1/v2 path is untouched.

Requires: pip install pefile unicorn
"""
import os, sys, struct
import pefile
from unicorn import *
from unicorn.x86_const import *

if len(sys.argv) < 3:
    sys.exit(__doc__)
dll_path, bin_path = sys.argv[1:3]
ids_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(__file__), 'ied_address_ids.txt')
BASE = 0x180000000
GAME_BASE = 0x140000000

pe = pefile.PE(dll_path)
img = pe.get_memory_mapped_image()
size = (len(img) + 0xFFF) & ~0xFFF

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(BASE, size)
mu.mem_write(BASE, img)
STACK = 0x10000000; mu.mem_map(STACK, 0x100000)
HEAP = 0x20000000; HEAP_SIZE = 0x4000000; mu.mem_map(HEAP, HEAP_SIZE)
heap_ptr = [HEAP]
def alloc(n):
    p = heap_ptr[0]; heap_ptr[0] += (n + 15) & ~15
    assert heap_ptr[0] < HEAP + HEAP_SIZE
    return p

fdata = open(bin_path, 'rb').read()
fpos = [4]  # loader already consumed the 4-byte format field

def ret(mu):
    rsp = mu.reg_read(UC_X86_REG_RSP)
    ra = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
    mu.reg_write(UC_X86_REG_RSP, rsp + 8)
    mu.reg_write(UC_X86_REG_RIP, ra)

def rd64(a): return struct.unpack('<Q', mu.mem_read(a, 8))[0]
def wr64(a, v): mu.mem_write(a, struct.pack('<Q', v))

calls = {'read': 0, 'seekg': 0, 'reserve': 0, 'emplace': 0}
def hook_code(mu, addr, size, user):
    rva = addr - BASE
    if rva == 0xCB010:      # istream::read(this, buf, n)
        buf = mu.reg_read(UC_X86_REG_RDX); n = mu.reg_read(UC_X86_REG_R8)
        chunk = fdata[fpos[0]:fpos[0] + n]; fpos[0] += n
        assert len(chunk) == n, "read past EOF"
        mu.mem_write(buf, chunk); mu.reg_write(UC_X86_REG_RAX, mu.reg_read(UC_X86_REG_RCX))
        calls['read'] += 1; ret(mu)
    elif rva == 0x23D020:   # istream::seekg(this, off, dir)
        off = mu.reg_read(UC_X86_REG_RDX); d = mu.reg_read(UC_X86_REG_R8) & 0xFFFFFFFF
        assert d == 1, "expected ios_base::cur"
        fpos[0] += off; calls['seekg'] += 1
        mu.reg_write(UC_X86_REG_RAX, mu.reg_read(UC_X86_REG_RCX)); ret(mu)
    elif rva == 0x2A1F70:   # vector reallocate-exactly(this, &newcap)
        vec = mu.reg_read(UC_X86_REG_RCX); n = rd64(mu.reg_read(UC_X86_REG_RDX))
        b, e = rd64(vec), rd64(vec + 8)
        nb = alloc(n * 16)
        if e > b: mu.mem_write(nb, bytes(mu.mem_read(b, e - b)))
        wr64(vec, nb); wr64(vec + 8, nb + (e - b)); wr64(vec + 16, nb + n * 16)
        calls['reserve'] += 1; ret(mu)
    elif rva == 0x2B3BD0:   # vector emplace-reallocate(this, where, &id, &off)
        vec = mu.reg_read(UC_X86_REG_RCX)
        idv = rd64(mu.reg_read(UC_X86_REG_R8)); ov = rd64(mu.reg_read(UC_X86_REG_R9))
        b, e, c = rd64(vec), rd64(vec + 8), rd64(vec + 16)
        n = (e - b) // 16; cap = max(1, ((c - b) // 16) * 2)
        nb = alloc(cap * 16)
        if e > b: mu.mem_write(nb, bytes(mu.mem_read(b, e - b)))
        mu.mem_write(nb + n * 16, struct.pack('<QQ', idv, ov))
        wr64(vec, nb); wr64(vec + 8, nb + (n + 1) * 16); wr64(vec + 16, nb + cap * 16)
        calls['emplace'] += 1; ret(mu)

STOP = {BASE + 0x2B3ACE: 'success (sort + return true)', BASE + 0x2B3AEB: 'FAIL path',
        BASE + 0x2B370E: 'original v1/v2 path'}

def run_loader(fmt_read, expected):
    # fresh state
    db = BASE + 0x5338D0
    mu.mem_write(db, b'\0' * 0x28)
    rsp = STACK + 0x80000
    rbp = rsp + 0x80          # loader: lea rbp, [rsp - 0x1c0] after pushes; any consistent value works
    mu.reg_write(UC_X86_REG_RSP, rsp); mu.reg_write(UC_X86_REG_RBP, rbp)
    # fake ifstream: [rbp-0x70] -> vbtable with +4 = 0x10 ; stream state byte at rbp+0x10-0x60
    vbt = alloc(16); mu.mem_write(vbt, struct.pack('<II', 0, 0x10))
    wr64(rbp - 0x70, vbt); mu.mem_write(rbp + 0x10 - 0x60, b'\0')
    mu.mem_write(rsp + 0x4C, struct.pack('<I', fmt_read))
    mu.reg_write(UC_X86_REG_RBX, expected)
    mu.reg_write(UC_X86_REG_R14, db)
    fpos[0] = 4
    for k in calls: calls[k] = 0
    stop = {}
    def h_stop(mu, addr, size, user):
        if addr in STOP:
            stop['at'] = STOP[addr]; mu.emu_stop()
    h1 = mu.hook_add(UC_HOOK_CODE, hook_code)
    h2 = mu.hook_add(UC_HOOK_CODE, h_stop)
    mu.emu_start(BASE + 0x2B3704, 0, count=20_000_000)
    mu.hook_del(h1); mu.hook_del(h2)
    return stop.get('at'), db

# --- Test 1: format 5 file, AE path ------------------------------------------
where, db = run_loader(5, 2)
print("format 5 / AE  ->", where, calls, "file pos", fpos[0], "of", len(fdata))
assert where.startswith('success') and fpos[0] == len(fdata)
b, e = rd64(db), rd64(db + 8)
n = (e - b) // 16
vec = struct.unpack(f'<{2*n}Q', bytes(mu.mem_read(b, e - b)))
cnt = struct.unpack_from('<i', fdata, 92)[0]
offs = struct.unpack_from(f'<{cnt}I', fdata, 96)
expected = [(i, o) for i, o in enumerate(offs) if o]
got = list(zip(vec[0::2], vec[1::2]))
assert got == expected, "vector contents differ"
print(f"  vector has {n} entries, identical to the file's non-zero table, sorted by id")

# --- Test 2: unchanged behaviour for v2 file and SE path --------------------
where2, _ = run_loader(2, 2); print("format 2 / AE  ->", where2); assert where2 == 'original v1/v2 path'
where3, _ = run_loader(5, 1); print("format 5 / SE  ->", where3); assert where3 == 'FAIL path'
where4, _ = run_loader(3, 2); print("format 3 / AE  ->", where4); assert where4 == 'FAIL path'

# re-run the good load so the database is populated for lookups
where, db = run_loader(5, 2)
b, e = rd64(db), rd64(db + 8)
vec_bytes = bytes(mu.mem_read(b, e - b))
# The real code sorts afterwards (0x2B3ACE); our vector is already sorted.

# --- Test 3: resolve every ID through IED's own lookup (0xCD80 / 0xD600) ----
mu.mem_write(BASE + 0x5338A3, b'\x01')             # isAE
wr64(BASE + 0x5338F8, GAME_BASE)                     # module base
mu.mem_write(BASE + 0x5338A1, b'\x00')               # bad-query flag
RET_ADDR = BASE + 0x10                               # stop address (header area, never executed)

def call(fn_rva, rcx, rdx, r8=0, r9=0):
    rsp = STACK + 0x90000
    wr64(rsp, RET_ADDR)
    mu.reg_write(UC_X86_REG_RSP, rsp)
    for r, v in ((UC_X86_REG_RCX, rcx), (UC_X86_REG_RDX, rdx), (UC_X86_REG_R8, r8), (UC_X86_REG_R9, r9)):
        mu.reg_write(r, v)
    mu.emu_start(BASE + fn_rva, RET_ADDR, count=100000)
    return mu.reg_read(UC_X86_REG_RAX)

ids = []
for line in open(ids_path):
    p = line.split()
    ids.append((int(p[0]), int(p[1]), int(p[2]), int(p[3], 0) if len(p) > 3 else None))
bad = 0
for se, ae, kind, off in ids:
    if kind == 0:
        got_addr = call(0xCD80, se, ae)
        want = GAME_BASE + offs[ae]
    else:
        got_addr = call(0xD600, se, ae, 0, off)
        want = GAME_BASE + offs[ae] + off
    if got_addr != want:
        bad += 1; print("MISMATCH", se, ae, hex(got_addr), hex(want))
flag = mu.mem_read(BASE + 0x5338A1, 1)[0]
print(f"resolved {len(ids)} lookups through IED's IAL code: {len(ids)-bad} correct, bad-query flag = {flag}")
assert bad == 0 and flag == 0
print("ALL TESTS PASSED")
