"""Parsers for the Address Library for SKSE Plugins database.

load_v2: delta-compressed format used up to 1.6.1170 (versionlib-*.bin, format 2)
load_v5: flat uint32 offset table used from 1.7.99 (header: int32 5, uint32 version[4], char name[64],
         int32 pointerSize, int32 dataFormat, int32 count; then count x uint32 RVA, 0 = missing)
"""
import struct
def load_v5(path):
    d = open(path,'rb').read()
    fv, = struct.unpack_from('<i', d, 0)
    assert fv == 5, fv
    ver = struct.unpack_from('<4I', d, 4)
    name = d[20:84].split(b'\0')[0]
    ptrsz, dfmt, cnt = struct.unpack_from('<3i', d, 84)
    offs = struct.unpack_from(f'<{cnt}I', d, 96)
    return dict(ver=ver, name=name, ptrsz=ptrsz, dfmt=dfmt, cnt=cnt, size=len(d), offs=offs)
def load_v2(path):
    d = open(path,'rb').read(); p = 0
    def rd(fmt):
        nonlocal p
        v = struct.unpack_from(fmt, d, p); p += struct.calcsize(fmt); return v
    fmt, = rd('<i'); ver = rd('<4i'); nl, = rd('<i'); name = d[p:p+nl]; p += nl
    ptrsz, = rd('<i'); cnt, = rd('<i')
    m = {}; pid = 0; poff = 0
    for _ in range(cnt):
        t, = rd('<B'); lo = t & 0xF; hi = t >> 4
        if lo == 0: i, = rd('<Q')
        elif lo == 1: i = pid + 1
        elif lo == 2: i = pid + rd('<B')[0]
        elif lo == 3: i = pid - rd('<B')[0]
        elif lo == 4: i = pid + rd('<H')[0]
        elif lo == 5: i = pid - rd('<H')[0]
        elif lo == 6: i, = rd('<H')
        elif lo == 7: i, = rd('<I')
        tp = poff // ptrsz if hi & 8 else poff
        h = hi & 7
        if h == 0: o, = rd('<Q')
        elif h == 1: o = tp + 1
        elif h == 2: o = tp + rd('<B')[0]
        elif h == 3: o = tp - rd('<B')[0]
        elif h == 4: o = tp + rd('<H')[0]
        elif h == 5: o = tp - rd('<H')[0]
        elif h == 6: o, = rd('<H')
        elif h == 7: o, = rd('<I')
        if hi & 8: o *= ptrsz
        m[i] = o; pid = i; poff = o
    return dict(fmt=fmt, ver=ver, name=name, ptrsz=ptrsz, cnt=cnt, map=m)
