#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Replicate the discovery heuristics in src/parsec_zh.c and verify against a skel DLL.

Kept in sync with the C code:
  * AddFont uses the FIRST anchor reference (C find_ref returns the first hit).
  * real_entry() walks back across contiguous .pdata chunks to the real call
    target, matching the runtime behaviour.
"""
import sys, struct, pefile

def main():
    path = sys.argv[1]
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    sec = {s.Name.rstrip(b'\x00').decode(): s for s in pe.sections}
    text = sec['.text']; tva = base + text.VirtualAddress; tdata = text.get_data()
    rdata = sec['.rdata']; rva = base + rdata.VirtualAddress; rdata_b = rdata.get_data()
    dat = sec['.data']; dva = base + dat.VirtualAddress; ddata = dat.get_data()
    pd = sec['.pdata']; pva = base + pd.VirtualAddress; pdata = pd.get_data()

    funcs = []
    for i in range(len(pdata)//12):
        b,e,u = struct.unpack('<III', pdata[i*12:i*12+12])
        if b or e: funcs.append((base+b, base+e))
    funcs.sort()

    def func_start(addr):
        best = None
        for s,e in funcs:
            if s <= addr < e: return s
            if s <= addr: best = s
            elif s > addr: break
        return best

    def find_wide(s):
        pat = s.encode('utf-16-le')
        i = rdata_b.find(pat)
        if i >= 0: return rva + i
        i = ddata.find(pat)
        if i >= 0: return dva + i
        return None

    def find_ref(target):
        # C find_ref returns the FIRST hit.
        n = len(tdata)
        for i in range(n - 6):
            b0,b1,b2 = tdata[i], tdata[i+1], tdata[i+2]
            if (b0 in (0x48,0x4C)) and (b1 in (0x8D,0x8B)) and ((b2 & 0xC7) == 0x05):
                disp = struct.unpack('<i', tdata[i+3:i+7])[0]
                if tva + i + 7 + disp == target:
                    return tva + i
        return None

    # Set of addresses that are the direct target of some call/jmp rel32.
    direct = set()
    n = len(tdata)
    for i in range(n - 4):
        if tdata[i] in (0xE8, 0xE9):
            rel = struct.unpack('<i', tdata[i+1:i+5])[0]
            direct.add(tva + i + 5 + rel)

    def real_entry(frag):
        cur = frag
        for _ in range(64):
            if cur in direct: return cur
            prev = None
            for s,e in funcs:
                if e == cur: prev = s; break
            if prev is None or prev >= cur: break
            cur = prev
        return cur

    print('=== %s ===' % path)
    print('imagebase 0x%x' % base)
    s1 = find_wide("font_cfg->FontData != 0 && font_cfg->FontDataSize > 0")
    if s1:
        r = find_ref(s1)
        if r:
            frag = func_start(r)
            ent = real_entry(frag)
            print('AddFont anchor@0x%x ref@0x%x frag@0x%x -> real_entry@0x%x' % (s1, r, frag, ent))
        else:
            print('AddFont anchor found but no ref')
    else:
        print('AddFont anchor NOT FOUND')

    s2 = find_wide("font->ContainerAtlas->TexID == _TextureIdStack.back()")
    addtext = None; addtext_end = None; rendertext = None
    if s2:
        r = find_ref(s2)
        f = func_start(r) if r else None
        if f:
            addtext = f
            for sb,se in funcs:
                if sb <= f < se: addtext_end = se; break
        print('AddText 0x%x-0x%x' % (addtext, addtext_end))
        if addtext and addtext_end:
            p = addtext
            while p + 10 < addtext_end:
                off = p - tva
                if tdata[off] == 0xE8:
                    rel = struct.unpack('<i', tdata[off+1:off+5])[0]
                    t = p + 5 + rel
                    o2 = t - tva
                    if 0 <= o2 < len(tdata)-7:
                        if tdata[o2:o2+7] == bytes([0x48,0x8B,0xC4,0x48,0x89,0x50,0x10]):
                            rendertext = t; break
                p += 1
        print('RenderText @0x%x' % rendertext if rendertext else 'RenderText NOT FOUND')

    pat = bytes([0x48,0x8B,0xC4,0x53,0x56,0x48,0x81,0xEC])
    cts = None
    for i in range(len(tdata) - 11):
        if tdata[i:i+8] == pat and tdata[i+8:i+12] == bytes([0x98,0x00,0x00,0x00]):
            cand = tva + i
            if func_start(cand) == cand:
                cts = cand; break
    print('CalcTextSizeA @0x%x' % cts if cts else 'CalcTextSizeA NOT FOUND')

    bpat = bytes([0x4C,0x8B,0xDC,0x55,0x53,0x48,0x8D,0xAB,0x38,0xFE,0xFF,0xFF,0x48,0x81,0xEC,0xB8,0x02,0x00,0x00])
    bld = None
    for i in range(len(tdata) - 18):
        if tdata[i:i+19] == bpat:
            bld = tva + i; break
    print('Build @0x%x' % bld if bld else 'Build NOT FOUND')

if __name__ == '__main__':
    main()
