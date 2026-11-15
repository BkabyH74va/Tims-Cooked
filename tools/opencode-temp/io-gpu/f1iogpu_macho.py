import struct, sys, os

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_INFO_ONLY = 0x80000022

class M:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        self.magic, self.cputype, self.cpusubtype, self.filetype, self.ncmds, self.sizeofcmds, self.flags, _ = struct.unpack_from('<IiiIIIII', d, 0)
        self.base = 0
        off = 32
        self.lcs = []
        for i in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from('<II', d, off)
            self.lcs.append((cmd, cmdsize, off))
            off += cmdsize
        self.segs = []
        for cmd, cmdsize, o in self.lcs:
            if cmd == LC_SEGMENT_64:
                name = d[o+8:o+24].split(b'\0')[0].decode('utf8', 'replace')
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from('<QQQQiiII', d, o+24)
                self.segs.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                                      filesize=filesize, nsects=nsects, off=o, flags=flags))
        self.symtab = None
        for cmd, cmdsize, o in self.lcs:
            if cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', d, o+8)
                self.symtab = (symoff, nsyms, stroff, strsize)
        self.fixups_off = None
        for cmd, cmdsize, o in self.lcs:
            if cmd == LC_DYLD_CHAINED_FIXUPS:
                self.fixups_off = o + 8

    def seg_by_name(self, n):
        for s in self.segs:
            if s['name'] == n:
                return s
        return None

    def cstr(self, off):
        e = self.d.index(b'\0', off)
        return self.d[off:e].decode('utf8', 'replace')

    def syms(self):
        if not self.symtab: return []
        symoff, nsyms, stroff, strsize = self.symtab
        out = []
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', self.d, symoff + i*16)
            name = self.cstr(stroff+n_strx) if n_strx else ''
            out.append((name, n_type, n_sect, n_desc, n_value))
        return out


def dump(m):
    print('file', m.d.__len__(), 'ncmds', m.ncmds, 'filetype', m.filetype)
    for s in m.segs:
        print('SEG %-24s vmaddr=0x%x vmsize=0x%x fileoff=0x%x filesize=0x%x nsects=%d' % (
            s['name'], s['vmaddr'], s['vmsize'], s['fileoff'], s['filesize'], s['nsects']))
    for cmd, cmdsize, o in m.lcs:
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from('<I', m.d, o+64)[0]
            so = o + 72
            for i in range(nsects):
                sectname = m.d[so:so+16].split(b'\0')[0].decode('utf8','replace')
                segname = m.d[so+16:so+32].split(b'\0')[0].decode('utf8','replace')
                addr, size, offset, align, reloff, nreloc, flags2, r1, r2, r3 = struct.unpack_from('<QQIIIIIIII', m.d, so+32)
                print('   SECT %-20s %-18s addr=0x%x size=0x%x off=0x%x' % (sectname, segname, addr, size, offset))
                so += 80
    print('fixups off', m.fixups_off)


if __name__ == '__main__':
    m = M(sys.argv[1])
    dump(m)
