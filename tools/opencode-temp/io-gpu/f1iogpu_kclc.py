import struct, sys

KC = r"G:/REPO\firmware\24A446\kernelcache.release.macho"
d = open(KC, 'rb').read()
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = struct.unpack_from('<IiiIIIII', d, 0)
print('magic 0x%x ncmds %d sizeofcmds %d filetype %d' % (magic, ncmds, sizeofcmds, filetype))
off = 32
for i in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    name = ''
    if cmd == 0x19:
        nm = d[off+8:off+24].split(b'\0')[0].decode()
        vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, fl = struct.unpack_from('<QQQQiiII', d, off+24)
        name = 'SEG %s vm=0x%x sz=0x%x off=0x%x fsz=0x%x nsects=%d' % (nm, vmaddr, vmsize, fileoff, filesize, nsects)
    elif cmd == 0x80000034:
        name = 'DYLD_CHAINED_FIXUPS @0x%x' % off
    elif cmd == 0x80000033:
        name = 'DYLD_EXPORTS_TRIE'
    elif cmd == 0x2:
        name = 'SYMTAB'
    elif cmd == 0xb:
        name = 'DYSYMTAB'
    elif cmd == 0x1b:
        name = 'UUID'
    elif cmd == 0x26:
        name = 'FUNCTION_STARTS'
    elif cmd == 0x29:
        name = 'DATA_IN_CODE'
    elif cmd == 0x32:
        name = 'BUILD_VERSION'
    elif cmd == 0x24:
        name = 'VERSION_MIN'
    elif cmd == 0x25:
        name = 'VERSION_MAX'
    elif cmd == 0x1d:
        name = 'CODE_SIGNATURE'
    elif cmd == 0x1e:
        name = 'SEGMENT_SPLIT_INFO'
    elif cmd == 0x80000022:
        name = 'DYLD_INFO_ONLY'
    elif cmd == 0x80000028:
        name = 'MAIN'
    print('  cmd=0x%-10x size=%-8d %s' % (cmd, cmdsize, name))
    off += cmdsize
