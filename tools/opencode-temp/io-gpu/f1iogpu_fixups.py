import struct, sys

KC = r"G:/REPO\firmware\24A446\kernelcache.release.macho"
d = open(KC, 'rb').read()

off = 32
fix = None
for i in range(314):
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    if cmd == 0x80000034:
        dataoff, datasize = struct.unpack_from('<II', d, off+8)
        fix = (off, dataoff, datasize)
        break
    off += cmdsize

print('LC_DYLD_CHAINED_FIXUPS cmd@0x%x dataoff=0x%x datasize=0x%x' % fix)
doff, dsize = fix[1], fix[2]
version, starts_off, imports_off, symbols_off, imports_count, imports_format, symbols_format = struct.unpack_from('<IIIIIII', d, doff)
print('fixups_version=%d starts_offset=0x%x imports_offset=0x%x symbols_offset=0x%x imports_count=%d imports_format=%d symbols_format=%d' % (
    version, starts_off, imports_off, symbols_off, imports_count, imports_format, symbols_format))

starts = doff + starts_off
seg_count, = struct.unpack_from('<I', d, starts)
print('seg_count', seg_count)
segs = []
for i in range(seg_count):
    so, = struct.unpack_from('<I', d, starts+4+4*i)
    if so == 0:
        segs.append(None)
        continue
    p = starts + so
    size, page_size, pointer_format = struct.unpack_from('<IHH', d, p)
    segment_offset, = struct.unpack_from('<Q', d, p+8)
    max_valid, = struct.unpack_from('<I', d, p+16)
    page_count, = struct.unpack_from('<H', d, p+20)
    page_start = struct.unpack_from('<%dH' % page_count, d, p+22)
    segs.append(dict(size=size, page_size=page_size, pointer_format=pointer_format,
                     segment_offset=segment_offset, max_valid=max_valid,
                     page_count=page_count, page_start=page_start, hdr_off=p))
    print('  seg[%d] ptrfmt=0x%x page_size=0x%x seg_off=0x%x max_valid=0x%x pages=%d starts=%s' % (
        i, pointer_format, page_size, segment_offset, max_valid, page_count,
        [hex(x) for x in page_start[:8]]))
