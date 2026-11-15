#!/usr/bin/env python3
"""Search kernel __TEXT_EXEC for strings related to zone_require_ro."""
from pathlib import Path

data = Path('G:/REPO/tools/agx-reach/kernel_analysis/kernel_text_exec.bin').read_bytes()
print(f'Searching {len(data):,} bytes of kernel __TEXT_EXEC')

# Search for 'zone_require' as ASCII string
pattern = b'zone_require'
offsets = []
start = 0
while True:
    idx = data.find(pattern, start)
    if idx == -1:
        break
    offsets.append(idx)
    start = idx + 1
print('Found', len(offsets), 'occurrences of zone_require')
for off in offsets[:20]:
    ctx = data[max(0, off-16):off+len(pattern)+16]
    print('  offset', hex(off), ':', ctx)

print()
# Search for 'panic' string
pattern = b'panic'
offsets2 = []
start = 0
while True:
    idx = data.find(pattern, start)
    if idx == -1:
        break
    offsets2.append(idx)
    start = idx + 1
print('Found', len(offsets2), 'occurrences of panic (first 10):')
for off in offsets2[:10]:
    ctx = data[max(0, off-16):off+len(pattern)+16]
    print('  offset', hex(off), ':', ctx)
