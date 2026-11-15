#!/usr/bin/env python3
"""Check bl instructions in text_exec_part3.txt."""
from pathlib import Path

data = Path('G:/REPO/tools/agx-reach/kernel_analysis/text_exec_part3.txt').read_bytes()
text = data.decode('utf-16-le')
lines = text.split('\n')
print(f'Total lines: {len(lines)}')

# Find lines with 'bl'
bl_lines = [l for l in lines if 'bl' in l]
print(f'Lines containing "bl": {len(bl_lines)}')
for l in bl_lines[:10]:
    print(f'  {l[:120]}')

# Find lines with 'adrp'
adrp_lines = [l for l in lines if 'adrp' in l.lower()]
print(f'\nLines containing "adrp": {len(adrp_lines)}')
for l in adrp_lines[:10]:
    print(f'  {l[:120]}')

# Find lines with 'cmp w'
cmp_lines = [l for l in lines if '\tcmp\tw' in l.lower()]
print(f'\nLines with cmp w: {len(cmp_lines)}')
for l in cmp_lines[:10]:
    print(f'  {l[:120]}')
