#!/usr/bin/env python3
"""Check encoding of disassembly file."""
from pathlib import Path

data = Path('G:/REPO/tools/agx-reach/kernel_analysis/text_exec_part3.txt').read_bytes()
print(f'File size: {len(data):,} bytes')
print(f'First 100 bytes hex: {data[:100].hex()}')
print(f'Has UTF-16LE BOM: {data[:2] == b"\\xff\\xfe"}')

# Try reading as UTF-16LE
try:
    text = data.decode('utf-16-le')
    print(f'Successfully decoded as UTF-16LE, {len(text)} chars')
    lines = text.split('\n')
    print(f'Number of lines: {len(lines)}')
    # Check for 'bl'
    bl_count = sum(1 for line in lines if '\\tbl\\t' in line or '\\tbl ' in line)
    print(f'Lines with bl: {bl_count}')
    # Show first few bl lines
    count = 0
    for line in lines:
        if '\\tbl\\t' in line or '\\tbl ' in line:
            print(f'  {line[:100]}')
            count += 1
            if count >= 5:
                break
except Exception as e:
    print(f'UTF-16LE decode error: {e}')
    # Try UTF-8
    try:
        text = data.decode('utf-8')
        print(f'Successfully decoded as UTF-8, {len(text)} chars')
    except Exception as e2:
        print(f'UTF-8 decode error: {e2}')
