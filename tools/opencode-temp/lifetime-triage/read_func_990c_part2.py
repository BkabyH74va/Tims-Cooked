import re

with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

def read_func_range(va, start_offset=0, max_lines=60):
    va_str = f'{va:#018x}:'
    found = False
    for i, line in enumerate(lines):
        if line.startswith(va_str):
            found = True
            # Skip to start_offset lines
            start = i + start_offset
            print(f'=== Function at {va_str} (lines {start}-{start+max_lines}) ===')
            for j in range(start, min(start+max_lines, len(lines))):
                print(f'  {lines[j].rstrip()}')
                if 'ret' in lines[j] and j > start + 3:
                    break
            print()
            break
    if not found:
        print(f'=== Function at {va_str} NOT FOUND ===\n')

read_func_range(0xfffffe000900990c, start_offset=25, max_lines=60)
