import re

with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

def read_func(va, max_lines=50):
    va_str = f'{va:#018x}:'
    found = False
    for i, line in enumerate(lines):
        if line.startswith(va_str):
            found = True
            print(f'=== Function at {va_str} ===')
            for j in range(i, min(i+max_lines, len(lines))):
                print(f'  {lines[j].rstrip()}')
                if 'ret' in lines[j] and j > i + 3:
                    break
            print()
            break
    if not found:
        print(f'=== Function at {va_str} NOT FOUND ===\n')

read_func(0xfffffe0009009490, 40)
read_func(0xfffffe000900985c, 40)
