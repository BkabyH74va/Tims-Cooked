import re

with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

va = 0xfffffe0009015df8
va_str = f'{va:#018x}:'
found = False
for i, line in enumerate(lines):
    if line.startswith(va_str):
        found = True
        print(f'=== Function at {va_str} ===')
        for j in range(i, min(i+80, len(lines))):
            print(f'  {lines[j].rstrip()}')
            if 'ret' in lines[j] and j > i + 3:
                break
        print()
        break
